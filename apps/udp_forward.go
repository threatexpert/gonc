package apps

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/threatexpert/gonc/v2/netx"
)

const (
	udpFwdSessionTimeout  = 120 * time.Second
	udpFwdCleanupInterval = 30 * time.Second
)

type udpForwarder struct {
	udpConn     *net.UDPConn
	targetHost  string
	targetPort  int
	session     interface{}
	muxcfg      *MuxSessionConfig
	logger      *log.Logger
	sessionDead int32 // atomic: mux session 失效后标记为 1

	clients   map[string]*udpFwdClient
	clientsMu sync.RWMutex

	done chan struct{}
}

type udpFwdClient struct {
	clientAddr   *net.UDPAddr
	tunnelStream net.Conn
	fwd          *udpForwarder
	lastActive   time.Time
	done         chan struct{}
	closeOnce    sync.Once
}

func startUDPForward(muxcfg *MuxSessionConfig, session interface{}, listenAddr string, targetHost string, targetPort int, doneChan <-chan struct{}) {
	logger := muxcfg.Logger

	lc := net.ListenConfig{Control: netx.ControlUDP}
	pc, err := lc.ListenPacket(context.Background(), "udp4", listenAddr)
	if err != nil {
		logger.Printf("[udp-fwd] Failed to listen UDP on %s: %v", listenAddr, err)
		return
	}
	udpConn := pc.(*net.UDPConn)

	fwd := &udpForwarder{
		udpConn:    udpConn,
		targetHost: targetHost,
		targetPort: targetPort,
		session:    session,
		muxcfg:     muxcfg,
		logger:     logger,
		clients:    make(map[string]*udpFwdClient),
		done:       make(chan struct{}),
	}

	logger.Printf("[udp-fwd] Listening on UDP %s -> %s:%d", udpConn.LocalAddr(), targetHost, targetPort)

	go func() {
		select {
		case <-doneChan:
		case <-fwd.done:
		}
		udpConn.Close()
		fwd.closeAll()
	}()

	go fwd.cleanupLoop()
	fwd.readLoop()
}

// readLoop 收包循环
// 已有会话：同步转发（无 goroutine，保序）
// 新会话：异步建立
func (f *udpForwarder) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, srcAddr, err := f.udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-f.done:
				return
			default:
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			f.logger.Printf("[udp-fwd] Read error: %v", err)
			return
		}

		// 串行检查状态（readLoop 是单线程，无竞态窗口）
		select {
		case <-f.done:
			return
		default:
		}
		if atomic.LoadInt32(&f.sessionDead) != 0 {
			continue
		}

		clientKey := srcAddr.String()

		// 快速路径：已有会话，同步转发，直接用 buf
		f.clientsMu.RLock()
		c, exists := f.clients[clientKey]
		f.clientsMu.RUnlock()

		if exists {
			c.sendToTunnel(buf[:n])
			continue
		}

		// 慢速路径：新会话，copy + 开协程
		dataCopy := make([]byte, n)
		copy(dataCopy, buf[:n])
		go f.handleNewClient(srcAddr, dataCopy)
	}
}

// handleNewClient 仅处理新客户端首包（独立 goroutine 中运行）
func (f *udpForwarder) handleNewClient(srcAddr *net.UDPAddr, data []byte) {
	select {
	case <-f.done:
		return
	default:
	}
	if atomic.LoadInt32(&f.sessionDead) != 0 {
		return
	}

	clientKey := srcAddr.String()

	f.clientsMu.Lock()
	if c, exists := f.clients[clientKey]; exists {
		f.clientsMu.Unlock()
		c.sendToTunnel(data)
		return
	}

	stream, err := openMuxStream(f.session)
	if err != nil {
		f.clientsMu.Unlock()
		atomic.StoreInt32(&f.sessionDead, 1)
		f.logger.Printf("[udp-fwd] Open mux stream failed (marking dead): %v", err)
		return
	}
	sw := newStreamWrapper(stream,
		muxSessionRemoteAddr(f.session),
		muxSessionLocalAddr(f.session))

	targetAddr := net.JoinHostPort(f.targetHost, strconv.Itoa(f.targetPort))
	requestLine := fmt.Sprintf("%s%s\n", TUNNEL_REQ_UDP, targetAddr)
	if _, err = sw.Write([]byte(requestLine)); err != nil {
		f.clientsMu.Unlock()
		sw.Close()
		atomic.StoreInt32(&f.sessionDead, 1)
		f.logger.Printf("[udp-fwd] Send tunnel request failed (marking dead): %v", err)
		return
	}

	sw.SetReadDeadline(time.Now().Add(25 * time.Second))
	resp, err := netx.ReadString(sw, '\n', 1024)
	if err != nil {
		f.clientsMu.Unlock()
		sw.Close()
		atomic.StoreInt32(&f.sessionDead, 1)
		f.logger.Printf("[udp-fwd] Read tunnel response failed (marking dead): %v", err)
		return
	}
	resp = udpFwdTrimCRLF(resp)
	if len(resp) < 2 || resp[:2] != "OK" {
		f.clientsMu.Unlock()
		sw.Close()
		atomic.StoreInt32(&f.sessionDead, 1)
		f.logger.Printf("[udp-fwd] Tunnel UDP associate failed (marking dead): %s", resp)
		return
	}
	sw.SetReadDeadline(time.Time{})

	c := &udpFwdClient{
		clientAddr:   srcAddr,
		tunnelStream: sw,
		fwd:          f,
		lastActive:   time.Now(),
		done:         make(chan struct{}),
	}
	f.clients[clientKey] = c
	f.clientsMu.Unlock()

	f.logger.Printf("[udp-fwd] New session: %s -> %s", srcAddr, targetAddr)

	go c.readFromTunnel()
	c.sendToTunnel(data)
}

func (c *udpFwdClient) sendToTunnel(data []byte) {
	c.lastActive = time.Now()

	select {
	case <-c.done:
		return
	default:
	}

	targetIP := net.ParseIP(c.fwd.targetHost)
	var hdr []byte

	if targetIP != nil {
		if v4 := targetIP.To4(); v4 != nil {
			hdr = []byte{0, 0, 0, ATYP_IPV4}
			hdr = append(hdr, v4...)
		} else if v6 := targetIP.To16(); v6 != nil {
			hdr = []byte{0, 0, 0, ATYP_IPV6}
			hdr = append(hdr, v6...)
		}
	} else {
		hb := []byte(c.fwd.targetHost)
		hdr = []byte{0, 0, 0, ATYP_DOMAINNAME, byte(len(hb))}
		hdr = append(hdr, hb...)
	}
	hdr = append(hdr, byte(c.fwd.targetPort>>8), byte(c.fwd.targetPort&0xFF))

	fullPacket := append(hdr, data...)
	if len(fullPacket) > 65535 {
		return
	}

	combined := make([]byte, 2+len(fullPacket))
	binary.BigEndian.PutUint16(combined[0:2], uint16(len(fullPacket)))
	copy(combined[2:], fullPacket)

	if _, err := c.tunnelStream.Write(combined); err != nil {
		c.fwd.logger.Printf("[udp-fwd] Tunnel write failed: %v", err)
		c.close()
	}
}

func (c *udpFwdClient) readFromTunnel() {
	defer c.close()

	lenBuf := make([]byte, 2)
	pktBuf := make([]byte, 65535)

	for {
		select {
		case <-c.done:
			return
		default:
		}

		c.tunnelStream.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err := udpFwdReadFull(c.tunnelStream, lenBuf, c.done); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		pktLen := int(binary.BigEndian.Uint16(lenBuf))
		if pktLen == 0 || pktLen > len(pktBuf) {
			continue
		}

		c.tunnelStream.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := udpFwdReadFullBuf(c.tunnelStream, pktBuf[:pktLen]); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		c.lastActive = time.Now()

		payload, err := udpFwdStripSocks5Header(pktBuf[:pktLen])
		if err != nil {
			continue
		}

		c.fwd.udpConn.WriteToUDP(payload, c.clientAddr)
	}
}

func (c *udpFwdClient) close() {
	c.closeOnce.Do(func() {
		close(c.done)
		c.tunnelStream.Close()
		c.fwd.logger.Printf("[udp-fwd] Closed: %s", c.clientAddr)
	})
}

// --- 清理 ---

func (f *udpForwarder) cleanupLoop() {
	ticker := time.NewTicker(udpFwdCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-f.done:
			return
		case <-ticker.C:
			f.cleanup()
		}
	}
}

func (f *udpForwarder) cleanup() {
	now := time.Now()

	var expired []*udpFwdClient
	f.clientsMu.Lock()
	for key, c := range f.clients {
		if now.Sub(c.lastActive) > udpFwdSessionTimeout {
			expired = append(expired, c)
			delete(f.clients, key)
		}
	}
	f.clientsMu.Unlock()

	for _, c := range expired {
		c.close()
	}
}

func (f *udpForwarder) closeAll() {
	select {
	case <-f.done:
		return
	default:
		close(f.done)
	}

	f.clientsMu.Lock()
	all := make([]*udpFwdClient, 0, len(f.clients))
	for _, c := range f.clients {
		all = append(all, c)
	}
	f.clients = make(map[string]*udpFwdClient)
	f.clientsMu.Unlock()

	for _, c := range all {
		c.close()
	}
}

// --- 辅助函数 ---

func udpFwdTrimCRLF(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

func udpFwdStripSocks5Header(pkt []byte) ([]byte, error) {
	if len(pkt) < 10 {
		return nil, fmt.Errorf("too short: %d", len(pkt))
	}
	atyp := pkt[3]
	hl := 0
	switch atyp {
	case ATYP_IPV4:
		hl = 10
	case ATYP_IPV6:
		if len(pkt) < 22 {
			return nil, fmt.Errorf("v6 too short")
		}
		hl = 22
	case ATYP_DOMAINNAME:
		if len(pkt) < 5 {
			return nil, fmt.Errorf("domain too short")
		}
		hl = 4 + 1 + int(pkt[4]) + 2
		if len(pkt) < hl {
			return nil, fmt.Errorf("domain data short")
		}
	default:
		return nil, fmt.Errorf("bad ATYP: %d", atyp)
	}
	return pkt[hl:], nil
}

func udpFwdReadFull(r net.Conn, buf []byte, done <-chan struct{}) error {
	rd := 0
	for rd < len(buf) {
		select {
		case <-done:
			return fmt.Errorf("session closed")
		default:
		}
		n, err := r.Read(buf[rd:])
		rd += n
		if err != nil {
			return err
		}
	}
	return nil
}

func udpFwdReadFullBuf(r net.Conn, buf []byte) (int, error) {
	rd := 0
	for rd < len(buf) {
		n, err := r.Read(buf[rd:])
		rd += n
		if err != nil {
			return rd, err
		}
	}
	return rd, nil
}
