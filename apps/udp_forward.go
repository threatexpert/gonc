package apps

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/threatexpert/gonc/v2/netx"
)

// =============================================================================
// UDP Forward for f:// mode (proto=udp / proto=all)
//
// 固定目标的 UDP 端口转发：
//   本地 UDP listen → 收到客户端 UDP 包 → 通过 mux tunnel 转发 → 远端 UDP 发出
//
// 与 tproxy 不同：目标地址是配置时确定的（to=host:port），无需 magic IP 解析。
// 远端复用现有的 handleRemoteUDPAssociate，零改动。
// =============================================================================

const (
	udpFwdSessionTimeout  = 120 * time.Second
	udpFwdCleanupInterval = 30 * time.Second
)

// udpForwarder 管理一个 UDP 端口转发实例
type udpForwarder struct {
	udpConn    *net.UDPConn
	targetHost string
	targetPort int
	session    interface{} // mux session
	muxcfg     *MuxSessionConfig
	logger     *log.Logger

	clients   map[string]*udpFwdClient // key = clientAddr
	clientsMu sync.RWMutex

	done chan struct{}
}

// udpFwdClient 对应一个客户端地址的转发会话
type udpFwdClient struct {
	clientAddr   *net.UDPAddr
	tunnelStream net.Conn
	fwd          *udpForwarder
	lastActive   time.Time
	done         chan struct{}
	closeOnce    sync.Once
}

// startUDPForward 启动 UDP 端口转发（在 runLinkListener 中调用）
func startUDPForward(muxcfg *MuxSessionConfig, session interface{}, listenAddr string, targetHost string, targetPort int, doneChan <-chan struct{}) {
	logger := muxcfg.Logger

	lc := net.ListenConfig{
		Control: netx.ControlUDP,
	}
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

		dataCopy := make([]byte, n)
		copy(dataCopy, buf[:n])
		go f.handlePacket(srcAddr, dataCopy)
	}
}

func (f *udpForwarder) handlePacket(srcAddr *net.UDPAddr, data []byte) {
	clientKey := srcAddr.String()

	f.clientsMu.RLock()
	c, exists := f.clients[clientKey]
	f.clientsMu.RUnlock()

	if exists {
		c.sendToTunnel(data)
		return
	}

	f.clientsMu.Lock()
	if c, exists = f.clients[clientKey]; exists {
		f.clientsMu.Unlock()
		c.sendToTunnel(data)
		return
	}

	// 打开 mux stream
	stream, err := openMuxStream(f.session)
	if err != nil {
		f.clientsMu.Unlock()
		f.logger.Printf("[udp-fwd] Open mux stream failed: %v", err)
		return
	}
	sw := newStreamWrapper(stream,
		muxSessionRemoteAddr(f.session),
		muxSessionLocalAddr(f.session))

	// 发送 UDP Associate 请求
	targetAddr := net.JoinHostPort(f.targetHost, strconv.Itoa(f.targetPort))
	requestLine := fmt.Sprintf("%s%s\n", TUNNEL_REQ_UDP, targetAddr)
	if _, err = sw.Write([]byte(requestLine)); err != nil {
		f.clientsMu.Unlock()
		sw.Close()
		f.logger.Printf("[udp-fwd] Send tunnel request failed: %v", err)
		return
	}

	sw.SetReadDeadline(time.Now().Add(25 * time.Second))
	resp, err := netx.ReadString(sw, '\n', 1024)
	if err != nil {
		f.clientsMu.Unlock()
		sw.Close()
		f.logger.Printf("[udp-fwd] Read tunnel response failed: %v", err)
		return
	}
	resp = udpFwdTrimCRLF(resp)
	if len(resp) < 2 || resp[:2] != "OK" {
		f.clientsMu.Unlock()
		sw.Close()
		f.logger.Printf("[udp-fwd] Tunnel UDP associate failed: %s", resp)
		return
	}
	sw.SetReadDeadline(time.Time{})

	c = &udpFwdClient{
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

// sendToTunnel 封装为 SOCKS5 UDP 格式写入 tunnel
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

// readFromTunnel 从 tunnel 读回包，剥离 SOCKS5 头，发回客户端
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

		c.fwd.clientsMu.Lock()
		delete(c.fwd.clients, c.clientAddr.String())
		c.fwd.clientsMu.Unlock()

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
	f.clientsMu.Lock()
	for key, c := range f.clients {
		if now.Sub(c.lastActive) > udpFwdSessionTimeout {
			c.close()
			delete(f.clients, key)
		}
	}
	f.clientsMu.Unlock()
}

func (f *udpForwarder) closeAll() {
	select {
	case <-f.done:
		return
	default:
		close(f.done)
	}

	f.clientsMu.Lock()
	for _, c := range f.clients {
		c.close()
	}
	f.clients = make(map[string]*udpFwdClient)
	f.clientsMu.Unlock()
}

// --- 辅助函数（避免与 udp_tproxy.go 中的同名函数冲突）---

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
