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
	udpTProxySessionTimeout  = 120 * time.Second
	udpTProxyCleanupInterval = 30 * time.Second
	udpOOBSize               = 256
)

type udpTProxyRelay struct {
	mainConn    *net.UDPConn
	listenPort  int
	allowPublic bool
	session     interface{}
	muxcfg      *MuxSessionConfig
	logger      *log.Logger

	magicSessions map[string]*udpMagicIPSession
	mu            sync.RWMutex

	done chan struct{}
}

type udpMagicIPSession struct {
	magicIP     net.IP
	udpConn     *net.UDPConn
	clients     map[string]*udpClientSession
	clientsMu   sync.RWMutex
	relay       *udpTProxyRelay
	lastActive  time.Time
	done        chan struct{}
	sessionDead int32 // atomic: mux session 失效后标记为 1，不再尝试建新会话

	resolveOnce sync.Once
	targetHost  string
	targetPort  int
	resolveErr  error
}

type udpClientSession struct {
	clientAddr   *net.UDPAddr
	targetHost   string
	targetPort   int
	tunnelStream net.Conn
	magicSession *udpMagicIPSession
	lastActive   time.Time
	done         chan struct{}
	closeOnce    sync.Once
	logger       *log.Logger
}

func startUDPTProxy(muxcfg *MuxSessionConfig, session interface{}, listenPort int, allowPublic bool, doneChan <-chan struct{}) {
	logger := muxcfg.Logger

	lc := net.ListenConfig{Control: netx.ControlUDP}
	bindAddr := fmt.Sprintf("0.0.0.0:%d", listenPort)
	pc, err := lc.ListenPacket(context.Background(), "udp4", bindAddr)
	if err != nil {
		logger.Printf("[udp-tproxy] Failed to listen UDP on %s: %v", bindAddr, err)
		return
	}
	mainConn := pc.(*net.UDPConn)

	if err := enablePktInfo(mainConn); err != nil {
		logger.Printf("[udp-tproxy] Failed to enable IP_PKTINFO: %v", err)
		mainConn.Close()
		return
	}

	relay := &udpTProxyRelay{
		mainConn:      mainConn,
		listenPort:    listenPort,
		allowPublic:   allowPublic,
		session:       session,
		muxcfg:        muxcfg,
		logger:        logger,
		magicSessions: make(map[string]*udpMagicIPSession),
		done:          make(chan struct{}),
	}

	logger.Printf("[udp-tproxy] Listening on UDP %s", mainConn.LocalAddr())

	go func() {
		select {
		case <-doneChan:
		case <-relay.done:
		}
		mainConn.Close()
		relay.closeAll()
	}()

	go relay.cleanupLoop()
	relay.mainReadLoop()
}

func (r *udpTProxyRelay) mainReadLoop() {
	buf := make([]byte, 65535)
	oob := make([]byte, udpOOBSize)

	for {
		n, oobn, _, srcAddr, err := r.mainConn.ReadMsgUDP(buf, oob)
		if err != nil {
			select {
			case <-r.done:
				return
			default:
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			r.logger.Printf("[udp-tproxy] Main read error: %v", err)
			return
		}

		if srcAddr == nil || oobn == 0 {
			continue
		}

		// 检查 relay 是否已关闭
		select {
		case <-r.done:
			return
		default:
		}

		dstIP, err := parseDstIPFromOOB(oob[:oobn])
		if err != nil || dstIP == nil {
			continue
		}

		dstIPv4 := dstIP.To4()
		if dstIPv4 == nil || dstIPv4[0] != 127 || dstIPv4.Equal(net.IPv4(127, 0, 0, 1)) {
			continue
		}

		magicIPStr := dstIPv4.String()
		magicSess := r.getOrCreateMagicSession(magicIPStr, dstIPv4)
		if magicSess == nil {
			continue
		}

		// 主 socket 收到的首包：必须 copy + 异步（因为后续专用 socket 接管）
		dataCopy := make([]byte, n)
		copy(dataCopy, buf[:n])
		go magicSess.handleNewClient(srcAddr, dataCopy)
	}
}

func (r *udpTProxyRelay) getOrCreateMagicSession(magicIPStr string, magicIP net.IP) *udpMagicIPSession {
	r.mu.RLock()
	sess, exists := r.magicSessions[magicIPStr]
	r.mu.RUnlock()
	if exists {
		return sess
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if sess, exists = r.magicSessions[magicIPStr]; exists {
		return sess
	}

	lc := net.ListenConfig{Control: netx.ControlUDP}
	bindAddr := net.JoinHostPort(magicIPStr, strconv.Itoa(r.listenPort))
	pc, err := lc.ListenPacket(context.Background(), "udp4", bindAddr)
	if err != nil {
		r.logger.Printf("[udp-tproxy] Bind %s failed: %v", bindAddr, err)
		return nil
	}

	sess = &udpMagicIPSession{
		magicIP:    make(net.IP, len(magicIP)),
		udpConn:    pc.(*net.UDPConn),
		clients:    make(map[string]*udpClientSession),
		relay:      r,
		lastActive: time.Now(),
		done:       make(chan struct{}),
	}
	copy(sess.magicIP, magicIP)
	r.magicSessions[magicIPStr] = sess

	r.logger.Printf("[udp-tproxy] New magic socket: %s", bindAddr)
	go sess.readLoop()

	return sess
}

func (ms *udpMagicIPSession) resolveTarget() (string, int, error) {
	ms.resolveOnce.Do(func() {
		ms.targetHost, ms.targetPort, ms.resolveErr = DNSLookupMagicIP(ms.magicIP.String(), ms.relay.allowPublic)
	})
	return ms.targetHost, ms.targetPort, ms.resolveErr
}

// readLoop 专用 socket 收包循环
// 已有会话：同步转发（无 goroutine 开销，保序）
// 新会话：异步建立（因为有阻塞握手）
func (ms *udpMagicIPSession) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, srcAddr, err := ms.udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ms.done:
				return
			default:
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			ms.relay.logger.Printf("[udp-tproxy] Socket %s read error: %v", ms.magicIP, err)
			return
		}

		if srcAddr.IP.To4() == nil || srcAddr.IP.To4()[0] != 127 {
			continue
		}

		// 串行检查 relay 和 session 状态（在 readLoop 线程内，无竞态窗口）
		select {
		case <-ms.relay.done:
			return
		default:
		}
		if atomic.LoadInt32(&ms.sessionDead) != 0 {
			continue // mux 已死，静默丢弃
		}

		ms.lastActive = time.Now()
		clientKey := srcAddr.String()

		// 快速路径：已有会话，同步转发，直接用 buf（sendToTunnel 内会 copy）
		ms.clientsMu.RLock()
		cs, exists := ms.clients[clientKey]
		ms.clientsMu.RUnlock()

		if exists {
			cs.sendToTunnel(buf[:n])
			continue
		}

		// 慢速路径：新会话，copy 数据 + 开协程（阻塞握手）
		dataCopy := make([]byte, n)
		copy(dataCopy, buf[:n])
		go ms.handleNewClient(srcAddr, dataCopy)
	}
}

// handleNewClient 仅处理新客户端的首包（在独立 goroutine 中运行）
func (ms *udpMagicIPSession) handleNewClient(srcAddr *net.UDPAddr, data []byte) {
	// 再次检查（可能在排队期间状态变了）
	select {
	case <-ms.relay.done:
		return
	default:
	}
	if atomic.LoadInt32(&ms.sessionDead) != 0 {
		return
	}

	clientKey := srcAddr.String()

	ms.clientsMu.Lock()
	// double-check：可能另一个 goroutine 已经创建了
	if cs, exists := ms.clients[clientKey]; exists {
		ms.clientsMu.Unlock()
		cs.sendToTunnel(data)
		return
	}

	targetHost, targetPort, err := ms.resolveTarget()
	if err != nil {
		ms.clientsMu.Unlock()
		ms.relay.logger.Printf("[udp-tproxy] MagicIP lookup %s failed: %v", ms.magicIP, err)
		return
	}

	stream, err := openMuxStream(ms.relay.session)
	if err != nil {
		ms.clientsMu.Unlock()
		atomic.StoreInt32(&ms.sessionDead, 1) // 标记为 dead，后续包全部丢弃
		ms.relay.logger.Printf("[udp-tproxy] Open mux stream failed (marking dead): %v", err)
		return
	}
	sw := newStreamWrapper(stream,
		muxSessionRemoteAddr(ms.relay.session),
		muxSessionLocalAddr(ms.relay.session))

	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	requestLine := fmt.Sprintf("%s%s\n", TUNNEL_REQ_UDP, targetAddr)
	if _, err = sw.Write([]byte(requestLine)); err != nil {
		ms.clientsMu.Unlock()
		sw.Close()
		atomic.StoreInt32(&ms.sessionDead, 1)
		ms.relay.logger.Printf("[udp-tproxy] Send tunnel request failed (marking dead): %v", err)
		return
	}

	sw.SetReadDeadline(time.Now().Add(25 * time.Second))
	resp, err := netx.ReadString(sw, '\n', 1024)
	if err != nil {
		ms.clientsMu.Unlock()
		sw.Close()
		atomic.StoreInt32(&ms.sessionDead, 1)
		ms.relay.logger.Printf("[udp-tproxy] Read tunnel response failed (marking dead): %v", err)
		return
	}
	resp = trimCRLF(resp)
	if len(resp) < 2 || resp[:2] != "OK" {
		ms.clientsMu.Unlock()
		sw.Close()
		atomic.StoreInt32(&ms.sessionDead, 1)
		ms.relay.logger.Printf("[udp-tproxy] Tunnel UDP associate failed (marking dead): %s", resp)
		return
	}
	sw.SetReadDeadline(time.Time{})

	cs := &udpClientSession{
		clientAddr:   srcAddr,
		targetHost:   targetHost,
		targetPort:   targetPort,
		tunnelStream: sw,
		magicSession: ms,
		lastActive:   time.Now(),
		done:         make(chan struct{}),
		logger:       ms.relay.logger,
	}
	ms.clients[clientKey] = cs
	ms.clientsMu.Unlock()

	ms.relay.logger.Printf("[udp-tproxy] New: %s -> %s (via %s)", srcAddr, targetAddr, ms.magicIP)

	go cs.readFromTunnel()
	cs.sendToTunnel(data)
}

// sendToTunnel 封装为 SOCKS5 UDP 格式写入 tunnel
// 注意：此函数可能在 readLoop 线程中同步调用，也可能在 handleNewClient goroutine 中调用
// 内部会 make 新 buffer，不持有调用方的 buf 引用
func (cs *udpClientSession) sendToTunnel(data []byte) {
	cs.lastActive = time.Now()

	select {
	case <-cs.done:
		return
	default:
	}

	targetIP := net.ParseIP(cs.targetHost)
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
		hb := []byte(cs.targetHost)
		hdr = []byte{0, 0, 0, ATYP_DOMAINNAME, byte(len(hb))}
		hdr = append(hdr, hb...)
	}
	hdr = append(hdr, byte(cs.targetPort>>8), byte(cs.targetPort&0xFF))

	fullPacket := append(hdr, data...)
	if len(fullPacket) > 65535 {
		return
	}

	// 分配新 buffer，不持有调用方 data 的引用
	combined := make([]byte, 2+len(fullPacket))
	binary.BigEndian.PutUint16(combined[0:2], uint16(len(fullPacket)))
	copy(combined[2:], fullPacket)

	if _, err := cs.tunnelStream.Write(combined); err != nil {
		cs.logger.Printf("[udp-tproxy] Tunnel write failed: %v", err)
		cs.close()
	}
}

func (cs *udpClientSession) readFromTunnel() {
	defer cs.close()

	lenBuf := make([]byte, 2)
	pktBuf := make([]byte, 65535)

	for {
		select {
		case <-cs.done:
			return
		default:
		}

		cs.tunnelStream.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err := udpReadFull(cs.tunnelStream, lenBuf, cs.done); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		pktLen := int(binary.BigEndian.Uint16(lenBuf))
		if pktLen == 0 || pktLen > len(pktBuf) {
			continue
		}

		cs.tunnelStream.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := udpReadFullBuf(cs.tunnelStream, pktBuf[:pktLen]); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		cs.lastActive = time.Now()

		payload, err := udpStripSocks5Header(pktBuf[:pktLen])
		if err != nil {
			continue
		}

		cs.magicSession.udpConn.WriteToUDP(payload, cs.clientAddr)
	}
}

func (cs *udpClientSession) close() {
	cs.closeOnce.Do(func() {
		close(cs.done)
		cs.tunnelStream.Close()
		cs.logger.Printf("[udp-tproxy] Closed: %s -> %s:%d", cs.clientAddr, cs.targetHost, cs.targetPort)
	})
}

// --- 清理 ---

func (r *udpTProxyRelay) cleanupLoop() {
	ticker := time.NewTicker(udpTProxyCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-ticker.C:
			r.cleanup()
		}
	}
}

func (r *udpTProxyRelay) cleanup() {
	now := time.Now()

	r.mu.RLock()
	snap := make(map[string]*udpMagicIPSession, len(r.magicSessions))
	for k, v := range r.magicSessions {
		snap[k] = v
	}
	r.mu.RUnlock()

	for key, ms := range snap {
		var expired []*udpClientSession
		ms.clientsMu.Lock()
		for ck, cs := range ms.clients {
			if now.Sub(cs.lastActive) > udpTProxySessionTimeout {
				expired = append(expired, cs)
				delete(ms.clients, ck)
			}
		}
		remaining := len(ms.clients)
		ms.clientsMu.Unlock()

		for _, cs := range expired {
			cs.close()
		}

		if remaining == 0 && now.Sub(ms.lastActive) > udpTProxySessionTimeout {
			r.mu.Lock()
			if s, ok := r.magicSessions[key]; ok && s == ms {
				delete(r.magicSessions, key)
				select {
				case <-ms.done:
				default:
					close(ms.done)
				}
				ms.udpConn.Close()
				r.logger.Printf("[udp-tproxy] Cleaned: %s", key)
			}
			r.mu.Unlock()
		}
	}
}

func (r *udpTProxyRelay) closeAll() {
	select {
	case <-r.done:
		return
	default:
		close(r.done)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, ms := range r.magicSessions {
		ms.clientsMu.Lock()
		for _, cs := range ms.clients {
			cs.close()
		}
		ms.clients = make(map[string]*udpClientSession)
		ms.clientsMu.Unlock()
		select {
		case <-ms.done:
		default:
			close(ms.done)
		}
		ms.udpConn.Close()
	}
	r.magicSessions = make(map[string]*udpMagicIPSession)
}

// --- 辅助函数 ---

func trimCRLF(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

func udpStripSocks5Header(pkt []byte) ([]byte, error) {
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

func udpReadFull(r net.Conn, buf []byte, done <-chan struct{}) error {
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

func udpReadFullBuf(r net.Conn, buf []byte) (int, error) {
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
