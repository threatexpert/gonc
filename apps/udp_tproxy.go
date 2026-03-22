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
// UDP Transparent Proxy for TProxy mode
//
// 当 tproxy=1 时，在同一端口上额外监听 UDP。
// 客户端发往 127.x.y.z:port 的 UDP 包，通过 MagicIP 解析出真实目标地址，
// 然后通过 mux tunnel 的 UDP Associate 转发到远端。
//
// 关键设计：
//   - 主 socket (0.0.0.0:port) 通过 syscall IP_PKTINFO + ReadMsgUDP 获取首包 dst IP
//   - 为每个 magic IP 创建专用 socket (magicIP:port, SO_REUSEADDR)
//   - 专用 socket 的回包源地址天然正确，Linux/Windows 通用
//   - 不依赖 golang.org/x/net/ipv4（Windows 上 SetControlMessage 未实现）
//   - 平台差异封装在 udp_pktinfo_unix.go / udp_pktinfo_windows.go 中
// =============================================================================

const (
	udpTProxySessionTimeout  = 120 * time.Second // UDP 会话超时
	udpTProxyCleanupInterval = 30 * time.Second  // 清理间隔
	udpOOBSize               = 256               // OOB buffer 大小
)

// udpTProxyRelay 管理整个 UDP 透明代理
type udpTProxyRelay struct {
	mainConn    *net.UDPConn // 主 socket: 0.0.0.0:port
	listenPort  int
	allowPublic bool
	session     interface{} // mux session
	muxcfg      *MuxSessionConfig
	logger      *log.Logger

	magicSessions map[string]*udpMagicIPSession // key = magicIP string
	mu            sync.RWMutex

	done chan struct{}
}

// udpMagicIPSession 对应一个 magic IP 的专用 socket
type udpMagicIPSession struct {
	magicIP    net.IP
	udpConn    *net.UDPConn
	clients    map[string]*udpClientSession // key = clientAddr
	clientsMu  sync.RWMutex
	relay      *udpTProxyRelay
	lastActive time.Time
	done       chan struct{}
}

// udpClientSession 对应一个 (clientAddr + magicIP) 的转发会话
type udpClientSession struct {
	clientAddr   *net.UDPAddr
	targetHost   string
	targetPort   int
	tunnelStream net.Conn // mux stream
	magicSession *udpMagicIPSession
	lastActive   time.Time
	done         chan struct{}
	closeOnce    sync.Once
	logger       *log.Logger
}

// startUDPTProxy 启动 UDP 透明代理（在 runLinkListener 中调用）
func startUDPTProxy(muxcfg *MuxSessionConfig, session interface{}, listenPort int, allowPublic bool, doneChan <-chan struct{}) {
	logger := muxcfg.Logger

	// 创建主 UDP socket (SO_REUSEADDR)
	lc := net.ListenConfig{
		Control: netx.ControlUDP,
	}
	bindAddr := fmt.Sprintf("0.0.0.0:%d", listenPort)
	pc, err := lc.ListenPacket(context.Background(), "udp4", bindAddr)
	if err != nil {
		logger.Printf("[udp-tproxy] Failed to listen UDP on %s: %v", bindAddr, err)
		return
	}
	mainConn := pc.(*net.UDPConn)

	// 通过 syscall 启用 IP_PKTINFO（见 udp_pktinfo_unix.go / udp_pktinfo_windows.go）
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

// mainReadLoop 使用 ReadMsgUDP + OOB 解析获取 dst IP
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

		// 平台特定的 OOB 解析（见 udp_pktinfo_*.go）
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

		dataCopy := make([]byte, n)
		copy(dataCopy, buf[:n])
		go magicSess.handlePacket(srcAddr, dataCopy)
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

	// 创建绑定到 magicIP:port 的专用 socket (SO_REUSEADDR)
	lc := net.ListenConfig{
		Control: netx.ControlUDP,
	}
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

// readLoop 专用 socket 收包循环
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

		dataCopy := make([]byte, n)
		copy(dataCopy, buf[:n])
		go ms.handlePacket(srcAddr, dataCopy)
	}
}

func (ms *udpMagicIPSession) handlePacket(srcAddr *net.UDPAddr, data []byte) {
	ms.lastActive = time.Now()
	clientKey := srcAddr.String()

	ms.clientsMu.RLock()
	cs, exists := ms.clients[clientKey]
	ms.clientsMu.RUnlock()

	if exists {
		cs.sendToTunnel(data)
		return
	}

	ms.clientsMu.Lock()
	if cs, exists = ms.clients[clientKey]; exists {
		ms.clientsMu.Unlock()
		cs.sendToTunnel(data)
		return
	}

	// 解析 magic IP -> 真实目标
	targetHost, targetPort, err := DNSLookupMagicIP(ms.magicIP.String(), ms.relay.allowPublic)
	if err != nil {
		ms.clientsMu.Unlock()
		ms.relay.logger.Printf("[udp-tproxy] MagicIP lookup %s failed: %v", ms.magicIP, err)
		return
	}

	// 打开 mux stream
	stream, err := openMuxStream(ms.relay.session)
	if err != nil {
		ms.clientsMu.Unlock()
		ms.relay.logger.Printf("[udp-tproxy] Open mux stream failed: %v", err)
		return
	}
	sw := newStreamWrapper(stream,
		muxSessionRemoteAddr(ms.relay.session),
		muxSessionLocalAddr(ms.relay.session))

	// 发送 UDP Associate 请求
	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	requestLine := fmt.Sprintf("%s%s\n", TUNNEL_REQ_UDP, targetAddr)
	if _, err = sw.Write([]byte(requestLine)); err != nil {
		ms.clientsMu.Unlock()
		sw.Close()
		ms.relay.logger.Printf("[udp-tproxy] Send tunnel request failed: %v", err)
		return
	}

	// 等待 OK
	sw.SetReadDeadline(time.Now().Add(25 * time.Second))
	resp, err := netx.ReadString(sw, '\n', 1024)
	if err != nil {
		ms.clientsMu.Unlock()
		sw.Close()
		ms.relay.logger.Printf("[udp-tproxy] Read tunnel response failed: %v", err)
		return
	}
	resp = trimCRLF(resp)
	if len(resp) < 2 || resp[:2] != "OK" {
		ms.clientsMu.Unlock()
		sw.Close()
		ms.relay.logger.Printf("[udp-tproxy] Tunnel UDP associate failed: %s", resp)
		return
	}
	sw.SetReadDeadline(time.Time{})

	cs = &udpClientSession{
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
func (cs *udpClientSession) sendToTunnel(data []byte) {
	cs.lastActive = time.Now()

	select {
	case <-cs.done:
		return
	default:
	}

	// SOCKS5 UDP header: RSV(2) + FRAG(1) + ATYP(1) + ADDR(var) + PORT(2)
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

	// [2 bytes length] + [socks5 udp packet] — 原子写入
	combined := make([]byte, 2+len(fullPacket))
	binary.BigEndian.PutUint16(combined[0:2], uint16(len(fullPacket)))
	copy(combined[2:], fullPacket)

	if _, err := cs.tunnelStream.Write(combined); err != nil {
		cs.logger.Printf("[udp-tproxy] Tunnel write failed: %v", err)
		cs.close()
	}
}

// readFromTunnel 从 tunnel 读取回包，剥离 SOCKS5 头，发回客户端
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

		// 剥离 SOCKS5 UDP 头
		payload, err := udpStripSocks5Header(pktBuf[:pktLen])
		if err != nil {
			continue
		}

		// 通过专用 socket 回包（源 IP 天然正确）
		cs.magicSession.udpConn.WriteToUDP(payload, cs.clientAddr)
	}
}

func (cs *udpClientSession) close() {
	cs.closeOnce.Do(func() {
		close(cs.done)
		cs.tunnelStream.Close()

		cs.magicSession.clientsMu.Lock()
		delete(cs.magicSession.clients, cs.clientAddr.String())
		cs.magicSession.clientsMu.Unlock()

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
		ms.clientsMu.Lock()
		for ck, cs := range ms.clients {
			if now.Sub(cs.lastActive) > udpTProxySessionTimeout {
				cs.close()
				delete(ms.clients, ck)
			}
		}
		rem := len(ms.clients)
		ms.clientsMu.Unlock()

		if rem == 0 && now.Sub(ms.lastActive) > udpTProxySessionTimeout {
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
