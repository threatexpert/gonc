package easyp2p

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/threatexpert/gonc/v2/misc"
	"golang.org/x/net/ipv4"
)

// ============================================================================
// LAN Discovery Protocol v6
//
// 核心修改:
//   1. 单读协程分发模型 — 一个 goroutine 读 mconn, 按消息类型分发到不同 channel,
//      彻底消除 initiator/responder 争抢同一个 socket 的问题
//   2. 四步握手: Beacon → Response → Confirm → Ack
//      confirm 和 response 都持续重发直到收到对方回应
//   3. 打洞传 round=0 跳过 Mqtt_P2P_Round_Sync,
//      四步握手本身就完成了时机同步
// ============================================================================

const (
	LANMulticastIP   = "239.255.255.250"
	LANMulticastPort = 19730
	LANBeaconMagic   = "GONC-LAN-V1"
	LANNonceSize     = 16

	lanActiveBeaconInterval     = 1500 * time.Millisecond
	lanActiveSlowBeaconInterval = 5 * time.Second
	lanActiveFastBeaconWindow   = 30 * time.Second
	lanPassiveBeaconInterval    = 15 * time.Second

	lanMsgBeacon   = "B"
	lanMsgResponse = "R"
	lanMsgConfirm  = "C"
	lanMsgAck      = "A"
)

// ── 消息 ────────────────────────────────────────────────────

type lanMsg struct {
	Magic   string `json:"m"`
	Type    string `json:"t"`
	Payload string `json:"p"`
	HMAC    string `json:"mac"`
}

type lanBeacon struct {
	SessionID string `json:"sid"`
	NonceA    string `json:"na"`
	Transport string `json:"tp"`
}

type lanResponse struct {
	NonceA    string `json:"na"`
	NonceB    string `json:"nb"`
	Transport string `json:"tp"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
}

type lanConfirm struct {
	NonceB    string `json:"nb"`
	Transport string `json:"tp"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
}

type lanAck struct {
	NonceA string `json:"na"`
}

type LANDiscoverResult struct {
	LocalIP     string
	LocalPort   int
	RemoteIP    string
	RemotePort  int
	Transport   string
	IsInitiator bool
}

// ── 带源地址的收包 ──────────────────────────────────────────

type lanRecvPacket struct {
	msg *lanMsg
	src net.Addr
}

// ── 密钥 / HMAC ─────────────────────────────────────────────

func lanDeriveKey(sessionKey string) []byte {
	h := sha256.New()
	h.Write([]byte("gonc-lan-discovery-v1"))
	h.Write([]byte(sessionKey))
	return h.Sum(nil)
}

func lanDeriveSessionID(sessionKey string) string {
	h := sha256.New()
	h.Write([]byte("gonc-lan-session-id-v1"))
	h.Write([]byte(sessionKey))
	return base64.RawStdEncoding.EncodeToString(h.Sum(nil)[:12])
}

func lanHMAC(key []byte, t, p string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(t + "|" + p))
	return base64.RawStdEncoding.EncodeToString(mac.Sum(nil))
}

func lanVerify(key []byte, m *lanMsg) bool {
	return hmac.Equal([]byte(lanHMAC(key, m.Type, m.Payload)), []byte(m.HMAC))
}

func lanNonce() string {
	b := make([]byte, LANNonceSize)
	rand.Read(b)
	return base64.RawStdEncoding.EncodeToString(b)
}

func lanEncode(key []byte, t string, payload interface{}) []byte {
	pb, _ := json.Marshal(payload)
	p64 := base64.RawStdEncoding.EncodeToString(pb)
	data, _ := json.Marshal(lanMsg{Magic: LANBeaconMagic, Type: t, Payload: p64, HMAC: lanHMAC(key, t, p64)})
	return data
}

func lanDecode(key, data []byte) (*lanMsg, error) {
	var m lanMsg
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m.Magic != LANBeaconMagic || !lanVerify(key, &m) {
		return nil, fmt.Errorf("invalid")
	}
	return &m, nil
}

func lanUnmarshal(m *lanMsg, out interface{}) error {
	raw, _ := base64.RawStdEncoding.DecodeString(m.Payload)
	return json.Unmarshal(raw, out)
}

func negotiateTransport(a, b string) string {
	if a == "udp" || b == "udp" {
		return "udp"
	}
	return "tcp"
}

func bestLocalIPForRemote(remoteIP string) (string, error) {
	c, err := net.Dial("udp4", net.JoinHostPort(remoteIP, "1"))
	if err != nil {
		return "", err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String(), nil
}

func addrToIP(src net.Addr) string {
	if ua, ok := src.(*net.UDPAddr); ok {
		return ua.IP.String()
	}
	host, _, err := net.SplitHostPort(src.String())
	if err != nil {
		return ""
	}
	return host
}

type lanSelfFilter struct {
	mu sync.Mutex
	m  map[string]struct{}
}

func newSelfFilter() *lanSelfFilter { return &lanSelfFilter{m: map[string]struct{}{}} }
func (f *lanSelfFilter) Add(n string) {
	f.mu.Lock()
	f.m[n] = struct{}{}
	f.mu.Unlock()
}
func (f *lanSelfFilter) IsSelf(n string) bool {
	f.mu.Lock()
	_, ok := f.m[n]
	f.mu.Unlock()
	return ok
}

type lanPunchPortSelector struct {
	once     sync.Once
	allocate func() (int, error)
	logger   *log.Logger
	port     int
	err      error
}

func newLanPunchPortSelector(allocate func() (int, error), logger *log.Logger) *lanPunchPortSelector {
	if allocate == nil {
		allocate = GetFreePort
	}
	return &lanPunchPortSelector{allocate: allocate, logger: logger}
}

func (s *lanPunchPortSelector) Get() (int, error) {
	s.once.Do(func() {
		s.port, s.err = s.allocate()
		if s.err != nil {
			s.err = fmt.Errorf("allocate LAN punch port: %w", s.err)
			return
		}
		if s.logger != nil {
			s.logger.Printf("Selected punchPort=%d after authenticated peer discovery\n", s.port)
		}
	})
	return s.port, s.err
}

// ============================================================================
// 组播网络层
// ============================================================================

type lanMcast struct {
	rawConn net.PacketConn
	conn    *ipv4.PacketConn
	dst     *net.UDPAddr
	ifaces  []lanMcastIface
	logger  *log.Logger
	warned  map[string]struct{}
	warnMu  sync.Mutex
	enumErr error
}

type lanMcastIface struct {
	iface net.Interface
}

type lanMessenger interface {
	broadcast([]byte)
	broadcastAndSendTo([]byte, net.Addr)
}

func newLanMcast(loggers ...*log.Logger) (*lanMcast, error) {
	gip := net.ParseIP(LANMulticastIP)
	dst := &net.UDPAddr{IP: gip, Port: LANMulticastPort}
	var logger *log.Logger
	if len(loggers) > 0 {
		logger = loggers[0]
	}

	c, err := net.ListenPacket("udp4", fmt.Sprintf("%s:%d", LANMulticastIP, LANMulticastPort))
	if err != nil {
		return nil, fmt.Errorf("bind %s:%d: %v", LANMulticastIP, LANMulticastPort, err)
	}
	p := ipv4.NewPacketConn(c)

	ifaces, enumErr := net.Interfaces()
	var good []lanMcastIface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagMulticast == 0 {
			continue
		}
		if err := p.JoinGroup(&iface, &net.UDPAddr{IP: gip}); err == nil {
			good = append(good, lanMcastIface{iface: iface})
		} else if logger != nil {
			logger.Printf("WARN: multicast join on %s failed: %v\n", iface.Name, err)
		}
	}
	p.SetMulticastLoopback(true)

	return &lanMcast{
		rawConn: c, conn: p, dst: dst, ifaces: good,
		logger: logger, warned: map[string]struct{}{},
		enumErr: enumErr,
	}, nil
}

func (mc *lanMcast) Close() { mc.rawConn.Close() }

func (mc *lanMcast) broadcast(data []byte) {
	if mc.enumErr != nil {
		mc.warnOnce("ifaces-enum", "interface enumeration failed: %v", mc.enumErr)
	}
	for i := range mc.ifaces {
		iface := &mc.ifaces[i]
		if err := mc.conn.SetMulticastInterface(&iface.iface); err != nil {
			mc.warnOnce("mcast-iface:"+iface.iface.Name, "multicast iface %s: %v", iface.iface.Name, err)
			continue
		}
		mc.conn.SetMulticastTTL(2)
		if _, err := mc.conn.WriteTo(data, nil, mc.dst); err != nil {
			mc.warnOnce("mcast-write:"+iface.iface.Name, "multicast send on %s to %s: %v", iface.iface.Name, mc.dst, err)
		}
	}
	if len(mc.ifaces) == 0 {
		if _, err := mc.conn.WriteTo(data, nil, mc.dst); err != nil {
			mc.warnOnce("fallback-write:"+mc.dst.String(), "fallback multicast send to %s: %v", mc.dst, err)
		}
	}
}

func (mc *lanMcast) sendTo(data []byte, dst net.Addr) {
	if dst == nil {
		return
	}
	if _, err := mc.conn.WriteTo(data, nil, dst); err != nil {
		mc.warnOnce("unicast-write:"+dst.String(), "unicast send to %s: %v", dst, err)
	}
}

func (mc *lanMcast) broadcastAndSendTo(data []byte, dst net.Addr) {
	mc.broadcast(data)
	mc.sendTo(data, dst)
}

func (mc *lanMcast) ifaceSummary() string {
	if len(mc.ifaces) == 0 {
		summary := "none"
		if mc.enumErr != nil {
			summary += fmt.Sprintf(" (enumErr=%v)", mc.enumErr)
		}
		return summary + " (fallback=239.255.255.250)"
	}
	parts := make([]string, 0, len(mc.ifaces))
	for _, iface := range mc.ifaces {
		parts = append(parts, iface.iface.Name)
	}
	return strings.Join(parts, "; ")
}

func (mc *lanMcast) warnOnce(key, format string, args ...interface{}) {
	if mc.logger == nil {
		return
	}
	mc.warnMu.Lock()
	defer mc.warnMu.Unlock()
	if _, ok := mc.warned[key]; ok {
		return
	}
	mc.warned[key] = struct{}{}
	mc.logger.Printf("WARN: "+format+"\n", args...)
}

// ============================================================================
// 消息分发器: 单 goroutine 读 mconn, 按 Type 分发到不同 channel
// ============================================================================

type lanDispatcher struct {
	beaconCh   chan lanRecvPacket
	responseCh chan lanRecvPacket
	confirmCh  chan lanRecvPacket
	ackCh      chan lanRecvPacket
}

func newLanDispatcher() *lanDispatcher {
	return &lanDispatcher{
		beaconCh:   make(chan lanRecvPacket, 32),
		responseCh: make(chan lanRecvPacket, 32),
		confirmCh:  make(chan lanRecvPacket, 32),
		ackCh:      make(chan lanRecvPacket, 32),
	}
}

// run 持续读 mconn, 解码后按类型分发, ctx 取消后退出
func (d *lanDispatcher) run(ctx context.Context, mc *lanMcast, key []byte) {
	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		mc.rawConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, src, err := mc.conn.ReadFrom(buf)
		if err != nil {
			continue // timeout 或其他错误, 继续
		}

		m, err := lanDecode(key, buf[:n])
		if err != nil {
			continue
		}

		pkt := lanRecvPacket{msg: m, src: src}

		switch m.Type {
		case lanMsgBeacon:
			select {
			case d.beaconCh <- pkt:
			default: // channel 满了, 丢弃
			}
		case lanMsgResponse:
			select {
			case d.responseCh <- pkt:
			default:
			}
		case lanMsgConfirm:
			select {
			case d.confirmCh <- pkt:
			default:
			}
		case lanMsgAck:
			select {
			case d.ackCh <- pkt:
			default:
			}
		}
	}
}

// ============================================================================
// LANDiscover
// ============================================================================

func LANDiscover(ctx context.Context, sessionKey, transportPref string, timeout time.Duration, logWriter io.Writer) (*LANDiscoverResult, error) {
	return lanDiscover(ctx, sessionKey, transportPref, timeout, false, logWriter)
}

func LANDiscoverPassive(ctx context.Context, sessionKey, transportPref string, timeout time.Duration, logWriter io.Writer) (*LANDiscoverResult, error) {
	return lanDiscover(ctx, sessionKey, transportPref, timeout, true, logWriter)
}

type lanDiscoverWorker func() (*LANDiscoverResult, error)

func runLANDiscoverWorkers(ctx context.Context, cancel context.CancelFunc, workers ...lanDiscoverWorker) (*LANDiscoverResult, error) {
	type workerResult struct {
		result *LANDiscoverResult
		err    error
	}
	results := make(chan workerResult, len(workers))
	for _, worker := range workers {
		worker := worker
		go func() {
			result, err := worker()
			results <- workerResult{result: result, err: err}
		}()
	}

	defer cancel()
	for range workers {
		select {
		case outcome := <-results:
			if outcome.err != nil {
				return nil, outcome.err
			}
			if outcome.result != nil {
				return outcome.result, nil
			}
		case <-ctx.Done():
			return nil, fmt.Errorf("LAN discovery timeout")
		}
	}
	return nil, fmt.Errorf("LAN discovery failed")
}

func lanDiscover(ctx context.Context, sessionKey, transportPref string, timeout time.Duration, passive bool, logWriter io.Writer) (*LANDiscoverResult, error) {
	return lanDiscoverWithPortAllocator(ctx, sessionKey, transportPref, timeout, passive, logWriter, GetFreePort)
}

func lanDiscoverWithPortAllocator(
	ctx context.Context,
	sessionKey, transportPref string,
	timeout time.Duration,
	passive bool,
	logWriter io.Writer,
	allocate func() (int, error),
) (*LANDiscoverResult, error) {
	logger := misc.NewLog(logWriter, "[LAN] ", log.LstdFlags|log.Lmsgprefix)
	key := lanDeriveKey(sessionKey)
	sid := lanDeriveSessionID(sessionKey)
	sf := newSelfFilter()
	punchPorts := newLanPunchPortSelector(allocate, logger)

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	mc, err := newLanMcast(logger)
	if err != nil {
		return nil, err
	}
	defer mc.Close()

	logger.Printf("Multicast %s:%d, %d ifaces\n", LANMulticastIP, LANMulticastPort, len(mc.ifaces))
	logger.Printf("Interfaces: %s\n", mc.ifaceSummary())

	// 启动分发器
	disp := newLanDispatcher()
	go disp.run(ctx, mc, key)

	initiatorRole := "Initiator"
	if passive {
		initiatorRole = "Passive"
		logger.Printf("Mode: passive startup burst, then beacon every %s\n", lanPassiveBeaconInterval)
	} else {
		logger.Printf("Mode: active beacon every %s for %s, then every %s\n",
			lanActiveBeaconInterval, lanActiveFastBeaconWindow, lanActiveSlowBeaconInterval)
	}
	return runLANDiscoverWorkers(ctx, cancel,
		func() (*LANDiscoverResult, error) {
			return lanInitiator(ctx, mc, disp, key, sid, transportPref, bestLocalIPForRemote, punchPorts, sf, logger, passive, initiatorRole)
		},
		func() (*LANDiscoverResult, error) {
			return lanResponder(ctx, mc, disp, key, sid, transportPref, bestLocalIPForRemote, punchPorts, sf, logger)
		},
	)
}

// ============================================================================
// Initiator
//   1. 组播 Beacon (持续)
//   2. 从 disp.responseCh 等 Response
//   3. 组播 Confirm (持续)
//   4. 从 disp.ackCh 等 Ack → 完成
// ============================================================================

func lanInitiator(
	ctx context.Context, mc lanMessenger, disp *lanDispatcher,
	key []byte, sid, tp string, selectLocalIP func(string) (string, error), punchPorts *lanPunchPortSelector,
	sf *lanSelfFilter, logger *log.Logger,
	passive bool, roleName string,
) (*LANDiscoverResult, error) {

	nonceA := lanNonce()
	sf.Add(nonceA)

	beaconData := lanEncode(key, lanMsgBeacon, lanBeacon{
		SessionID: sid, NonceA: nonceA, Transport: tp,
	})

	logger.Printf("%s: broadcasting beacon\n", roleName)
	mc.broadcast(beaconData)

	beaconsSent := 1
	beaconTimer := time.NewTimer(lanNextBeaconDelay(passive, beaconsSent))
	defer beaconTimer.Stop()

	// ── Phase 1: 从 responseCh 等 Response ──
	var resp lanResponse
	var respSrc net.Addr
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-beaconTimer.C:
			mc.broadcast(beaconData)
			beaconsSent++
			beaconTimer.Reset(lanNextBeaconDelay(passive, beaconsSent))
		case pkt := <-disp.responseCh:
			if err := lanUnmarshal(pkt.msg, &resp); err != nil {
				continue
			}
			if resp.NonceA != nonceA {
				continue
			}
			respSrc = pkt.src
			goto GotResponse
		}
	}
GotResponse:

	localIP, _ := selectLocalIP(resp.IP)
	finalTP := negotiateTransport(tp, resp.Transport)
	punchPort, err := punchPorts.Get()
	if err != nil {
		return nil, err
	}
	logger.Printf("%s: got response from %s:%d, localIP=%s\n", roleName, resp.IP, resp.Port, localIP)

	// ── Phase 2: 发 Confirm + 等 Ack ──
	{
		confirmData := lanEncode(key, lanMsgConfirm, lanConfirm{
			NonceB: resp.NonceB, Transport: finalTP,
			IP: localIP, Port: punchPort,
		})

		// 立即发几轮
		for i := 0; i < 3; i++ {
			mc.broadcastAndSendTo(confirmData, respSrc)
			time.Sleep(50 * time.Millisecond)
		}

		// 持续发 confirm + 等 ack
		confirmTk := time.NewTicker(300 * time.Millisecond)
		defer confirmTk.Stop()

		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-confirmTk.C:
				mc.broadcastAndSendTo(confirmData, respSrc)
			case pkt := <-disp.ackCh:
				var ack lanAck
				if err := lanUnmarshal(pkt.msg, &ack); err != nil {
					continue
				}
				if ack.NonceA != nonceA {
					continue
				}

				logger.Printf("%s: got ACK → discovery complete\n", roleName)
				logger.Printf("  local=%s:%d remote=%s:%d tp=%s\n",
					localIP, punchPort, resp.IP, resp.Port, finalTP)

				return &LANDiscoverResult{
					LocalIP: localIP, LocalPort: punchPort,
					RemoteIP: resp.IP, RemotePort: resp.Port,
					Transport: finalTP, IsInitiator: true,
				}, nil
			}
		}
	}
}

func lanNextBeaconDelay(passive bool, beaconsSent int) time.Duration {
	if !passive {
		fastBeaconCount := int(lanActiveFastBeaconWindow / lanActiveBeaconInterval)
		if beaconsSent > fastBeaconCount {
			return lanActiveSlowBeaconInterval
		}
		return lanActiveBeaconInterval
	}

	startupDelays := [...]time.Duration{
		250 * time.Millisecond,
		750 * time.Millisecond,
		4 * time.Second,
		10 * time.Second,
	}
	if index := beaconsSent - 1; index >= 0 && index < len(startupDelays) {
		return startupDelays[index]
	}

	return lanPassiveBeaconInterval
}

// ============================================================================
// Responder
//   1. 从 disp.beaconCh 等 Beacon
//   2. 组播 Response (持续)
//   3. 从 disp.confirmCh 等 Confirm
//   4. 组播 Ack → 完成
// ============================================================================

func lanResponder(
	ctx context.Context, mc lanMessenger, disp *lanDispatcher,
	key []byte, sid, tp string, selectLocalIP func(string) (string, error), punchPorts *lanPunchPortSelector,
	sf *lanSelfFilter, logger *log.Logger,
) (*LANDiscoverResult, error) {

	logger.Printf("Responder: listening\n")

	for {
		// ── Phase 1: 从 beaconCh 等 Beacon ──
		var b lanBeacon
		var remoteIP, localIP string
		var beaconSrc net.Addr
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case pkt := <-disp.beaconCh:
			if err := lanUnmarshal(pkt.msg, &b); err != nil {
				continue
			}
			if b.SessionID != sid || sf.IsSelf(b.NonceA) {
				continue
			}

			remoteIP = addrToIP(pkt.src)
			if remoteIP == "" {
				continue
			}
			var err error
			localIP, err = selectLocalIP(remoteIP)
			if err != nil || localIP == remoteIP {
				continue
			}
			beaconSrc = pkt.src
		}
		punchPort, err := punchPorts.Get()
		if err != nil {
			return nil, err
		}

		logger.Printf("Responder: beacon from %s, bestLocal=%s\n", remoteIP, localIP)

		nonceB := lanNonce()

		respData := lanEncode(key, lanMsgResponse, lanResponse{
			NonceA: b.NonceA, NonceB: nonceB, Transport: tp,
			IP: localIP, Port: punchPort,
		})

		// 立即发几轮
		for i := 0; i < 3; i++ {
			mc.broadcastAndSendTo(respData, beaconSrc)
			time.Sleep(50 * time.Millisecond)
		}

		// ── Phase 2: 持续发 Response + 从 confirmCh 等 Confirm ──
		respTk := time.NewTicker(300 * time.Millisecond)
		confirmDeadline := time.After(10 * time.Second)
		var confirm lanConfirm
		var confirmSrc net.Addr
		gotConfirm := false

		for !gotConfirm {
			select {
			case <-ctx.Done():
				respTk.Stop()
				return nil, ctx.Err()
			case <-confirmDeadline:
				respTk.Stop()
				logger.Printf("Responder: confirm timeout, resume beacon listen\n")
				goto NextBeacon
			case <-respTk.C:
				mc.broadcastAndSendTo(respData, beaconSrc)
			case pkt := <-disp.confirmCh:
				if err := lanUnmarshal(pkt.msg, &confirm); err != nil {
					continue
				}
				if confirm.NonceB != nonceB {
					continue
				}
				confirmSrc = pkt.src
				gotConfirm = true
			}
		}
		respTk.Stop()

		// ── Phase 3: 发 ACK ──
		{
			ackData := lanEncode(key, lanMsgAck, lanAck{NonceA: b.NonceA})

			// 多发几轮, 确保 initiator 收到
			for i := 0; i < 8; i++ {
				mc.broadcastAndSendTo(ackData, confirmSrc)
				time.Sleep(100 * time.Millisecond)
			}

			logger.Printf("Responder: sent ACK → discovery complete\n")
			logger.Printf("  local=%s:%d remote=%s:%d tp=%s\n",
				localIP, punchPort, confirm.IP, confirm.Port, confirm.Transport)

			return &LANDiscoverResult{
				LocalIP: localIP, LocalPort: punchPort,
				RemoteIP: confirm.IP, RemotePort: confirm.Port,
				Transport: confirm.Transport, IsInitiator: false,
			}, nil
		}

	NextBeacon:
		continue
	}
}

// ============================================================================
// Easy_P2P_LAN
//
// 流程: 组播发现(四步握手) → 构造 P2PAddressInfo → Auto_P2P_*(round=0)
//
// round=0 使打洞函数跳过 Mqtt_P2P_Round_Sync:
//   if round > 0 {
//       err = Mqtt_P2P_Round_Sync(...)  // round=0 不进这里
//   }
//
// 时机同步由四步握手保证: 双方都收到并确认了对方地址后才返回,
// 之后几乎同时进入打洞阶段。
// ============================================================================

func Easy_P2P_LAN(ctx context.Context, sessionKey, transportPref string, timeout time.Duration, logWriter io.Writer) (*P2PConnInfo, error) {
	return easyP2PLAN(ctx, sessionKey, transportPref, timeout, false, logWriter)
}

func Easy_P2P_LAN_Passive(ctx context.Context, sessionKey, transportPref string, timeout time.Duration, logWriter io.Writer) (*P2PConnInfo, error) {
	return easyP2PLAN(ctx, sessionKey, transportPref, timeout, true, logWriter)
}

func easyP2PLAN(ctx context.Context, sessionKey, transportPref string, timeout time.Duration, passive bool, logWriter io.Writer) (*P2PConnInfo, error) {
	fmt.Fprintf(logWriter, "=== LAN Discovery Mode ===\n")

	var result *LANDiscoverResult
	var err error
	if passive {
		result, err = LANDiscoverPassive(ctx, sessionKey, transportPref, timeout, logWriter)
	} else {
		result, err = LANDiscover(ctx, sessionKey, transportPref, timeout, logWriter)
	}
	if err != nil {
		return nil, err
	}

	localAddr := net.JoinHostPort(result.LocalIP, fmt.Sprintf("%d", result.LocalPort))
	remoteAddr := net.JoinHostPort(result.RemoteIP, fmt.Sprintf("%d", result.RemotePort))
	sharedKey := sha256.Sum256([]byte("gonc-lan-shared-" + sessionKey))

	p2pInfo := &P2PAddressInfo{
		LocalLAN: localAddr, LocalNAT: localAddr, LocalNATType: "easy",
		RemoteLAN: remoteAddr, RemoteNAT: remoteAddr, RemoteNATType: "easy",
	}
	sessCtx := &P2PSessionContext{SharedKey: sharedKey}

	var conn net.Conn
	var isClient bool

	if result.Transport == "udp" {
		p2pInfo.Network = "udp4"
		conn, isClient, _, err = Auto_P2P_UDP_NAT_Traversal(
			ctx, "udp4", sessionKey, p2pInfo, sessCtx, 0, nil, logWriter)
	} else {
		p2pInfo.Network = "tcp4"
		conn, isClient, err = Auto_P2P_TCP_NAT_Traversal(
			ctx, "tcp4", sessionKey, p2pInfo, sessCtx, 0, logWriter)
	}
	if err != nil {
		return nil, fmt.Errorf("LAN traversal: %w", err)
	}

	return &P2PConnInfo{
		Conns: []net.Conn{conn}, SharedKey: sharedKey, IsClient: isClient,
		RelayUsed: false, RelayMode: false, NetworksUsed: []string{p2pInfo.Network},
		PeerAddress: conn.RemoteAddr().String(),
	}, nil
}

func LANTransportFromConfig(udpProtocol bool) string {
	if udpProtocol {
		return "udp"
	}
	return ""
}
