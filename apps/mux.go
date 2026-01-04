package apps

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/threatexpert/gonc/v2/acl"
	"github.com/threatexpert/gonc/v2/httpfileshare"
	"github.com/threatexpert/gonc/v2/misc"
	"github.com/threatexpert/gonc/v2/netx"
	"github.com/threatexpert/gonc/v2/secure"
	"github.com/xtaci/smux"
)

const DefaultVarMuxKeepAliveTimeout = 30

var (
	VarmuxEngine                    = "smux"
	VarmuxLastListenAddress         = ""
	VarhttpDownloadNoCompress *bool = new(bool)
	VarMuxKeepAliveTimeout    int   = DefaultVarMuxKeepAliveTimeout
)

var GlobalPortRegistry sync.Map

type PortOwner struct {
	OwnerID  string       // 客户端指纹
	Listener net.Listener // 监听句柄
}

type AppMuxConfig struct {
	Logger           *log.Logger
	Engine           string
	AppMode          string
	Port             string   // listen port
	LinkLocalConf    string   // for mux link L config
	LinkRemoteConf   string   // for mux link R config
	HttpServerVDirs  []string // for httpserver
	HttpClientDir    string   // for httpclient
	DownloadPath     string
	AccessCtrl       *acl.ACL
	KeepAliveTimeout int
}

type MuxSessionConfig struct {
	AppMuxConfig
	SessionConn net.Conn
}

type ChanError struct {
	id  int
	err error
}

type muxListener struct {
	session interface{}
	raddr   string
	laddr   string
}

func newMuxListener(session interface{}) *muxListener {
	return &muxListener{
		session: session,
		raddr:   muxSessionRemoteAddr(session),
		laddr:   muxSessionLocalAddr(session),
	}
}

func (m *muxListener) Accept() (net.Conn, error) {
	var stream net.Conn
	var err error

	switch s := m.session.(type) {
	case *yamux.Session:
		stream, err = s.Accept()
	case *smux.Session:
		stream, err = s.AcceptStream()
	default:
		return nil, fmt.Errorf("unknown session type")
	}
	if err != nil {
		return nil, err
	}

	return newStreamWrapper(stream, m.raddr, m.laddr), nil
}

func (m *muxListener) Close() error {
	switch s := m.session.(type) {
	case *yamux.Session:
		return s.Close()
	case *smux.Session:
		return s.Close()
	default:
		return fmt.Errorf("unknown session type")
	}
}

func (m *muxListener) Addr() net.Addr {
	return misc.DummyAddr("mux")
}

type streamWrapper struct {
	net.Conn
	raddr string
	laddr string
}

func newStreamWrapper(conn net.Conn, remoteAddr, localAddr string) *streamWrapper {
	if remoteAddr == "" {
		remoteAddr = "remote"
	}
	if localAddr == "" {
		localAddr = "local"
	}
	return &streamWrapper{
		Conn:  conn,
		raddr: remoteAddr,
		laddr: localAddr,
	}
}

func (s *streamWrapper) CloseWrite() error {
	return s.Conn.Close()
}

func (s *streamWrapper) LocalAddr() net.Addr {
	return misc.DummyAddr(s.laddr)
}

func (s *streamWrapper) RemoteAddr() net.Addr {
	return misc.DummyAddr(s.raddr)
}

func (s *streamWrapper) SetDeadline(t time.Time) error {
	return s.Conn.SetDeadline(t)
}

func (s *streamWrapper) SetReadDeadline(t time.Time) error {
	return s.Conn.SetReadDeadline(t)
}

func (s *streamWrapper) SetWriteDeadline(t time.Time) error {
	return s.Conn.SetWriteDeadline(t)
}

func streamCopy(dst io.WriteCloser, src io.Reader, errCh chan<- ChanError, id int) {
	type closeWriter interface {
		CloseWrite() error
	}
	_, err := io.Copy(dst, src)
	if tcpConn, ok := dst.(closeWriter); ok {
		tcpConn.CloseWrite()
	}
	errCh <- ChanError{id: id, err: err}
}

func bidirectionalCopy(local io.ReadWriteCloser, stream io.ReadWriteCloser) {
	errCh := make(chan ChanError, 2)
	go streamCopy(stream, local, errCh, 1)
	go streamCopy(local, stream, errCh, 2)
	for i := 0; i < 2; i++ {
		<-errCh
	}
}

func App_mux_usage(logWriter io.Writer) {
	fmt.Fprintln(logWriter, "Usage:")
	fmt.Fprintln(logWriter, "   :mux socks5")
	fmt.Fprintln(logWriter, "   :mux linkagent")
	fmt.Fprintln(logWriter, "   :mux link <L-Config>;<R-Config> (e.g. mux link x://127.0.0.1:8000;none)")
	fmt.Fprintln(logWriter, "   :mux httpserver <rootDir1> <rootDir2>...")
	fmt.Fprintln(logWriter, "   :mux httpclient <saveDir> <remotePath>")
	fmt.Fprintln(logWriter, "   :mux -l listen_port")
}

func AppMuxConfigByArgs(logWriter io.Writer, args []string) (*AppMuxConfig, error) {
	config := &AppMuxConfig{
		Logger:           misc.NewLog(logWriter, "[:mux] ", log.LstdFlags|log.Lmsgprefix),
		Engine:           VarmuxEngine,
		KeepAliveTimeout: VarMuxKeepAliveTimeout,
	}

	if len(args) == 0 {
		return nil, fmt.Errorf("missing arguments for :mux")
	}

	cmd := args[0]

	switch cmd {

	case "-l":
		if len(args) != 2 {
			return nil, fmt.Errorf("usage: :mux -l <listen_port>")
		}
		config.AppMode = "listen"
		config.Port = args[1]

	case "linkagent":
		if len(args) != 1 {
			return nil, fmt.Errorf("usage: :mux linkagent")
		}
		config.AppMode = "linkagent"

	case "link":
		// mux link L,R or L;R
		if len(args) < 2 {
			return nil, fmt.Errorf("usage: :mux link <L-Config>;<R-Config>")
		}
		fullStr := strings.Join(args[1:], "")
		fullStr = strings.ReplaceAll(fullStr, ",", ";")
		parts := strings.Split(fullStr, ";")
		if len(parts) != 2 {
			if len(parts) == 1 {
				parts = append(parts, "none")
			} else {
				return nil, fmt.Errorf("invalid link config. usage: mux link L;R")
			}
		}
		config.AppMode = "link"
		confL, err := normalizeLinkConf(parts[0])
		if err != nil {
			return nil, err
		}
		confR, err := normalizeLinkConf(parts[1])
		if err != nil {
			return nil, err
		}
		config.LinkLocalConf = confL
		config.LinkRemoteConf = confR

	case "socks5":
		if len(args) != 1 {
			return nil, fmt.Errorf("usage: :mux socks5")
		}
		config.AppMode = "socks5"

	case "httpserver":
		config.AppMode = "httpserver"
		if len(args) < 2 {
			return nil, fmt.Errorf("usage: :mux httpserver <rootDir> ...(other dirs)")
		} else {
			config.HttpServerVDirs = args[1:]
		}
		err := validateRootPaths(config.HttpServerVDirs)
		if err != nil {
			return nil, err
		}

	case "httpclient":
		if len(args) < 2 || len(args) > 3 {
			return nil, fmt.Errorf("usage: :mux httpclient <saveDir> <remotePath>")
		}
		config.AppMode = "httpclient"
		config.HttpClientDir = args[1]
		if len(args) == 3 {
			config.DownloadPath = args[2]
		}

	default:
		return nil, fmt.Errorf("invalid arguments for :mux")
	}

	return config, nil
}

func normalizeLinkConf(conf string) (string, error) {
	conf = strings.TrimSpace(conf)

	// 判断是否全部为数字
	if _, err := strconv.Atoi(conf); err == nil {
		// 是纯端口号
		conf = fmt.Sprintf("x://0.0.0.0:%s?tproxy=1", conf)
	}

	_, _, _, err := parseLinkConfig(conf) //校验
	if err != nil {
		return "", err
	}

	// 不是纯端口，原样返回
	return conf, nil
}

func App_mux_main_withconfig(conn net.Conn, config *AppMuxConfig) {
	defer conn.Close()

	cfg := MuxSessionConfig{
		AppMuxConfig: *config,
		SessionConn:  conn,
	}

	err := handleMuxSession(&cfg)
	if err != nil {
		config.Logger.Printf(":mux: %v\n", err)
	}
}

func handleMuxSession(cfg *MuxSessionConfig) error {
	switch cfg.AppMode {
	case "listen":
		return handleListenMode(cfg, nil, nil)
	case "link":
		return handleLinkMode(cfg)
	case "socks5":
		return handleSocks5uMode(cfg)
	case "linkagent":
		return handleLinkAgentMode(cfg)
	case "httpserver":
		return handleHTTPServerMode(cfg)
	case "httpclient":
		return handleHTTPClientMode(cfg)
	default:
		return fmt.Errorf("unsupported app mode: %s", cfg.AppMode)
	}
}

// -----------------------------------------------------------------------------
// Link Logic Implementation
// -----------------------------------------------------------------------------

// parseLinkConfig 解析单个 Link 配置 (L 或 R)
// 修改说明: 确保 params 始终不为 nil，支持 none?param=val 格式
func parseLinkConfig(conf string) (string, string, url.Values, error) {
	// 创建一个空的 Values，防止返回 nil 导致调用方 .Get() panic
	safeParams := make(url.Values)

	if conf == "none" {
		return "none", "", safeParams, nil
	}

	// 支持 "none?outbound_bind=x.x.x.x" 这种写法
	if strings.HasPrefix(conf, "none?") {
		parts := strings.SplitN(conf, "?", 2)
		if len(parts) == 2 {
			q, err := url.ParseQuery(parts[1])
			if err != nil {
				return "", "", nil, fmt.Errorf("invalid none query: %v", err)
			}
			return "none", "", q, nil
		}
		// 只有 none? 但没有参数
		return "none", "", safeParams, nil
	}

	u, err := url.Parse(conf)
	if err != nil {
		return "", "", nil, err
	}

	rawScheme := u.Scheme
	baseScheme := rawScheme
	useTLS := false

	// 支持 x+tls / f+tls / raw+tls
	if strings.Contains(rawScheme, "+") {
		parts := strings.Split(rawScheme, "+")
		baseScheme = parts[0]
		for _, p := range parts[1:] {
			if p == "tls" {
				useTLS = true
			} else {
				return "", "", nil, fmt.Errorf("unknown scheme modifier '+%s'", p)
			}
		}
	}

	// "x" -> socks5/dynamic
	// "f" -> forward
	// "raw" -> raw bridge (internal use)
	// "none" -> no operation (but might carry params)
	if baseScheme != "x" && baseScheme != "f" && baseScheme != "raw" && baseScheme != "none" {
		return "", "", nil, fmt.Errorf("unknown scheme '%s', use x:// or f://", baseScheme)
	}

	user := u.User.Username()
	pass, _ := u.User.Password()

	q := u.Query()
	q.Set("_user", user)
	q.Set("_password", pass)

	if useTLS {
		q.Set("_tls", "1")
	}

	return baseScheme, u.Host, q, nil
}

// linkRuntimeConfig 保存预处理后的运行参数
// 这里的字段是从 url.Values 解析出来的，用于 runLinkListener 直接使用
type linkRuntimeConfig struct {
	UseTLS              bool
	NtConfig            *secure.NegotiationConfig
	UseTProxy           bool
	TProxyAllowPublicIP bool
	Username            string
	Password            string
	TargetHost          string
	TargetPort          int
	ForwardTarget       string
}

// setupLinkRuntimeConfig 负责在 Accept 之前完成所有配置分析、TLS加载和参数校验
// 如果这一步返回 nil error，说明配置完全可用，可以放心地回复 OK
func setupLinkRuntimeConfig(muxcfg *MuxSessionConfig, scheme string, params url.Values, ln net.Listener) (*linkRuntimeConfig, error) {
	cfg := &linkRuntimeConfig{}
	var err error
	var cert *tls.Certificate

	actualListenAddr := ln.Addr().String()
	_, actualListenPort, _ := net.SplitHostPort(actualListenAddr)

	// 1. TLS 配置分析
	if params.Get("_tls") == "1" {
		cfg.UseTLS = true
		cfg.NtConfig = secure.NewNegotiationConfig()
		cfg.NtConfig.Label = "[link-tls]"
		cfg.NtConfig.IsClient = false
		cfg.NtConfig.SecureLayer = "tls"
		cfg.NtConfig.KeepAlive = 0
		sslCertFile := params.Get("cert")
		sslKeyFile := params.Get("key")
		if len(sslCertFile) > 0 && len(sslKeyFile) > 0 {
			cert, err = secure.LoadCertificate(sslCertFile, sslKeyFile)
		} else {
			cert, err = secure.GenerateECDSACertificate("link-tls", "")
		}
		if err != nil {
			return nil, fmt.Errorf("failed to load/generate TLS certificate: %v", err)
		}
		cfg.NtConfig.Certs = []tls.Certificate{*cert}
	}

	// 2. Scheme 特定配置分析
	switch scheme {
	case "x":
		if params.Get("tproxy") == "1" {
			cfg.UseTProxy = true
		}
		switch params.Get("allow") {
		case "any", "domain":
			cfg.TProxyAllowPublicIP = true
		case "private":
			cfg.TProxyAllowPublicIP = false
		}
		cfg.Username = params.Get("_user")
		cfg.Password = params.Get("_password")

		muxcfg.Logger.Printf("[link-x] Listening on %s (TProxy=%v)\n", ln.Addr().String(), cfg.UseTProxy)
		if cfg.UseTProxy {
			donotUsePublicMagicDNS := IsValidABC0IP(MagicDNServer)
			if donotUsePublicMagicDNS {
				targetIpPref := strings.TrimRight(MagicDNServer, ".0")
				muxcfg.Logger.Printf("   TProxy Format: 127.1.13.61:%s -> %s.1:3389\n", actualListenPort, targetIpPref)
			} else {
				muxcfg.Logger.Printf("   TProxy Format: 10.0.0.1-3389.%s:%s -> 10.0.0.1:3389\n", MagicDNServer, actualListenPort)
			}
		}
	case "f":
		cfg.ForwardTarget = params.Get("to")
		if cfg.ForwardTarget == "" {
			return nil, fmt.Errorf("missing 'to' parameter for forward mode (f://)")
		}
		var pStr string
		cfg.TargetHost, pStr, err = net.SplitHostPort(cfg.ForwardTarget)
		if err != nil {
			return nil, fmt.Errorf("invalid target address '%s': %v", cfg.ForwardTarget, err)
		}
		cfg.TargetPort, _ = strconv.Atoi(pStr)
		muxcfg.Logger.Printf("[link-f] Listening on %s -> Forward to %s\n", ln.Addr().String(), cfg.ForwardTarget)
	case "raw":
		muxcfg.Logger.Printf("[listen] Listening on %s\n", ln.Addr().String())
		if params.Get("mode") == "httpserver" {
			muxcfg.Logger.Printf("You can open http://127.0.0.1:%s in your browser\n", actualListenPort)
		}
	}

	return cfg, nil
}

// runLinkListener 核心运行循环
// 注意：现在它接收预处理好的 *linkRuntimeConfig，不再进行配置解析
func runLinkListener(muxcfg *MuxSessionConfig, session interface{}, ln net.Listener, scheme string, rtConfig *linkRuntimeConfig, doneChan <-chan struct{}) error {
	defer ln.Close()

	s5config := Socks5uConfig{
		Logger:     muxcfg.Logger,
		Username:   rtConfig.Username,
		Password:   rtConfig.Password,
		AccessCtrl: muxcfg.AccessCtrl,
	}

	// 监听 doneChan (Session 死则 Listener 死)
	go func() {
		<-doneChan
		ln.Close()
	}()

	handleConn := func(c net.Conn, magicIP string) {
		// tls处理
		var keyingMaterial [32]byte
		if rtConfig.UseTLS {
			nconn, err := secure.DoNegotiation(rtConfig.NtConfig, c, io.Discard)
			if err != nil {
				muxcfg.Logger.Println("[link-x] TLS negotiation failed:", err)
				c.Close()
				return
			}
			copy(keyingMaterial[:], nconn.KeyingMaterial[:])
			c = nconn
		}

		defer c.Close()

		stream, err := openMuxStream(session)
		if err != nil {
			muxcfg.Logger.Println("mux Open failed:", err)
			return
		}
		streamWithCloseWrite := newStreamWrapper(stream, muxSessionRemoteAddr(session), muxSessionLocalAddr(session))
		defer streamWithCloseWrite.Close()

		if scheme == "raw" {
			bidirectionalCopy(c, streamWithCloseWrite)
			return
		}

		cmd := ""
		tHost := rtConfig.TargetHost
		tPort := rtConfig.TargetPort

		if scheme == "f" {
			cmd = "T-CONNECT"
		} else {
			// x://
			if rtConfig.UseTProxy && magicIP != "" {
				cmd = "T-CONNECT"
				tHost, tPort, err = DNSLookupMagicIP(magicIP, rtConfig.TProxyAllowPublicIP)
				if err != nil {
					muxcfg.Logger.Println("MagicIP lookup failed:", err)
					return
				}
			}
		}

		ServeProxyOnTunnel(&s5config, c, keyingMaterial, streamWithCloseWrite, cmd, tHost, tPort)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-doneChan:
				return fmt.Errorf("mux session closed")
			default:
				return fmt.Errorf("listener accept failed: %v", err)
			}
		}

		// 透明代理 IP 过滤 (逻辑保留)
		localMagicTargetIP := ""
		if scheme == "x" && rtConfig.UseTProxy {
			rhost, _, err := net.SplitHostPort(conn.RemoteAddr().String())
			if err != nil || !strings.HasPrefix(rhost, "127.") {
				conn.Close()
				continue // Only accept 127.x
			}
			lhost, _, _ := net.SplitHostPort(conn.LocalAddr().String())
			if lhost != "127.0.0.1" {
				localMagicTargetIP = lhost
			}
		}

		go handleConn(conn, localMagicTargetIP)
	}
}

// runLinkSessionWithHandshake 客户端握手逻辑
func runLinkSessionWithHandshake(cfg *MuxSessionConfig, lConf string, rConf string) error {
	// 提前解析 Local Config
	lScheme, lHost, lParams, err := parseLinkConfig(lConf)
	if err != nil {
		return fmt.Errorf("local config parse error: %v", err)
	}

	localActive := "0"
	if lScheme != "none" {
		localActive = "1"
	}

	sendConf := rConf
	separator := "?"
	if strings.Contains(sendConf, "?") {
		separator = "&"
	}
	sendConf += fmt.Sprintf("%speer_active=%s", separator, localActive)
	separator = "&"

	if !strings.HasPrefix(rConf, "none") {
		// 追加 owner 参数
		fingerprint := GenerateNetworkFingerprint(cfg.SessionConn.LocalAddr().String())
		sendConf += fmt.Sprintf("%sowner=%s", separator, fingerprint)
	}
	sendConf += "\n"
	// -------------------------------------------------------------

	cfg.Logger.Printf("[link] Sending R-Config: %s", strings.TrimSpace(sendConf))
	if _, err := cfg.SessionConn.Write([]byte(sendConf)); err != nil {
		return fmt.Errorf("failed to send remote config: %v", err)
	}

	cfg.Logger.Printf("[link] Waiting for Remote ACK...")

	// 2. 等待 ACK
	ack, err := netx.ReadString(cfg.SessionConn, '\n', 1024)
	if err != nil {
		return fmt.Errorf("failed to receive ack: %v", err)
	}
	ack = strings.TrimSpace(ack)
	if !strings.HasPrefix(ack, "OK") {
		return fmt.Errorf("remote link failed: %s", ack)
	}
	cfg.Logger.Printf("[link] Remote ready (%s).", ack)

	cfg.SessionConn.SetDeadline(time.Time{})

	session, err := createMuxSession(cfg.Engine, cfg.SessionConn, true)
	if err != nil {
		return err
	}

	remoteActive := !strings.HasPrefix(rConf, "none")
	sessionDone := make(chan struct{})
	go func() {
		startRemoteStreamAcceptLoop(cfg, session, lParams.Get("outbound_bind"), !remoteActive)
		close(sessionDone)
	}()

	if lScheme != "none" {
		enableTProxy := (lScheme == "x" && lParams.Get("tproxy") == "1")
		ln, err := prepareLocalListener(lHost, enableTProxy)
		if err != nil {
			return fmt.Errorf("local bind failed: %v", err)
		}

		rtConfig, err := setupLinkRuntimeConfig(cfg, lScheme, lParams, ln)
		if err != nil {
			ln.Close()
			return fmt.Errorf("local config setup failed: %v", err)
		}

		cfg.Logger.Printf("[link] Local service started.")
		return runLinkListener(cfg, session, ln, lScheme, rtConfig, sessionDone)
	}

	<-sessionDone
	return fmt.Errorf("link session closed")
}

// handleLinkMode (Local)
func handleLinkMode(cfg *MuxSessionConfig) error {
	cfg.Logger.Println("Waiting for linkagent handshake...")
	cfg.SessionConn.SetDeadline(time.Now().Add(60 * time.Second))

	// 1. 读取 Hello
	hello := make([]byte, 16)
	if _, err := io.ReadFull(cfg.SessionConn, hello); err != nil {
		return fmt.Errorf("link read hello failed: %v", err)
	}
	peerModeStr := string(bytes.TrimRight(hello, "\x00"))

	if peerModeStr != "linkagent" {
		return fmt.Errorf("protocol mismatch: expected 'linkagent', got '%s'", peerModeStr)
	}

	// 2. 复用握手和运行逻辑
	return runLinkSessionWithHandshake(cfg, cfg.LinkLocalConf, cfg.LinkRemoteConf)
}

// handleListenMode 仅用于 -l 模式
// 已增强：自动探测 peer 类型。如果是 linkagent，则构造虚拟配置复用 Link 流程。
func handleListenMode(cfg *MuxSessionConfig, notifyAddrChan chan<- string, done context.CancelFunc) error {
	if done != nil {
		defer done()
	}
	cfg.Logger.Println("Waiting for :mux handshake...")
	cfg.SessionConn.SetDeadline(time.Now().Add(60 * time.Second))

	hello := make([]byte, 16)
	if _, err := io.ReadFull(cfg.SessionConn, hello); err != nil {
		return fmt.Errorf("mux read hello failed: %v", err)
	}
	peerModeStr := string(bytes.TrimRight(hello, "\x00"))

	// ============================================
	// 分支 A: Peer 是 LinkAgent -> 复用 Link 流程
	// ============================================
	if peerModeStr == "linkagent" {
		// 构造虚拟配置：
		// L = x://port?tproxy=1 (如果不含冒号) 或 x://port
		// R = none
		lConf := ""
		if !strings.Contains(cfg.Port, ":") {
			// 隐式 TProxy，IP 需要是 0.0.0.0
			lConf = fmt.Sprintf("x://0.0.0.0:%s?tproxy=1", cfg.Port)
		} else {
			// 标准地址，如果是 x:// 模式，用户 -l :8080 实际上就是 x://:8080
			lConf = fmt.Sprintf("x://%s", cfg.Port)
		}
		rConf := "none"

		cfg.Logger.Printf("[listen] Detected linkagent peer. Upgrading to link mode (L=%s, R=%s)", lConf, rConf)

		return runLinkSessionWithHandshake(cfg, lConf, rConf)
	}

	// ============================================
	// 分支 B: Peer 是 Legacy (Socks5/Other) -> 走旧流程 (无配置握手)
	// ============================================
	cfg.SessionConn.SetDeadline(time.Time{})

	session, err := createMuxSession(cfg.Engine, cfg.SessionConn, true)
	if err != nil {
		return err
	}

	// 单向模式：drainOnly = true
	sessionDone := make(chan struct{})
	go func() {
		startRemoteStreamAcceptLoop(cfg, session, "", true)
		close(sessionDone)
	}()

	scheme := "raw"
	params := make(url.Values)
	useTProxy := false

	if strings.HasPrefix(peerModeStr, "socks5") {
		scheme = "x"
		if !strings.Contains(cfg.Port, ":") {
			useTProxy = true
			params.Set("tproxy", "1")
		}
	} else {
		scheme = "raw"
		if peerModeStr == "httpserver" {
			params.Set("mode", "httpserver")
		}
	}

	ln, err := prepareLocalListener(cfg.Port, useTProxy)
	if err != nil {
		return fmt.Errorf("local listen failed: %v", err)
	}

	if notifyAddrChan != nil {
		notifyAddrChan <- ln.Addr().String()
	}

	// 关键改动：调用 setupLinkRuntimeConfig
	rtConfig, err := setupLinkRuntimeConfig(cfg, scheme, params, ln)
	if err != nil {
		ln.Close()
		return fmt.Errorf("legacy setup failed: %v", err)
	}

	cfg.Logger.Printf("[listen] Service started (Legacy). PeerMode=%s", peerModeStr)
	return runLinkListener(cfg, session, ln, scheme, rtConfig, sessionDone)
}

// handleLinkAgentMode (Remote)
func handleLinkAgentMode(cfg *MuxSessionConfig) error {
	if err := sendHello(cfg.SessionConn, "linkagent"); err != nil {
		return err
	}

	cfg.SessionConn.SetReadDeadline(time.Now().Add(25 * time.Second))
	reqStr, err := netx.ReadString(cfg.SessionConn, '\n', 1024)
	if err != nil {
		return fmt.Errorf("read config error: %w", err)
	}
	cfg.SessionConn.SetReadDeadline(time.Time{})

	reqStr = strings.TrimSpace(reqStr)
	rConf := reqStr
	peerActive := strings.Contains(rConf, "peer_active=1")

	rScheme, rHost, rParams, err := parseLinkConfig(rConf)
	if err != nil {
		cfg.SessionConn.Write([]byte(fmt.Sprintf("ERROR: %v\n", err)))
		return err
	}

	var ln net.Listener
	var rtConfig *linkRuntimeConfig
	ackMsg := "OK"

	if rScheme != "none" {
		// -------------------------------------------------------------
		// [STEP 2] 严格的端口抢占安全检查
		// -------------------------------------------------------------
		ownerID := rParams.Get("owner") // 新请求带来的指纹

		bindKey := rHost
		if !strings.Contains(bindKey, ":") {
			bindKey = ":" + bindKey
		}

		if val, loaded := GlobalPortRegistry.Load(bindKey); loaded {
			oldOwner := val.(*PortOwner)

			// 默认拒绝
			canPreempt := false

			if oldOwner.OwnerID == "" {
				// 情况 A: 旧连接是 Legacy 版 (没有指纹)
				// 逻辑: "旧版无法被踢"。即便是新版也不允许踢旧版。
				// 必须等旧版自己断开。
				cfg.Logger.Printf("[mux] Port %s is held by Legacy client. Preemption DENIED.", bindKey)
				canPreempt = false
			} else {
				// 情况 B: 旧连接是 New 版 (有指纹)
				// 逻辑: "新版有owner，按照认证匹配才能踢"
				// 必须两个指纹都存在且相等
				if ownerID != "" && ownerID == oldOwner.OwnerID {
					cfg.Logger.Printf("[mux] Port %s owner match (%s). Allowing preemption.", bindKey, ownerID)
					canPreempt = true
				} else {
					// 指纹不匹配，或者新请求没带指纹
					cfg.Logger.Printf("[mux] Port %s locked by %s. Rejecting %s.", bindKey, oldOwner.OwnerID, ownerID)
					canPreempt = false
				}
			}

			if !canPreempt {
				errMsg := fmt.Sprintf("ERROR: Port %s is locked. Preemption denied.\n", bindKey)
				cfg.SessionConn.Write([]byte(errMsg))
				return fmt.Errorf("port conflict: permission denied")
			}

			// 验证通过，执行踢人
			cfg.Logger.Printf("[mux] Preempting port %s...", bindKey)
			if oldOwner.Listener != nil {
				oldOwner.Listener.Close() // 这会强制旧 Session 退出
			}
			GlobalPortRegistry.Delete(bindKey)
			time.Sleep(1 * time.Second)
		}
		// -------------------------------------------------------------

		// 3.1 绑定端口
		enableTProxy := (rScheme == "x" && rParams.Get("tproxy") == "1")
		ln, err = prepareLocalListener(rHost, enableTProxy)
		if err != nil {
			cfg.SessionConn.Write([]byte(fmt.Sprintf("ERROR: bind failed: %v\n", err)))
			return err
		}

		// 3.2 配置分析
		rtConfig, err = setupLinkRuntimeConfig(cfg, rScheme, rParams, ln)
		if err != nil {
			ln.Close()
			errMsg := fmt.Sprintf("ERROR: config setup failed: %v\n", err)
			cfg.SessionConn.Write([]byte(errMsg))
			return err
		}

		// 3.3 注册当前客户端
		actualAddr := ln.Addr().String()
		newOwnerEntry := &PortOwner{
			OwnerID:  ownerID,
			Listener: ln,
		}
		GlobalPortRegistry.Store(bindKey, newOwnerEntry)

		// 退出时清理 Map (防止僵尸条目)
		// 只有当 Map 里的还是我自己时才删
		defer func() {
			if v, ok := GlobalPortRegistry.Load(bindKey); ok {
				if v.(*PortOwner) == newOwnerEntry {
					GlobalPortRegistry.Delete(bindKey)
				}
			}
		}()

		ackMsg = fmt.Sprintf("OK:%s", actualAddr)
	} else {
		ackMsg = "OK:none"
	}

	session, err := createMuxSession(cfg.Engine, cfg.SessionConn, false)
	if err != nil {
		if ln != nil {
			ln.Close()
		}
		cfg.SessionConn.Write([]byte(fmt.Sprintf("ERROR: createMuxSession failed: %v\n", err)))
		return err
	}

	if _, err := cfg.SessionConn.Write([]byte(ackMsg + "\n")); err != nil {
		if ln != nil {
			ln.Close()
		}
		return err
	}

	cfg.Logger.Printf("[linkagent] Session established. OwnerID=%s", rParams.Get("owner"))

	sessionDone := make(chan struct{})
	go func() {
		startRemoteStreamAcceptLoop(cfg, session, rParams.Get("outbound_bind"), !peerActive)
		close(sessionDone)
	}()

	if rScheme != "none" && ln != nil {
		return runLinkListener(cfg, session, ln, rScheme, rtConfig, sessionDone)
	}

	<-sessionDone
	return fmt.Errorf("linkagent session closed")
}

// -----------------------------------------------------------------------------
// Legacy & Common Handlers
// -----------------------------------------------------------------------------

func handleHTTPClientMode(cfg *MuxSessionConfig) error {
	cfg.Port = "0"
	serverURL := ""
	listenAddrChan := make(chan string, 1)
	ctx, done := context.WithCancel(context.Background())
	go handleListenMode(cfg, listenAddrChan, done)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case webHost := <-listenAddrChan:
		serverURL = fmt.Sprintf("http://%s/", webHost)
		if cfg.DownloadPath != "" {
			serverURL += strings.TrimLeft(cfg.DownloadPath, "/")
		}
		httpcfg := httpfileshare.ClientConfig{
			ServerURL:              serverURL,
			LocalDir:               cfg.HttpClientDir,
			Concurrency:            2,
			Resume:                 true,
			DryRun:                 false,
			Verbose:                false,
			LogLevel:               httpfileshare.LogLevelError,
			LoggerOutput:           cfg.Logger.Writer(),
			ProgressOutput:         cfg.Logger.Writer(),
			ProgressUpdateInterval: 1 * time.Second,
			NoCompress:             *VarhttpDownloadNoCompress,
		}

		c, err := httpfileshare.NewClient(httpcfg)
		if err != nil {
			cfg.Logger.Printf("Failed to create HTTP client: %v\n", err)
			return err
		}
		if err := c.Start(ctx); err != nil {
			cfg.Logger.Printf("Client operation failed: %v\n", err)
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	}
}

// startRemoteStreamAcceptLoop 从 mux session 接受流并处理 SOCKS5 请求
func startRemoteStreamAcceptLoop(cfg *MuxSessionConfig, session interface{}, localbind string, drainOnly bool) error {
	listener := newMuxListener(session)
	s5config := Socks5uConfig{
		Logger:     cfg.Logger,
		AccessCtrl: cfg.AccessCtrl,
		Localbind:  localbind,
	}
	for {
		stream, err := listener.Accept()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		if drainOnly {
			stream.Close()
			continue
		}

		go handleSocks5ClientOnStream(&s5config, stream)
	}
}

// prepareLocalListener 负责绑定本地端口
func prepareLocalListener(listenAddrConf string, enableTProxy bool) (net.Listener, error) {
	network := "tcp"
	laddr := listenAddrConf

	if laddr == "0" && VarmuxLastListenAddress != "" {
		laddr = VarmuxLastListenAddress
	}

	noColons := false
	host, port, err := net.SplitHostPort(laddr)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			if !strings.Contains(laddr, ":") {
				noColons = true
				laddr = ":" + laddr
				host, port, err = net.SplitHostPort(laddr)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("invalid listen address '%s': %v", laddr, err)
		}
	}

	if enableTProxy {
		if host != "" && host != "0.0.0.0" {
			return nil, fmt.Errorf("tproxy mode requires bind address 0.0.0.0, but got '%s'", host)
		}
		if host == "" {
			host = "0.0.0.0"
		}
	} else {
		if host == "" && noColons {
			host = "127.0.0.1"
		}
	}

	laddr = net.JoinHostPort(host, port)

	if strings.HasPrefix(laddr, "0.0.0.0") {
		network = "tcp4"
	}

	ln, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}

	if port == "0" || listenAddrConf == "0" {
		VarmuxLastListenAddress = ln.Addr().String()
	}

	return ln, nil
}

func handleSocks5uMode(cfg *MuxSessionConfig) error {
	if err := sendHello(cfg.SessionConn, cfg.AppMode); err != nil {
		return err
	}

	session, err := createMuxSession(cfg.Engine, cfg.SessionConn, false)
	if err != nil {
		return fmt.Errorf("create mux session failed: %v", err)
	}

	cfg.Logger.Printf("[socks5] tunnel server ready on mux session(%s).", cfg.SessionConn.RemoteAddr().String())
	err = startRemoteStreamAcceptLoop(cfg, session, "", false)
	cfg.Logger.Printf("[socks5] finished(%s).", cfg.SessionConn.RemoteAddr().String())
	return err
}

func handleHTTPServerMode(cfg *MuxSessionConfig) error {
	if err := sendHello(cfg.SessionConn, cfg.AppMode); err != nil {
		return err
	}

	session, err := createMuxSession(cfg.Engine, cfg.SessionConn, false)
	if err != nil {
		return err
	}

	ln := newMuxListener(session)
	enableZstd := true

	srvcfg := httpfileshare.ServerConfig{
		RootPaths:    cfg.HttpServerVDirs,
		LoggerOutput: cfg.Logger.Writer(),
		EnableZstd:   enableZstd,
		Listener:     ln,
	}

	server, err := httpfileshare.NewServer(srvcfg)
	if err != nil {
		cfg.Logger.Fatalf("Failed to create server: %v", err)
	}

	cfg.Logger.Println("httpserver ready on mux")

	return server.Start()
}

func sendHello(conn net.Conn, mode string) error {
	hello := make([]byte, 16)
	copy(hello, mode)
	_, err := conn.Write(hello)
	return err
}

func createMuxSession(engine string, conn net.Conn, isClient bool) (interface{}, error) {
	switch engine {
	case "yamux":
		muxConfig := yamux.DefaultConfig()
		if VarMuxKeepAliveTimeout == 0 {
			muxConfig.EnableKeepAlive = false
		} else {
			muxConfig.EnableKeepAlive = true
			muxConfig.KeepAliveInterval = time.Duration(VarMuxKeepAliveTimeout) * time.Second
		}
		if isClient {
			return yamux.Client(conn, muxConfig)
		}
		return yamux.Server(conn, muxConfig)
	case "smux":
		muxConfig := smux.DefaultConfig()
		if VarMuxKeepAliveTimeout == 0 {
			muxConfig.KeepAliveDisabled = true
		} else {
			muxConfig.KeepAliveDisabled = false
			if VarMuxKeepAliveTimeout < 30 {
				muxConfig.KeepAliveInterval = time.Duration(VarMuxKeepAliveTimeout/2) * time.Second
			} else {
				muxConfig.KeepAliveInterval = time.Duration(15) * time.Second
			}
			muxConfig.KeepAliveTimeout = time.Duration(VarMuxKeepAliveTimeout) * time.Second
		}
		if isClient {
			return smux.Client(conn, muxConfig)
		}
		return smux.Server(conn, muxConfig)
	default:
		return nil, fmt.Errorf("unknown mux engine: %s", engine)
	}
}

func openMuxStream(session interface{}) (net.Conn, error) {
	switch s := session.(type) {
	case *yamux.Session:
		return s.Open()
	case *smux.Session:
		return s.OpenStream()
	default:
		return nil, fmt.Errorf("unknown session type")
	}
}

func muxSessionLocalAddr(session interface{}) string {
	var addr net.Addr
	switch s := session.(type) {
	case *yamux.Session:
		addr = s.LocalAddr()
	case *smux.Session:
		addr = s.LocalAddr()
	default:
		return ""
	}
	if addr != nil {
		return addr.String()
	} else {
		return ""
	}
}

func muxSessionRemoteAddr(session interface{}) string {
	var addr net.Addr
	switch s := session.(type) {
	case *yamux.Session:
		addr = s.RemoteAddr()
	case *smux.Session:
		addr = s.RemoteAddr()
	default:
		return ""
	}
	if addr != nil {
		return addr.String()
	} else {
		return ""
	}
}

// GenerateNetworkFingerprint 生成纯网络特征指纹 (无 Hostname/Username)
func GenerateNetworkFingerprint(localAddr string) string {
	// 1. 获取出口网卡特征 (MAC 或 接口名)
	netIdentity := getOutboundInterfaceIdentity(localAddr)

	// 2. 生成 SHA256 哈希 (仅依赖网络身份)
	// 加一个固定的盐值 (Salt) 防止彩虹表，虽然这里没传密码，但好习惯
	raw := fmt.Sprintf("mux_salt_v1|%s", netIdentity)
	hash := sha256.Sum256([]byte(raw))

	// 返回前 16 位 Hex
	return fmt.Sprintf("%x", hash)[:16]
}

// getOutboundInterfaceIdentity 获取出口网卡的唯一标识 (MAC 或 Name+Index)
func getOutboundInterfaceIdentity(localAddr string) string {
	localIP, _, err := net.SplitHostPort(localAddr)
	if err != nil {
		return getFallbackIdentity("")
	}

	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip.String() == localIP {
				// 优先返回 MAC
				if len(iface.HardwareAddr) > 0 {
					return fmt.Sprintf("%s|%s|a", localIP, iface.HardwareAddr.String())
				}
				// VPN/Tun 接口无 MAC，返回 "Name"
				return fmt.Sprintf("%s|%s|b", localIP, iface.Name)
			}
		}
	}
	return getFallbackIdentity(localIP)
}

// getFallbackIdentity 兜底方案
func getFallbackIdentity(localIP string) string {
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback == 0 && len(i.HardwareAddr) > 0 {
			return fmt.Sprintf("%s|%s|c", localIP, i.HardwareAddr.String())
		}
	}
	if len(ifaces) > 0 {
		return fmt.Sprintf("%s|%s|d", localIP, ifaces[0].Name)
	}
	return fmt.Sprintf("%s||e", localIP)
}
