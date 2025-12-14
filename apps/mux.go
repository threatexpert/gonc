package apps

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/threatexpert/gonc/v2/acl"
	"github.com/threatexpert/gonc/v2/httpfileshare"
	"github.com/threatexpert/gonc/v2/misc"
	"github.com/threatexpert/gonc/v2/netx"
	"github.com/xtaci/smux"
)

const DefaultVarMuxKeepAliveTimeout = 30

var (
	VarmuxEngine                    = "smux"
	VarmuxLastListenAddress         = ""
	VarhttpDownloadNoCompress *bool = new(bool)
	VarMuxKeepAliveTimeout    int   = DefaultVarMuxKeepAliveTimeout
)

type AppMuxConfig struct {
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

	return &streamWrapper{Conn: stream}, nil
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
}

func (s *streamWrapper) CloseWrite() error {
	return s.Conn.Close()
}

func (s *streamWrapper) LocalAddr() net.Addr {
	return misc.DummyAddr("local")
}

func (s *streamWrapper) RemoteAddr() net.Addr {
	return misc.DummyAddr("remote")
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

func App_mux_usage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "   :mux socks5")
	fmt.Fprintln(os.Stderr, "   :mux linkagent")
	fmt.Fprintln(os.Stderr, "   :mux link <L-Config>;<R-Config> (e.g. mux link x://127.0.0.1:8000;none)")
	fmt.Fprintln(os.Stderr, "   :mux httpserver <rootDir1> <rootDir2>...")
	fmt.Fprintln(os.Stderr, "   :mux httpclient <saveDir> <remotePath>")
	fmt.Fprintln(os.Stderr, "   :mux -l listen_port")
}

func AppMuxConfigByArgs(args []string) (*AppMuxConfig, error) {
	config := &AppMuxConfig{
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

	err := handleMuxSession(cfg)
	if err != nil {
		log.Printf(":mux: %v\n", err)
	}
}

func handleMuxSession(cfg MuxSessionConfig) error {
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
func parseLinkConfig(conf string) (string, string, url.Values, error) {
	if conf == "none" {
		return "none", "", nil, nil
	}
	u, err := url.Parse(conf)
	if err != nil {
		return "", "", nil, err
	}
	// "x" -> socks5/dynamic, "f" -> forward, "raw" -> raw bridge (internal use)
	scheme := u.Scheme
	if scheme != "x" && scheme != "f" && scheme != "raw" {
		return "", "", nil, fmt.Errorf("unknown scheme '%s', use x:// or f://", scheme)
	}
	return scheme, u.Host, u.Query(), nil
}

// runLinkListener 通用的监听器，用于 L 端和 R 端
// scheme 支持: "x" (Dynamic/Socks5, tproxy), "f" (Forward), "raw" (Legacy Bridge)
func runLinkListener(session interface{}, ln net.Listener, scheme string, params url.Values, doneChan <-chan struct{}) error {
	defer ln.Close()

	useTProxy := false
	targetHost := ""
	targetPort := 0
	forwardTarget := ""

	actualListenAddr := ln.Addr().String()
	_, actualListenPort, _ := net.SplitHostPort(actualListenAddr)

	// 解析配置
	switch scheme {
	case "x":
		if params.Get("tproxy") == "1" {
			useTProxy = true
		}
		log.Printf("[link-x] Listening on %s (TProxy=%v)\n", ln.Addr().String(), useTProxy)
		if useTProxy {
			donotUsePublicMagicDNS := IsValidABC0IP(MagicDNServer)
			if donotUsePublicMagicDNS {
				targetIpPref := strings.TrimRight(MagicDNServer, ".0")
				log.Printf("   TProxy Format: 127.1.13.61:%s -> %s.1:3389\n", actualListenPort, targetIpPref)
			} else {
				log.Printf("   TProxy Format: 10.0.0.1-3389.%s:%s -> 10.0.0.1:3389\n", MagicDNServer, actualListenPort)
			}
		}
	case "f":
		forwardTarget = params.Get("to")
		if forwardTarget == "" {
			return fmt.Errorf("missing 'to' parameter for forward mode (f://)")
		}
		var err error
		var pStr string
		targetHost, pStr, err = net.SplitHostPort(forwardTarget)
		if err != nil {
			return fmt.Errorf("invalid target address '%s': %v", forwardTarget, err)
		}
		targetPort, _ = strconv.Atoi(pStr)
		log.Printf("[link-f] Listening on %s -> Forward to %s\n", ln.Addr().String(), forwardTarget)
	case "raw":
		log.Printf("[listen] Listening on %s\n", ln.Addr().String())
		if params.Get("mode") == "httpserver" {
			log.Printf("You can open http://127.0.0.1:%s in your browser\n", actualListenPort)
		}
	}

	// 监听 doneChan (Session 死则 Listener 死)
	go func() {
		<-doneChan
		ln.Close()
	}()

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

		// 透明代理 IP 过滤
		magicTargetIP := ""
		if scheme == "x" && useTProxy {
			rhost, _, err := net.SplitHostPort(conn.RemoteAddr().String())
			if err != nil || !strings.HasPrefix(rhost, "127.") {
				conn.Close()
				continue // Only accept 127.x
			}
			lhost, _, _ := net.SplitHostPort(conn.LocalAddr().String())
			if lhost != "127.0.0.1" {
				magicTargetIP = lhost
			}
		}

		go func(c net.Conn) {
			defer c.Close()
			stream, err := openMuxStream(session)
			if err != nil {
				log.Println("mux Open failed:", err)
				return
			}
			streamWithCloseWrite := &streamWrapper{Conn: stream}
			defer streamWithCloseWrite.Close()

			if scheme == "raw" {
				bidirectionalCopy(c, streamWithCloseWrite)
				return
			}

			cmd := ""
			tHost := ""
			tPort := 0

			if scheme == "f" {
				cmd = "T-CONNECT"
				tHost = targetHost
				tPort = targetPort
			} else {
				// x://
				if useTProxy && magicTargetIP != "" {
					cmd = "T-CONNECT"
					tHost, tPort, err = DNSLookupMagicIP(magicTargetIP, false)
					if err != nil {
						log.Println("MagicIP lookup failed:", err)
						return
					}
				}
			}

			ServeProxyOnTunnel(c, streamWithCloseWrite, cmd, tHost, tPort)
		}(conn)
	}
}

// runLinkSessionWithHandshake 提取的公共逻辑：握手 -> 建Session -> 启动业务
// 此函数假定 Hello 已经被读取并确认为 "linkagent"
func runLinkSessionWithHandshake(cfg MuxSessionConfig, lConf string, rConf string) error {
	// 1. 发送 R 配置给远端
	// LocalActive 表示本地有业务，远端可以发送流过来
	localActive := "0"
	if lConf != "none" {
		localActive = "1"
	}

	sendConf := rConf
	if sendConf == "none" {
		sendConf = fmt.Sprintf("none?peer_active=%s", localActive)
	} else {
		if strings.Contains(sendConf, "?") {
			sendConf += fmt.Sprintf("&peer_active=%s", localActive)
		} else {
			sendConf += fmt.Sprintf("?peer_active=%s", localActive)
		}
	}
	sendConf += "\n"

	log.Printf("[link] Sending Remote Config: %s", strings.TrimSpace(sendConf))
	if _, err := cfg.SessionConn.Write([]byte(sendConf)); err != nil {
		return fmt.Errorf("failed to send remote config: %v", err)
	}

	log.Printf("[link] Waiting for Remote ACK...")

	// 2. 等待 ACK
	ack, err := netx.ReadString(cfg.SessionConn, '\n', 1024)
	if err != nil {
		return fmt.Errorf("failed to receive ack: %v", err)
	}
	ack = strings.TrimSpace(ack)
	if !strings.HasPrefix(ack, "OK") {
		return fmt.Errorf("remote link failed: %s", ack)
	}
	log.Printf("[link] Remote ready (%s).", ack)

	cfg.SessionConn.SetDeadline(time.Time{})

	// 3. 创建 Session
	session, err := createMuxSession(cfg.Engine, cfg.SessionConn, true)
	if err != nil {
		return err
	}

	// 4. 启动 Session 监控 (兼任 AcceptLoop)
	remoteActive := (rConf != "none")
	sessionDone := make(chan struct{})
	go func() {
		// 如果 remoteActive 为 false，说明单向模式，这里设置为 drainOnly=true
		startRemoteStreamAcceptLoop(session, cfg.AccessCtrl, !remoteActive)
		close(sessionDone)
	}()

	lScheme, lHost, lParams, err := parseLinkConfig(lConf)
	if err != nil {
		return fmt.Errorf("local config parse error: %v", err)
	}

	if lScheme != "none" {
		enableTProxy := (lScheme == "x" && lParams.Get("tproxy") == "1")
		ln, err := prepareLocalListener(lHost, enableTProxy)
		if err != nil {
			return fmt.Errorf("local bind failed: %v", err)
		}
		log.Printf("[link] Local service started.")
		return runLinkListener(session, ln, lScheme, lParams, sessionDone)
	}

	// Active-only mode
	<-sessionDone
	return fmt.Errorf("link session closed")
}

// handleLinkMode (Local)
func handleLinkMode(cfg MuxSessionConfig) error {
	log.Println("Waiting for linkagent handshake...")
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
func handleListenMode(cfg MuxSessionConfig, notifyAddrChan chan<- string, done context.CancelFunc) error {
	if done != nil {
		defer done()
	}
	log.Println("Waiting for :mux handshake...")
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

		log.Printf("[listen] Detected linkagent peer. Upgrading to link mode (L=%s, R=%s)", lConf, rConf)

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
		startRemoteStreamAcceptLoop(session, cfg.AccessCtrl, true)
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

	log.Printf("[listen] Service started (Legacy). PeerMode=%s", peerModeStr)
	return runLinkListener(session, ln, scheme, params, sessionDone)
}

// handleLinkAgentMode (Remote)
func handleLinkAgentMode(cfg MuxSessionConfig) error {
	// 1. 发送 Hello
	if err := sendHello(cfg.SessionConn, "linkagent"); err != nil {
		return err
	}

	log.Printf("[linkagent] Receiving config request...")

	// 2. 读取配置
	cfg.SessionConn.SetReadDeadline(time.Now().Add(25 * time.Second))
	reqStr, err := netx.ReadString(cfg.SessionConn, '\n', 1024)
	if err != nil {
		return fmt.Errorf("read config error: %w", err)
	}
	cfg.SessionConn.SetReadDeadline(time.Time{})

	reqStr = strings.TrimSpace(reqStr)
	log.Printf("[linkagent] Received config request: %s", reqStr)

	rConf := reqStr
	peerActive := false

	if strings.HasPrefix(rConf, "none") {
		if strings.Contains(rConf, "peer_active=1") {
			peerActive = true
		}
		rConf = "none"
	} else {
		u, err := url.Parse(rConf)
		if err == nil {
			if u.Query().Get("peer_active") == "1" {
				peerActive = true
			}
		}
	}

	rScheme, rHost, rParams, err := parseLinkConfig(rConf)
	if err != nil {
		cfg.SessionConn.Write([]byte(fmt.Sprintf("ERROR: %v\n", err)))
		return err
	}

	// 3. 绑定端口 (如果 R 不是 none)
	var ln net.Listener
	ackMsg := "OK"

	if rScheme != "none" {
		enableTProxy := (rScheme == "x" && rParams.Get("tproxy") == "1")
		ln, err = prepareLocalListener(rHost, enableTProxy)
		if err != nil {
			cfg.SessionConn.Write([]byte(fmt.Sprintf("ERROR: bind failed %v\n", err)))
			return err
		}
		ackMsg = fmt.Sprintf("OK:%s", ln.Addr().String())
	} else {
		ackMsg = "OK:none"
	}

	if _, err := cfg.SessionConn.Write([]byte(ackMsg + "\n")); err != nil {
		if ln != nil {
			ln.Close()
		}
		return err
	}

	// 4. 创建 Session
	session, err := createMuxSession(cfg.Engine, cfg.SessionConn, false)
	if err != nil {
		if ln != nil {
			ln.Close()
		}
		return err
	}

	log.Printf("[linkagent] Session established.")

	// 5. 启动 Session 监控 (兼任 AcceptLoop)
	sessionDone := make(chan struct{})
	go func() {
		startRemoteStreamAcceptLoop(session, cfg.AccessCtrl, !peerActive)
		close(sessionDone)
	}()

	if rScheme != "none" && ln != nil {
		return runLinkListener(session, ln, rScheme, rParams, sessionDone)
	}

	<-sessionDone
	return fmt.Errorf("linkagent session closed")
}

// -----------------------------------------------------------------------------
// Legacy & Common Handlers
// -----------------------------------------------------------------------------

func handleHTTPClientMode(cfg MuxSessionConfig) error {
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
			LoggerOutput:           os.Stderr,
			ProgressOutput:         os.Stderr,
			ProgressUpdateInterval: 1 * time.Second,
			NoCompress:             *VarhttpDownloadNoCompress,
		}

		c, err := httpfileshare.NewClient(httpcfg)
		if err != nil {
			log.Printf("Failed to create HTTP client: %v\n", err)
			return err
		}
		if err := c.Start(ctx); err != nil {
			log.Printf("Client operation failed: %v\n", err)
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	}
}

// startRemoteStreamAcceptLoop 从 mux session 接受流并处理 SOCKS5 请求
func startRemoteStreamAcceptLoop(session interface{}, accessCtrl *acl.ACL, drainOnly bool) error {
	listener := &muxListener{session}
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

		go handleSocks5ClientOnStream(stream, "", accessCtrl)
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

func handleSocks5uMode(cfg MuxSessionConfig) error {
	if err := sendHello(cfg.SessionConn, cfg.AppMode); err != nil {
		return err
	}

	session, err := createMuxSession(cfg.Engine, cfg.SessionConn, false)
	if err != nil {
		return fmt.Errorf("create mux session failed: %v", err)
	}

	log.Printf("[socks5] tunnel server ready on mux session(%s).", cfg.SessionConn.RemoteAddr().String())
	err = startRemoteStreamAcceptLoop(session, cfg.AccessCtrl, false)
	log.Printf("[socks5] finished(%s).", cfg.SessionConn.RemoteAddr().String())
	return err
}

func handleHTTPServerMode(cfg MuxSessionConfig) error {
	if err := sendHello(cfg.SessionConn, cfg.AppMode); err != nil {
		return err
	}

	session, err := createMuxSession(cfg.Engine, cfg.SessionConn, false)
	if err != nil {
		return err
	}

	ln := &muxListener{session}
	enableZstd := true

	srvcfg := httpfileshare.ServerConfig{
		RootPaths:    cfg.HttpServerVDirs,
		LoggerOutput: os.Stderr,
		EnableZstd:   enableZstd,
		Listener:     ln,
	}

	server, err := httpfileshare.NewServer(srvcfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	log.Println("httpserver ready on mux")

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
