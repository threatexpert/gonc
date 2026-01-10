package apps

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	//_ "net/http/pprof"

	"github.com/threatexpert/gonc/v2/acl"
	"github.com/threatexpert/gonc/v2/easyp2p"
	"github.com/threatexpert/gonc/v2/httpfileshare"
	"github.com/threatexpert/gonc/v2/misc"
	"github.com/threatexpert/gonc/v2/netx"
	"github.com/threatexpert/gonc/v2/secure"
	"golang.org/x/term"
)

var (
	VERSION = "v2.4.9"
)

type AppNetcatConfig struct {
	ConsoleMode                bool
	Logger                     *log.Logger
	LogWriter                  io.Writer
	goroutineConnectionCounter int32

	ctx                          context.Context
	callback_OnConnectionDestroy func(localAddrStr, remoteAddrStr string)

	network, host, port, p2pSessionKey string
	connConfig                         *secure.NegotiationConfig
	sessionReady                       bool
	tlsVerifyCert                      bool
	keepAlive                          int

	app_mux_args          string
	app_mux_Config        *AppMuxConfig
	app_s5s_args          string
	app_s5s_Config        *AppS5SConfig
	arg_proxyc_Config     *ProxyClientConfig
	fallbackRelayMode     bool
	app_sh_args           string
	app_sh_Config         *PtyShellConfig
	app_nc_args           string
	app_nc_Config         *AppNetcatConfig
	app_tp_Config         *AppTPConfig
	app_pr_args           string
	app_pr_Config         *AppPortRotateConfig
	app_br_args           string
	app_br_Config         *AppBridgeConfig
	app_httpserver_args   string
	app_httpserver_Config *AppHttpServerConfig

	accessControl *acl.ACL
	term_oldstat  *term.State

	proxyProt         string
	proxyAddr         string
	proxyAddr2        string
	auth              string
	sendfile          string
	sendsize          int64
	writefile         string
	tlsEnabled        bool
	tlsServerMode     bool
	tls10_forced      bool
	tls11_forced      bool
	tls12_forced      bool
	tls13_forced      bool
	tlsECCertEnabled  bool
	tlsRSACertEnabled bool
	tlsSNI            string
	sslCertFile       string
	sslKeyFile        string
	presharedKey      string
	autoPSK           bool
	shadowStream      bool
	enableCRLF        bool
	listenMode        bool
	udpProtocol       bool
	useUNIXdomain     bool
	kcpEnabled        bool
	kcpSEnabled       bool
	localbind         string
	localbindIP       string
	remoteAddr        string
	progressEnabled   bool
	runCmd            string
	remoteCall        string
	keepOpen          bool
	enablePty         bool
	useSTUN           bool
	stunSrv           string
	mqttServers       string
	autoP2P           string
	useMutilPath      bool
	useMQTTWait       bool
	useMQTTHello      bool
	MQTTHelloPayload  easyp2p.HelloPayload
	useIPv4           bool
	useIPv6           bool
	useDNS            string
	runAppFileServ    string
	runAppFileGet     string
	downloadSubPath   string
	appMuxListenMode  bool
	appMuxListenOn    string
	appMuxSocksMode   bool
	appMuxLinkAgent   bool
	runAppLink        string
	fileACL           string
	plainTransport    bool
	framedStdio       bool
	framedTCP         bool
	p2pReportURL      string
	featureModulesRun []string
	Args              []string
	natchecker        bool
	httpdownload      bool
	portRotate        bool
	kcpBridgeMode     bool
	verbose           bool
	verboseWithTime   bool
	muxEnabled        bool
	muxLocalPort      string
	muxLocalListener  net.Listener
	dialreadTimeout   int
	scanOnly          bool
}

// AppNetcatConfigByArgs 解析给定的 []string 参数，生成 AppNetcatConfig
func AppNetcatConfigByArgs(logWriter io.Writer, argv0 string, args []string) (*AppNetcatConfig, error) {
	var swriter *misc.SwitchableWriter
	if sw, ok := logWriter.(*misc.SwitchableWriter); ok {
		// 复用，不再包一层
		swriter = sw
	} else {
		swriter = misc.NewSwitchableWriter(logWriter, true)
	}

	config := &AppNetcatConfig{
		LogWriter: swriter,
		Logger:    log.New(swriter, "", 0),
		ctx:       context.Background(),
	}

	// 创建一个自定义的 FlagSet，而不是使用全局的 flag.CommandLine
	// 设置 ContinueOnError 允许我们捕获错误而不是直接退出
	fs := flag.NewFlagSet("AppNetcatConfig", flag.ContinueOnError)
	fs.SetOutput(logWriter)

	// 定义命令行参数
	fs.StringVar(&config.proxyProt, "X", "", "proxy_protocol. Supported protocols are “5” (SOCKS v.5) and “connect” (HTTPS proxy).  If the protocol is not specified, SOCKS version 5 is used.")
	fs.StringVar(&config.proxyAddr, "x", "", "\"[options: -tls -psk] ip:port\" for proxy_address")
	fs.StringVar(&config.proxyAddr2, "x2", "", "Proxy address (same format as -x). Only used if P2P connection fails.")
	fs.StringVar(&config.auth, "auth", "", "user:password for proxy")
	fs.StringVar(&config.sendfile, "send", "", "path to file to send (optional)")
	fs.Int64Var(&config.sendsize, "sendsize", 0, "size of file to send (optional, default is full file size)")
	fs.StringVar(&config.writefile, "write", "", "write to file")
	fs.BoolVar(&config.tlsEnabled, "tls", false, "Enable TLS connection")
	fs.BoolVar(&config.tlsServerMode, "tlsserver", false, "force as TLS server while connecting")
	fs.BoolVar(&config.tls10_forced, "tls10", false, "force negotiation to specify TLS version")
	fs.BoolVar(&config.tls11_forced, "tls11", false, "force negotiation to specify TLS version")
	fs.BoolVar(&config.tls12_forced, "tls12", false, "force negotiation to specify TLS version")
	fs.BoolVar(&config.tls13_forced, "tls13", false, "force negotiation to specify TLS version")
	fs.BoolVar(&config.tlsECCertEnabled, "tlsec", true, "enable TLS EC cert")
	fs.BoolVar(&config.tlsRSACertEnabled, "tlsrsa", false, "enable TLS RSA cert")
	fs.StringVar(&config.tlsSNI, "sni", "", "specify TLS SNI")
	fs.StringVar(&config.sslCertFile, "ssl-cert", "", "Specify SSL certificate file (PEM) for listening")
	fs.StringVar(&config.sslKeyFile, "ssl-key", "", "Specify SSL private key (PEM) for listening")
	fs.StringVar(&config.presharedKey, "psk", "", "Pre-shared key for deriving TLS certificate identity (anti-MITM) and for TCP/KCP encryption; when using -p2p, the P2P session key overrides this value.")
	fs.BoolVar(&config.autoPSK, "auto-psk", false, "Use MQTT/ECDHE to automatically derive shared encryption key")
	fs.BoolVar(&config.shadowStream, "ss", false, "TLS-free, lightweight, low-signature encrypted transport in P2P mode")
	fs.BoolVar(&config.enableCRLF, "C", false, "enable CRLF")
	fs.BoolVar(&config.listenMode, "l", false, "listen mode")
	fs.BoolVar(&config.udpProtocol, "u", false, "use UDP protocol")
	fs.BoolVar(&config.useUNIXdomain, "U", false, "Specifies to use UNIX-domain sockets.")
	fs.BoolVar(&config.kcpEnabled, "kcp", false, "use UDP+KCP protocol, -u can be omitted")
	fs.BoolVar(&config.kcpSEnabled, "kcps", false, "kcp server mode")
	fs.StringVar(&config.localbind, "local", "", "ip:port")
	fs.StringVar(&config.remoteAddr, "remote", "", "host:port address to connect to; do not need to provide final <host> <port> arguments if this is set")
	fs.BoolVar(&config.progressEnabled, "progress", false, "show transfer progress")
	fs.StringVar(&config.runCmd, "exec", "", "runs a command for each connection")
	fs.StringVar(&config.remoteCall, "call", "", "send a string with LF for each connection")
	fs.BoolVar(&config.keepOpen, "keep-open", false, "keep listening after client disconnects")
	fs.BoolVar(&config.enablePty, "pty", false, "put the terminal into raw mode")
	fs.BoolVar(&config.useSTUN, "stun", false, "use STUN to discover public IP")
	fs.StringVar(&config.autoP2P, "p2p", "", "P2P session key (or @file). Auto try UDP/TCP via NAT traversal")
	fs.StringVar(&config.p2pReportURL, "p2p-report-url", "", "API for reporting P2P status")
	fs.BoolVar(&config.useMutilPath, "mp", false, "enable multipath(NOT IMPL)")
	fs.BoolVar(&config.useMQTTWait, "mqtt-wait", false, "wait for MQTT hello message before initiating P2P connection")
	fs.BoolVar(&config.useMQTTWait, "W", false, "alias for -mqtt-wait")
	fs.BoolVar(&config.useMQTTHello, "mqtt-hello", false, "send MQTT hello message before initiating P2P connection")
	fs.BoolVar(&config.useMQTTHello, "H", false, "alias for -mqtt-hello")
	fs.BoolVar(&config.useIPv4, "4", false, "Forces to use IPv4 addresses only")
	fs.BoolVar(&config.useIPv6, "6", false, "Forces to use IPv4 addresses only")
	fs.StringVar(&config.useDNS, "dns", "", "set DNS Server")
	fs.StringVar(&config.runAppFileServ, "httpserver", "", "(mux tunnel mode)http server root directory")
	fs.StringVar(&config.runAppFileGet, "download", "", "(mux tunnel mode)Enable directory download; specifies the local path where the remote directory will be saved")
	fs.StringVar(&config.downloadSubPath, "download-subpath", "", "Remote directory to download (default: /); used together with -download")
	fs.BoolVar(&config.appMuxListenMode, "httplocal", false, "(mux tunnel mode)local listen mode for remote httpserver")
	fs.StringVar(&config.appMuxListenOn, "httplocal-port", "", "(mux tunnel mode)local listen port for remote httpserver")
	fs.BoolVar(&config.appMuxSocksMode, "socks5server", false, "(mux tunnel mode)socks5 server")
	fs.BoolVar(&config.appMuxLinkAgent, "linkagent", false, "(mux tunnel mode)dual proxy service")
	fs.StringVar(&config.runAppLink, "link", "", "(mux tunnel mode)\"<L-Config>;<R-Config>\" (e.g. mux link \"1080;1080\")")
	fs.BoolVar(&config.portRotate, "port-rotate", false, "enable port rotation feature")
	fs.BoolVar(&config.kcpBridgeMode, "kcpbr", false, "kcp bridge mode")
	fs.StringVar(&config.fileACL, "acl", "", "ACL file for inbound/outbound connections")
	fs.BoolVar(&config.plainTransport, "plain", false, "use plain TCP/UDP without TLS/KCP/Encryption for P2P")
	fs.BoolVar(&config.framedStdio, "framed", false, "stdin/stdout is framed stream (2 bytes length prefix for each frame)")
	fs.BoolVar(&config.framedTCP, "framed-tcp", false, "tcp is framed stream (2 bytes length prefix for each frame)")
	fs.BoolVar(&config.tlsVerifyCert, "verify", false, "verify TLS certificate (client mode only)")
	fs.IntVar(&config.keepAlive, "keepalive", 0, "none 0 will enable keepalive feature")
	fs.BoolVar(&config.verbose, "v", true, "verbose output")
	fs.BoolVar(&config.muxEnabled, "mux", false, "Enable multiplexing protocol. Server mux mode")
	fs.StringVar(&config.muxLocalPort, "mux-l", "", "Client mux mode: local listen port or '-' for stdin/stdout")
	fs.IntVar(&config.dialreadTimeout, "w", 0, "timeout in seconds for dialing or idle reads (0 = disabled)")
	fs.BoolVar(&config.scanOnly, "z", false, "connection test mode (establish connection only, no data transfer")

	fs.StringVar(&config.runCmd, "e", "", "alias for -exec")
	fs.BoolVar(&config.progressEnabled, "P", false, "alias for -progress")
	fs.BoolVar(&config.keepOpen, "k", false, "alias for -keep-open")
	fs.BoolVar(&config.appMuxListenMode, "socks5local", false, "(mux tunnel mode)local random port for remote socks5server")
	fs.StringVar(&config.appMuxListenOn, "socks5local-port", "", "(mux tunnel mode)local listen port for remote socks5server")
	fs.BoolVar(&config.appMuxListenMode, "browser", false, "alias for -httplocal")
	fs.StringVar(&config.app_mux_args, ":mux", "-", "enable and config :mux for dynamic service")
	fs.StringVar(&config.app_s5s_args, ":s5s", "-", "enable and config :s5s for dynamic service")
	fs.StringVar(&config.app_sh_args, ":sh", "-", "enable and config :sh for dynamic service")
	fs.StringVar(&config.app_nc_args, ":nc", "-", "enable and config :nc for dynamic service")
	fs.StringVar(&config.app_pr_args, ":pr", "-", "enable and config :pr for dynamic service")
	fs.StringVar(&config.app_br_args, ":br", "-", "enable and config :br for dynamic service")
	fs.StringVar(&config.app_httpserver_args, ":httpserver", "-", "enable and config :httpserver for dynamic service")
	fs.BoolVar(&config.natchecker, "nat-checker", false, "detect NAT type and public IP")
	fs.BoolVar(&config.httpdownload, "http-download", false, "<localDir> <urlPath>; download from gonc's (-httplocal-port) HTTP service")

	//<----- Global flags
	fs.StringVar(&config.stunSrv, "stunsrv", strings.Join(easyp2p.STUNServers, ","), "STUN server list, comma-separated (e.g. stun1,stun2) or '@<file>' with one server per line")
	fs.StringVar(&config.mqttServers, "mqttsrv", strings.Join(easyp2p.MQTTBrokerServers, ","), "MQTT servers")
	fs.StringVar(&MagicDNServer, "magicdns", MagicDNServer, "MagicDNServer")
	disableCompress := fs.Bool("no-compress", false, "disable compression for http download")
	VarhttpDownloadNoCompress = disableCompress
	fs.StringVar(&easyp2p.TopicExchange, "mqtt-nat-topic", easyp2p.TopicExchange, "")
	fs.IntVar(&easyp2p.PunchingShortTTL, "punch-short-ttl", easyp2p.PunchingShortTTL, "")
	fs.IntVar(&easyp2p.PunchingRandomPortCount, "punch-random-count", easyp2p.PunchingRandomPortCount, "")
	fs.IntVar(&secure.UdpOutputBlockSize, "udp-size", secure.UdpOutputBlockSize, "")
	fs.IntVar(&secure.KcpWindowSize, "kcp-window-size", secure.KcpWindowSize, "")
	fs.IntVar(&secure.KCPIdleTimeoutSecond, "kcp-timeout", secure.KCPIdleTimeoutSecond, "kcp idle timeout seconds (0 means no timeout)")
	fs.IntVar(&secure.KcpUpdateInterval, "kcp-update-interval", secure.KcpUpdateInterval, "KCP update interval in milliseconds")
	fs.StringVar(&secure.UdpKeepAlivePayload, "udp-ping-data", secure.UdpKeepAlivePayload, "")
	fs.IntVar(&secure.UDPIdleTimeoutSecond, "udp-timeout", secure.UDPIdleTimeoutSecond, "udp idle timeout seconds (0 means no timeout)")
	fs.StringVar(&VarmuxEngine, "mux-engine", VarmuxEngine, "yamux | smux")
	fs.IntVar(&VarMuxKeepAliveTimeout, "mux-timeout", VarMuxKeepAliveTimeout, "mux keepalive timeout seconds (0 means no timeout)")
	//----->

	fs.Usage = func() {
		usage_full(argv0, fs)
	}

	args = reorderNetcatArgs(args)

	// 解析传入的 args 切片
	// 注意：我们假设 args 已经不包含程序名 (os.Args[0])，所以直接传入
	err := fs.Parse(args)
	if err != nil {
		return nil, err // 解析错误直接返回
	}
	config.Args = fs.Args()
	if config.verbose {
		if config.verboseWithTime || config.keepOpen || isAppModeRequiredKeepOpen(config) || argv0 == ":nc" {
			prefix := ""
			if argv0 != "" {
				prefix = fmt.Sprintf("[%s] ", argv0)
			}
			config.Logger = misc.NewLog(swriter, prefix, log.LstdFlags|log.Lmsgprefix)
			config.verboseWithTime = true
		}
	}

	// 1. 初始化基本设置
	firstInit(config)

	// 2. 配置内置应用程序模式（例如http服务器，socks5）
	configureAppMode(config)

	// 3. 配置安全功能，如PSK和ACL
	err = configureSecurity(config)
	if err != nil {
		fmt.Fprintf(logWriter, "Security configuration failed: %v\n", err)
		os.Exit(1)
	}

	if fs.NFlag() == 0 && fs.NArg() == 0 {
		usage_less(logWriter, argv0)
		os.Exit(1)
	}

	// 4. 从参数和标志确定网络类型、地址和P2P会话密钥
	network, host, port, P2PSessionKey, err := determineNetworkAndAddress(config)
	if err != nil && len(config.featureModulesRun) == 0 {
		fmt.Fprintf(logWriter, "Error determining network address: %v\n", err)
		os.Exit(1)
	}

	config.network = network
	config.host = host
	config.port = port
	config.p2pSessionKey = P2PSessionKey

	// 5. 配置TLS、DNS、会话协商参数等
	if config.tlsSNI == "" {
		if config.listenMode {
			config.tlsSNI = "localhost"
		} else {
			config.tlsSNI = host
		}
	}
	configureDNS(config)

	config.connConfig = preinitNegotiationConfig(config)
	swriter.Enable(config.verbose)
	return config, nil
}

// reorderNetcatArgs 对参数列表进行“清洗”和重排
// 目的：让标准库 flag 能解析所有的 -flag，将非 flag 参数（IP, Port, -l 的值）统一赶到最后
func reorderNetcatArgs(args []string) []string {
	var keepArgs []string // 放在前面，供 flag.Parse 解析
	var tailArgs []string // 挪到最后，作为剩余参数

	// 标记是否已经遇到过第一个 flag
	// 用途：用于判断出现在开头的参数是否需要移动
	firstFlagFound := false

	i := 0
	for i < len(args) {
		arg := args[i]
		isFlag := strings.HasPrefix(arg, "-")

		// ------------------------------------------------------
		// 逻辑 1: 处理开头的非 Flag 参数 (如: gonc 127.0.0.1 -e cmd)
		// ------------------------------------------------------
		// 如果还没遇到过 flag，且当前参数不是 flag，说明这是开头的 args，先存入 tail
		if !firstFlagFound && !isFlag {
			tailArgs = append(tailArgs, arg)
			i++
			continue
		}

		// 一旦遇到了 flag (以 - 开头)，改变状态
		if isFlag {
			firstFlagFound = true
		}

		// ------------------------------------------------------
		// 逻辑 2: 处理 -l 或 --l 及其参数
		// ------------------------------------------------------
		if arg == "-l" || arg == "--l" {
			// 向后看一位 (Lookahead)
			// 如果后面还有参数，且该参数 **不是** 以 "-" 开头
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				// 判定为：-l 携带了参数 (如 -l 2222)
				// 将 -l 和它的参数都挪到 tailArgs
				tailArgs = append(tailArgs, arg)
				i++

				// 贪婪匹配：继续吃掉后续的非 flag 参数 (IP, Port)
				for i < len(args) {
					nextArg := args[i]
					if strings.HasPrefix(nextArg, "-") {
						break // 遇到下一个 flag，停止移动
					}
					tailArgs = append(tailArgs, nextArg)
					i++
				}
				continue // 完成本次处理，进入下一轮
			}
		}

		// ------------------------------------------------------
		// 逻辑 3: 普通参数 (正常的 flag 或 flag 的值)
		// ------------------------------------------------------
		// 直接保留在原位
		keepArgs = append(keepArgs, arg)
		i++
	}

	// 将被移动的参数拼接到最后
	return append(keepArgs, tailArgs...)
}

func App_Netcat_main(console *misc.ConsoleIO, args []string) int {
	config, err := AppNetcatConfigByArgs(os.Stderr, "gonc", args)
	if err != nil {
		if err == flag.ErrHelp {
			return 1
		}
		fmt.Fprintf(os.Stderr, "Error parsing gonc args: %v\n", err)
		return 1
	}
	config.ConsoleMode = true

	return App_Netcat_main_withconfig(console, config)
}

var pprofOnce sync.Once

func startPprofFromEnv(config *AppNetcatConfig) {
	// 真要开启pprof要去掉上面import里注释掉的 _ "net/http/pprof"
	debugPort := os.Getenv("PPROF_DEBUG")
	if debugPort != "" {
		pprofOnce.Do(func() {
			go func() {
				addr := "127.0.0.1:" + debugPort
				config.Logger.Printf("pprof enabled on http://%s/debug/pprof/", addr)
				if err := http.ListenAndServe(addr, nil); err != nil {
					config.Logger.Printf("pprof server stopped: %v", err)
				}
			}()
			time.Sleep(1 * time.Second)
		})
	}
}

func App_Netcat_main_withconfig(console net.Conn, config *AppNetcatConfig) int {
	startPprofFromEnv(config)
	defer console.Close()
	if len(config.featureModulesRun) != 0 {
		return runFeatureModules(console, config)
	}

	if isLocalMuxMode(config) && config.muxLocalListener == nil && config.muxLocalPort != "-" {
		ln, err := prepareLocalListener(config.muxLocalPort, false)
		if err != nil {
			config.Logger.Printf("Error starting local mux listener on %s: %v\n", config.muxLocalPort, err)
			return 1
		}
		config.muxLocalListener = ln
		config.Logger.Printf("Mux local listener started on %s\n", ln.Addr().String())
	}

	if config.p2pSessionKey != "" {
		return runP2PMode(console, config)
	} else {
		if config.listenMode {
			return runListenMode(console, config, config.network, config.host, config.port)
		} else {
			startPort, endPort, isRange := parsePortRange(config.port)
			if isRange {
				// 进入并发扫描模式
				concurrency := 50
				return runScanMode(console, config, startPort, endPort, concurrency)
			}
			return runDialMode(console, config, config.network, config.host, config.port)
		}
	}
}

func firstInit(ncconfig *AppNetcatConfig) {
	easyp2p.MQTTBrokerServers = parseMultiItems(ncconfig.mqttServers, true)

	if ncconfig.stunSrv != "" {
		if strings.HasPrefix(ncconfig.stunSrv, "@") {
			data, err := os.ReadFile(strings.TrimPrefix(ncconfig.stunSrv, "@"))
			if err != nil {
				ncconfig.Logger.Printf("read stun server file failed: %v\n", err)
				os.Exit(1)
			}
			lines := strings.Split(string(data), "\n")
			ncconfig.stunSrv = strings.Join(lines, ",")
		}
	}

	easyp2p.STUNServers = parseMultiItems(ncconfig.stunSrv, true)
	if conflictCheck(ncconfig) != 0 {
		os.Exit(1)
	}
}

func isEnabledMuxMode(ncconfig *AppNetcatConfig) bool {
	return ncconfig.muxEnabled || ncconfig.muxLocalPort != ""
}

func isLocalMuxMode(ncconfig *AppNetcatConfig) bool {
	return isEnabledMuxMode(ncconfig) && ncconfig.muxLocalPort != ""
}

func isAppModeRequiredKeepOpen(ncconfig *AppNetcatConfig) bool {
	if ncconfig.runAppFileServ != "" ||
		ncconfig.runAppFileGet != "" ||
		ncconfig.appMuxSocksMode ||
		ncconfig.appMuxLinkAgent ||
		ncconfig.appMuxListenMode || ncconfig.appMuxListenOn != "" ||
		ncconfig.runAppLink != "" ||
		ncconfig.muxLocalPort != "" {
		return true
	}
	return false
}

// configureAppMode 为内置应用程序设置命令参数
func configureAppMode(ncconfig *AppNetcatConfig) {
	userSpecifiedRunCmd := ncconfig.runCmd != ""
	appMode := false
	if ncconfig.runAppFileServ != "" {
		//使用了-httpserver 的情况，获取多余的参数都当作根目录添加进去。
		rootPaths := []string{ncconfig.runAppFileServ}
		if len(ncconfig.Args) > 0 {
			if ncconfig.autoP2P != "" || //P2P模式
				(ncconfig.listenMode && ncconfig.localbind != "") || //监听模式，但使用了-local而不是使用多余参数作为监听地址
				(!ncconfig.listenMode && ncconfig.remoteAddr != "") { //dial模式，但使用了-remote而不是使用多余参数作为dial目的地址
				rootPaths = append(rootPaths, ncconfig.Args...)
				ncconfig.Args = nil
			}
		}
		ncconfig.runCmd = ":mux httpserver"
		for _, p := range rootPaths {
			escapedPath := strings.ReplaceAll(p, "\\", "/")
			ncconfig.runCmd += fmt.Sprintf(" \"%s\"", escapedPath)
		}

		ncconfig.useMQTTWait = true
		ncconfig.progressEnabled = true
		ncconfig.keepOpen = true
		appMode = true
	} else if ncconfig.runAppFileGet != "" {
		escapedPath := strings.ReplaceAll(ncconfig.runAppFileGet, "\\", "/")
		downloadSubPath := strings.ReplaceAll(ncconfig.downloadSubPath, "\\", "/")
		ncconfig.runCmd = fmt.Sprintf(":mux httpclient \"%s\"", escapedPath)
		if downloadSubPath != "" {
			ncconfig.runCmd += fmt.Sprintf(" \"%s\"", downloadSubPath)
		}
		if ncconfig.appMuxListenOn != "" {
			VarmuxLastListenAddress = ncconfig.appMuxListenOn
		}
		ncconfig.useMQTTHello = true
		ncconfig.keepOpen = true
		appMode = true
	} else if ncconfig.appMuxSocksMode {
		ncconfig.runCmd = ":mux socks5"
		ncconfig.useMQTTWait = true
		ncconfig.progressEnabled = true
		ncconfig.keepOpen = true
		appMode = true
	} else if ncconfig.appMuxLinkAgent {
		ncconfig.runCmd = ":mux linkagent"
		ncconfig.useMQTTWait = true
		ncconfig.progressEnabled = true
		ncconfig.keepOpen = true
		appMode = true
	} else if ncconfig.runAppLink != "" {
		ncconfig.runCmd = ":mux link " + ncconfig.runAppLink
		ncconfig.useMQTTHello = true
		ncconfig.keepOpen = true
		appMode = true
	} else if ncconfig.appMuxListenMode || ncconfig.appMuxListenOn != "" {
		if ncconfig.appMuxListenOn == "" {
			ncconfig.appMuxListenOn = "0"
		}
		ncconfig.runCmd = fmt.Sprintf(":mux -l %s", ncconfig.appMuxListenOn)
		ncconfig.useMQTTHello = true
		ncconfig.keepOpen = true
		appMode = true
	}

	if appMode && userSpecifiedRunCmd {
		// appMode（-linkagent等） 需要替换runCmd， 如果本来用户配置了-e，则有冲突
		ncconfig.Logger.Printf("Error: App modes (-httpserver, -linkagent, etc.) cannot be used with -e \n")
		os.Exit(1)
	}

	if ncconfig.portRotate {
		if strings.HasPrefix(ncconfig.runCmd, ":mux ") {
			ncconfig.remoteCall = ":pr"
			if ncconfig.app_pr_args == "-" {
				ncconfig.app_pr_args = ""
			}
			ncconfig.app_mux_args = strings.TrimPrefix(ncconfig.runCmd, ":mux ")
			ncconfig.runCmd = ":service"
		} else {
			ncconfig.Logger.Printf("-portrate and -e \":mux ...\"(socks5server/httpserver/linkagent) must be used together\n")
			os.Exit(1)
		}
	} else if ncconfig.kcpBridgeMode {
		if !strings.HasPrefix(ncconfig.runCmd, ":mux ") {
			ncconfig.Logger.Printf("-kcpbr and -e \":mux ...\"(socks5server/httpserver/linkagent) must be used together\n")
			os.Exit(1)
		}
	}

	var err error
	if ncconfig.runCmd != "" && ncconfig.runCmd != ":service" {
		err = preinitBuiltinAppConfig(ncconfig, ncconfig.runCmd)
	} else {
		if ncconfig.app_mux_args != "-" {
			err = preinitBuiltinAppConfig(ncconfig, ":mux "+ncconfig.app_mux_args)
		}
		if err == nil && ncconfig.app_s5s_args != "-" {
			err = preinitBuiltinAppConfig(ncconfig, ":s5s "+ncconfig.app_s5s_args)
		}
		if err == nil && ncconfig.app_sh_args != "-" {
			err = preinitBuiltinAppConfig(ncconfig, ":sh "+ncconfig.app_sh_args)
		}
		if err == nil && ncconfig.app_nc_args != "-" {
			err = preinitBuiltinAppConfig(ncconfig, ":nc "+ncconfig.app_nc_args)
		}
		if err == nil && ncconfig.app_pr_args != "-" {
			err = preinitBuiltinAppConfig(ncconfig, ":pr "+ncconfig.app_pr_args)
		}
		if err == nil && ncconfig.app_br_args != "-" {
			err = preinitBuiltinAppConfig(ncconfig, ":br "+ncconfig.app_br_args)
		}
		if err == nil && ncconfig.app_httpserver_args != "-" {
			err = preinitBuiltinAppConfig(ncconfig, ":httpserver "+ncconfig.app_httpserver_args)
		}
	}
	if err != nil {
		if err != flag.ErrHelp {
			ncconfig.Logger.Printf("%v\n", err)
		}
		os.Exit(1)
	}

	xcommandline := ncconfig.proxyAddr
	if ncconfig.proxyAddr2 != "" {
		xcommandline = ncconfig.proxyAddr2
		ncconfig.fallbackRelayMode = true
	}
	if xcommandline != "" {
		xconfig, err := ProxyClientConfigByCommandline(ncconfig.LogWriter, ncconfig.proxyProt, ncconfig.auth, xcommandline)
		if err != nil {
			if err != flag.ErrHelp {
				ncconfig.Logger.Printf("Error init proxy config: %v\n", err)
			}
			os.Exit(1)
		}
		ncconfig.arg_proxyc_Config = xconfig
	}
	if ncconfig.natchecker {
		ncconfig.featureModulesRun = append(ncconfig.featureModulesRun, "nat-checker")
	}
	if ncconfig.httpdownload {
		ncconfig.featureModulesRun = append(ncconfig.featureModulesRun, "http-download")
	}
	if ncconfig.kcpBridgeMode {
		ncconfig.featureModulesRun = append(ncconfig.featureModulesRun, "kcp-bridge")
	}
}

func configureSecurity(ncconfig *AppNetcatConfig) error {
	var err error
	if ncconfig.presharedKey == "." {
		ncconfig.presharedKey, err = secure.GenerateSecureRandomString(22)
		if err != nil {
			panic(err)
		}
		fmt.Fprintf(os.Stdout, "%s\n", ncconfig.presharedKey)
		os.Exit(1)
	}
	if ncconfig.presharedKey != "" {
		if strings.HasPrefix(ncconfig.presharedKey, "@") {
			ncconfig.presharedKey, err = secure.ReadPSKFile(ncconfig.presharedKey)
			if err != nil {
				ncconfig.Logger.Printf("Error reading PSK file: %v\n", err)
				os.Exit(1)
			}
		}
	}

	var aclData *acl.ACL
	if ncconfig.fileACL != "" {
		aclData, err = acl.LoadACL(ncconfig.fileACL)
		if err != nil {
			return fmt.Errorf("failed to load ACL file: %w", err)
		}
	}
	ncconfig.accessControl = aclData
	return nil
}

// determineNetworkAndAddress 解析网络协议、主机、端口和P2P密钥
func determineNetworkAndAddress(ncconfig *AppNetcatConfig) (network, host, port, P2PSessionKey string, err error) {
	if ncconfig.kcpEnabled || ncconfig.kcpSEnabled {
		ncconfig.udpProtocol = true
	}
	if ncconfig.udpProtocol {
		network = "udp"
	} else if ncconfig.useUNIXdomain {
		network = "unix"
	} else {
		network = "tcp"
	}
	if network != "unix" {
		if ncconfig.useIPv4 {
			network += "4"
		} else if ncconfig.useIPv6 {
			network += "6"
		}
	}

	if ncconfig.localbind != "" {
		localbindIP, _, err := net.SplitHostPort(ncconfig.localbind)
		if err != nil {
			return network, "", "", "", fmt.Errorf("invalid local bind address: %v", err)
		}
		ncconfig.localbindIP = localbindIP
	}

	switch len(ncconfig.Args) {
	case 2:
		host, port = ncconfig.Args[0], ncconfig.Args[1]
	case 1:
		if ncconfig.listenMode {
			port = ncconfig.Args[0]
		} else if ncconfig.useUNIXdomain {
			port = ncconfig.Args[0]
		} else {
			return network, "", "", "", fmt.Errorf("invalid arguments")
		}
	case 0:
		if ncconfig.listenMode && ncconfig.localbind != "" {
			host, port, err = net.SplitHostPort(ncconfig.localbind)
			if err != nil {
				return network, "", "", "", fmt.Errorf("invalid local address %q: %v", ncconfig.localbind, err)
			}
		} else if !ncconfig.listenMode && ncconfig.remoteAddr != "" {
			host, port, err = net.SplitHostPort(ncconfig.remoteAddr)
			if err != nil {
				return network, "", "", "", fmt.Errorf("invalid remote address %q: %v", ncconfig.remoteAddr, err)
			}
		} else if ncconfig.autoP2P != "" {
			ncconfig.listenMode = false
			P2PSessionKey = ncconfig.autoP2P
			network = "any"
			if ncconfig.udpProtocol {
				network = "udp"
			}
			if ncconfig.useIPv4 {
				network += "4"
			} else if ncconfig.useIPv6 {
				network += "6"
			}
			if strings.HasPrefix(P2PSessionKey, "@") {
				P2PSessionKey, err = secure.ReadPSKFile(P2PSessionKey)
				if err != nil {
					ncconfig.Logger.Printf("Error reading PSK file: %v\n", err)
					os.Exit(1)
				}
			}
			if P2PSessionKey == "." {
				P2PSessionKey, err = secure.GenerateSecureRandomString(22)
				if err != nil {
					panic(err)
				}
				ncconfig.Logger.Printf("Keep this key secret! It is used to establish the secure P2P tunnel: %s\n", P2PSessionKey)
			} else if secure.IsWeakPassword(P2PSessionKey) {
				return network, "", "", "", fmt.Errorf("weak password detected")
			}
			if !ncconfig.plainTransport {
				//没-plain的情况，P2P默认启用kcp tls
				if ncconfig.udpProtocol {
					ncconfig.kcpEnabled = true
				}
				ncconfig.tlsEnabled = true
				ncconfig.presharedKey = P2PSessionKey
				if ncconfig.shadowStream {
					ncconfig.MQTTHelloPayload.SetControlValue("cs", "ss")
				} else {
					ncconfig.MQTTHelloPayload.SetControlValue("cs", "tls")
				}
				if isLocalMuxMode(ncconfig) {
					ncconfig.MQTTHelloPayload.SetControlValue("mux", "1")
				}
			}
			if isTLSEnabled(ncconfig) {
				if ncconfig.presharedKey == "" {
					ncconfig.presharedKey = P2PSessionKey
				}
			}

			if ncconfig.arg_proxyc_Config != nil {
				if ncconfig.arg_proxyc_Config.Prot != "socks5" {
					return network, "", "", "", fmt.Errorf("only allow socks5 proxy with p2p")
				}
				if strings.HasPrefix(network, "tcp") {
					return network, "", "", "", fmt.Errorf("only allow socks5 proxy with p2p udp mode")
				}
			}
		} else {
			return network, "", "", "", fmt.Errorf("not enough arguments")
		}
	default:
		return network, "", "", "", fmt.Errorf("too many arguments")
	}

	return network, host, port, P2PSessionKey, nil
}

// configureDNS 如果指定，则设置DNS解析器，并为Android提供默认值
func configureDNS(ncconfig *AppNetcatConfig) {
	if ncconfig.useDNS != "" {
		setDns(ncconfig.useDNS, ncconfig.localbindIP)
	} else if isAndroid() {
		setDns("8.8.8.8:53", ncconfig.localbindIP)
	}
}

// runP2PMode 处理建立和维护P2P连接的逻辑
func runP2PMode(console net.Conn, ncconfig *AppNetcatConfig) int {
	stats_in := misc.NewProgressStats()
	stats_out := misc.NewProgressStats()
	if ncconfig.progressEnabled {
		wg := &sync.WaitGroup{}
		done := make(chan bool)
		defer func() {
			done <- true
			wg.Wait()
		}()
		showProgress(ncconfig, stats_in, stats_out, done, wg)
	}

	if ncconfig.keepOpen {
		for {
			nconn, err := do_P2P_multipath(ncconfig, ncconfig.useMutilPath)
			if err != nil {
				ncconfig.Logger.Printf("P2P failed: %v\n", err)
				ncconfig.Logger.Printf("Will retry in 10 seconds...\n")
				time.Sleep(10 * time.Second)
				continue
			}

			if ncconfig.useMQTTWait {
				go func(c *secure.NegotiatedConn) {
					addr := c.RemoteAddr().String()
					handleP2PConnection(console, ncconfig, c, stats_in, stats_out)
					ncconfig.Logger.Printf("Disconnected from: %s\n", addr)
				}(nconn)
			} else {
				addr := nconn.RemoteAddr().String()
				handleP2PConnection(console, ncconfig, nconn, stats_in, stats_out)
				ncconfig.Logger.Printf("Disconnected from: %s\n", addr)
			}
			time.Sleep(2 * time.Second)
		}
	} else {
		nconn, err := do_P2P_multipath(ncconfig, ncconfig.useMutilPath)
		if err != nil {
			ncconfig.Logger.Printf("P2P failed: %v\n", err)
			return 1
		}
		return handleP2PConnection(console, ncconfig, nconn, stats_in, stats_out)
	}
}

// runListenMode 在监听模式下启动服务器
func runListenMode(console net.Conn, ncconfig *AppNetcatConfig, network, host, port string) int {
	if ncconfig.arg_proxyc_Config == nil {
		if port == "0" {
			portInt, err := easyp2p.GetFreePort()
			if err != nil {
				ncconfig.Logger.Printf("Get Free Port: %v\n", err)
				return 1
			}
			port = strconv.Itoa(portInt)
		}
	}
	if ncconfig.udpProtocol {
		return startUDPListener(console, ncconfig, network, host, port)
	} else {
		return startTCPListener(console, ncconfig, network, host, port)
	}
}

// startUDPListener 启动UDP监听器并处理传入会话
func startUDPListener(console net.Conn, ncconfig *AppNetcatConfig, network, host, port string) int {
	listenAddr := net.JoinHostPort(host, port)
	addr, err := net.ResolveUDPAddr(network, listenAddr)
	if err != nil {
		ncconfig.Logger.Printf("Error resolving UDP address: %v\n", err)
		return 1
	}

	if ncconfig.useSTUN {
		if err = ShowPublicIP(ncconfig, network, addr.String()); err != nil {
			ncconfig.Logger.Printf("Error getting public IP: %v\n", err)
			return 1
		}
		time.Sleep(1500 * time.Millisecond)
	}

	uconn, err := net.ListenUDP(network, addr)
	if err != nil {
		ncconfig.Logger.Printf("Error listening on UDP address: %v\n", err)
		return 1
	}
	defer uconn.Close()
	ncconfig.Logger.Printf("Listening %s on %s\n", uconn.LocalAddr().Network(), uconn.LocalAddr().String())

	logDiscard := misc.NewLog(io.Discard, "[UDPSession] ", log.LstdFlags|log.Lmsgprefix)
	usessListener, err := netx.NewUDPSessionListener(uconn, 65535, logDiscard)
	if err != nil {
		ncconfig.Logger.Printf("Error NewUDPSessionListener: %v\n", err)
		return 1
	}
	defer usessListener.Close()

	if ncconfig.keepOpen {
		stats_in := misc.NewProgressStats()
		stats_out := misc.NewProgressStats()
		if ncconfig.progressEnabled {
			wg := &sync.WaitGroup{}
			done := make(chan bool)
			showProgress(ncconfig, stats_in, stats_out, done, wg)
		}
		for {
			newSess, err := usessListener.Accept()
			if err != nil {
				if err == net.ErrClosed {
					ncconfig.Logger.Printf("UDPSessionListener accept failed: %v\n", err)
					return 1
				}
				continue
			}
			if !acl.ACL_inbound_allow(ncconfig.accessControl, newSess.RemoteAddr()) {
				ncconfig.Logger.Printf("ACL refused: %s\n", newSess.RemoteAddr())
				newSess.Close()
				continue
			}
			go func(c net.Conn) {
				raddr := c.RemoteAddr().String()
				ncconfig.Logger.Printf("UDP session established from %s\n", raddr)
				handleConnection(console, ncconfig, ncconfig.connConfig, c, stats_in, stats_out)
				ncconfig.Logger.Printf("UDP session disconnected from %s\n", raddr)
			}(newSess)
		}
	} else {
		newSess, err := usessListener.Accept()
		if err != nil {
			ncconfig.Logger.Printf("UDPSessionListener accept failed: %v\n", err)
			return 1
		}
		if !acl.ACL_inbound_allow(ncconfig.accessControl, newSess.RemoteAddr()) {
			ncconfig.Logger.Printf("ACL refused: %s\n", newSess.RemoteAddr())
			newSess.Close()
			return 1
		}
		ncconfig.Logger.Printf("UDP session established from %s\n", newSess.RemoteAddr().String())
		return handleSingleConnection(console, ncconfig, newSess)
	}
}

func retrySocks5Bind(ncconfig *AppNetcatConfig, proxyClient *ProxyClient, network, listenAddr string) (net.Listener, error) {
	retryDelay := 5 * time.Second
	maxDelay := 60 * time.Second

	var listener net.Listener
	var err error

	for {
		ncconfig.Logger.Printf("Attempting SOCKS5 BIND on proxy at %s...\n", listenAddr)
		listener, err = proxyClient.Dialer.Listen(network, listenAddr)
		if err == nil {
			ncconfig.Logger.Printf("SOCKS5 BIND listening on %s", listenAddr)
			return listener, nil
		}

		ncconfig.Logger.Printf("SOCKS5 BIND failed on %s: %v", listenAddr, err)
		if !ncconfig.keepOpen {
			return nil, err
		}
		ncconfig.Logger.Printf("Retrying in %s...", retryDelay)
		time.Sleep(retryDelay)

		// 指数退避，最多不超过 maxDelay
		retryDelay *= 2
		if retryDelay > maxDelay {
			retryDelay = maxDelay
		}
	}
}

// startTCPListener 启动TCP/Unix监听器并处理传入连接
func startTCPListener(console net.Conn, ncconfig *AppNetcatConfig, network, host, port string) int {
	listenAddr := net.JoinHostPort(host, port)
	if ncconfig.useUNIXdomain {
		listenAddr = port
		if err := cleanupUnixSocket(port); err != nil {
			ncconfig.Logger.Printf("%v\n", err)
			return 1
		}
	}

	var listener net.Listener
	var err error
	socks5BindMode := false
	proxyClient, err := NewProxyClient(ncconfig.arg_proxyc_Config)
	if err != nil {
		ncconfig.Logger.Printf("Error create proxy client: %v\n", err)
		return 1
	}
	if proxyClient.SupportBIND() {
		socks5BindMode = true
		listener, err = retrySocks5Bind(ncconfig, proxyClient, network, listenAddr)
		if err != nil {
			return 1
		}
	} else {
		lc := net.ListenConfig{}
		if ncconfig.useSTUN {
			if err = ShowPublicIP(ncconfig, network, listenAddr); err != nil {
				ncconfig.Logger.Printf("Error getting public IP: %v\n", err)
				return 1
			}
			lc.Control = netx.ControlTCP
		}
		listener, err = lc.Listen(context.Background(), network, listenAddr)
		if err != nil {
			ncconfig.Logger.Printf("Error listening on %s: %v\n", listenAddr, err)
			return 1
		}
		defer listener.Close()
	}

	ncconfig.Logger.Printf("Listening %s on %s\n", listener.Addr().Network(), listener.Addr().String())
	if port == "0" {
		//记下成功绑定的端口，keepOpen的话，如果需要重新监听就继续用这个端口
		listenAddr = listener.Addr().String()
	}

	if ncconfig.keepOpen {
		stats_in := misc.NewProgressStats()
		stats_out := misc.NewProgressStats()
		if ncconfig.progressEnabled {
			wg := &sync.WaitGroup{}
			done := make(chan bool)
			showProgress(ncconfig, stats_in, stats_out, done, wg)
		}
		for {
			conn, err := listener.Accept()
			if err != nil {
				ncconfig.Logger.Printf("Error accepting connection: %v\n", err)
				if socks5BindMode {
					listener.Close()
					listener, err = retrySocks5Bind(ncconfig, proxyClient, network, listenAddr)
					if err != nil {
						return 1
					}
					continue
				} else {
					time.Sleep(1 * time.Second)
					continue
				}
			}
			if conn.LocalAddr().Network() == "unix" {
				go func(c net.Conn) {
					addr := c.LocalAddr().String()
					ncconfig.Logger.Printf("Connection on %s received!\n", addr)
					handleConnection(console, ncconfig, ncconfig.connConfig, c, stats_in, stats_out)
					ncconfig.Logger.Printf("Connection on %s closed!\n", addr)
				}(conn)
			} else {
				if !acl.ACL_inbound_allow(ncconfig.accessControl, conn.RemoteAddr()) {
					ncconfig.Logger.Printf("ACL refused: %s\n", conn.RemoteAddr())
					conn.Close()
					continue
				}
				go func(c net.Conn) {
					addr := c.RemoteAddr().String()
					ncconfig.Logger.Printf("Connected from: %s\n", addr)
					handleConnection(console, ncconfig, ncconfig.connConfig, c, stats_in, stats_out)
					ncconfig.Logger.Printf("Disconnected from: %s\n", addr)
				}(conn)
			}
			if socks5BindMode {
				if listener != nil {
					listener.Close()
				}
				listener, err = retrySocks5Bind(ncconfig, proxyClient, network, listenAddr)
				if err != nil {
					return 1
				}
			}
		}
	} else {
		conn, err := listener.Accept()
		listener.Close()
		if err != nil {
			ncconfig.Logger.Printf("Error accepting connection: %v\n", err)
			return 1
		}

		if conn.LocalAddr().Network() == "unix" {
			ncconfig.Logger.Printf("Connection on %s received!\n", conn.LocalAddr().String())
		} else {
			if !acl.ACL_inbound_allow(ncconfig.accessControl, conn.RemoteAddr()) {
				ncconfig.Logger.Printf("ACL refused: %s\n", conn.RemoteAddr())
				conn.Close()
				return 1
			}
			ncconfig.Logger.Printf("Connected from: %s\n", conn.RemoteAddr().String())
		}
		return handleSingleConnection(console, ncconfig, conn)
	}
}

// parsePortRange 解析端口字符串。
// 返回值: (起始端口, 结束端口, 是否是范围格式)
func parsePortRange(portStr string) (int, int, bool) {
	if !strings.Contains(portStr, "-") {
		return 0, 0, false
	}

	parts := strings.Split(portStr, "-")
	if len(parts) != 2 {
		return 0, 0, false
	}

	start, err1 := strconv.Atoi(parts[0])
	end, err2 := strconv.Atoi(parts[1])

	// 简单的校验：必须是数字，且 start <= end
	if err1 != nil || err2 != nil || start > end {
		return 0, 0, false
	}

	return start, end, true
}

func runScanMode(console net.Conn, ncconfig *AppNetcatConfig, start, end, limit int) int {
	var wg sync.WaitGroup
	// 使用带缓冲的 channel 作为信号量，控制最大并发数
	sem := make(chan struct{}, limit)

	for port := start; port <= end; port++ {
		// 1. 获取令牌：如果信道满了，这里会阻塞，直到有协程释放
		sem <- struct{}{}
		wg.Add(1)

		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }() // 3. 释放令牌

			// 将 int 转为 string
			portStr := strconv.Itoa(p)

			runDialMode(console, ncconfig, ncconfig.network, ncconfig.host, portStr)
		}(port)
	}

	wg.Wait()
	return 0
}

// runDialMode 在主动连接模式下启动客户端
func runDialMode(console net.Conn, ncconfig *AppNetcatConfig, network, host, port string) int {
	var conn net.Conn
	var err error

	proxyClient, err := NewProxyClient(ncconfig.arg_proxyc_Config)
	if err != nil {
		ncconfig.Logger.Printf("Error create proxy client: %v\n", err)
		return 1
	}

	if ncconfig.useUNIXdomain {
		conn, err = net.Dial("unix", port)
	} else {
		var localAddr net.Addr
		if ncconfig.localbind != "" {
			switch {
			case strings.HasPrefix(network, "tcp"):
				localAddr, err = net.ResolveTCPAddr(network, ncconfig.localbind)
			case strings.HasPrefix(network, "udp"):
				localAddr, err = net.ResolveUDPAddr(network, ncconfig.localbind)
			}
			if err != nil {
				ncconfig.Logger.Printf("Error resolving address: %v\n", err)
				return 1
			}
		}

		if ncconfig.useSTUN {
			if ncconfig.localbind == "" {
				ncconfig.Logger.Printf("-stun need be with -local while connecting\n")
				return 1
			}
			if err = ShowPublicIP(ncconfig, network, localAddr.String()); err != nil {
				ncconfig.Logger.Printf("Error getting public IP: %v\n", err)
				return 1
			}
		}

		if localAddr == nil {
			dialTimeout := 20 * time.Second
			if ncconfig.dialreadTimeout != 0 {
				dialTimeout = time.Duration(ncconfig.dialreadTimeout) * time.Second
			}
			conn, err = proxyClient.DialTimeout(network, net.JoinHostPort(host, port), dialTimeout)
		} else {
			dialer := &net.Dialer{LocalAddr: localAddr}
			switch {
			case strings.HasPrefix(network, "tcp"):
				dialer.Control = netx.ControlTCP
			case strings.HasPrefix(network, "udp"):
				dialer.Control = netx.ControlUDP
			}
			if ncconfig.dialreadTimeout != 0 {
				dialer.Timeout = time.Duration(ncconfig.dialreadTimeout) * time.Second
			}
			conn, err = dialer.Dial(network, net.JoinHostPort(host, port))
		}
	}

	if err != nil {
		ncconfig.Logger.Printf("Error: %v\n", err)
		return 1
	}

	onTip := ""
	offTip := ""
	remoteTargetAddr := net.JoinHostPort(host, port)
	if strings.HasPrefix(conn.LocalAddr().Network(), "udp") {
		proxyRemoteAddr := ""
		if ncconfig.arg_proxyc_Config != nil {
			if pktConn, ok := conn.(*netx.ConnFromPacketConn); ok {
				if s5conn, ok := pktConn.PacketConn.(*Socks5UDPPacketConn); ok {
					proxyRemoteAddr = s5conn.GetUDPAssociateAddr().String()
				}
			}
		}
		if proxyRemoteAddr != "" {
			onTip = fmt.Sprintf("UDP ready for: %s -> %s -> %s", conn.LocalAddr().String(), proxyRemoteAddr, remoteTargetAddr)
			offTip = fmt.Sprintf("UDP closed for: %s -> %s -> %s", conn.LocalAddr().String(), proxyRemoteAddr, remoteTargetAddr)
		} else {
			onTip = fmt.Sprintf("UDP ready for: %s", remoteTargetAddr)
			offTip = fmt.Sprintf("UDP closed for: %s", remoteTargetAddr)
		}
	} else {
		if ncconfig.arg_proxyc_Config == nil {
			onTip = fmt.Sprintf("Connected to: %s", conn.RemoteAddr().String())
			offTip = fmt.Sprintf("Disconnected from: %s", conn.RemoteAddr().String())
		} else {
			onTip = fmt.Sprintf("Connected to: %s -> %s", conn.RemoteAddr().String(), remoteTargetAddr)
			offTip = fmt.Sprintf("Disconnected from: %s -> %s", conn.RemoteAddr().String(), remoteTargetAddr)
		}
	}

	ncconfig.Logger.Printf("%s\n", onTip)
	if ncconfig.verboseWithTime {
		defer ncconfig.Logger.Printf("%s\n", offTip)
	}

	return handleSingleConnection(console, ncconfig, conn)
}

func runFeatureModules(console net.Conn, ncconfig *AppNetcatConfig) int {
	ret := 0
	for _, module := range ncconfig.featureModulesRun {
		switch module {
		case "nat-checker":
			ret = runNATChecker(console, ncconfig)
			if ret != 0 {
				return ret
			}
		case "http-download":
			ret = runHTTPDownload(console, ncconfig)
			if ret != 0 {
				return ret
			}
		case "kcp-bridge":
			ret = runKCPBridge(console, ncconfig)
			if ret != 0 {
				return ret
			}
		default:
			ncconfig.Logger.Printf("Unknown feature module: %s\n", module)
			return 1
		}
	}
	return 0
}

func runHTTPDownload(console net.Conn, ncconfig *AppNetcatConfig) int {
	ctx, done := context.WithCancel(context.Background())
	defer done()

	if len(ncconfig.Args) < 2 {
		ncconfig.Logger.Printf("not enough arguments\n")
		ncconfig.Logger.Printf("Usage:\n")
		ncconfig.Logger.Printf(" -http-download <localDir> <serverURL>\n")
		return 1
	}
	localDir := ncconfig.Args[0]
	serverURL := ncconfig.Args[1]
	if !strings.HasPrefix(serverURL, "http://") && !strings.HasPrefix(serverURL, "https://") {
		ncconfig.Logger.Printf("invalid serverURL, must start with http:// or https://\n")
		return 1
	}

	httpcfg := httpfileshare.ClientConfig{
		ServerURL:              serverURL,
		LocalDir:               localDir,
		Concurrency:            2,
		Resume:                 true,
		DryRun:                 false,
		Verbose:                false,
		LogLevel:               httpfileshare.LogLevelError,
		LoggerOutput:           ncconfig.LogWriter,
		ProgressOutput:         ncconfig.LogWriter,
		ProgressUpdateInterval: 1 * time.Second,
		NoCompress:             *VarhttpDownloadNoCompress,
	}

	c, err := httpfileshare.NewClient(httpcfg)
	if err != nil {
		ncconfig.Logger.Printf("Failed to create HTTP client: %v\n", err)
		return 1
	}
	if err := c.Start(ctx); err != nil {
		ncconfig.Logger.Printf("Client operation failed: %v\n", err)
		return 1
	}

	return 0
}

func runNATChecker(console net.Conn, ncconfig *AppNetcatConfig) int {

	networksToTryStun := []string{"tcp6", "tcp4", "udp6", "udp4"}

	ncconfig.Logger.Printf("STUN Results (Local -> NAT -> STUNServer)\n")
	ncconfig.Logger.Printf("-----------\n")

	Addresses, allSTUNResults, err := easyp2p.DetectNATAddressInfo(networksToTryStun, ncconfig.localbind, nil, io.Discard)
	if len(allSTUNResults) > 0 && len(Addresses) > 0 {
		for _, r := range allSTUNResults {
			srv := strings.TrimPrefix(easyp2p.STUNServers[r.Index], "udp://")
			srv = strings.TrimPrefix(srv, "tcp://")
			if r.Err != nil {
				ncconfig.Logger.Printf("%s://%s\t(failed)\n", r.Network, srv)
			}
		}

		succeeded := 0
		for _, r := range allSTUNResults {
			srv := strings.TrimPrefix(easyp2p.STUNServers[r.Index], "udp://")
			srv = strings.TrimPrefix(srv, "tcp://")
			if r.Err == nil {
				succeeded += 1
				ncconfig.Logger.Printf("%s://%s\n", r.Network, srv)
				ncconfig.Logger.Printf("    %s -> %s -> %s\n", r.Local, r.Nat, r.Remote)
			}
		}

		ncconfig.Logger.Printf("\n")
		ncconfig.Logger.Printf("NAT Summary (%d STUN servers, %d answers)\n", len(easyp2p.STUNServers), succeeded)
		ncconfig.Logger.Printf("-----------\n")

		for _, info := range Addresses {
			net := info.Network
			nattype := info.NatType
			lan := info.Lan
			nat := info.Nat
			if lan == nat {
				ncconfig.Logger.Printf("%-5s: %s (%s)\n", net, nat, nattype)
			} else {
				ncconfig.Logger.Printf("%-5s: LAN=%s | NAT=%s (%s)\n", net, lan, nat, nattype)
			}
		}

		return 0
	} else {
		ncconfig.Logger.Printf("failed: %v\n", err)
	}

	return 1
}

func getUDPFreePort(network, localip string) (string, string, error) {
	udpAddr, _ := net.ResolveUDPAddr(network, net.JoinHostPort(localip, "0"))
	udpConn, err := net.ListenUDP(network, udpAddr)
	if err != nil {
		return "", "", err
	}
	host, port, err := net.SplitHostPort(udpConn.LocalAddr().String())
	defer udpConn.Close()
	return host, port, err
}

func runKCPBridge(console net.Conn, ncconfig *AppNetcatConfig) int {

	if ncconfig.p2pSessionKey == "" {
		ncconfig.Logger.Printf("-kcpbr must be used with -p2p <sessionkey>\n")
		return 1
	}

	MUX_timeout := 120
	KCP_timeout := 120
	UDP_timeout := 41
	TCP_timeout := 30

	if VarMuxKeepAliveTimeout == DefaultVarMuxKeepAliveTimeout {
		VarMuxKeepAliveTimeout = MUX_timeout
	}
	if secure.KCPIdleTimeoutSecond == secure.DefaultKCPIdleTimeoutSecond {
		secure.KCPIdleTimeoutSecond = KCP_timeout
	}
	if secure.UDPIdleTimeoutSecond == secure.DefaultUDPIdleTimeoutSecond {
		secure.UDPIdleTimeoutSecond = UDP_timeout
	}
	if ncconfig.keepAlive == 0 {
		ncconfig.keepAlive = TCP_timeout
	}

	ctx, cancel := context.WithCancel(ncconfig.ctx)
	defer cancel()
	done := make(chan int, 2)

	if ncconfig.useMQTTWait {
		//server(remote) side:
		//       gonc -p2p xxxxxxxx -linkagent -kcpbr  ( -e ":mux linkagent" -mqtt-wait )
		//nc1. runListenMode -kcp -e "{ncconfig.runCmd}" -l 127.0.0.1 port1
		//nc2. runP2PMode -e ":br -u -framed local port1" -plain -tls -mqtt-wait -framed -framed-tcp
		var err error
		nc1 := *ncconfig
		nc1.ctx = ctx
		//nc1.runCmd 一样
		nc1.listenMode = true
		nc1.p2pSessionKey = ""
		nc1.featureModulesRun = nil
		nc1.kcpBridgeMode = false
		nc1.kcpEnabled = true
		nc1.kcpSEnabled = true
		nc1.udpProtocol = true
		nc1.framedStdio = false
		nc1.framedTCP = false
		nc1.keepAlive = 0
		nc1.Args = nil
		nc1.network = "udp4"
		nc1.host, nc1.port, err = getUDPFreePort(nc1.network, "127.0.0.1")
		if err != nil {
			ncconfig.Logger.Printf("Error getting free udp port: %v\n", err)
			return 1
		}
		disableTLS(&nc1)
		nc1.presharedKey = ""
		nc1.connConfig = preinitNegotiationConfig(&nc1)

		nc1.callback_OnConnectionDestroy = func(localAddrStr, remoteAddrStr string) {
			found := brDialSessKickByConnAddr(
				remoteAddrStr, // 注意：反过来
				localAddrStr,
			)
			ncconfig.Logger.Printf("Connection Destroying(%s-%s)..., kick bridge result=%v\n", localAddrStr, remoteAddrStr, found)
		}

		go func() {
			done <- runListenMode(console, &nc1, nc1.network, nc1.host, nc1.port)
		}()

		time.Sleep(1 * time.Second)

		nc2 := *ncconfig
		nc2.ctx = ctx
		nc2.listenMode = false
		nc2.kcpBridgeMode = false
		nc2.featureModulesRun = nil
		nc2.runCmd = fmt.Sprintf(":br -u -framed 127.0.0.1 %s", nc1.port)
		nc2.plainTransport = true
		nc2.kcpEnabled = false
		nc2.kcpSEnabled = false
		nc2.framedStdio = true
		nc2.framedTCP = true
		nc2.keepAlive = ncconfig.keepAlive
		err = preinitBuiltinAppConfig(&nc2, nc2.runCmd)
		if err != nil {
			ncconfig.Logger.Printf("%v\n", err)
			return 1
		}
		nc2.connConfig = preinitNegotiationConfig(&nc2)
		nc2.connConfig.UDPIdleTimeoutSecond = 41
		nc2.progressEnabled = false

		go func() {
			done <- runP2PMode(console, &nc2)
		}()

		ret := <-done
		cancel()
		return ret
	} else if ncconfig.useMQTTHello {
		//Local side:
		//       gonc -p2p xxxxxxxx -link 1080,1081 -kcpbr  ( -e ":mux link 1080,1081" -mqtt-hello )
		//nc2. runListenMode -e ":br -p2p xxxxx -mqtt-hello -keepalive 30 -framed -framed-tcp -plain -tls" -k -framed -u -l 127.0.0.1 port2
		//nc1. runDialMode -kcp -e "{ncconfig.runCmd}" 127.0.0.1 port2

		var err error
		nc2 := *ncconfig
		nc2.ctx = ctx
		nc2.kcpBridgeMode = false
		nc2.featureModulesRun = nil
		nc2.runCmd = fmt.Sprintf(":br -p2p \"%s\" -mqtt-hello -keepalive %d -framed -framed-tcp -plain",
			ncconfig.p2pSessionKey, ncconfig.keepAlive)
		if isTLSEnabled(ncconfig) {
			nc2.runCmd += " -tls"
		}
		if ncconfig.udpProtocol {
			nc2.runCmd += " -u"
		}
		nc2.listenMode = true
		nc2.udpProtocol = true
		nc2.framedStdio = true
		nc2.kcpEnabled = false
		nc2.kcpSEnabled = false
		nc2.autoP2P = ""
		nc2.p2pSessionKey = ""
		nc2.network = "udp4"
		nc2.host, nc2.port, err = getUDPFreePort(nc2.network, "127.0.0.1")
		if err != nil {
			ncconfig.Logger.Printf("Error getting free udp port: %v\n", err)
			return 1
		}
		disableTLS(&nc2)
		nc2.presharedKey = ""
		nc2.keepAlive = ncconfig.keepAlive
		nc2.connConfig = preinitNegotiationConfig(&nc2)
		err = preinitBuiltinAppConfig(&nc2, nc2.runCmd)
		if err != nil {
			ncconfig.Logger.Printf("%v\n", err)
			return 1
		}
		nc2.progressEnabled = false

		go func() {
			done <- runListenMode(console, &nc2, nc2.network, nc2.host, nc2.port)
		}()
		time.Sleep(1 * time.Second)

		nc1 := nc2
		nc1.listenMode = false
		nc1.framedStdio = false
		nc1.kcpEnabled = true
		nc1.kcpSEnabled = false
		nc1.keepAlive = ncconfig.keepAlive
		nc1.connConfig = preinitNegotiationConfig(&nc1)
		nc1.runCmd = ncconfig.runCmd
		err = preinitBuiltinAppConfig(&nc2, nc1.runCmd)
		if err != nil {
			ncconfig.Logger.Printf("%v\n", err)
			return 1
		}
		nc1.callback_OnConnectionDestroy = func(localAddrStr, remoteAddrStr string) {
			brAcceptSessKickByConnAddr(
				remoteAddrStr, // 注意：反过来
				localAddrStr,
			)
		}
		nc1.progressEnabled = ncconfig.progressEnabled

		go func() {
			for {
				ret := runDialMode(console, &nc1, nc1.network, nc1.host, nc1.port)
				if !nc1.keepOpen {
					done <- ret
					return
				}

				ncconfig.Logger.Printf("Will retry in 10 seconds...\n")
				select {
				case <-time.After(10 * time.Second):
					// sleep 完成
				case <-ctx.Done():
					// 被提前取消
					done <- 1
				}
			}
		}()

		ret := <-done
		cancel()
		return ret
	} else {
		ncconfig.Logger.Printf("-kcpbr must be used with -mqtt-hello or -mqtt-wait\n")
		return 1
	}
}

func init_TLS(ncconfig *AppNetcatConfig, genCertForced bool) []tls.Certificate {
	var certs []tls.Certificate
	if isTLSEnabled(ncconfig) {
		if ncconfig.listenMode || ncconfig.kcpSEnabled {
			ncconfig.tlsServerMode = true
		}
		if genCertForced || ncconfig.tlsServerMode {
			if ncconfig.sslCertFile != "" && ncconfig.sslKeyFile != "" {
				fmt.Fprintf(ncconfig.LogWriter, "Loading cert...")
				cert, err := secure.LoadCertificate(ncconfig.sslCertFile, ncconfig.sslKeyFile)
				if err != nil {
					fmt.Fprintf(ncconfig.LogWriter, "Error load certificate: %v\n", err)
					os.Exit(1)
				}
				certs = append(certs, *cert)
				ncconfig.tlsECCertEnabled = false
				ncconfig.tlsRSACertEnabled = false
			} else {
				if !ncconfig.tlsECCertEnabled && !ncconfig.tlsRSACertEnabled {
					fmt.Fprintf(ncconfig.LogWriter, "EC and RSA both are disabled\n")
					os.Exit(1)
				}
				if ncconfig.tlsECCertEnabled {
					if ncconfig.presharedKey != "" {
						fmt.Fprintf(ncconfig.LogWriter, "Generating ECDSA(PSK-derived) cert for secure communication...")
					} else {
						fmt.Fprintf(ncconfig.LogWriter, "Generating ECDSA(randomly) cert for secure communication...")
					}
					cert, err := secure.GenerateECDSACertificate(ncconfig.tlsSNI, ncconfig.presharedKey)
					if err != nil {
						fmt.Fprintf(ncconfig.LogWriter, "Error generating EC certificate: %v\n", err)
						os.Exit(1)
					}
					certs = append(certs, *cert)
				}
				if ncconfig.tlsRSACertEnabled {
					fmt.Fprintf(ncconfig.LogWriter, "Generating RSA cert...")
					cert, err := secure.GenerateRSACertificate(ncconfig.tlsSNI)
					if err != nil {
						fmt.Fprintf(ncconfig.LogWriter, "Error generating RSA certificate: %v\n", err)
						os.Exit(1)
					}
					certs = append(certs, *cert)
				}
			}

			fmt.Fprintf(ncconfig.LogWriter, "completed.\n")
		}
	}
	return certs
}

func isTLSEnabled(ncconfig *AppNetcatConfig) bool {
	return ncconfig.tlsServerMode || ncconfig.tlsEnabled || ncconfig.tls10_forced || ncconfig.tls11_forced || ncconfig.tls12_forced || ncconfig.tls13_forced
}

func disableTLS(ncconfig *AppNetcatConfig) {
	ncconfig.tlsEnabled = false
	ncconfig.tlsServerMode = false
	ncconfig.tls10_forced = false
	ncconfig.tls11_forced = false
	ncconfig.tls12_forced = false
	ncconfig.tls13_forced = false
}

func showProgress(ncconfig *AppNetcatConfig, statsIn, statsOut *misc.ProgressStats, done chan bool, wg *sync.WaitGroup) {
	wg.Add(1)
	ticker := time.NewTicker(1 * time.Second)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ticker.C:
				if ncconfig.sessionReady {
					now := time.Now()
					in := statsIn.Stats(now, false)
					out := statsOut.Stats(now, false)
					elapsed := int(now.Sub(statsIn.StartTime()).Seconds())
					h := elapsed / 3600
					m := (elapsed % 3600) / 60
					s := elapsed % 60
					connCount := atomic.LoadInt32(&ncconfig.goroutineConnectionCounter)
					if connCount > 1 {
						fmt.Fprintf(ncconfig.LogWriter,
							"IN: %s (%d bytes), %s/s | OUT: %s (%d bytes), %s/s | %d | %02d:%02d:%02d\r",
							misc.FormatBytes(in.TotalBytes), in.TotalBytes, misc.FormatBytes(int64(in.SpeedBps)),
							misc.FormatBytes(out.TotalBytes), out.TotalBytes, misc.FormatBytes(int64(out.SpeedBps)),
							connCount,
							h, m, s,
						)
					} else if connCount == 1 {
						fmt.Fprintf(ncconfig.LogWriter,
							"IN: %s (%d bytes), %s/s | OUT: %s (%d bytes), %s/s | %02d:%02d:%02d\r",
							misc.FormatBytes(in.TotalBytes), in.TotalBytes, misc.FormatBytes(int64(in.SpeedBps)),
							misc.FormatBytes(out.TotalBytes), out.TotalBytes, misc.FormatBytes(int64(out.SpeedBps)),
							h, m, s,
						)
					}

				}

			case <-done:
				ticker.Stop()
				if ncconfig.sessionReady {
					// 打印最终进度
					now := time.Now()
					in := statsIn.Stats(now, true)
					out := statsOut.Stats(now, true)
					elapsed := int(now.Sub(statsIn.StartTime()).Seconds())
					h := elapsed / 3600
					m := (elapsed % 3600) / 60
					s := elapsed % 60
					fmt.Fprintf(ncconfig.LogWriter,
						"IN: %s (%d bytes), %s/s | OUT: %s (%d bytes), %s/s | %02d:%02d:%02d\n",
						misc.FormatBytes(in.TotalBytes), in.TotalBytes, misc.FormatBytes(int64(in.SpeedBps)),
						misc.FormatBytes(out.TotalBytes), out.TotalBytes, misc.FormatBytes(int64(out.SpeedBps)),
						h, m, s,
					)
				}
				return
			}
		}
	}()
}

func usage_full(argv0 string, fs *flag.FlagSet) {
	usage_less(fs.Output(), argv0)
	fs.PrintDefaults()
	fmt.Fprintln(fs.Output(), "Built-in commands for -e option:")
	fmt.Fprintf(fs.Output(), "  %-6s %s\n", ":mux", "Stream-multiplexing proxy")
	fmt.Fprintf(fs.Output(), "  %-6s %s\n", ":s5s", "SOCKS5 server")
	fmt.Fprintf(fs.Output(), "  %-6s %s\n", ":nc", "netcat")
	fmt.Fprintf(fs.Output(), "  %-6s %s\n", ":sh", "pseudo-terminal shell")
	fmt.Fprintf(fs.Output(), "  %-6s %s\n", ":tp", "transparent proxy")
	fmt.Fprintf(fs.Output(), "  %-6s %s\n", ":httpserver", "HTTP file server")
	fmt.Fprintf(fs.Output(), "  %-6s %s\n", ":service", "dynamic service mode, clients can use -call to invoke the above configured and enabled services.")
	fmt.Fprintln(fs.Output(), "")
	fmt.Fprintln(fs.Output(), "To get help for a built-in command, run:")
	fmt.Fprintf(fs.Output(), "  %s -e \":sh -h\"\n", argv0)
}

func usage_less(logWriter io.Writer, argv0 string) {
	fmt.Fprintln(logWriter, "go-netcat "+VERSION)
	fmt.Fprintln(logWriter, "Usage:")
	fmt.Fprintf(logWriter, "    %s [-x socks5_ip:port] [-auth user:pass] [-send path] [-tls] [-l] [-u] target_host target_port\n", argv0)
	fmt.Fprintln(logWriter, "         [-p2p sessionKey]")
	fmt.Fprintln(logWriter, "         [-e \":builtin-command [args]\" or \"external-command [args]\"]")
	fmt.Fprintln(logWriter, "         [-h] for full help")
}

func conflictCheck(ncconfig *AppNetcatConfig) int {
	if ncconfig.sendfile != "" && ncconfig.runCmd != "" {
		ncconfig.Logger.Printf("-send and -exec cannot be used together\n")
		return 1
	}
	if ncconfig.enablePty && ncconfig.enableCRLF {
		ncconfig.Logger.Printf("-pty and -C cannot be used together\n")
		return 1
	}
	if ncconfig.proxyAddr != "" && ncconfig.useSTUN {
		ncconfig.Logger.Printf("-stun and -x cannot be used together\n")
		return 1
	}
	if ncconfig.proxyProt == "connect" && (ncconfig.udpProtocol || ncconfig.kcpEnabled || ncconfig.kcpSEnabled) {
		ncconfig.Logger.Printf("http proxy and udp cannot be used together\n")
		return 1
	}
	if ncconfig.listenMode && (ncconfig.remoteAddr != "" || ncconfig.autoP2P != "") {
		ncconfig.Logger.Printf("-l and (-remote -p2p) cannot be used together\n")
		return 1
	}
	if ncconfig.presharedKey != "" && (ncconfig.tlsRSACertEnabled || (ncconfig.sslCertFile != "" && ncconfig.sslKeyFile != "") || ncconfig.autoPSK) {
		ncconfig.Logger.Printf("-psk and (-tlsrsa -ssl-cert -ssl-key -auto-psk) cannot be used together\n")
		return 1
	}
	if ncconfig.useIPv4 && ncconfig.useIPv6 {
		ncconfig.Logger.Printf("-4 and -6 cannot be used together\n")
		return 1
	}
	if ncconfig.useUNIXdomain && (ncconfig.useIPv6 || ncconfig.useIPv4 || ncconfig.useSTUN || ncconfig.udpProtocol || ncconfig.kcpEnabled || ncconfig.kcpSEnabled || ncconfig.localbind != "" || ncconfig.proxyAddr != "") {
		ncconfig.Logger.Printf("-U and (-4 -6 -stun -u -kcp -kcps -bind -x) cannot be used together\n")
		return 1
	}
	if ncconfig.runAppFileServ != "" && (ncconfig.appMuxListenMode || ncconfig.appMuxListenOn != "") {
		ncconfig.Logger.Printf("-httpserver and (-httplocal -download) cannot be used together\n")
		return 1
	}
	if (ncconfig.sslCertFile != "" && ncconfig.sslKeyFile == "") || (ncconfig.sslCertFile == "" && ncconfig.sslKeyFile != "") {
		ncconfig.Logger.Printf("-ssl-cert and -ssl-key both must be set, only one given")
		return 1
	}
	if (ncconfig.sslCertFile != "" && ncconfig.sslKeyFile != "") && !isTLSEnabled(ncconfig) {
		ncconfig.Logger.Printf("-ssl-cert and -ssl-key set without -tls ?\n")
		return 1
	}
	if (ncconfig.sslCertFile != "" && ncconfig.sslKeyFile != "") && (ncconfig.autoP2P != "") {
		ncconfig.Logger.Printf("(-ssl-cert -ssl-key) and (-p2p -p2p-tcp) cannot be used together\n")
		return 1
	}
	if ncconfig.kcpBridgeMode && ncconfig.portRotate {
		ncconfig.Logger.Printf("-kcpbr and -port-rotate cannot be used together\n")
		return 1
	}
	if ncconfig.kcpBridgeMode && ncconfig.autoP2P == "" {
		ncconfig.Logger.Printf("-kcpbr and -p2p must be used together\n")
		return 1
	}
	if ncconfig.autoPSK && ncconfig.autoP2P == "" {
		ncconfig.Logger.Printf("-auto-psk and -p2p must be used together\n")
		return 1
	}
	if ncconfig.shadowStream && ncconfig.autoP2P == "" {
		ncconfig.Logger.Printf("-ss and -p2p must be used together\n")
		return 1
	}
	if ncconfig.shadowStream && (ncconfig.plainTransport || isTLSEnabled(ncconfig)) {
		ncconfig.Logger.Printf("-ss and (-plain -tls) cannot be used together\n")
		return 1
	}
	if isEnabledMuxMode(ncconfig) && ncconfig.app_mux_args != "-" {
		ncconfig.Logger.Printf("mux mode and -e \":mux\" cannot be used together\n")
		return 1
	}
	return 0
}

func preinitBuiltinAppConfig(ncconfig *AppNetcatConfig, commandline string) error {
	args, err := misc.ParseCommandLine(commandline)
	if err != nil {
		return fmt.Errorf("error parsing command: %w", err)
	}

	if len(args) == 0 {
		return fmt.Errorf("empty command")
	}

	var usage func(io.Writer)
	builtinApp := args[0]
	switch builtinApp {
	case ":mux":
		if isEnabledMuxMode(ncconfig) {
			return fmt.Errorf("mux mode and -e \":mux\" cannot be used together")
		}
		ncconfig.app_mux_Config, err = AppMuxConfigByArgs(ncconfig.LogWriter, args[1:])
		if err != nil {
			usage = App_mux_usage
		} else {
			ncconfig.app_mux_Config.AccessCtrl = ncconfig.accessControl
		}
	case ":s5s":
		ncconfig.app_s5s_Config, err = AppS5SConfigByArgs(ncconfig.LogWriter, args[1:])
		if err == nil {
			ncconfig.app_s5s_Config.AccessCtrl = ncconfig.accessControl
		}
	case ":nc":
		ncconfig.app_nc_Config, err = AppNetcatConfigByArgs(ncconfig.LogWriter, ":nc", args[1:])
	case ":sh":
		ncconfig.app_sh_Config, err = PtyShellConfigByArgs(ncconfig.LogWriter, args[1:])
	case ":tp":
		ncconfig.app_tp_Config, err = AppTPConfigByArgs(ncconfig.LogWriter, args[1:])
	case ":pr":
		ncconfig.app_pr_Config, err = AppPortRotateConfigByArgs(ncconfig.LogWriter, args[1:])
	case ":br":
		ncconfig.app_br_Config, err = AppBridgeConfigByArgs(ncconfig.LogWriter, args[1:])
	case ":httpserver":
		ncconfig.app_httpserver_Config, err = AppHttpServerConfigByArgs(ncconfig.LogWriter, args[1:])
	case ":service":
	default:
		if strings.HasPrefix(builtinApp, ":") {
			return fmt.Errorf("unknown built-in command: %s", builtinApp)
		}
		return nil // not a built-in app, let caller handle it
	}

	if err != nil {
		if err != flag.ErrHelp {
			msg := fmt.Sprintf("error init %s config: %v", builtinApp, err)
			if usage != nil {
				usage(ncconfig.LogWriter)
			}
			return fmt.Errorf("%s", msg)
		}
		return err
	}
	return nil
}

// 用于在数据传输时显示进度
func copyWithProgress(ncconfig *AppNetcatConfig, dst io.Writer, src io.Reader, blocksize int, bufferedReader bool, stats *misc.ProgressStats, maxBytes int64, readIdleTimeout int) error {
	bufsize := blocksize
	if bufsize < 32*1024 {
		bufsize = 32 * 1024 // reader 缓冲区更大，提高吞吐
	}

	reader := src
	if bufferedReader {
		reader = bufio.NewReaderSize(src, bufsize)
	} // UDP不能用bufio积包，会粘包

	buf := make([]byte, blocksize)
	var n int
	var err, err1 error
	var totalWritten int64

	for {
		rtimeout := false
		if readIdleTimeout > 0 {
			type readDeadliner interface {
				SetReadDeadline(t time.Time) error
			}
			if rd, ok := src.(readDeadliner); ok {
				err = rd.SetReadDeadline(time.Now().Add(time.Duration(readIdleTimeout) * time.Second))
				if err == nil {
					rtimeout = true
				}
			}
		}
		n, err1 = reader.Read(buf)
		if err1 != nil && err1 != io.EOF {
			if rtimeout && os.IsTimeout(err1) {
				ncconfig.Logger.Printf("Read error: %v\n", err1)
			}
			break
		}
		if n == 0 {
			break
		}

		// 判断是否超过最大传输限制
		if maxBytes > 0 {
			remaining := maxBytes - totalWritten
			if remaining <= 0 {
				break // 达到限制
			}
			if int64(n) > remaining {
				n = int(remaining)
			}
		}

		_, err = dst.Write(buf[:n])
		if err != nil {
			//ncconfig.Logger.Printf("Write error: %v\n", err)
			err1 = err
			break
		}

		if stats != nil {
			stats.Update(int64(n))
		}
		totalWritten += int64(n)

		if err1 == io.EOF {
			break
		}
	}
	return err1
}

func copyCharDeviceWithProgress(ncconfig *AppNetcatConfig, dst io.Writer, src io.Reader, stats *misc.ProgressStats) {
	var n int
	var err, err1 error
	var line string

	reader := bufio.NewReader(src)
	writer := bufio.NewWriter(dst)
	for {
		line, err1 = reader.ReadString('\n')
		if err1 != nil && err1 != io.EOF {
			ncconfig.Logger.Printf("ReadString error: %v\n", err1)
			break
		}

		if len(line) > 0 {
			if line[len(line)-1] == '\n' {
				// 注意：line读到的可能是 "\r\n" 或 "\n"，都要统一处理
				line = strings.TrimRight(line, "\r\n") // 去掉任何结尾的 \r 或 \n
				if ncconfig.enableCRLF {
					line += "\r\n" // 统一加上 CRLF
				} else {
					line += "\n"
				}
			}
			n, err = writer.WriteString(line)
			if err != nil {
				//ncconfig.Logger.Printf("Write error: %v\n", err)
				break
			}
			writer.Flush()
			if stats != nil {
				stats.Update(int64(n))
			}
		}

		if err1 == io.EOF {
			break
		}
	}
}

func preinitNegotiationConfig(ncconfig *AppNetcatConfig) *secure.NegotiationConfig {
	config := secure.NewNegotiationConfig()

	config.InsecureSkipVerify = !ncconfig.tlsVerifyCert
	config.KeepAlive = ncconfig.keepAlive

	genCertForced := ncconfig.presharedKey != ""
	config.Certs = init_TLS(ncconfig, genCertForced)
	config.TlsSNI = ncconfig.tlsSNI
	config.ReadIdleTimeoutSecond = ncconfig.dialreadTimeout

	if ncconfig.listenMode || ncconfig.kcpSEnabled || ncconfig.tlsServerMode {
		config.IsClient = false
	} else {
		config.IsClient = true
	}

	if ncconfig.presharedKey != "" {
		config.KeyType = "PSK"
		config.Key = ncconfig.presharedKey
	} else if ncconfig.autoPSK {
		config.KeyType = "ECDHE"
	}

	if ncconfig.udpProtocol {
		config.KcpWithUDP = isKCPEnabled(ncconfig)
		if isTLSEnabled(ncconfig) {
			config.SecureLayer = "dtls"
		} else if config.KcpWithUDP && (config.Key != "" || ncconfig.autoPSK) {
			config.KcpEncryption = true
		} else if config.Key != "" || ncconfig.autoPSK {
			config.SecureLayer = "dss"
		}
	} else {
		if isTLSEnabled(ncconfig) {
			if ncconfig.tls10_forced {
				config.SecureLayer = "tls10"
			} else if ncconfig.tls11_forced {
				config.SecureLayer = "tls11"
			} else if ncconfig.tls12_forced {
				config.SecureLayer = "tls12"
			} else if ncconfig.tls13_forced {
				config.SecureLayer = "tls13"
			} else {
				config.SecureLayer = "tls"
			}
		} else if config.Key != "" || ncconfig.autoPSK {
			config.SecureLayer = "ss"
		}

		config.FramedTCP = ncconfig.framedTCP
	}

	return config
}

func handleMuxChannelConnection(console net.Conn, ncconfig *AppNetcatConfig, channel net.Conn, stats_in, stats_out *misc.ProgressStats) int {
	nconn := &secure.NegotiatedConn{
		Config:     secure.NewNegotiationConfig(),
		ConnLayers: []net.Conn{channel},
		TopLayer:   channel,
	}

	return handleNegotiatedConnection(console, ncconfig, nconn, stats_in, stats_out)
}

func handleNegotiatedConnection(console net.Conn, ncconfig *AppNetcatConfig, nconn *secure.NegotiatedConn, stats_in, stats_out *misc.ProgressStats) int {
	defer atomic.AddInt32(&ncconfig.goroutineConnectionCounter, -1)
	atomic.AddInt32(&ncconfig.goroutineConnectionCounter, 1)

	defer nconn.Close()

	localAddrStr := nconn.LocalAddr().String()
	remoteAddrStr := nconn.RemoteAddr().String()
	defer func() {
		if ncconfig.callback_OnConnectionDestroy != nil {
			ncconfig.callback_OnConnectionDestroy(localAddrStr, remoteAddrStr)
		}
	}()

	if !ncconfig.sessionReady {
		stats_in.ResetStart()
		stats_out.ResetStart()
		ncconfig.sessionReady = true
	}

	// 默认使用标准输入输出
	var input io.ReadCloser = console
	var output io.WriteCloser = console
	var cmdErrorPipe io.ReadCloser
	var binaryInputMode = false
	var cmd *exec.Cmd
	var err error
	var maxSendBytes int64
	var bufsize int = 32 * 1024
	var blocksize int = bufsize

	if !ncconfig.ConsoleMode {
		binaryInputMode = true
	}
	if nconn.IsUDP && !nconn.WithKCP { // KCP内部已经做了分片处理
		//源如果是stdio或文件流，应该限制每次拷贝形成的udp包的大小
		if ncconfig.ConsoleMode || ncconfig.sendfile != "" {
			blocksize = nconn.Config.UdpOutputBlockSize
		}
	}
	if ncconfig.sendfile != "" {
		var file io.ReadCloser
		if ncconfig.sendfile == "/dev/zero" || ncconfig.sendfile == "/dev/urandom" {
			file, err = misc.NewPseudoDevice(ncconfig.sendfile)
		} else {
			file, err = os.Open(ncconfig.sendfile)
		}
		if err != nil {
			ncconfig.Logger.Printf("Error opening file: %v\n", err)
			return 1
		}
		defer file.Close()
		input = file
		binaryInputMode = true
		maxSendBytes = ncconfig.sendsize
	}

	if ncconfig.writefile != "" {
		var file *os.File
		var writePath string
		if ncconfig.writefile == "/dev/null" {
			// 判断操作系统
			if runtime.GOOS == "windows" {
				writePath = "NUL"
			} else {
				writePath = "/dev/null"
			}
		} else {
			writePath = ncconfig.writefile
		}
		file, err = os.Create(writePath)
		if err != nil {
			ncconfig.Logger.Printf("Error opening file for writing: %v\n", err)
			return 1
		}
		defer file.Close()
		output = file
	}

	if ncconfig.remoteCall != "" {
		_, err = nconn.Write([]byte(ncconfig.remoteCall + "\n"))
		if err != nil {
			ncconfig.Logger.Printf("Error Sending: %v\n", err)
			return 1
		}
	}

	serviceCommand := strings.TrimSpace(ncconfig.runCmd)
	if serviceCommand == ":service" {
		nconn.SetDeadline(time.Now().Add(15 * time.Second))
		line, err := netx.ReadString(nconn, '\n', 1024)
		if err != nil {
			ncconfig.Logger.Printf("Error ReadString: %v\n", err)
			return 1
		}
		nconn.SetDeadline(time.Time{})
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, ":") {
			ncconfig.Logger.Printf("Invalid service command: %s\n", line)
			return 1
		}
		serviceCommand = line
	}

	if serviceCommand != "" {
		binaryInputMode = true
		// 分割命令和参数（支持带空格的参数）
		args, err := misc.ParseCommandLine(serviceCommand)
		if err != nil {
			ncconfig.Logger.Printf("Error parsing command: %v\n", err)
			return 1
		}

		if len(args) == 0 {
			ncconfig.Logger.Printf("Empty command\n")
			return 1
		}

		builtinApp := args[0]
		if builtinApp == ":mux" {
			if ncconfig.app_mux_Config == nil {
				ncconfig.Logger.Printf("Not initialized %s config\n", builtinApp)
				return 1
			}
			pipeConn := misc.NewPipeConn(nconn)
			input = pipeConn.In
			output = pipeConn.Out
			defer pipeConn.Close()
			go App_mux_main_withconfig(pipeConn, ncconfig.app_mux_Config)
		} else if builtinApp == ":s5s" {
			if ncconfig.app_s5s_Config == nil {
				ncconfig.Logger.Printf("Not initialized %s config\n", builtinApp)
				return 1
			}
			pipeConn := misc.NewPipeConn(nconn)
			input = pipeConn.In
			output = pipeConn.Out
			defer pipeConn.Close()
			go App_s5s_main_withconfig(pipeConn, nconn.KeyingMaterial, ncconfig.app_s5s_Config, stats_in, stats_out)
		} else if builtinApp == ":nc" {
			if ncconfig.app_nc_Config == nil {
				ncconfig.Logger.Printf("Not initialized %s config\n", builtinApp)
				return 1
			}
			pipeConn := misc.NewPipeConn(nconn)
			input = pipeConn.In
			output = pipeConn.Out
			defer pipeConn.Close()
			if strings.Contains(ncconfig.app_nc_Config.network, "udp") {
				//udp的端口转发，避免截断数据包，也不应该会粘包（pipeConn内部是net.Pipe()，它无内置缓冲区）
				blocksize = bufsize
			}
			go App_Netcat_main_withconfig(pipeConn, ncconfig.app_nc_Config)
		} else if builtinApp == ":sh" {
			if ncconfig.app_sh_Config == nil {
				ncconfig.Logger.Printf("Not initialized %s config\n", builtinApp)
				return 1
			}
			pipeConn := misc.NewPipeConn(nconn)
			input = pipeConn.In
			output = pipeConn.Out
			defer pipeConn.Close()
			go App_shell_main_withconfig(pipeConn, ncconfig.app_sh_Config)
		} else if builtinApp == ":tp" {
			if ncconfig.app_tp_Config == nil {
				ncconfig.Logger.Printf("Not initialized %s config\n", builtinApp)
				return 1
			}
			pipeConn := misc.NewPipeConn(nconn)
			input = pipeConn.In
			output = pipeConn.Out
			defer pipeConn.Close()
			go App_tp_main_withconfig(pipeConn, ncconfig.app_tp_Config)
		} else if builtinApp == ":pr" {
			if ncconfig.app_pr_Config == nil {
				ncconfig.Logger.Printf("Not initialized %s config\n", builtinApp)
				return 1
			}
			pipeConn := misc.NewPipeConn(nconn)
			input = pipeConn.In
			output = pipeConn.Out
			defer pipeConn.Close()
			go App_PortRotate_main_withconfig(pipeConn, nconn.Config, ncconfig, ncconfig.app_pr_Config)
		} else if builtinApp == ":br" {
			if ncconfig.app_br_Config == nil {
				ncconfig.Logger.Printf("Not initialized %s config\n", builtinApp)
				return 1
			}
			pipeConn := misc.NewPipeConn(nconn)
			input = pipeConn.In
			output = pipeConn.Out
			defer pipeConn.Close()
			go App_Bridge_main_withconfig(pipeConn, nconn.MQTTHelloAppPayload, ncconfig, ncconfig.app_br_Config)
		} else if builtinApp == ":httpserver" {
			if ncconfig.app_httpserver_Config == nil {
				ncconfig.Logger.Printf("Not initialized %s config\n", builtinApp)
				return 1
			}
			pipeConn := misc.NewPipeConn(nconn)
			input = pipeConn.In
			output = pipeConn.Out
			defer pipeConn.Close()
			go App_HttpServer_main_withconfig(pipeConn, ncconfig.app_httpserver_Config)
		} else if strings.HasPrefix(builtinApp, ":") {
			ncconfig.Logger.Printf("Invalid service command: %s\n", builtinApp)
			return 1
		} else {
			// 创建命令
			cmd = exec.Command(args[0], args[1:]...)

			// 创建管道
			stdinPipe, err := cmd.StdinPipe()
			if err != nil {
				ncconfig.Logger.Printf("Error creating stdin pipe: %v\n", err)
				return 1
			}

			stdoutPipe, err := cmd.StdoutPipe()
			if err != nil {
				ncconfig.Logger.Printf("Error creating stdout pipe: %v\n", err)
				return 1
			}

			cmdErrorPipe, err = cmd.StderrPipe()
			if err != nil {
				ncconfig.Logger.Printf("Error creating stderr pipe: %v\n", err)
				return 1
			}

			input = stdoutPipe
			output = stdinPipe

			// 启动命令
			if err := cmd.Start(); err != nil {
				ncconfig.Logger.Printf("Command start error: %v\n", err)
				return 1
			}
			//ncconfig.Logger.Printf("PID:%d child created.\n", cmd.Process.Pid)
		}
	}

	if ncconfig.framedStdio {
		fc := netx.NewFramedConn(input, output)
		input = fc
		output = fc
		//framed了，表示进来的数据流本身是有边界的，拷贝时就blocksize就按缓冲区最大能力拷贝
		blocksize = bufsize
	}

	var wg sync.WaitGroup
	done := make(chan struct{})
	abort := make(chan struct{})
	inExited := make(chan struct{})  //
	outExited := make(chan struct{}) //
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer close(outExited)

		info, err := os.Stdin.Stat()
		if err == nil && info.Mode()&os.ModeCharDevice != 0 && !binaryInputMode {
			if ncconfig.enablePty {
				ncconfig.term_oldstat, err = term.MakeRaw(int(os.Stdin.Fd()))
				if err != nil {
					ncconfig.Logger.Printf("MakeRaw error: %v\n", err)
					return
				}
				defer term.Restore(int(os.Stdin.Fd()), ncconfig.term_oldstat)
				copyWithProgress(ncconfig, nconn, input, blocksize, !nconn.IsUDP, stats_out, 0, 0)
			} else {
				copyCharDeviceWithProgress(ncconfig, nconn, input, stats_out)
			}
		} else {
			copyWithProgress(ncconfig, nconn, input, blocksize, !nconn.IsUDP, stats_out, maxSendBytes, 0)
		}

		time.Sleep(1 * time.Second)
		nconn.CloseWrite()
		//ncconfig.Logger.Printf("PID:%d (%s) conn-write routine completed.\n", os.Getpid(), nconn.RemoteAddr().String())
	}()
	// 从连接读取并输出到输出
	go func() {
		defer wg.Done()
		defer close(inExited)

		copyWithProgress(ncconfig, output, nconn, bufsize, !nconn.IsUDP, stats_in, 0, ncconfig.dialreadTimeout)
		time.Sleep(1 * time.Second)
		//ncconfig.Logger.Printf("PID:%d (%s) conn-read routine completed.\n", os.Getpid(), nconn.RemoteAddr().String())
	}()

	if cmdErrorPipe != nil {
		go func() {
			io.Copy(ncconfig.LogWriter, cmdErrorPipe)
			//ncconfig.Logger.Printf("PID:%d (%s) ErrorPipe routine completed.\n", os.Getpid(), nconn.RemoteAddr().String())
		}()
	}

	go func() {
		wg.Wait()
		close(done)
	}()

	// 等第一个 goroutine 退出
	select {
	case <-inExited:
		close(abort)
	case <-outExited:
		//
	}
	select {
	case <-abort:
		//ncconfig.Logger.Printf("PID:%d (%s) Input routine completed.\n", os.Getpid(), nconn.RemoteAddr().String())
	case <-done:
		//ncconfig.Logger.Printf("PID:%d (%s) All routines completed.\n", os.Getpid(), nconn.RemoteAddr().String())
	case <-time.After(60 * time.Second):
		//ncconfig.Logger.Printf("PID:%d (%s) Timeout after one routine exited.\n", os.Getpid(), nconn.RemoteAddr().String())
	}

	//ncconfig.Logger.Printf("PID:%d (%s) closing nconn...\n", os.Getpid(), nconn.RemoteAddr().String())
	nconn.Close()
	if ncconfig.term_oldstat != nil {
		term.Restore(int(os.Stdin.Fd()), ncconfig.term_oldstat)
	}
	// 如果使用了命令，等待命令结束
	if cmd != nil {
		//ncconfig.Logger.Printf("PID:%d killing cmd process...\n", os.Getpid())
		cmd.Process.Kill()
		cmd.Wait()
	}
	//ncconfig.Logger.Printf("PID:%d (%s) connection done.\n", os.Getpid(), nconn.RemoteAddr().String())
	return 0
}

func handleSingleConnection(console net.Conn, ncconfig *AppNetcatConfig, conn net.Conn) int {
	stats_in := misc.NewProgressStats()
	stats_out := misc.NewProgressStats()

	if ncconfig.progressEnabled {
		wg := &sync.WaitGroup{}
		done := make(chan bool)
		showProgress(ncconfig, stats_in, stats_out, done, wg)
		defer func() {
			done <- true
			wg.Wait()
		}()
	}

	return handleConnection(console, ncconfig, ncconfig.connConfig, conn, stats_in, stats_out)
}

func handleConnection(console net.Conn, ncconfig *AppNetcatConfig, cfg *secure.NegotiationConfig, conn net.Conn, stats_in, stats_out *misc.ProgressStats) int {
	nconn, err := secure.DoNegotiation(cfg, conn, ncconfig.LogWriter)
	if err != nil {
		conn.Close()
		return 1
	}

	if ncconfig.scanOnly {
		nconn.Close()
		return 0
	}

	if isEnabledMuxMode(ncconfig) {
		return handleMuxConnection(console, ncconfig, nconn, stats_in, stats_out)
	}

	return handleNegotiatedConnection(console, ncconfig, nconn, stats_in, stats_out)
}

func handleP2PConnection(console net.Conn, ncconfig *AppNetcatConfig, nconn *secure.NegotiatedConn, stats_in *misc.ProgressStats, stats_out *misc.ProgressStats) int {
	if ncconfig.scanOnly {
		nconn.Close()
		return 0
	}

	ctrlPayload := easyp2p.HelloPayloadFromString(nconn.MQTTHelloCtrlPayload)

	muxVal, _ := ctrlPayload.GetControlValue("mux")

	if isEnabledMuxMode(ncconfig) || muxVal == "1" {
		return handleMuxConnection(console, ncconfig, nconn, stats_in, stats_out)
	}

	return handleNegotiatedConnection(console, ncconfig, nconn, stats_in, stats_out)
}

type NetcatMuxStreamHandler func(client, server net.Conn)

func runMuxLocalListener(ncconfig *AppNetcatConfig, session interface{}, doneChan <-chan struct{}, handler NetcatMuxStreamHandler) error {
	defer ncconfig.muxLocalListener.Close()

	// 监听 doneChan (Session 死则 Listener 死)
	go func() {
		<-doneChan
		ncconfig.muxLocalListener.Close()
	}()

	handleConn := func(c net.Conn) {
		defer c.Close()
		stream, err := openMuxStream(session)
		if err != nil {
			ncconfig.Logger.Println("mux Open failed:", err)
			return
		}
		streamWithCloseWrite := newStreamWrapper(stream, muxSessionRemoteAddr(session), muxSessionLocalAddr(session))
		defer streamWithCloseWrite.Close()
		handler(c, streamWithCloseWrite)
	}

	for {
		conn, err := ncconfig.muxLocalListener.Accept()
		if err != nil {
			select {
			case <-doneChan:
				return fmt.Errorf("mux session closed")
			default:
				return fmt.Errorf("listener accept failed: %v", err)
			}
		}

		go handleConn(conn)
	}
}

func handleMuxConnection(console net.Conn, ncconfig *AppNetcatConfig, conn net.Conn, stats_in, stats_out *misc.ProgressStats) int {
	defer conn.Close()
	isClient := false
	if isLocalMuxMode(ncconfig) {
		isClient = true
		if ncconfig.muxLocalListener == nil && ncconfig.muxLocalPort != "-" {
			ln, err := prepareLocalListener(ncconfig.muxLocalPort, false)
			if err != nil {
				ncconfig.Logger.Printf("Error starting local mux listener on %s: %v\n", ncconfig.muxLocalPort, err)
				return 1
			}
			ncconfig.muxLocalListener = ln
		}
	}

	session, err := createMuxSession(VarmuxEngine, conn, isClient)
	if err != nil {
		ncconfig.Logger.Printf("create mux session failed: %v", err)
		return 1
	}

	ncconfig.ConsoleMode = false
	listener := newMuxListener(session)
	defer listener.Close()

	if isClient {
		if ncconfig.muxLocalPort == "-" {
			stream, err := openMuxStream(session)
			if err != nil {
				ncconfig.Logger.Println("mux Open failed:", err)
				return 1
			}
			server := newStreamWrapper(stream, muxSessionRemoteAddr(session), muxSessionLocalAddr(session))
			handleMuxChannelConnection(console, ncconfig, server, stats_in, stats_out)
		} else {
			ncconfig.Logger.Printf(
				"Mux client ready, remote service mapped to %s",
				ncconfig.muxLocalListener.Addr(),
			)

			sessionDone := make(chan struct{})
			go func() {
				defer close(sessionDone)
				stream, err := listener.Accept()
				if err != nil {
					return
				}
				stream.Close()
			}()

			handler := func(client, server net.Conn) {
				cliRaddr := client.RemoteAddr().String()
				ncconfig.Logger.Printf(
					"Open mux stream from %s",
					cliRaddr,
				)
				handleMuxChannelConnection(client, ncconfig, server, stats_in, stats_out)
				ncconfig.Logger.Printf(
					"Close mux stream from %s",
					cliRaddr,
				)
			}
			err = runMuxLocalListener(ncconfig, session, sessionDone, handler)
			ncconfig.muxLocalListener = nil //runMuxLocalListener总是会Close它，这里重置nil
			if err != nil {
				return 1
			}
		}
	} else {
		ncconfig.Logger.Printf("Enter mux server mode\n")
		for {
			stream, err := listener.Accept()
			if err != nil {
				if err == io.EOF {
					return 0
				}
				return 1
			}

			go handleMuxChannelConnection(console, ncconfig, stream, stats_in, stats_out)
		}
	}

	return 0
}

func isKCPEnabled(ncconfig *AppNetcatConfig) bool {
	return ncconfig.udpProtocol && (ncconfig.kcpEnabled || ncconfig.kcpSEnabled)
}

func ShowPublicIP(ncconfig *AppNetcatConfig, network, bind string) error {
	index, _, nata, err := easyp2p.GetPublicIP(network, bind, 7*time.Second)
	if err == nil {
		ncconfig.Logger.Printf("Public Address: %s (via %s)\n", nata, easyp2p.STUNServers[index])
	}

	return err
}

func Mqtt_ensure_ready(ncconfig *AppNetcatConfig) (string, error) {
	var err error
	var salt string

	if ncconfig.useMQTTWait {
		ReportP2PStatus(ncconfig, "", "wait", ncconfig.network, "", "")
		salt, err = easyp2p.MqttWait(ncconfig.ctx, ncconfig.p2pSessionKey, ncconfig.localbindIP, 30*time.Minute, ncconfig.LogWriter)
		if err != nil {
			return "", fmt.Errorf("mqtt-wait: %v", err)
		}
	}

	if ncconfig.useMQTTHello {
		ReportP2PStatus(ncconfig, "", "wait", ncconfig.network, "", "")
		salt, err = easyp2p.MQTTHello(ncconfig.ctx, ncconfig.p2pSessionKey, ncconfig.localbindIP, ncconfig.MQTTHelloPayload, 15*time.Second, ncconfig.LogWriter)
		if err != nil {
			return "", fmt.Errorf("mqtt-hello: %v", err)
		}
	}
	return salt, nil
}

func do_P2P(ncconfig *AppNetcatConfig) (*secure.NegotiatedConn, error) {
	//使用其他客户端push过来的salt，构建一个仅和对端单独共享的topic，避免P2P交换地址时有多个端点在一起错乱发生

	topicSalt, err := Mqtt_ensure_ready(ncconfig)
	if err != nil {
		ReportP2PStatus(ncconfig, "", fmt.Sprintf("error:%v", err), ncconfig.network, "", "")
		return nil, err
	}

	ReportP2PStatus(ncconfig, topicSalt, "connecting", ncconfig.network, "", "")

	cipherSuite := ""
	if ncconfig.plainTransport {
		cipherSuite = "plain"
	} else if ncconfig.shadowStream {
		cipherSuite = "ss"
	} else {
		cipherSuite = "tls"
	}

	var helloPayload easyp2p.HelloPayload
	if ncconfig.useMQTTWait && !ncconfig.useMQTTHello {
		helloPayload = easyp2p.HelloPayloadFromString(topicSalt)
		switch helloPayload.App {
		case "br":
			//Wait模式，如果对方hello的载荷是bridge类型，则提前验证session是否接受，免得浪费资源建立连接
			if !Bridge_IsP2PHelloAllowed(helloPayload.AppString()) {
				ReportP2PStatus(ncconfig, topicSalt, "error:bridge session not found", ncconfig.network, "", "")
				return nil, fmt.Errorf("bridge session not found: %s", helloPayload.AppString())
			}
		}

		if cs, ok := helloPayload.GetControlValue("cs"); ok {
			switch cs {
			case "ss", "tls":
				cipherSuite = cs
			default:
				return nil, fmt.Errorf("unsupported cipher suite from hello payload: %s", cs)
			}
		}
	}

	var relayConn *easyp2p.RelayPacketConn
	socks5UDPClient, err := CreateSocks5UDPClient(ncconfig.arg_proxyc_Config)
	if err != nil {
		ReportP2PStatus(ncconfig, topicSalt, fmt.Sprintf("error: socks5: %v", err), ncconfig.network, "", "")
		return nil, fmt.Errorf("prepare socks5 UDP client failed: %v", err)
	} else if socks5UDPClient != nil {
		relayConn = &easyp2p.RelayPacketConn{
			PacketConn: socks5UDPClient,
		}
		if ncconfig.fallbackRelayMode {
			relayConn.FallbackMode = true
		}
	}

	//sessionKey+topicSalt组合成和对端单独共享的mqtt topic
	connInfo, err := easyp2p.Easy_P2P_MP(ncconfig.ctx, ncconfig.network, ncconfig.localbind, ncconfig.p2pSessionKey+topicSalt, false, relayConn, ncconfig.LogWriter)
	if err != nil {
		if relayConn != nil {
			relayConn.Close()
		}
		ReportP2PStatus(ncconfig, topicSalt, fmt.Sprintf("error:%v", err), ncconfig.network, "", "")
		return nil, err
	}

	conn := connInfo.Conns[0]
	config := *ncconfig.connConfig
	config.IsClient = connInfo.IsClient

	switch cipherSuite {
	case "plain":
		if strings.HasPrefix(conn.LocalAddr().Network(), "udp") {
			if strings.HasPrefix(config.SecureLayer, "tls") {
				config.SecureLayer = "dtls"
			} else if strings.HasPrefix(config.SecureLayer, "ss") {
				config.SecureLayer = "dss"
			}
		}
		if ncconfig.autoPSK {
			config.Key = string(connInfo.SharedKey[:])
			config.KeyType = "ECDHE"
		}
	case "ss":
		config.Key = string(connInfo.SharedKey[:])
		config.KeyType = "ECDHE"

		if strings.HasPrefix(conn.LocalAddr().Network(), "udp") {
			config.KcpWithUDP = true
			config.SecureLayer = "dss"
		} else {
			config.KcpWithUDP = false
			config.SecureLayer = "ss"
		}
	case "", "tls":
		config.Key = ncconfig.p2pSessionKey
		config.KeyType = "PSK"

		if strings.HasPrefix(conn.LocalAddr().Network(), "udp") {
			config.KcpWithUDP = true
			config.SecureLayer = "dtls"
		} else {
			config.KcpWithUDP = false
			config.SecureLayer = "tls13"
		}
	default:
		return nil, fmt.Errorf("unsupported cipher suite: %s", cipherSuite)
	}

	nconn, err := secure.DoNegotiation(&config, conn, ncconfig.LogWriter)
	if err != nil {
		conn.Close()
		ReportP2PStatus(ncconfig, topicSalt, fmt.Sprintf("error:%v", err), ncconfig.network, "", "")
		return nil, err
	}
	if nconn.IsUDP {
		proxyRemoteAddr := ""
		if pktConn, ok := conn.(*netx.ConnFromPacketConn); ok {
			if s5conn, ok := pktConn.PacketConn.(*Socks5UDPPacketConn); ok {
				proxyRemoteAddr = s5conn.GetUDPAssociateAddr().String()
			}
		}
		if proxyRemoteAddr != "" {
			ncconfig.Logger.Printf("UDP ready for: %s -> %s -> %s\n", conn.LocalAddr().String(), proxyRemoteAddr, conn.RemoteAddr().String())
		} else {
			ncconfig.Logger.Printf("UDP ready for: %s -> %s\n", conn.LocalAddr().String(), conn.RemoteAddr().String())
		}
	} else {
		ncconfig.Logger.Printf("Connected to: %s\n", conn.RemoteAddr().String())
	}
	statusNetwork := strings.Join(connInfo.NetworksUsed, "+")
	statusMode := "P2P"
	if connInfo.RelayUsed {
		statusMode = "Relay"
	}
	ReportP2PStatus(ncconfig, topicSalt, "connected", statusNetwork, statusMode, connInfo.PeerAddress)
	preOnClose := nconn.OnClose
	nconn.OnClose = func() {
		ReportP2PStatus(ncconfig, topicSalt, "disconnected", statusNetwork, statusMode, connInfo.PeerAddress)
		if preOnClose != nil {
			preOnClose()
		}
	}
	nconn.MQTTHelloCtrlPayload = helloPayload.CtrlString()
	nconn.MQTTHelloAppPayload = helloPayload.AppString()
	return nconn, nil
}

func do_P2P_multipath(ncconfig *AppNetcatConfig, enableMP bool) (*secure.NegotiatedConn, error) {
	if !enableMP {
		return do_P2P(ncconfig)
	}
	//建立多个连接，例如包含UDP TCP TCP6几个会话，然后封装为哪个协议快用哪个，规避Qos
	return nil, fmt.Errorf("multipath not implemented yet")
}

func setDns(dnsServer string, localIP string) {
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Second * 5,
			}

			// 如果指定了本地IP，就绑定
			if localIP != "" {
				ip := net.ParseIP(localIP)
				if ip != nil {
					if strings.HasPrefix(network, "udp") {
						d.LocalAddr = &net.UDPAddr{IP: ip}
					} else if strings.HasPrefix(network, "tcp") {
						d.LocalAddr = &net.TCPAddr{IP: ip}
					}
				}
			}

			// 确保端口存在
			if strings.Contains(dnsServer, ":") {
				if _, _, err := net.SplitHostPort(dnsServer); err != nil {
					dnsServer = net.JoinHostPort(dnsServer, "53")
				}
			} else {
				dnsServer = net.JoinHostPort(dnsServer, "53")
			}

			return d.DialContext(ctx, network, dnsServer)
		},
	}
}

func isAndroid() bool {
	return runtime.GOOS == "android"
}

func parseMultiItems(s string, randomize bool) []string {
	servers := strings.Split(s, ",")
	var result []string
	for _, srv := range servers {
		trimmed := strings.TrimSpace(srv)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	if randomize {
		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(len(result), func(i, j int) { result[i], result[j] = result[j], result[i] })
	}
	return result
}

// cleanupUnixSocket 检查指定路径的文件是否是Unix域套接字，如果是则删除它。
func cleanupUnixSocket(path string) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		// 其他错误，例如权限问题
		return fmt.Errorf("could not stat %s: %w", path, err)
	}

	// 检查文件类型是否为 Unix 域套接字
	if fileInfo.Mode().Type() == os.ModeSocket {
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("failed to remove existing Unix socket %s: %w", path, err)
		}
	} else {
		// 目标路径存在但不是 Unix 域套接字，应避免删除
		return fmt.Errorf("path %s exists but is not a Unix socket (mode: %s), refusing to remove it", path, fileInfo.Mode().String())
	}
	return nil
}

type P2PStatusReport struct {
	Topic     string `json:"topic"`     // random string
	Status    string `json:"status"`    // wait / connecting / connected / disconnected / error
	Network   string `json:"network"`   // tcp / udp
	Mode      string `json:"mode"`      // p2p / relay
	Peer      string `json:"peer"`      // IP:port
	Timestamp int64  `json:"timestamp"` // unix time
	PID       int    `json:"pid"`       // process ID
}

func ReportP2PStatus(ncconfig *AppNetcatConfig, mqttsess, status, network, mode, peer string) {
	if ncconfig.p2pReportURL == "" {
		return
	}

	report := P2PStatusReport{
		Topic:     mqttsess,
		Status:    status,
		Network:   network,
		Mode:      mode,
		Peer:      peer,
		Timestamp: time.Now().Unix(),
		PID:       os.Getpid(),
	}

	body, err := json.Marshal(report)
	if err != nil {
		ncconfig.Logger.Printf("ReportP2PStatus: marshal report: %v\n", err)
		return
	}

	req, err := http.NewRequest("POST", ncconfig.p2pReportURL, bytes.NewReader(body))
	if err != nil {
		ncconfig.Logger.Printf("ReportP2PStatus: create request: %v\n", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 5 * time.Second, // 控制整个请求过程
	}

	resp, err := client.Do(req)
	if err != nil {
		ncconfig.Logger.Printf("ReportP2PStatus: http post: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		//respBody, _ := io.ReadAll(resp.Body)
		ncconfig.Logger.Printf("ReportP2PStatus: server returned %d\n", resp.StatusCode)
		return
	}
}
