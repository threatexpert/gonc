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

	"github.com/threatexpert/gonc/v2/acl"
	"github.com/threatexpert/gonc/v2/easyp2p"
	"github.com/threatexpert/gonc/v2/misc"
	"github.com/threatexpert/gonc/v2/netx"
	"github.com/threatexpert/gonc/v2/secure"
	"golang.org/x/term"
	// "net/http"
	// _ "net/http/pprof"
)

var (
	VERSION = "v2.3.0"
)

type AppNetcatConfig struct {
	ConsoleMode bool
	LogWriter   io.Writer

	network, host, port, p2pSessionKey string

	connConfig                 *secure.NegotiationConfig
	sessionReady               bool
	goroutineConnectionCounter int32
	tlsVerifyCert              bool
	keepAlive                  int

	app_mux_args      string
	app_mux_Config    *AppMuxConfig
	app_s5s_args      string
	app_s5s_Config    *AppS5SConfig
	arg_proxyc_Config *ProxyClientConfig
	fallbackRelayMode bool
	app_sh_args       string
	app_sh_Config     *PtyShellConfig
	app_nc_args       string
	app_nc_Config     *AppNetcatConfig

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
	enableCRLF        bool
	listenMode        bool
	udpProtocol       bool
	useUNIXdomain     bool
	kcpEnabled        bool
	kcpSEnabled       bool
	localbind         string
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
	useIPv4           bool
	useIPv6           bool
	useDNS            string
	runAppFileServ    string
	runAppFileGet     string
	appMuxListenMode  bool
	appMuxListenOn    string
	appMuxSocksMode   bool
	fileACL           string
	plainTransport    bool
	framedStdio       bool
	p2pReportURL      string
}

// AppNetcatConfigByArgs 解析给定的 []string 参数，生成 AppNetcatConfig
func AppNetcatConfigByArgs(argv0 string, args []string) (*AppNetcatConfig, error) {
	config := &AppNetcatConfig{
		LogWriter: os.Stderr,
	}

	// 创建一个自定义的 FlagSet，而不是使用全局的 flag.CommandLine
	// 设置 ContinueOnError 允许我们捕获错误而不是直接退出
	fs := flag.NewFlagSet("AppNetcatConfig", flag.ContinueOnError)

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
	fs.StringVar(&config.presharedKey, "psk", "", "Pre-shared key for deriving TLS certificate identity (anti-MITM); also key for TCP/KCP encryption")
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
	fs.BoolVar(&config.useMQTTHello, "mqtt-hello", false, "send MQTT hello message before initiating P2P connection")
	fs.BoolVar(&config.useIPv4, "4", false, "Forces to use IPv4 addresses only")
	fs.BoolVar(&config.useIPv6, "6", false, "Forces to use IPv4 addresses only")
	fs.StringVar(&config.useDNS, "dns", "", "set DNS Server")
	fs.StringVar(&config.runAppFileServ, "httpserver", "", "http server root directory")
	fs.StringVar(&config.runAppFileGet, "download", "", "http client download directory")
	fs.BoolVar(&config.appMuxListenMode, "httplocal", false, "local listen mode for remote httpserver")
	fs.StringVar(&config.appMuxListenOn, "httplocal-port", "", "local listen port for remote httpserver")
	fs.BoolVar(&config.appMuxSocksMode, "socks5server", false, "for socks5 tunnel")
	fs.StringVar(&config.fileACL, "acl", "", "ACL file for inbound/outbound connections")
	fs.BoolVar(&config.plainTransport, "plain", false, "use plain TCP/UDP without TLS/KCP/Encryption for P2P")
	fs.BoolVar(&config.framedStdio, "framed", false, "stdin/stdout is framed stream (2 bytes length prefix for each frame)")
	fs.BoolVar(&config.tlsVerifyCert, "verify", false, "verify TLS certificate (client mode only)")
	fs.IntVar(&config.keepAlive, "keepalive", 0, "none 0 will enable keepalive feature")

	fs.StringVar(&config.runCmd, "e", "", "alias for -exec")
	fs.BoolVar(&config.progressEnabled, "P", false, "alias for -progress")
	fs.BoolVar(&config.keepOpen, "k", false, "alias for -keep-open")
	fs.BoolVar(&config.appMuxListenMode, "socks5local", false, "")
	fs.StringVar(&config.appMuxListenOn, "socks5local-port", "", "")
	fs.BoolVar(&config.appMuxListenMode, "browser", false, "alias for -httplocal")
	fs.StringVar(&config.app_mux_args, ":mux", "-", "enable and config :mux for dynamic service")
	fs.StringVar(&config.app_s5s_args, ":s5s", "-", "enable and config :s5s for dynamic service")
	fs.StringVar(&config.app_sh_args, ":sh", "-", "enable and config :sh for dynamic service")
	fs.StringVar(&config.app_nc_args, ":nc", "-", "enable and config :nc for dynamic service")

	//<----- Global flags
	fs.StringVar(&config.stunSrv, "stunsrv", strings.Join(easyp2p.STUNServers, ","), "stun servers")
	fs.StringVar(&config.mqttServers, "mqttsrv", strings.Join(easyp2p.MQTTBrokerServers, ","), "MQTT servers")
	disableCompress := fs.Bool("no-compress", false, "disable compression for http download")
	VarhttpDownloadNoCompress = disableCompress
	fs.StringVar(&easyp2p.TopicExchange, "mqtt-nat-topic", easyp2p.TopicExchange, "")
	fs.IntVar(&easyp2p.PunchingShortTTL, "punch-short-ttl", easyp2p.PunchingShortTTL, "")
	fs.IntVar(&easyp2p.PunchingRandomPortCount, "punch-random-count", easyp2p.PunchingRandomPortCount, "")
	fs.IntVar(&secure.UdpOutputBlockSize, "udp-size", secure.UdpOutputBlockSize, "")
	fs.IntVar(&secure.KcpWindowSize, "kcp-window-size", secure.KcpWindowSize, "")
	fs.StringVar(&secure.UdpKeepAlivePayload, "udp-ping-data", secure.UdpKeepAlivePayload, "")
	fs.StringVar(&VarmuxEngine, "mux-engine", VarmuxEngine, "yamux | smux")
	//----->

	fs.Usage = func() {
		usage_full(argv0, fs)
	}

	// 解析传入的 args 切片
	// 注意：我们假设 args 已经不包含程序名 (os.Args[0])，所以直接传入
	err := fs.Parse(args)
	if err != nil {
		return nil, err // 解析错误直接返回
	}

	// 1. 初始化基本设置
	firstInit(config)

	// 2. 配置内置应用程序模式（例如http服务器，socks5）
	configureAppMode(config)

	// 3. 配置安全功能，如PSK和ACL
	err = configureSecurity(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Security configuration failed: %v\n", err)
		os.Exit(1)
	}

	if fs.NFlag() == 0 && fs.NArg() == 0 {
		usage_less(argv0)
		os.Exit(1)
	}

	// 4. 从参数和标志确定网络类型、地址和P2P会话密钥
	network, host, port, P2PSessionKey, err := determineNetworkAndAddress(config, fs.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error determining network address: %v\n", err)
		usage_less(argv0)
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

	return config, nil
}

func App_Netcat_main(console *misc.ConsoleIO, args []string) int {
	config, err := AppNetcatConfigByArgs("gonc", args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing gonc args: %v\n", err)
		return 1
	}
	config.ConsoleMode = true

	return App_Netcat_main_withconfig(console, config)
}

func App_Netcat_main_withconfig(console net.Conn, config *AppNetcatConfig) int {
	defer console.Close()
	if config.p2pSessionKey != "" {
		return runP2PMode(console, config)
	} else {
		if config.listenMode {
			return runListenMode(console, config, config.network, config.host, config.port)
		} else {
			return runDialMode(console, config, config.network, config.host, config.port)
		}
	}
}

func firstInit(ncconfig *AppNetcatConfig) {
	easyp2p.MQTTBrokerServers = parseMultiItems(ncconfig.mqttServers, true)
	easyp2p.STUNServers = parseMultiItems(ncconfig.stunSrv, true)
	conflictCheck(ncconfig)
}

// configureAppMode 为内置应用程序设置命令参数
func configureAppMode(ncconfig *AppNetcatConfig) {
	if ncconfig.runAppFileServ != "" {
		escapedPath := strings.ReplaceAll(ncconfig.runAppFileServ, "\\", "/")
		ncconfig.runCmd = fmt.Sprintf(":mux httpserver \"%s\"", escapedPath)
		ncconfig.useMQTTWait = true
		ncconfig.progressEnabled = true
		ncconfig.keepOpen = true
	} else if ncconfig.runAppFileGet != "" {
		escapedPath := strings.ReplaceAll(ncconfig.runAppFileGet, "\\", "/")
		ncconfig.runCmd = fmt.Sprintf(":mux httpclient \"%s\"", escapedPath)
		if ncconfig.appMuxListenOn != "" {
			VarmuxLastListenAddress = ncconfig.appMuxListenOn
		}
		ncconfig.useMQTTHello = true
		ncconfig.keepOpen = true
	} else if ncconfig.appMuxSocksMode {
		ncconfig.runCmd = ":mux socks5"
		if !ncconfig.useMQTTWait {
			ncconfig.useMQTTWait = true
		}
		ncconfig.progressEnabled = true
		ncconfig.keepOpen = true
	} else if ncconfig.appMuxListenMode || ncconfig.appMuxListenOn != "" {
		if ncconfig.appMuxListenOn == "" {
			ncconfig.appMuxListenOn = "0"
		}
		ncconfig.runCmd = fmt.Sprintf(":mux -l %s", ncconfig.appMuxListenOn)
		ncconfig.useMQTTHello = true
		ncconfig.keepOpen = true
	}

	if ncconfig.runCmd != "" && ncconfig.runCmd != ":service" {
		err := preinitBuiltinAppConfig(ncconfig, ncconfig.runCmd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
	} else {
		if ncconfig.app_mux_args != "-" {
			err := preinitBuiltinAppConfig(ncconfig, ":mux "+ncconfig.app_mux_args)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
		}
		if ncconfig.app_s5s_args != "-" {
			err := preinitBuiltinAppConfig(ncconfig, ":s5s "+ncconfig.app_s5s_args)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
		}
		if ncconfig.app_sh_args != "-" {
			err := preinitBuiltinAppConfig(ncconfig, ":sh "+ncconfig.app_sh_args)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
		}
		if ncconfig.app_nc_args != "-" {
			err := preinitBuiltinAppConfig(ncconfig, ":nc "+ncconfig.app_nc_args)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
		}
	}

	xcommandline := ncconfig.proxyAddr
	if ncconfig.proxyAddr2 != "" {
		xcommandline = ncconfig.proxyAddr2
		ncconfig.fallbackRelayMode = true
	}
	if xcommandline != "" {
		xconfig, err := ProxyClientConfigByCommandline(ncconfig.proxyProt, ncconfig.auth, xcommandline)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error init proxy config: %v\n", err)
			os.Exit(1)
		}
		ncconfig.arg_proxyc_Config = xconfig
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
				fmt.Fprintf(os.Stderr, "Error reading PSK file: %v\n", err)
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
func determineNetworkAndAddress(ncconfig *AppNetcatConfig, args []string) (network, host, port, P2PSessionKey string, err error) {
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

	switch len(args) {
	case 2:
		host, port = args[0], args[1]
	case 1:
		if ncconfig.listenMode {
			port = args[0]
		} else if ncconfig.useUNIXdomain {
			port = args[0]
		} else {
			return "", "", "", "", fmt.Errorf("invalid arguments")
		}
	case 0:
		if ncconfig.listenMode && ncconfig.localbind != "" {
			host, port, err = net.SplitHostPort(ncconfig.localbind)
			if err != nil {
				return "", "", "", "", fmt.Errorf("invalid local address %q: %v", ncconfig.localbind, err)
			}
		} else if !ncconfig.listenMode && ncconfig.remoteAddr != "" {
			host, port, err = net.SplitHostPort(ncconfig.remoteAddr)
			if err != nil {
				return "", "", "", "", fmt.Errorf("invalid remote address %q: %v", ncconfig.remoteAddr, err)
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
					fmt.Fprintf(os.Stderr, "Error reading PSK file: %v\n", err)
					os.Exit(1)
				}
			}
			if P2PSessionKey == "." {
				P2PSessionKey, err = secure.GenerateSecureRandomString(22)
				if err != nil {
					panic(err)
				}
				fmt.Fprintf(os.Stderr, "Keep this key secret! It is used to establish the secure P2P tunnel: %s\n", P2PSessionKey)
			} else if secure.IsWeakPassword(P2PSessionKey) {
				return "", "", "", "", fmt.Errorf("weak password detected")
			}
			if !ncconfig.plainTransport {
				//没-plain的情况，P2P默认启用kcp tls
				if ncconfig.udpProtocol {
					ncconfig.kcpEnabled = true
				}
				ncconfig.tlsEnabled = true
				ncconfig.presharedKey = P2PSessionKey
			}
			if isTLSEnabled(ncconfig) {
				if ncconfig.presharedKey == "" {
					ncconfig.presharedKey = P2PSessionKey
				}
			}

			if ncconfig.arg_proxyc_Config != nil {
				if ncconfig.arg_proxyc_Config.Prot != "socks5" {
					return "", "", "", "", fmt.Errorf("only allow socks5 proxy with p2p")
				}
				if strings.HasPrefix(network, "tcp") {
					return "", "", "", "", fmt.Errorf("only allow socks5 proxy with p2p udp mode")
				}
			}
		} else {
			return "", "", "", "", fmt.Errorf("not enough arguments")
		}
	default:
		return "", "", "", "", fmt.Errorf("too many arguments")
	}

	return network, host, port, P2PSessionKey, nil
}

// configureDNS 如果指定，则设置DNS解析器，并为Android提供默认值
func configureDNS(ncconfig *AppNetcatConfig) {
	if ncconfig.useDNS != "" {
		setDns(ncconfig.useDNS)
	} else if isAndroid() {
		setDns("8.8.8.8:53")
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
				fmt.Fprintf(ncconfig.LogWriter, "P2P failed: %v\n", err)
				fmt.Fprintf(ncconfig.LogWriter, "Will retry in 10 seconds...\n")
				time.Sleep(10 * time.Second)
				continue
			}
			if ncconfig.useMQTTWait {
				go handleNegotiatedConnection(console, ncconfig, nconn, stats_in, stats_out)
			} else {
				handleNegotiatedConnection(console, ncconfig, nconn, stats_in, stats_out)
			}
			time.Sleep(2 * time.Second)
		}
	} else {
		nconn, err := do_P2P_multipath(ncconfig, ncconfig.useMutilPath)
		if err != nil {
			fmt.Fprintf(ncconfig.LogWriter, "P2P failed: %v\n", err)
			return 1
		}
		return handleNegotiatedConnection(console, ncconfig, nconn, stats_in, stats_out)
	}
}

// runListenMode 在监听模式下启动服务器
func runListenMode(console net.Conn, ncconfig *AppNetcatConfig, network, host, port string) int {
	if ncconfig.arg_proxyc_Config == nil {
		if port == "0" {
			portInt, err := easyp2p.GetFreePort()
			if err != nil {
				fmt.Fprintf(ncconfig.LogWriter, "Get Free Port: %v\n", err)
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
		fmt.Fprintf(ncconfig.LogWriter, "Error resolving UDP address: %v\n", err)
		return 1
	}

	if ncconfig.useSTUN {
		if err = ShowPublicIP(ncconfig, network, addr.String()); err != nil {
			fmt.Fprintf(ncconfig.LogWriter, "Error getting public IP: %v\n", err)
			return 1
		}
		time.Sleep(1500 * time.Millisecond)
	}

	uconn, err := net.ListenUDP(network, addr)
	if err != nil {
		fmt.Fprintf(ncconfig.LogWriter, "Error listening on UDP address: %v\n", err)
		return 1
	}
	defer uconn.Close()
	fmt.Fprintf(ncconfig.LogWriter, "Listening %s on %s\n", uconn.LocalAddr().Network(), uconn.LocalAddr().String())

	logDiscard := log.New(io.Discard, "", log.LstdFlags)
	usessListener, err := netx.NewUDPCustomListener(uconn, logDiscard)
	if err != nil {
		fmt.Fprintf(ncconfig.LogWriter, "Error NewUDPCustomListener: %v\n", err)
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
					fmt.Fprintf(ncconfig.LogWriter, "UDPCustomListener accept failed: %v\n", err)
					return 1
				}
				continue
			}
			if !acl.ACL_inbound_allow(ncconfig.accessControl, newSess.RemoteAddr()) {
				fmt.Fprintf(ncconfig.LogWriter, "ACL refused: %s\n", newSess.RemoteAddr())
				newSess.Close()
				continue
			}
			fmt.Fprintf(ncconfig.LogWriter, "UDP session established from %s\n", newSess.RemoteAddr().String())
			go handleConnection(console, ncconfig, ncconfig.connConfig, newSess, stats_in, stats_out)
		}
	} else {
		newSess, err := usessListener.Accept()
		if err != nil {
			fmt.Fprintf(ncconfig.LogWriter, "UDPCustomListener accept failed: %v\n", err)
			return 1
		}
		if !acl.ACL_inbound_allow(ncconfig.accessControl, newSess.RemoteAddr()) {
			fmt.Fprintf(ncconfig.LogWriter, "ACL refused: %s\n", newSess.RemoteAddr())
			newSess.Close()
			return 1
		}
		fmt.Fprintf(ncconfig.LogWriter, "UDP session established from %s\n", newSess.RemoteAddr().String())
		return handleSingleConnection(console, ncconfig, newSess)
	}
}

// startTCPListener 启动TCP/Unix监听器并处理传入连接
func startTCPListener(console net.Conn, ncconfig *AppNetcatConfig, network, host, port string) int {
	listenAddr := net.JoinHostPort(host, port)
	if ncconfig.useUNIXdomain {
		listenAddr = port
		if err := cleanupUnixSocket(port); err != nil {
			fmt.Fprintf(ncconfig.LogWriter, "%v\n", err)
			return 1
		}
	}

	var listener net.Listener
	var err error
	socks5BindMode := false
	proxyClient, err := NewProxyClient(ncconfig.arg_proxyc_Config)
	if err != nil {
		fmt.Fprintf(ncconfig.LogWriter, "Error create proxy client: %v\n", err)
		return 1
	}
	if proxyClient.SupportBIND() {
		fmt.Fprintf(ncconfig.LogWriter, "Attempting SOCKS5 BIND on proxy at %s...\n", listenAddr)
		listener, err = proxyClient.Dialer.Listen(network, listenAddr)
		//socks5listener的Close函数是空，无需Close()
		socks5BindMode = true
	} else {
		lc := net.ListenConfig{}
		if ncconfig.useSTUN {
			if err = ShowPublicIP(ncconfig, network, listenAddr); err != nil {
				fmt.Fprintf(ncconfig.LogWriter, "Error getting public IP: %v\n", err)
				return 1
			}
			lc.Control = netx.ControlTCP
		}
		listener, err = lc.Listen(context.Background(), network, listenAddr)
		if err == nil {
			defer listener.Close()
		}
	}
	if err != nil {
		fmt.Fprintf(ncconfig.LogWriter, "Error listening on %s: %v\n", listenAddr, err)
		return 1
	}

	fmt.Fprintf(ncconfig.LogWriter, "Listening %s on %s\n", listener.Addr().Network(), listener.Addr().String())
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
				fmt.Fprintf(ncconfig.LogWriter, "Error accepting connection: %v\n", err)
				if socks5BindMode {
					goto RE_BIND
				} else {
					time.Sleep(1 * time.Second)
					continue
				}
			}
			if conn.LocalAddr().Network() == "unix" {
				fmt.Fprintf(ncconfig.LogWriter, "Connection on %s received!\n", conn.LocalAddr().String())
			} else {
				if !acl.ACL_inbound_allow(ncconfig.accessControl, conn.RemoteAddr()) {
					fmt.Fprintf(ncconfig.LogWriter, "ACL refused: %s\n", conn.RemoteAddr())
					conn.Close()
					continue
				}
				fmt.Fprintf(ncconfig.LogWriter, "Connected from: %s        \n", conn.RemoteAddr().String())
			}
			go handleConnection(console, ncconfig, ncconfig.connConfig, conn, stats_in, stats_out)
		RE_BIND:
			if socks5BindMode {
				listener.Close()
				for tt := 0; tt < 60; tt++ {
					fmt.Fprintf(ncconfig.LogWriter, "Re-attempting SOCKS5 BIND on proxy at %s...", listenAddr)
					listener, err = proxyClient.Dialer.Listen(network, listenAddr)
					if err != nil {
						fmt.Fprintf(ncconfig.LogWriter, "Error listening on %s: %v\n", listenAddr, err)
						fmt.Fprintf(ncconfig.LogWriter, "Will retry in 5 seconds...\n")
						time.Sleep(5 * time.Second)
					} else {
						fmt.Fprintf(ncconfig.LogWriter, "completed\n")
						break
					}
				}
			}
		}
	} else {
		conn, err := listener.Accept()
		listener.Close()
		if err != nil {
			fmt.Fprintf(ncconfig.LogWriter, "Error accepting connection: %v\n", err)
			return 1
		}

		if conn.LocalAddr().Network() == "unix" {
			fmt.Fprintf(ncconfig.LogWriter, "Connection on %s received!\n", conn.LocalAddr().String())
		} else {
			if !acl.ACL_inbound_allow(ncconfig.accessControl, conn.RemoteAddr()) {
				fmt.Fprintf(ncconfig.LogWriter, "ACL refused: %s\n", conn.RemoteAddr())
				conn.Close()
				return 1
			}
			fmt.Fprintf(ncconfig.LogWriter, "Connected from: %s\n", conn.RemoteAddr().String())
		}
		return handleSingleConnection(console, ncconfig, conn)
	}
}

// runDialMode 在主动连接模式下启动客户端
func runDialMode(console net.Conn, ncconfig *AppNetcatConfig, network, host, port string) int {
	var conn net.Conn
	var err error

	// go func() {
	// 	log.Println(http.ListenAndServe("localhost:6060", nil))
	// }()

	proxyClient, err := NewProxyClient(ncconfig.arg_proxyc_Config)
	if err != nil {
		fmt.Fprintf(ncconfig.LogWriter, "Error create proxy client: %v\n", err)
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
				fmt.Fprintf(ncconfig.LogWriter, "Error resolving address: %v\n", err)
				return 1
			}
		}

		if ncconfig.useSTUN {
			if ncconfig.localbind == "" {
				fmt.Fprintf(ncconfig.LogWriter, "-stun need be with -local while connecting\n")
				return 1
			}
			if err = ShowPublicIP(ncconfig, network, localAddr.String()); err != nil {
				fmt.Fprintf(ncconfig.LogWriter, "Error getting public IP: %v\n", err)
				return 1
			}
		}

		if localAddr == nil {
			conn, err = proxyClient.DialTimeout(network, net.JoinHostPort(host, port), 20*time.Second)
		} else {
			dialer := &net.Dialer{LocalAddr: localAddr}
			switch {
			case strings.HasPrefix(network, "tcp"):
				dialer.Control = netx.ControlTCP
			case strings.HasPrefix(network, "udp"):
				dialer.Control = netx.ControlUDP
			}
			conn, err = dialer.Dial(network, net.JoinHostPort(host, port))
		}
	}

	if err != nil {
		fmt.Fprintf(ncconfig.LogWriter, "Error: %v\n", err)
		return 1
	}

	// 连接成功后打印信息
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
			fmt.Fprintf(ncconfig.LogWriter, "UDP ready for: %s -> %s -> %s\n", conn.LocalAddr().String(), proxyRemoteAddr, remoteTargetAddr)
		} else {
			fmt.Fprintf(ncconfig.LogWriter, "UDP ready for: %s\n", remoteTargetAddr)
		}
	} else {
		if ncconfig.arg_proxyc_Config == nil {
			fmt.Fprintf(ncconfig.LogWriter, "Connected to: %s\n", conn.RemoteAddr().String())
		} else {
			fmt.Fprintf(ncconfig.LogWriter, "Connected to: %s -> %s\n", conn.RemoteAddr().String(), remoteTargetAddr)
		}
	}

	return handleSingleConnection(console, ncconfig, conn)
}

func init_TLS(ncconfig *AppNetcatConfig, genCertForced bool) []tls.Certificate {
	var certs []tls.Certificate
	if isTLSEnabled(ncconfig) {
		if ncconfig.listenMode || ncconfig.kcpSEnabled {
			ncconfig.tlsServerMode = true
		}
		if genCertForced || ncconfig.tlsServerMode {
			if ncconfig.sslCertFile != "" && ncconfig.sslKeyFile != "" {
				fmt.Fprintf(os.Stderr, "Loading cert...")
				cert, err := secure.LoadCertificate(ncconfig.sslCertFile, ncconfig.sslKeyFile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error load certificate: %v\n", err)
					os.Exit(1)
				}
				certs = append(certs, *cert)
				ncconfig.tlsECCertEnabled = false
				ncconfig.tlsRSACertEnabled = false
			} else {
				if !ncconfig.tlsECCertEnabled && !ncconfig.tlsRSACertEnabled {
					fmt.Fprintf(os.Stderr, "EC and RSA both are disabled\n")
					os.Exit(1)
				}
				if ncconfig.tlsECCertEnabled {
					if ncconfig.presharedKey != "" {
						fmt.Fprintf(os.Stderr, "Generating ECDSA(PSK-derived) cert for secure communication...")
					} else {
						fmt.Fprintf(os.Stderr, "Generating ECDSA(randomly) cert for secure communication...")
					}
					cert, err := secure.GenerateECDSACertificate(ncconfig.tlsSNI, ncconfig.presharedKey)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error generating EC certificate: %v\n", err)
						os.Exit(1)
					}
					certs = append(certs, *cert)
				}
				if ncconfig.tlsRSACertEnabled {
					fmt.Fprintf(os.Stderr, "Generating RSA cert...")
					cert, err := secure.GenerateRSACertificate(ncconfig.tlsSNI)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error generating RSA certificate: %v\n", err)
						os.Exit(1)
					}
					certs = append(certs, *cert)
				}
			}

			fmt.Fprintf(os.Stderr, "completed.\n")
		}
	}
	return certs
}

func isTLSEnabled(ncconfig *AppNetcatConfig) bool {
	return ncconfig.tlsServerMode || ncconfig.tlsEnabled || ncconfig.tls10_forced || ncconfig.tls11_forced || ncconfig.tls12_forced || ncconfig.tls13_forced
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
						fmt.Fprintf(os.Stderr,
							"IN: %s (%d bytes), %s/s | OUT: %s (%d bytes), %s/s | %d | %02d:%02d:%02d        \r",
							misc.FormatBytes(in.TotalBytes), in.TotalBytes, misc.FormatBytes(int64(in.SpeedBps)),
							misc.FormatBytes(out.TotalBytes), out.TotalBytes, misc.FormatBytes(int64(out.SpeedBps)),
							connCount,
							h, m, s,
						)
					} else if connCount == 1 {
						fmt.Fprintf(os.Stderr,
							"IN: %s (%d bytes), %s/s | OUT: %s (%d bytes), %s/s | %02d:%02d:%02d        \r",
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
					fmt.Fprintf(os.Stderr,
						"IN: %s (%d bytes), %s/s | OUT: %s (%d bytes), %s/s | %02d:%02d:%02d        \n",
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
	usage_less(argv0)
	fs.PrintDefaults()
	fmt.Fprintln(os.Stderr, "Built-in commands for -e option:")
	fmt.Fprintf(os.Stderr, "  %-6s %s\n", ":mux", "Stream-multiplexing proxy")
	fmt.Fprintf(os.Stderr, "  %-6s %s\n", ":s5s", "SOCKS5 server")
	fmt.Fprintf(os.Stderr, "  %-6s %s\n", ":nc", "netcat")
	fmt.Fprintf(os.Stderr, "  %-6s %s\n", ":sh", "pseudo-terminal shell")
	fmt.Fprintf(os.Stderr, "  %-6s %s\n", ":service", "dynamic service mode, clients can use -call to invoke the above configured and enabled services.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "To get help for a built-in command, run:")
	fmt.Fprintf(os.Stderr, "  %s -e \":sh -h\"\n", argv0)
}

func usage_less(argv0 string) {
	fmt.Fprintln(os.Stderr, "go-netcat "+VERSION)
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintf(os.Stderr, "    %s [-x socks5_ip:port] [-auth user:pass] [-send path] [-tls] [-l] [-u] target_host target_port\n", argv0)
	fmt.Fprintln(os.Stderr, "         [-p2p sessionKey]")
	fmt.Fprintln(os.Stderr, "         [-e \":builtin-command [args]\" or \"external-command [args]\"]")
	fmt.Fprintln(os.Stderr, "         [-h] for full help")
}

func conflictCheck(ncconfig *AppNetcatConfig) {
	if ncconfig.sendfile != "" && ncconfig.runCmd != "" {
		fmt.Fprintf(os.Stderr, "-send and -exec cannot be used together\n")
		os.Exit(1)
	}
	if ncconfig.enablePty && ncconfig.enableCRLF {
		fmt.Fprintf(os.Stderr, "-pty and -C cannot be used together\n")
		os.Exit(1)
	}
	if ncconfig.proxyAddr != "" && ncconfig.useSTUN {
		fmt.Fprintf(os.Stderr, "-stun and -x cannot be used together\n")
		os.Exit(1)
	}
	if ncconfig.proxyProt == "connect" && (ncconfig.udpProtocol || ncconfig.kcpEnabled || ncconfig.kcpSEnabled) {
		fmt.Fprintf(os.Stderr, "http proxy and udp cannot be used together\n")
		os.Exit(1)
	}
	if ncconfig.listenMode && (ncconfig.remoteAddr != "" || ncconfig.autoP2P != "") {
		fmt.Fprintf(os.Stderr, "-l and (-remote -p2p) cannot be used together\n")
		os.Exit(1)
	}
	if ncconfig.presharedKey != "" && (ncconfig.tlsRSACertEnabled || (ncconfig.sslCertFile != "" && ncconfig.sslKeyFile != "")) {
		fmt.Fprintf(os.Stderr, "-psk and (-tlsrsa -ssl-cert -ssl-key) cannot be used together\n")
		os.Exit(1)
	}
	if ncconfig.useIPv4 && ncconfig.useIPv6 {
		fmt.Fprintf(os.Stderr, "-4 and -6 cannot be used together\n")
		os.Exit(1)
	}
	if ncconfig.useUNIXdomain && (ncconfig.useIPv6 || ncconfig.useIPv4 || ncconfig.useSTUN || ncconfig.udpProtocol || ncconfig.kcpEnabled || ncconfig.kcpSEnabled || ncconfig.localbind != "" || ncconfig.proxyAddr != "") {
		fmt.Fprintf(os.Stderr, "-U and (-4 -6 -stun -u -kcp -kcps -bind -x) cannot be used together\n")
		os.Exit(1)
	}
	if ncconfig.runAppFileServ != "" && (ncconfig.appMuxListenMode || ncconfig.appMuxListenOn != "") {
		fmt.Fprintf(os.Stderr, "-httpserver and (-httplocal -download) cannot be used together\n")
		os.Exit(1)
	}
	if (ncconfig.sslCertFile != "" && ncconfig.sslKeyFile == "") || (ncconfig.sslCertFile == "" && ncconfig.sslKeyFile != "") {
		fmt.Fprintf(os.Stderr, "-ssl-cert and -ssl-key both must be set, only one given")
		os.Exit(1)
	}
	if (ncconfig.sslCertFile != "" && ncconfig.sslKeyFile != "") && !isTLSEnabled(ncconfig) {
		fmt.Fprintf(os.Stderr, "-ssl-cert and -ssl-key set without -tls ?")
		os.Exit(1)
	}
	if (ncconfig.sslCertFile != "" && ncconfig.sslKeyFile != "") && (ncconfig.autoP2P != "") {
		fmt.Fprintf(os.Stderr, "(-ssl-cert -ssl-key) and (-p2p -p2p-tcp) cannot be used together")
		os.Exit(1)
	}
}

func preinitBuiltinAppConfig(ncconfig *AppNetcatConfig, commandline string) error {
	args, err := misc.ParseCommandLine(commandline)
	if err != nil {
		return fmt.Errorf("error parsing command: %w", err)
	}

	if len(args) == 0 {
		return fmt.Errorf("empty command")
	}

	var usage func()
	builtinApp := args[0]
	switch builtinApp {
	case ":mux":
		ncconfig.app_mux_Config, err = AppMuxConfigByArgs(args[1:])
		if err != nil {
			usage = App_mux_usage
		} else {
			ncconfig.app_mux_Config.AccessCtrl = ncconfig.accessControl
		}
	case ":s5s":
		ncconfig.app_s5s_Config, err = AppS5SConfigByArgs(args[1:])
		if err == nil {
			ncconfig.app_s5s_Config.AccessCtrl = ncconfig.accessControl
		}
	case ":nc":
		ncconfig.app_nc_Config, err = AppNetcatConfigByArgs(":nc", args[1:])
		if err == nil {
			ncconfig.app_nc_Config.LogWriter = ncconfig.LogWriter
		}
	case ":sh":
		ncconfig.app_sh_Config, err = PtyShellConfigByArgs(args[1:])
	case ":service":
	default:
		if strings.HasPrefix(builtinApp, ":") {
			return fmt.Errorf("unknown built-in command: %s", builtinApp)
		}
		return nil // not a built-in app, let caller handle it
	}

	if err != nil {
		msg := fmt.Sprintf("error init %s config: %v", builtinApp, err)
		if usage != nil {
			usage()
		}
		return fmt.Errorf("%s", msg)
	}

	return nil
}

// 用于在数据传输时显示进度
func copyWithProgress(ncconfig *AppNetcatConfig, dst io.Writer, src io.Reader, blocksize int, bufferedReader bool, stats *misc.ProgressStats, maxBytes int64) {
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
		n, err1 = reader.Read(buf)
		if err1 != nil && err1 != io.EOF {
			//fmt.Fprintf(ncconfig.LogWriter, "Read error: %v\n", err1)
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
			//fmt.Fprintf(ncconfig.LogWriter, "Write error: %v\n", err)
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
			fmt.Fprintf(ncconfig.LogWriter, "ReadString error: %v\n", err1)
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
				//fmt.Fprintf(ncconfig.LogWriter, "Write error: %v\n", err)
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

	if ncconfig.listenMode || ncconfig.kcpSEnabled || ncconfig.tlsServerMode {
		config.IsClient = false
	} else {
		config.IsClient = true
	}

	if ncconfig.presharedKey != "" {
		config.KeyType = "PSK"
		config.Key = ncconfig.presharedKey
	}

	if ncconfig.udpProtocol {
		config.KcpWithUDP = isKCPEnabled(ncconfig)
		if isTLSEnabled(ncconfig) {
			config.SecureLayer = "dtls"
		} else if config.KcpWithUDP && config.Key != "" {
			config.KcpEncryption = true
		} else if config.Key != "" {
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
		} else if config.Key != "" {
			config.SecureLayer = "ss"
		}
	}

	return config
}

func handleNegotiatedConnection(console net.Conn, ncconfig *AppNetcatConfig, nconn *secure.NegotiatedConn, stats_in, stats_out *misc.ProgressStats) int {
	defer atomic.AddInt32(&ncconfig.goroutineConnectionCounter, -1)
	atomic.AddInt32(&ncconfig.goroutineConnectionCounter, 1)

	defer nconn.Close()

	var bufsize int = 32 * 1024
	blocksize := bufsize
	if nconn.IsUDP {
		//往udp连接拷贝数据，如果源是文件，应该限制每次拷贝到udp包的大小
		blocksize = nconn.Config.UdpOutputBlockSize
	}

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

	if !ncconfig.ConsoleMode {
		binaryInputMode = true
	}

	if ncconfig.sendfile != "" {
		var file io.ReadCloser
		if ncconfig.sendfile == "/dev/zero" || ncconfig.sendfile == "/dev/urandom" {
			file, err = misc.NewPseudoDevice(ncconfig.sendfile)
		} else {
			file, err = os.Open(ncconfig.sendfile)
		}
		if err != nil {
			fmt.Fprintf(ncconfig.LogWriter, "Error opening file: %v\n", err)
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
			fmt.Fprintf(ncconfig.LogWriter, "Error opening file for writing: %v\n", err)
			return 1
		}
		defer file.Close()
		output = file
	}

	serviceCommand := strings.TrimSpace(ncconfig.runCmd)
	if serviceCommand == ":service" {
		nconn.SetDeadline(time.Now().Add(15 * time.Second))
		line, err := ReadString(nconn, '\n')
		if err != nil {
			fmt.Fprintf(ncconfig.LogWriter, "Error ReadString: %v\n", err)
			return 1
		}
		nconn.SetDeadline(time.Time{})
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, ":") {
			fmt.Fprintf(ncconfig.LogWriter, "Invalid service command: %s\n", line)
			return 1
		}
		serviceCommand = line
	}

	if ncconfig.remoteCall != "" {
		_, err = nconn.Write([]byte(ncconfig.remoteCall + "\n"))
		if err != nil {
			fmt.Fprintf(ncconfig.LogWriter, "Error Sending: %v\n", err)
			return 1
		}
	}

	if serviceCommand != "" {
		binaryInputMode = true
		// 分割命令和参数（支持带空格的参数）
		args, err := misc.ParseCommandLine(serviceCommand)
		if err != nil {
			fmt.Fprintf(ncconfig.LogWriter, "Error parsing command: %v\n", err)
			return 1
		}

		if len(args) == 0 {
			fmt.Fprintf(ncconfig.LogWriter, "Empty command\n")
			return 1
		}

		builtinApp := args[0]
		if builtinApp == ":mux" {
			if ncconfig.app_mux_Config == nil {
				fmt.Fprintf(ncconfig.LogWriter, "Not initialized %s config\n", builtinApp)
				return 1
			}
			pipeConn := misc.NewPipeConn(nconn)
			input = pipeConn.In
			output = pipeConn.Out
			defer pipeConn.Close()
			go App_mux_main_withconfig(pipeConn, ncconfig.app_mux_Config)
		} else if builtinApp == ":s5s" {
			if ncconfig.app_s5s_Config == nil {
				fmt.Fprintf(ncconfig.LogWriter, "Not initialized %s config\n", builtinApp)
				return 1
			}
			pipeConn := misc.NewPipeConn(nconn)
			input = pipeConn.In
			output = pipeConn.Out
			defer pipeConn.Close()
			go App_s5s_main_withconfig(pipeConn, nconn.KeyingMaterial, ncconfig.app_s5s_Config)
		} else if builtinApp == ":nc" {
			if ncconfig.app_nc_Config == nil {
				fmt.Fprintf(ncconfig.LogWriter, "Not initialized %s config\n", builtinApp)
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
				fmt.Fprintf(ncconfig.LogWriter, "Not initialized %s config\n", builtinApp)
				return 1
			}
			pipeConn := misc.NewPipeConn(nconn)
			input = pipeConn.In
			output = pipeConn.Out
			defer pipeConn.Close()
			go App_shell_main_withconfig(pipeConn, ncconfig.app_sh_Config)
		} else if strings.HasPrefix(builtinApp, ":") {
			fmt.Fprintf(ncconfig.LogWriter, "Invalid service command: %s\n", builtinApp)
			return 1
		} else {
			// 创建命令
			cmd = exec.Command(args[0], args[1:]...)

			// 创建管道
			stdinPipe, err := cmd.StdinPipe()
			if err != nil {
				fmt.Fprintf(ncconfig.LogWriter, "Error creating stdin pipe: %v\n", err)
				return 1
			}

			stdoutPipe, err := cmd.StdoutPipe()
			if err != nil {
				fmt.Fprintf(ncconfig.LogWriter, "Error creating stdout pipe: %v\n", err)
				return 1
			}

			cmdErrorPipe, err = cmd.StderrPipe()
			if err != nil {
				fmt.Fprintf(ncconfig.LogWriter, "Error creating stderr pipe: %v\n", err)
				return 1
			}

			input = stdoutPipe
			output = stdinPipe

			// 启动命令
			if err := cmd.Start(); err != nil {
				fmt.Fprintf(ncconfig.LogWriter, "Command start error: %v\n", err)
				return 1
			}
			//fmt.Fprintf(ncconfig.LogWriter, "PID:%d child created.\n", cmd.Process.Pid)
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
					fmt.Fprintf(ncconfig.LogWriter, "MakeRaw error: %v\n", err)
					return
				}
				defer term.Restore(int(os.Stdin.Fd()), ncconfig.term_oldstat)
				copyWithProgress(ncconfig, nconn, input, blocksize, !nconn.IsUDP, stats_out, 0)
			} else {
				copyCharDeviceWithProgress(ncconfig, nconn, input, stats_out)
			}
		} else {
			copyWithProgress(ncconfig, nconn, input, blocksize, !nconn.IsUDP, stats_out, maxSendBytes)
		}

		time.Sleep(1 * time.Second)
		nconn.CloseWrite()
		//fmt.Fprintf(ncconfig.LogWriter, "PID:%d (%s) conn-write routine completed.\n", os.Getpid(), nconn.RemoteAddr().String())
	}()
	// 从连接读取并输出到输出
	go func() {
		defer wg.Done()
		defer close(inExited)

		copyWithProgress(ncconfig, output, nconn, bufsize, !nconn.IsUDP, stats_in, 0)
		time.Sleep(1 * time.Second)
		//fmt.Fprintf(ncconfig.LogWriter, "PID:%d (%s) conn-read routine completed.\n", os.Getpid(), nconn.RemoteAddr().String())
	}()

	if cmdErrorPipe != nil {
		go func() {
			io.Copy(ncconfig.LogWriter, cmdErrorPipe)
			//fmt.Fprintf(ncconfig.LogWriter, "PID:%d (%s) ErrorPipe routine completed.\n", os.Getpid(), nconn.RemoteAddr().String())
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
		//fmt.Fprintf(ncconfig.LogWriter, "PID:%d (%s) Input routine completed.\n", os.Getpid(), nconn.RemoteAddr().String())
	case <-done:
		//fmt.Fprintf(ncconfig.LogWriter, "PID:%d (%s) All routines completed.\n", os.Getpid(), nconn.RemoteAddr().String())
	case <-time.After(60 * time.Second):
		//fmt.Fprintf(ncconfig.LogWriter, "PID:%d (%s) Timeout after one routine exited.\n", os.Getpid(), nconn.RemoteAddr().String())
	}

	//fmt.Fprintf(ncconfig.LogWriter, "PID:%d (%s) closing nconn...\n", os.Getpid(), nconn.RemoteAddr().String())
	nconn.Close()
	if ncconfig.term_oldstat != nil {
		term.Restore(int(os.Stdin.Fd()), ncconfig.term_oldstat)
	}
	// 如果使用了命令，等待命令结束
	if cmd != nil {
		//fmt.Fprintf(ncconfig.LogWriter, "PID:%d killing cmd process...\n", os.Getpid())
		cmd.Process.Kill()
		cmd.Wait()
	}
	//fmt.Fprintf(ncconfig.LogWriter, "PID:%d (%s) connection done.\n", os.Getpid(), nconn.RemoteAddr().String())
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
	return handleNegotiatedConnection(console, ncconfig, nconn, stats_in, stats_out)
}

func isKCPEnabled(ncconfig *AppNetcatConfig) bool {
	return ncconfig.udpProtocol && (ncconfig.kcpEnabled || ncconfig.kcpSEnabled)
}

func ShowPublicIP(ncconfig *AppNetcatConfig, network, bind string) error {
	index, _, nata, err := easyp2p.GetPublicIP(network, bind, 7*time.Second)
	if err == nil {
		fmt.Fprintf(ncconfig.LogWriter, "Public Address: %s (via %s)\n", nata, easyp2p.STUNServers[index])
	}

	return err
}

func Mqtt_ensure_ready(ncconfig *AppNetcatConfig) (string, error) {
	var err error
	var salt string

	if ncconfig.useMQTTWait {
		ReportP2PStatus(ncconfig, "", "wait", ncconfig.network, "", "")
		salt, err = easyp2p.MqttWait(ncconfig.p2pSessionKey, 30*time.Minute, ncconfig.LogWriter)
		if err != nil {
			return "", fmt.Errorf("mqtt-wait: %v", err)
		}
	}

	if ncconfig.useMQTTHello {
		ReportP2PStatus(ncconfig, "", "wait", ncconfig.network, "", "")
		salt, err = easyp2p.MQTTHello(ncconfig.p2pSessionKey, 15*time.Second, ncconfig.LogWriter)
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
	connInfo, err := easyp2p.Easy_P2P(ncconfig.network, ncconfig.p2pSessionKey+topicSalt, relayConn, ncconfig.LogWriter)
	if err != nil {
		if relayConn != nil {
			relayConn.Close()
		}
		ReportP2PStatus(ncconfig, topicSalt, fmt.Sprintf("error:%v", err), ncconfig.network, "", "")
		return nil, err
	}

	conn := connInfo.Conns[0]
	config := *ncconfig.connConfig
	if ncconfig.plainTransport {
		config.IsClient = connInfo.IsClient
	} else {
		config.Key = ncconfig.p2pSessionKey
		config.KeyType = "PSK"
		config.IsClient = connInfo.IsClient

		if strings.HasPrefix(conn.LocalAddr().Network(), "udp") {
			config.KcpWithUDP = true
			config.SecureLayer = "dtls"
		} else {
			config.KcpWithUDP = false
			config.SecureLayer = "tls13"
		}
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
			fmt.Fprintf(ncconfig.LogWriter, "UDP ready for: %s -> %s -> %s\n", conn.LocalAddr().String(), proxyRemoteAddr, conn.RemoteAddr().String())
		} else {
			fmt.Fprintf(ncconfig.LogWriter, "UDP ready for: %s -> %s\n", conn.LocalAddr().String(), conn.RemoteAddr().String())
		}
	} else {
		fmt.Fprintf(ncconfig.LogWriter, "Connected to: %s\n", conn.RemoteAddr().String())
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
	return nconn, nil
}

func do_P2P_multipath(ncconfig *AppNetcatConfig, enableMP bool) (*secure.NegotiatedConn, error) {
	if !enableMP {
		return do_P2P(ncconfig)
	}
	//建立多个连接，例如包含UDP TCP TCP6几个会话，然后封装为哪个协议快用哪个，规避Qos
	return nil, fmt.Errorf("multipath not implemented yet")
}

func setDns(address2 string) {
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Second * 5,
			}
			if strings.Contains(address2, ":") {
				if _, _, err := net.SplitHostPort(address2); err != nil {
					address2 = net.JoinHostPort(address2, "53")
				}
			} else {
				address2 = net.JoinHostPort(address2, "53")
			}
			return d.DialContext(ctx, network, address2)
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
		fmt.Fprintf(ncconfig.LogWriter, "ReportP2PStatus: marshal report: %v\n", err)
		return
	}

	req, err := http.NewRequest("POST", ncconfig.p2pReportURL, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(ncconfig.LogWriter, "ReportP2PStatus: create request: %v\n", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 5 * time.Second, // 控制整个请求过程
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(ncconfig.LogWriter, "ReportP2PStatus: http post: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		//respBody, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(ncconfig.LogWriter, "ReportP2PStatus: server returned %d\n", resp.StatusCode)
		return
	}
}
