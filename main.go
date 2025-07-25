package main

import (
	"bufio"
	"bytes"
	"context"

	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/threatexpert/gonc/v2/acl"
	"github.com/threatexpert/gonc/v2/apps"
	"github.com/threatexpert/gonc/v2/easyp2p"
	"github.com/threatexpert/gonc/v2/misc"
	"github.com/threatexpert/gonc/v2/netx"
	"github.com/threatexpert/gonc/v2/secure"

	// "net/http"
	// _ "net/http/pprof"

	"golang.org/x/term"
)

var (
	VERSION                                              = "v2.1.1"
	connConfig                 *secure.NegotiationConfig = nil
	sessionReady                                         = false
	goroutineConnectionCounter int32                     = 0

	app_mux_Config    *apps.AppMuxConfig
	app_s5s_Config    *apps.AppS5SConfig
	app_pf_Config     *apps.AppPFConfig
	arg_proxyc_Config *apps.ProxyClientConfig
	accessControl     *acl.ACL
	// 定义命令行参数
	proxyProt         = flag.String("X", "", "proxy_protocol. Supported protocols are “5” (SOCKS v.5) and “connect” (HTTPS proxy).  If the protocol is not specified, SOCKS version 5 is used.")
	proxyAddr         = flag.String("x", "", "\"[options: -tls -psk] ip:port\" for proxy_address")
	auth              = flag.String("auth", "", "user:password for proxy")
	sendfile          = flag.String("send", "", "path to file to send (optional)")
	writefile         = flag.String("write", "", "write to file")
	tlsEnabled        = flag.Bool("tls", false, "Enable TLS connection")
	tlsServerMode     = flag.Bool("tlsserver", false, "force as TLS server while connecting")
	tls10_forced      = flag.Bool("tls10", false, "force negotiation to specify TLS version")
	tls11_forced      = flag.Bool("tls11", false, "force negotiation to specify TLS version")
	tls12_forced      = flag.Bool("tls12", false, "force negotiation to specify TLS version")
	tls13_forced      = flag.Bool("tls13", false, "force negotiation to specify TLS version")
	tlsECCertEnabled  = flag.Bool("tlsec", true, "enable TLS EC cert")
	tlsRSACertEnabled = flag.Bool("tlsrsa", false, "enable TLS RSA cert")
	tlsSNI            = flag.String("sni", "", "specify TLS SNI")
	sslCertFile       = flag.String("ssl-cert", "", "Specify SSL certificate file (PEM) for listening")
	sslKeyFile        = flag.String("ssl-key", "", "Specify SSL private key (PEM) for listening")
	presharedKey      = flag.String("psk", "", "Pre-shared key for deriving TLS certificate identity (anti-MITM); also key for TCP/KCP encryption")
	enableCRLF        = flag.Bool("C", false, "enable CRLF")
	listenMode        = flag.Bool("l", false, "listen mode")
	udpProtocol       = flag.Bool("u", false, "use UDP protocol")
	useUNIXdomain     = flag.Bool("U", false, "Specifies to use UNIX-domain sockets.")
	kcpEnabled        = flag.Bool("kcp", false, "use UDP+KCP protocol, -u can be omitted")
	kcpSEnabled       = flag.Bool("kcps", false, "kcp server mode")
	localbind         = flag.String("bind", "", "ip:port")
	remoteAddr        = flag.String("remote", "", "host:port")
	progressEnabled   = flag.Bool("progress", false, "show transfer progress")
	runCmd            = flag.String("exec", "", "runs a command for each connection")
	mergeStderr       = flag.Bool("stderr", false, "when -exec, Merge stderr into stdout ")
	keepOpen          = flag.Bool("keep-open", false, "keep listening after client disconnects")
	enablePty         = flag.Bool("pty", false, "<-exec> will run in a pseudo-terminal, and put the terminal into raw mode")
	term_oldstat      *term.State
	useSTUN           = flag.Bool("stun", false, "use STUN to discover public IP")
	stunSrv           = flag.String("stunsrv", "tcp://turn.cloudflare.com:80,udp://turn.cloudflare.com:53,udp://stun.l.google.com:19302,udp://stun.miwifi.com:3478,global.turn.twilio.com:3478,stun.nextcloud.com:443", "stun servers")
	MQTTServers       = flag.String("mqttsrv", "tcp://broker.hivemq.com:1883,tcp://broker.emqx.io:1883,tcp://test.mosquitto.org:1883", "MQTT servers")
	autoP2P           = flag.String("p2p", "", "P2P session key (or @file). Auto try UDP/TCP via NAT traversal")
	useMutilPath      = flag.Bool("mp", false, "enable multipath(NOT IMPL)")
	MQTTWait          = flag.String("mqtt-wait", "", "wait for MQTT hello message before initiating P2P connection")
	MQTTPush          = flag.String("mqtt-push", "", "send MQTT hello message before initiating P2P connection")
	useIPv4           = flag.Bool("4", false, "Forces to use IPv4 addresses only")
	useIPv6           = flag.Bool("6", false, "Forces to use IPv4 addresses only")
	useDNS            = flag.String("dns", "", "set DNS Server")
	runAppFileServ    = flag.String("httpserver", "", "http server root directory")
	runAppFileGet     = flag.String("download", "", "http client download directory")
	appMuxListenMode  = flag.Bool("httplocal", false, "local listen mode for remote httpserver")
	appMuxListenOn    = flag.String("httplocal-port", "", "local listen port for remote httpserver")
	appMuxSocksMode   = flag.Bool("socks5server", false, "for socks5 tunnel")
	disableCompress   = flag.Bool("no-compress", false, "disable compression for http download")
	fileACL           = flag.String("acl", "", "ACL file for inbound/outbound connections")
)

func init() {
	flag.StringVar(runCmd, "e", "", "alias for -exec")
	flag.BoolVar(progressEnabled, "P", false, "alias for -progress")
	flag.BoolVar(keepOpen, "k", false, "alias for -keep-open")
	flag.StringVar(localbind, "local", "", "ip:port (alias for -bind)")
	flag.StringVar(&easyp2p.TopicExchange, "mqtt-nat-topic", easyp2p.TopicExchange, "")
	flag.StringVar(&easyp2p.TopicExchangeWait, "mqtt-wait-topic", easyp2p.TopicExchangeWait, "")
	flag.IntVar(&easyp2p.PunchingShortTTL, "punch-short-ttl", easyp2p.PunchingShortTTL, "")
	flag.IntVar(&easyp2p.PunchingRandomPortCount, "punch-random-count", easyp2p.PunchingRandomPortCount, "")
	flag.BoolVar(appMuxListenMode, "socks5local", false, "")
	flag.StringVar(appMuxListenOn, "socks5local-port", "", "")
	flag.BoolVar(appMuxListenMode, "browser", false, "alias for -httplocal")
	flag.IntVar(&secure.KeepAlive, "keepalive", secure.KeepAlive, "none 0 will enable TCP keepalive feature")
	flag.IntVar(&secure.UdpOutputBlockSize, "udp-size", secure.UdpOutputBlockSize, "")
	flag.IntVar(&secure.KcpWindowSize, "kcp-window-size", secure.KcpWindowSize, "")
	flag.StringVar(&secure.UdpKeepAlivePayload, "udp-ping-data", secure.UdpKeepAlivePayload, "")
	flag.StringVar(&apps.VarmuxEngine, "mux-engine", apps.VarmuxEngine, "yamux | smux")
	apps.VarhttpDownloadNoCompress = disableCompress
}

func main() {
	// 1. 解析标志并初始化基本设置
	parseFlagsAndInit()

	// 2. 配置内置应用程序模式（例如http服务器，socks5）
	configureAppMode()

	// 3. 配置安全功能，如PSK和ACL
	var err error
	accessControl, err = configureSecurity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Security configuration failed: %v\n", err)
		os.Exit(1)
	}

	// 4. 从参数和标志确定网络类型、地址和P2P会话密钥
	network, host, port, P2PSessionKey, err := determineNetworkAndAddress(flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error determining network address: %v\n", err)
		usage()
		os.Exit(1)
	}

	// 5. 配置TLS、DNS、会话协商参数等
	if *tlsSNI == "" {
		if *listenMode {
			*tlsSNI = "localhost"
		} else {
			*tlsSNI = host
		}
	}
	configureDNS()

	connConfig = preinitNegotiationConfig()

	// 6. 根据模式运行：P2P模式或标准客户端/服务器模式
	if P2PSessionKey != "" {
		runP2PMode(network, P2PSessionKey)
	} else {
		if *listenMode {
			runListenMode(network, host, port)
		} else {
			runDialMode(network, host, port)
		}
	}
}

// parseFlagsAndInit 处理基本的标志解析和设置
func parseFlagsAndInit() {
	flag.Usage = func() {
		usage_full()
	}
	flag.Parse()
	easyp2p.MQTTBrokerServers = parseMultiItems(*MQTTServers, true)
	easyp2p.STUNServers = parseMultiItems(*stunSrv, true)
	conflictCheck()
}

// configureAppMode 为内置应用程序设置命令参数
func configureAppMode() {
	if *runAppFileServ != "" {
		escapedPath := strings.ReplaceAll(*runAppFileServ, "\\", "/")
		*runCmd = fmt.Sprintf(":mux httpserver \"%s\"", escapedPath)
		if *MQTTWait == "" {
			*MQTTWait = "hello"
		}
		*progressEnabled = true
		*keepOpen = true
	} else if *runAppFileGet != "" {
		escapedPath := strings.ReplaceAll(*runAppFileGet, "\\", "/")
		*runCmd = fmt.Sprintf(":mux httpclient \"%s\"", escapedPath)
		if *appMuxListenOn != "" {
			apps.VarmuxLastListenAddress = *appMuxListenOn
		}
		if *MQTTPush == "" {
			*MQTTPush = "hello"
		}
		*keepOpen = true
	} else if *appMuxSocksMode {
		*runCmd = ":mux socks5"
		if *MQTTWait == "" {
			*MQTTWait = "hello"
		}
		*progressEnabled = true
		*keepOpen = true
	} else if *appMuxListenMode || *appMuxListenOn != "" {
		if *appMuxListenOn == "" {
			*appMuxListenOn = "0"
		}
		*runCmd = fmt.Sprintf(":mux -l %s", *appMuxListenOn)
		if *MQTTPush == "" {
			*MQTTPush = "hello"
		}
		*keepOpen = true
	}

	if *runCmd != "" {
		preinitBuiltinAppConfig()
	}

	if *proxyAddr != "" {
		args, err := parseCommandLine(*proxyAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing -x proxy_address: %v\n", err)
			os.Exit(1)
		}

		if len(args) == 0 {
			fmt.Fprintf(os.Stderr, "Empty proxy_address\n")
			os.Exit(1)
		}

		arg_proxyc_Config, err = apps.ProxyClientConfigByArgs(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error init proxy config: %v\n", err)
			os.Exit(1)
		}

		switch *proxyProt {
		case "", "5":
			arg_proxyc_Config.Prot = "socks5"
		case "connect":
			arg_proxyc_Config.Prot = "http"
		default:
			fmt.Fprintf(os.Stderr, "Invalid proxy protocol: %s\n", *proxyProt)
			os.Exit(1)
		}

		if *auth != "" {
			authParts := strings.SplitN(*auth, ":", 2)
			if len(authParts) != 2 {
				fmt.Fprintf(os.Stderr, "invalid auth format: expected user:pass\n")
				os.Exit(1)
			}
			arg_proxyc_Config.User, arg_proxyc_Config.Pass = authParts[0], authParts[1]
		}

	}
}

func configureSecurity() (*acl.ACL, error) {
	var err error
	if *presharedKey == "." {
		*presharedKey, err = secure.GenerateSecureRandomString(22)
		if err != nil {
			panic(err)
		}
		fmt.Fprintf(os.Stdout, "%s\n", *presharedKey)
		os.Exit(1)
	}
	if *presharedKey != "" {
		if strings.HasPrefix(*presharedKey, "@") {
			*presharedKey, err = secure.ReadPSKFile(*presharedKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading PSK file: %v\n", err)
				os.Exit(1)
			}
		}
	}

	var aclData *acl.ACL
	if *fileACL != "" {
		aclData, err = acl.LoadACL(*fileACL)
		if err != nil {
			return nil, fmt.Errorf("failed to load ACL file: %w", err)
		}
	}
	return aclData, nil
}

// determineNetworkAndAddress 解析网络协议、主机、端口和P2P密钥
func determineNetworkAndAddress(args []string) (network, host, port, P2PSessionKey string, err error) {
	if *kcpEnabled || *kcpSEnabled {
		*udpProtocol = true
	}
	if *udpProtocol {
		network = "udp"
	} else if *useUNIXdomain {
		network = "unix"
	} else {
		network = "tcp"
	}
	if network != "unix" {
		if *useIPv4 {
			network += "4"
		} else if *useIPv6 {
			network += "6"
		}
	}

	switch len(args) {
	case 2:
		host, port = args[0], args[1]
	case 1:
		if *listenMode {
			port = args[0]
		} else if *useUNIXdomain {
			port = args[0]
		} else {
			return "", "", "", "", fmt.Errorf("invalid arguments")
		}
	case 0:
		if *listenMode && *localbind != "" {
			host, port, err = net.SplitHostPort(*localbind)
			if err != nil {
				return "", "", "", "", fmt.Errorf("invalid local address %q: %v", *localbind, err)
			}
		} else if !*listenMode && *remoteAddr != "" {
			host, port, err = net.SplitHostPort(*remoteAddr)
			if err != nil {
				return "", "", "", "", fmt.Errorf("invalid remote address %q: %v", *remoteAddr, err)
			}
		} else if *autoP2P != "" {
			if *proxyAddr != "" || arg_proxyc_Config != nil {
				fmt.Fprintf(os.Stderr, "INFO: proxy is ignored with p2p\n")
				*proxyAddr = ""
				arg_proxyc_Config = nil
			}
			*listenMode = false
			P2PSessionKey = *autoP2P
			network = "any"
			if *udpProtocol {
				*kcpEnabled = true
				network = "udp"
			}
			*tlsEnabled = true
			if *useIPv4 {
				network += "4"
			} else if *useIPv6 {
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
			*presharedKey = P2PSessionKey
		} else {
			return "", "", "", "", fmt.Errorf("not enough arguments")
		}
	default:
		return "", "", "", "", fmt.Errorf("too many arguments")
	}

	return network, host, port, P2PSessionKey, nil
}

// configureDNS 如果指定，则设置DNS解析器，并为Android提供默认值
func configureDNS() {
	if *useDNS != "" {
		setDns(*useDNS)
	}
	if isAndroid() {
		setDns("8.8.8.8:53")
	}
}

// runP2PMode 处理建立和维护P2P连接的逻辑
func runP2PMode(network, P2PSessionKey string) {
	stats_in := misc.NewProgressStats()
	stats_out := misc.NewProgressStats()
	if *progressEnabled {
		wg := &sync.WaitGroup{}
		done := make(chan bool)
		defer func() {
			done <- true
			wg.Wait()
		}()
		showProgress(stats_in, stats_out, done, wg)
	}

	if *keepOpen {
		for {
			nconn, err := do_P2P_multipath(network, P2PSessionKey, *useMutilPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "P2P failed: %v\n", err)
				time.Sleep(10 * time.Second)
				continue
			}
			if *MQTTWait != "" {
				go handleNegotiatedConnection(nconn, stats_in, stats_out)
			} else {
				handleNegotiatedConnection(nconn, stats_in, stats_out)
			}
			time.Sleep(2 * time.Second)
		}
	} else {
		nconn, err := do_P2P_multipath(network, P2PSessionKey, *useMutilPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "P2P failed: %v\n", err)
			os.Exit(1)
		}
		handleNegotiatedConnection(nconn, stats_in, stats_out)
	}
}

// runListenMode 在监听模式下启动服务器
func runListenMode(network, host, port string) {
	if *proxyAddr == "" {
		if port == "0" {
			portInt, err := easyp2p.GetFreePort()
			if err != nil {
				panic(err)
			}
			port = strconv.Itoa(portInt)
		}
	}
	if *udpProtocol {
		startUDPListener(network, host, port)
	} else {
		startTCPListener(network, host, port)
	}
}

// startUDPListener 启动UDP监听器并处理传入会话
func startUDPListener(network, host, port string) {
	listenAddr := net.JoinHostPort(host, port)
	addr, err := net.ResolveUDPAddr(network, listenAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving UDP address: %v\n", err)
		os.Exit(1)
	}

	if *useSTUN {
		if err = ShowPublicIP(network, addr.String()); err != nil {
			fmt.Fprintf(os.Stderr, "Error getting public IP: %v\n", err)
			os.Exit(1)
		}
		time.Sleep(1500 * time.Millisecond)
	}

	uconn, err := net.ListenUDP(network, addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listening on UDP address: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Listening %s on %s\n", uconn.LocalAddr().Network(), uconn.LocalAddr().String())

	logDiscard := log.New(io.Discard, "", log.LstdFlags)
	usessListener, err := netx.NewUDPCustomListener(uconn, logDiscard)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error NewUDPCustomListener: %v\n", err)
		os.Exit(1)
	}

	if *keepOpen {
		stats_in := misc.NewProgressStats()
		stats_out := misc.NewProgressStats()
		if *progressEnabled {
			wg := &sync.WaitGroup{}
			done := make(chan bool)
			showProgress(stats_in, stats_out, done, wg)
		}
		for {
			newSess, err := usessListener.Accept()
			if err != nil {
				if err == net.ErrClosed {
					fmt.Fprintf(os.Stderr, "UDPCustomListener accept failed: %v\n", err)
					os.Exit(1)
				}
				continue
			}
			if !acl.ACL_inbound_allow(accessControl, newSess.RemoteAddr()) {
				fmt.Fprintf(os.Stderr, "ACL refused: %s\n", newSess.RemoteAddr())
				newSess.Close()
				continue
			}
			fmt.Fprintf(os.Stderr, "UDP session established from %s\n", newSess.RemoteAddr().String())
			go handleConnection(connConfig, newSess, stats_in, stats_out)
		}
	} else {
		newSess, err := usessListener.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "UDPCustomListener accept failed: %v\n", err)
			os.Exit(1)
		}
		if !acl.ACL_inbound_allow(accessControl, newSess.RemoteAddr()) {
			fmt.Fprintf(os.Stderr, "ACL refused: %s\n", newSess.RemoteAddr())
			newSess.Close()
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "UDP session established from %s\n", newSess.RemoteAddr().String())
		handleSingleConnection(newSess)
	}
}

// startTCPListener 启动TCP/Unix监听器并处理传入连接
func startTCPListener(network, host, port string) {
	listenAddr := net.JoinHostPort(host, port)
	if *useUNIXdomain {
		listenAddr = port
		if err := cleanupUnixSocket(port); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
	}

	var listener net.Listener
	var err error
	socks5BindMode := false
	proxyClient, err := apps.NewProxyClient(arg_proxyc_Config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error create proxy client: %v\n", err)
		os.Exit(1)
	}
	if proxyClient.SupportBIND() {
		fmt.Fprintf(os.Stderr, "Attempting SOCKS5 BIND on proxy at %s...\n", listenAddr)
		listener, err = proxyClient.Dialer.Listen(network, listenAddr)
		//socks5listener的Close函数是空，无需Close()
		socks5BindMode = true
	} else {
		lc := net.ListenConfig{}
		if *useSTUN {
			if err = ShowPublicIP(network, listenAddr); err != nil {
				fmt.Fprintf(os.Stderr, "Error getting public IP: %v\n", err)
				os.Exit(1)
			}
			lc.Control = netx.ControlTCP
		}
		listener, err = lc.Listen(context.Background(), network, listenAddr)
		if err == nil {
			defer listener.Close()
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listening on %s: %v\n", listenAddr, err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Listening %s on %s\n", listener.Addr().Network(), listener.Addr().String())
	if port == "0" {
		//记下成功绑定的端口，keepOpen的话，如果需要重新监听就继续用这个端口
		listenAddr = listener.Addr().String()
	}

	if *keepOpen {
		stats_in := misc.NewProgressStats()
		stats_out := misc.NewProgressStats()
		if *progressEnabled {
			wg := &sync.WaitGroup{}
			done := make(chan bool)
			showProgress(stats_in, stats_out, done, wg)
		}
		for {
			conn, err := listener.Accept()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error accepting connection: %v\n", err)
				if socks5BindMode {
					goto RE_BIND
				} else {
					time.Sleep(1 * time.Second)
					continue
				}
			}
			if conn.LocalAddr().Network() == "unix" {
				fmt.Fprintf(os.Stderr, "Connection on %s received!\n", conn.LocalAddr().String())
			} else {
				if !acl.ACL_inbound_allow(accessControl, conn.RemoteAddr()) {
					fmt.Fprintf(os.Stderr, "ACL refused: %s\n", conn.RemoteAddr())
					conn.Close()
					continue
				}
				fmt.Fprintf(os.Stderr, "Connected from: %s        \n", conn.RemoteAddr().String())
			}
			go handleConnection(connConfig, conn, stats_in, stats_out)
		RE_BIND:
			if socks5BindMode {
				listener.Close()
				for tt := 0; tt < 60; tt++ {
					fmt.Fprintf(os.Stderr, "Re-attempting SOCKS5 BIND on proxy at %s...", listenAddr)
					listener, err = proxyClient.Dialer.Listen(network, listenAddr)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error listening on %s: %v\n", listenAddr, err)
						time.Sleep(5 * time.Second)
					} else {
						fmt.Fprintf(os.Stderr, "completed\n")
						break
					}
				}
			}
		}
	} else {
		conn, err := listener.Accept()
		listener.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error accepting connection: %v\n", err)
			os.Exit((1))
		}

		if conn.LocalAddr().Network() == "unix" {
			fmt.Fprintf(os.Stderr, "Connection on %s received!\n", conn.LocalAddr().String())
		} else {
			if !acl.ACL_inbound_allow(accessControl, conn.RemoteAddr()) {
				fmt.Fprintf(os.Stderr, "ACL refused: %s\n", conn.RemoteAddr())
				conn.Close()
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Connected from: %s\n", conn.RemoteAddr().String())
		}
		handleSingleConnection(conn)
	}
}

// runDialMode 在主动连接模式下启动客户端
func runDialMode(network, host, port string) {
	var conn net.Conn
	var err error

	// go func() {
	// 	log.Println(http.ListenAndServe("localhost:6060", nil))
	// }()

	proxyClient, err := apps.NewProxyClient(arg_proxyc_Config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error create proxy client: %v\n", err)
		os.Exit(1)
	}

	if *useUNIXdomain {
		conn, err = net.Dial("unix", port)
	} else {
		var localAddr net.Addr
		if *localbind != "" {
			switch {
			case strings.HasPrefix(network, "tcp"):
				localAddr, err = net.ResolveTCPAddr(network, *localbind)
			case strings.HasPrefix(network, "udp"):
				localAddr, err = net.ResolveUDPAddr(network, *localbind)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error resolving address: %v\n", err)
				os.Exit(1)
			}
		}

		if *useSTUN {
			if *localbind == "" {
				fmt.Fprintf(os.Stderr, "-stun need be with -bind while connecting\n")
				os.Exit(1)
			}
			if err = ShowPublicIP(network, localAddr.String()); err != nil {
				fmt.Fprintf(os.Stderr, "Error getting public IP: %v\n", err)
				os.Exit(1)
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
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// 连接成功后打印信息
	remoteFullAddr := net.JoinHostPort(host, port)
	if strings.HasPrefix(conn.LocalAddr().Network(), "udp") {
		if *proxyAddr == "" {
			fmt.Fprintf(os.Stderr, "UDP ready for: %s\n", remoteFullAddr)
		} else {
			fmt.Fprintf(os.Stderr, "UDP ready for: %s -> %s\n", net.JoinHostPort(arg_proxyc_Config.ServerHost, arg_proxyc_Config.ServerPort), remoteFullAddr)
		}
	} else {
		if *proxyAddr == "" {
			fmt.Fprintf(os.Stderr, "Connected to: %s\n", conn.RemoteAddr().String())
		} else {
			fmt.Fprintf(os.Stderr, "Connected to: %s -> %s\n", conn.RemoteAddr().String(), remoteFullAddr)
		}
	}

	handleSingleConnection(conn)
}

func init_TLS(genCertForced bool) []tls.Certificate {
	var certs []tls.Certificate
	if isTLSEnabled() {
		if *listenMode || *kcpSEnabled {
			*tlsServerMode = true
		}
		if genCertForced || *tlsServerMode {
			if *sslCertFile != "" && *sslKeyFile != "" {
				fmt.Fprintf(os.Stderr, "Loading cert...")
				cert, err := secure.LoadCertificate(*sslCertFile, *sslKeyFile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error load certificate: %v\n", err)
					os.Exit(1)
				}
				certs = append(certs, *cert)
				*tlsECCertEnabled = false
				*tlsRSACertEnabled = false
			} else {
				if !*tlsECCertEnabled && !*tlsRSACertEnabled {
					fmt.Fprintf(os.Stderr, "EC and RSA both are disabled\n")
					os.Exit(1)
				}
				if *tlsECCertEnabled {
					if *presharedKey != "" {
						fmt.Fprintf(os.Stderr, "Generating ECDSA(PSK-derived) cert for secure communication...")
					} else {
						fmt.Fprintf(os.Stderr, "Generating ECDSA(randomly) cert for secure communication...")
					}
					cert, err := secure.GenerateECDSACertificate(*tlsSNI, *presharedKey)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error generating EC certificate: %v\n", err)
						os.Exit(1)
					}
					certs = append(certs, *cert)
				}
				if *tlsRSACertEnabled {
					fmt.Fprintf(os.Stderr, "Generating RSA cert...")
					cert, err := secure.GenerateRSACertificate(*tlsSNI)
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

func isTLSEnabled() bool {
	return *tlsServerMode || *tlsEnabled || *tls10_forced || *tls11_forced || *tls12_forced || *tls13_forced
}

func showProgress(statsIn, statsOut *misc.ProgressStats, done chan bool, wg *sync.WaitGroup) {
	wg.Add(1)
	ticker := time.NewTicker(1 * time.Second)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ticker.C:
				if sessionReady {
					now := time.Now()
					in := statsIn.Stats(now, false)
					out := statsOut.Stats(now, false)
					elapsed := int(now.Sub(statsIn.StartTime()).Seconds())
					h := elapsed / 3600
					m := (elapsed % 3600) / 60
					s := elapsed % 60
					connCount := atomic.LoadInt32(&goroutineConnectionCounter)
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
				if sessionReady {
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

func usage_full() {
	usage()
	flag.PrintDefaults()
	fmt.Fprintln(os.Stderr, "Built-in commands for -e option:")
	fmt.Fprintf(os.Stderr, "  %-6s %s\n", ":mux", "Stream-multiplexing proxy")
	fmt.Fprintf(os.Stderr, "  %-6s %s\n", ":s5s", "SOCKS5 server")
	fmt.Fprintf(os.Stderr, "  %-6s %s\n", ":pf", "Port forwarding")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "To get help for a built-in command, run:")
	fmt.Fprintln(os.Stderr, "  gonc -e \":pf -h\"")
}

func usage() {
	fmt.Fprintln(os.Stderr, "go-netcat "+VERSION)
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "    gonc [-x socks5_ip:port] [-auth user:pass] [-send path] [-tls] [-l] [-u] target_host target_port")
	fmt.Fprintln(os.Stderr, "         [-p2p sessionKey]")
	fmt.Fprintln(os.Stderr, "         [-e \":builtin-command [args]\" or \"external-command [args]\"]")
	fmt.Fprintln(os.Stderr, "         [-h] for full help")
}

func conflictCheck() {
	if *sendfile != "" && *runCmd != "" {
		fmt.Fprintf(os.Stderr, "-send and -exec cannot be used together\n")
		os.Exit(1)
	}
	if *enablePty && *enableCRLF {
		fmt.Fprintf(os.Stderr, "-pty and -C cannot be used together\n")
		os.Exit(1)
	}
	if *proxyAddr != "" && *localbind != "" {
		fmt.Fprintf(os.Stderr, "-bind and -x cannot be used together\n")
		os.Exit(1)
	}
	if *proxyAddr != "" && *useSTUN {
		fmt.Fprintf(os.Stderr, "-stun and -x cannot be used together\n")
		os.Exit(1)
	}
	if *proxyProt == "connect" && (*udpProtocol || *kcpEnabled || *kcpSEnabled) {
		fmt.Fprintf(os.Stderr, "http proxy and udp cannot be used together\n")
		os.Exit(1)
	}
	if *listenMode && (*remoteAddr != "" || *autoP2P != "") {
		fmt.Fprintf(os.Stderr, "-l and (-remote -p2p) cannot be used together\n")
		os.Exit(1)
	}
	if *presharedKey != "" && (*tlsRSACertEnabled || (*sslCertFile != "" && *sslKeyFile != "")) {
		fmt.Fprintf(os.Stderr, "-psk and (-tlsrsa -ssl-cert -ssl-key) cannot be used together\n")
		os.Exit(1)
	}
	if *useIPv4 && *useIPv6 {
		fmt.Fprintf(os.Stderr, "-4 and -6 cannot be used together\n")
		os.Exit(1)
	}
	if *useUNIXdomain && (*useIPv6 || *useIPv4 || *useSTUN || *udpProtocol || *kcpEnabled || *kcpSEnabled || *localbind != "" || *proxyAddr != "") {
		fmt.Fprintf(os.Stderr, "-U and (-4 -6 -stun -u -kcp -kcps -bind -x) cannot be used together\n")
		os.Exit(1)
	}
	if *runAppFileServ != "" && (*appMuxListenMode || *appMuxListenOn != "") {
		fmt.Fprintf(os.Stderr, "-httpserver and (-httplocal -download) cannot be used together\n")
		os.Exit(1)
	}
	if (*sslCertFile != "" && *sslKeyFile == "") || (*sslCertFile == "" && *sslKeyFile != "") {
		fmt.Fprintf(os.Stderr, "-ssl-cert and -ssl-key both must be set, only one given")
		os.Exit(1)
	}
	if (*sslCertFile != "" && *sslKeyFile != "") && !isTLSEnabled() {
		fmt.Fprintf(os.Stderr, "-ssl-cert and -ssl-key set without -tls ?")
		os.Exit(1)
	}
	if (*sslCertFile != "" && *sslKeyFile != "") && (*autoP2P != "") {
		fmt.Fprintf(os.Stderr, "(-ssl-cert -ssl-key) and (-p2p -p2p-tcp) cannot be used together")
		os.Exit(1)
	}
}

func preinitBuiltinAppConfig() {
	args, err := parseCommandLine(*runCmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing command: %v\n", err)
		os.Exit(1)
	}

	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Empty command\n")
		os.Exit(1)
	}

	builtinApp := args[0]
	if builtinApp == ":mux" {
		app_mux_Config, err = apps.AppMuxConfigByArgs(args[1:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error init %s config: %v\n", builtinApp, err)
			apps.App_mux_usage()
			os.Exit(1)
		}
		app_mux_Config.AccessCtrl = accessControl
	} else if builtinApp == ":s5s" {
		app_s5s_Config, err = apps.AppS5SConfigByArgs(args[1:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error init %s config: %v\n", builtinApp, err)
			os.Exit(1)
		}
		app_s5s_Config.AccessCtrl = accessControl
	} else if builtinApp == ":pf" {
		app_pf_Config, err = apps.AppPFConfigByArgs(args[1:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error init %s config: %v\n", builtinApp, err)
			os.Exit(1)
		}
	}
}

// 用于在数据传输时显示进度
func copyWithProgress(dst io.Writer, src io.Reader, blocksize int, bufferedReader bool, stats *misc.ProgressStats) {
	bufsize := blocksize
	if bufsize < 32*1024 {
		bufsize = 32 * 1024 //reader的缓存可以大一些，提高性能
	}
	reader := src
	if bufferedReader {
		reader = bufio.NewReaderSize(src, bufsize)
	} //udp的不能要用缓冲区积累包，否则读取的时候粘包就麻烦了
	buf := make([]byte, blocksize) //buf的大小按用户指定的bufsize来，如果dst是UDP可以限制每个写入发出去的UDP的大小
	var n int
	var err, err1 error
	for {
		n, err1 = reader.Read(buf)
		if err1 != nil && err1 != io.EOF {
			fmt.Fprintf(os.Stderr, "Read error: %v\n", err1)
			break
		}
		if n == 0 {
			break
		}

		_, err = dst.Write(buf[:n])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Write error: %v\n", err)
			break
		}

		if stats != nil {
			stats.Update(int64(n))
		}
		if err1 == io.EOF {
			break
		}
	}
}

func copyCharDeviceWithProgress(dst io.Writer, src io.Reader, stats *misc.ProgressStats) {
	var n int
	var err, err1 error
	var line string

	reader := bufio.NewReader(src)
	writer := bufio.NewWriter(dst)
	for {
		line, err1 = reader.ReadString('\n')
		if err1 != nil && err1 != io.EOF {
			fmt.Fprintf(os.Stderr, "ReadString error: %v\n", err1)
			break
		}

		if len(line) > 0 {
			if line[len(line)-1] == '\n' {
				// 注意：line读到的可能是 "\r\n" 或 "\n"，都要统一处理
				line = strings.TrimRight(line, "\r\n") // 去掉任何结尾的 \r 或 \n
				if *enableCRLF {
					line += "\r\n" // 统一加上 CRLF
				} else {
					line += "\n"
				}
			}
			n, err = writer.WriteString(line)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Write error: %v\n", err)
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

func parseCommandLine(command string) ([]string, error) {
	var args []string
	var buffer bytes.Buffer
	var inQuotes bool
	var escape bool

	for _, r := range command {
		switch {
		case escape:
			buffer.WriteRune(r)
			escape = false
		case r == '\\':
			escape = true
		case r == '"':
			inQuotes = !inQuotes
		case !inQuotes && unicode.IsSpace(r):
			if buffer.Len() > 0 {
				args = append(args, buffer.String())
				buffer.Reset()
			}
		default:
			buffer.WriteRune(r)
		}
	}

	if buffer.Len() > 0 {
		args = append(args, buffer.String())
	}

	if inQuotes {
		return nil, fmt.Errorf("unclosed quote in command line")
	}

	if args[0] == "." {
		exePath, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("failed to get executable path")
		}
		args[0] = exePath
	}

	return args, nil
}

func preinitNegotiationConfig() *secure.NegotiationConfig {
	config := secure.NewNegotiationConfig()

	genCertForced := *presharedKey != ""
	config.Certs = init_TLS(genCertForced)
	config.TlsSNI = *tlsSNI

	if *listenMode || *kcpSEnabled || *tlsServerMode {
		config.IsClient = false
	} else {
		config.IsClient = true
	}

	if *presharedKey != "" {
		config.KeyType = "PSK"
		config.Key = *presharedKey
	}

	if *udpProtocol {
		config.KcpWithUDP = isKCPEnabled()
		if isTLSEnabled() {
			config.SecureLayer = "dtls"
		} else if config.KcpWithUDP && config.Key != "" {
			config.KcpEncryption = true
		} else if config.Key != "" {
			config.SecureLayer = "dss"
		}
	} else {
		if isTLSEnabled() {
			if *tls10_forced {
				config.SecureLayer = "tls10"
			} else if *tls11_forced {
				config.SecureLayer = "tls11"
			} else if *tls12_forced {
				config.SecureLayer = "tls12"
			} else if *tls13_forced {
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

func handleNegotiatedConnection(nconn *secure.NegotiatedConn, stats_in, stats_out *misc.ProgressStats) {
	defer atomic.AddInt32(&goroutineConnectionCounter, -1)
	atomic.AddInt32(&goroutineConnectionCounter, 1)

	defer nconn.Close()

	var bufsize int = 32 * 1024
	blocksize := bufsize
	if nconn.IsUDP {
		//往udp连接拷贝数据，如果源是文件，应该限制每次拷贝到udp包的大小
		blocksize = nconn.Config.UdpOutputBlockSize
	}

	if !sessionReady {
		stats_in.ResetStart()
		stats_out.ResetStart()
		sessionReady = true
	}

	// 默认使用标准输入输出
	var input io.ReadCloser = os.Stdin
	var output io.WriteCloser = os.Stdout
	var binaryInputMode = false
	var cmd *exec.Cmd
	var err error

	if *sendfile != "" {
		var file io.ReadCloser
		if *sendfile == "/dev/zero" || *sendfile == "/dev/urandom" {
			file, err = misc.NewPseudoDevice(*sendfile)
		} else {
			file, err = os.Open(*sendfile)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		input = file
		binaryInputMode = true
	}

	if *writefile != "" {
		var file *os.File
		var writePath string
		if *writefile == "/dev/null" {
			// 判断操作系统
			if runtime.GOOS == "windows" {
				writePath = "NUL"
			} else {
				writePath = "/dev/null"
			}
		} else {
			writePath = *writefile
		}
		file, err = os.Create(writePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening file for writing: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		output = file
	}

	if *runCmd != "" {
		binaryInputMode = true
		// 分割命令和参数（支持带空格的参数）
		args, err := parseCommandLine(*runCmd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing command: %v\n", err)
			return
		}

		if len(args) == 0 {
			fmt.Fprintf(os.Stderr, "Empty command\n")
			return
		}

		builtinApp := args[0]
		if builtinApp == ":mux" {
			pipeConn := misc.NewPipeConn(nconn)
			input = pipeConn.In
			output = pipeConn.Out
			defer pipeConn.Close()
			go apps.App_mux_main_withconfig(pipeConn, app_mux_Config)
		} else if builtinApp == ":s5s" {
			pipeConn := misc.NewPipeConn(nconn)
			input = pipeConn.In
			output = pipeConn.Out
			defer pipeConn.Close()
			go apps.App_s5s_main_withconfig(pipeConn, app_s5s_Config)
		} else if builtinApp == ":pf" {
			pipeConn := misc.NewPipeConn(nconn)
			input = pipeConn.In
			output = pipeConn.Out
			defer pipeConn.Close()
			if strings.Contains(app_pf_Config.Network, "udp") {
				//udp的端口转发，避免截断数据包，也不应该会粘包（pipeConn内部是net.Pipe()，它无内置缓冲区）
				blocksize = bufsize
			}
			go apps.App_pf_main_withconfig(pipeConn, app_pf_Config)
		} else {

			// 创建命令
			cmd = exec.Command(args[0], args[1:]...)

			if *enablePty {
				ptmx, err := misc.PtyStart(cmd)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to start pty: %v", err)
					return
				}
				input = ptmx
				output = ptmx
			} else {
				// 创建管道
				stdinPipe, err := cmd.StdinPipe()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error creating stdin pipe: %v\n", err)
					return
				}

				stdoutPipe, err := cmd.StdoutPipe()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error creating stdout pipe: %v\n", err)
					return
				}

				if *mergeStderr {
					cmd.Stderr = cmd.Stdout
				} else {
					cmd.Stderr = os.Stderr
				}

				input = stdoutPipe
				output = stdinPipe

				// 启动命令
				if err := cmd.Start(); err != nil {
					fmt.Fprintf(os.Stderr, "Command start error: %v\n", err)
					return
				}
			}
		}
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
			if *enablePty {
				term_oldstat, err = term.MakeRaw(int(os.Stdin.Fd()))
				if err != nil {
					fmt.Fprintf(os.Stderr, "MakeRaw error: %v\n", err)
					return
				}
				defer term.Restore(int(os.Stdin.Fd()), term_oldstat)
				copyWithProgress(nconn, input, blocksize, !nconn.IsUDP, stats_out)
			} else {
				copyCharDeviceWithProgress(nconn, input, stats_out)
			}
		} else {
			copyWithProgress(nconn, input, blocksize, !nconn.IsUDP, stats_out)
		}

		time.Sleep(1 * time.Second)
		nconn.CloseWrite()
	}()
	// 从连接读取并输出到输出
	go func() {
		defer wg.Done()
		defer close(inExited)

		copyWithProgress(output, nconn, bufsize, !nconn.IsUDP, stats_in)
		time.Sleep(1 * time.Second)
	}()

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
		//fmt.Fprintf(os.Stderr, "Input routine completed.\n")
	case <-done:
		//fmt.Fprintf(os.Stderr, "All routines completed.\n")
	case <-time.After(60 * time.Second):
		//fmt.Fprintf(os.Stderr, "Timeout after one routine exited.\n")
	}

	nconn.Close()
	if *enablePty && output != nil {
		output.Close()
	}
	if term_oldstat != nil {
		term.Restore(int(os.Stdin.Fd()), term_oldstat)
	}
	// 如果使用了命令，等待命令结束
	if cmd != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}
}

func handleSingleConnection(conn net.Conn) {
	stats_in := misc.NewProgressStats()
	stats_out := misc.NewProgressStats()

	if *progressEnabled {
		wg := &sync.WaitGroup{}
		done := make(chan bool)
		showProgress(stats_in, stats_out, done, wg)
		defer func() {
			done <- true
			wg.Wait()
		}()
	}

	handleConnection(connConfig, conn, stats_in, stats_out)
}

func handleConnection(cfg *secure.NegotiationConfig, conn net.Conn, stats_in, stats_out *misc.ProgressStats) {
	nconn, err := secure.DoNegotiation(cfg, conn, os.Stderr)
	if err != nil {
		conn.Close()
		return
	}
	handleNegotiatedConnection(nconn, stats_in, stats_out)
}

func isKCPEnabled() bool {
	return *udpProtocol && (*kcpEnabled || *kcpSEnabled)
}

func ShowPublicIP(network, bind string) error {
	index, _, nata, err := easyp2p.GetPublicIP(network, bind, 7*time.Second)
	if err == nil {
		fmt.Fprintf(os.Stderr, "Public Address: %s (via %s)\n", nata, easyp2p.STUNServers[index])
	}

	return err
}

func Mqtt_ensure_ready(sessionKey string) error {
	var msg string
	var err error

	if *MQTTWait != "" {
		msg, err = easyp2p.MqttWait(sessionKey, 10*time.Minute, os.Stderr)
		if err != nil {
			return fmt.Errorf("mqtt-wait: %v", err)
		}
		if msg != *MQTTWait {
			return fmt.Errorf("mqtt-wait: not the expected message")
		}
	}

	if *MQTTPush != "" {
		err = easyp2p.MqttPush(*MQTTPush, sessionKey, os.Stderr)
		if err != nil {
			return fmt.Errorf("mqtt-push: %v", err)
		}

		// Ensure stopMqttPushChan is properly initialized
		select {
		case <-stopMqttPushChan:
			// If already closed, recreate the channel
			stopMqttPushChan = make(chan struct{})
		default:
		}

		// Start periodic push
		go func() {
			ticker := time.NewTicker(7 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					err := easyp2p.MqttPush(*MQTTPush, sessionKey, io.Discard)
					if err != nil {
						fmt.Fprintf(os.Stderr, "mqtt-push periodic error: %v\n", err)
					}
				case <-stopMqttPushChan:
					return
				}
			}
		}()
	}
	return nil
}

var stopMqttPushChan = make(chan struct{})

func Mqtt_stop_pushing() {
	if *MQTTPush == "" {
		return
	}
	select {
	case <-stopMqttPushChan:
		// Already closed, do nothing
	default:
		close(stopMqttPushChan)
	}
}

func do_P2P(network, sessionKey string) (*secure.NegotiatedConn, error) {
	defer Mqtt_stop_pushing()

	err := Mqtt_ensure_ready(sessionKey)
	if err != nil {
		return nil, err
	}
	connInfo, err := easyp2p.Easy_P2P(network, sessionKey, os.Stderr)
	if err != nil {
		return nil, err
	}
	conn := connInfo.Conns[0]
	config := *connConfig
	config.Key = sessionKey
	config.KeyType = "PSK"
	config.IsClient = connInfo.IsClient

	if strings.HasPrefix(conn.LocalAddr().Network(), "udp") {
		config.KcpWithUDP = true
		config.SecureLayer = "dtls"
	} else {
		config.KcpWithUDP = false
		config.SecureLayer = "tls13"
	}

	nconn, err := secure.DoNegotiation(&config, conn, os.Stderr)
	if err != nil {
		return nil, err
	}
	if nconn.IsUDP {
		fmt.Fprintf(os.Stderr, "UDP ready for: %s|%s\n", conn.LocalAddr().String(), conn.RemoteAddr().String())
	} else {
		fmt.Fprintf(os.Stderr, "Connected to: %s\n", conn.RemoteAddr().String())
	}
	return nconn, nil
}

func do_P2P_multipath(network, sessionKey string, enableMP bool) (*secure.NegotiatedConn, error) {
	if !enableMP {
		return do_P2P(network, sessionKey)
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
