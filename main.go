package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/pbkdf2"
	"crypto/sha1"
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

	"github.com/threatexpert/gonc/easyp2p"
	"github.com/threatexpert/gonc/misc"

	// "net/http"
	// _ "net/http/pprof"

	"github.com/pion/dtls/v3"
	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/term"
)

var (
	connConfig                 *connectionConfig = nil
	sessionReady                                 = false
	goroutineConnectionCounter int32             = 0
	udpOutputBlockSize         int               = 1320
	kcpWindowSize              int               = 1500
	app_mux_Config             *AppMuxConfig
	app_s5s_Config             *AppS5SConfig
	app_pf_Config              *AppPFConfig
	// 定义命令行参数
	proxyProt         = flag.String("X", "", "proxy_protocol. Supported protocols are “5” (SOCKS v.5) and “connect” (HTTPS proxy).  If the protocol is not specified, SOCKS version 5 is used.")
	proxyAddr         = flag.String("x", "", "ip:port for proxy_address")
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
	//appMux            = flag.Bool("app-mux", false, "a Stream Multiplexing based proxy app")
	keepAlive        = flag.Int("keepalive", 0, "none 0 will enable TCP keepalive feature")
	punchData        = flag.String("punchdata", "ping\n", "UDP punch payload")
	MQTTServers      = flag.String("mqttsrv", "tcp://broker.hivemq.com:1883,tcp://broker.emqx.io:1883,tcp://test.mosquitto.org:1883", "MQTT servers")
	autoP2P          = flag.String("p2p", "", "P2P session key (or @file). Auto try UDP/TCP via NAT traversal")
	useMutilPath     = flag.Bool("mp", false, "enable multipath(NOT IMPL)")
	MQTTWait         = flag.String("mqtt-wait", "", "wait for MQTT hello message before initiating P2P connection")
	MQTTPush         = flag.String("mqtt-push", "", "send MQTT hello message before initiating P2P connection")
	useIPv4          = flag.Bool("4", false, "Forces to use IPv4 addresses only")
	useIPv6          = flag.Bool("6", false, "Forces to use IPv4 addresses only")
	useDNS           = flag.String("dns", "", "set DNS Server")
	runAppFileServ   = flag.String("httpserver", "", "http server root directory")
	runAppFileGet    = flag.String("download", "", "http client download directory")
	appMuxListenMode = flag.Bool("httplocal", false, "local listen mode for remote httpserver")
	appMuxListenOn   = flag.String("httplocal-port", "", "local listen port for remote httpserver")
	appMuxSocksMode  = flag.Bool("socks5server", false, "for socks5 tunnel")
	disableCompress  = flag.Bool("no-compress", false, "disable compression for http download")
)

func init() {
	flag.StringVar(runCmd, "e", "", "alias for -exec")
	flag.BoolVar(progressEnabled, "P", false, "alias for -progress")
	flag.StringVar(localbind, "local", "", "ip:port (alias for -bind)")
	flag.StringVar(&easyp2p.TopicExchange, "mqtt-nat-topic", easyp2p.TopicExchange, "")
	flag.StringVar(&easyp2p.TopicExchangeWait, "mqtt-wait-topic", easyp2p.TopicExchangeWait, "")
	flag.IntVar(&easyp2p.PunchingShortTTL, "punch-short-ttl", easyp2p.PunchingShortTTL, "")
	flag.IntVar(&easyp2p.PunchingRandomPortCount, "punch-random-count", easyp2p.PunchingRandomPortCount, "")
	flag.BoolVar(appMuxListenMode, "socks5local", false, "")
	flag.StringVar(appMuxListenOn, "socks5local-port", "", "")
	flag.BoolVar(appMuxListenMode, "browser", false, "alias for -httplocal")
	flag.IntVar(&udpOutputBlockSize, "udp-size", udpOutputBlockSize, "")
	flag.IntVar(&kcpWindowSize, "kcp-window-size", kcpWindowSize, "")
	httpDownloadNoCompress = disableCompress
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
				cert, err := misc.LoadCertificate(*sslCertFile, *sslKeyFile)
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
					cert, err := misc.GenerateECDSACertificate(*tlsSNI, *presharedKey)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error generating EC certificate: %v\n", err)
						os.Exit(1)
					}
					certs = append(certs, *cert)
				}
				if *tlsRSACertEnabled {
					fmt.Fprintf(os.Stderr, "Generating RSA cert...")
					cert, err := misc.GenerateRSACertificate(*tlsSNI)
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

func do_TLS(config *connectionConfig, conn net.Conn) net.Conn {
	// 获取所有安全加密套件
	safeCiphers := tls.CipherSuites()
	// 获取所有不安全加密套件
	insecureCiphers := tls.InsecureCipherSuites()
	// 合并两个列表
	var allCiphers []uint16
	for _, cipher := range safeCiphers {
		allCiphers = append(allCiphers, cipher.ID)
	}
	for _, cipher := range insecureCiphers {
		allCiphers = append(allCiphers, cipher.ID)
	}

	// 创建 TLS 配置
	tlsConfig := &tls.Config{
		CipherSuites:             allCiphers,
		InsecureSkipVerify:       true,             // 忽略证书验证（可选）
		MinVersion:               tls.VersionTLS10, // 至少 TLSv1
		MaxVersion:               tls.VersionTLS13, // 最大支持 TLSv1.3
		PreferServerCipherSuites: true,             // 优先使用服务器的密码套件
	}
	if config.secureLayer == "tls10" {
		tlsConfig.MinVersion = tls.VersionTLS10
		tlsConfig.MaxVersion = tls.VersionTLS10
	}
	if config.secureLayer == "tls11" {
		tlsConfig.MinVersion = tls.VersionTLS11
		tlsConfig.MaxVersion = tls.VersionTLS11
	}
	if config.secureLayer == "tls12" {
		tlsConfig.MinVersion = tls.VersionTLS12
		tlsConfig.MaxVersion = tls.VersionTLS12
	}
	if config.secureLayer == "tls13" {
		tlsConfig.MinVersion = tls.VersionTLS13
		tlsConfig.MaxVersion = tls.VersionTLS13
	}
	timeout_sec := 20
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout_sec)*time.Second)
	defer cancel()
	// 使用 TLS 握手
	var conn_tls *tls.Conn
	var certs []tls.Certificate = config.certs

	if !config.isClient {
		tlsConfig.Certificates = config.certs
		if config.key != "" && config.keyType == "PSK" {
			tlsConfig.ClientAuth = tls.RequireAnyClientCert
			tlsConfig.VerifyPeerCertificate = misc.VerifyPeerCertificateByPSK(config.key)
			fmt.Fprintf(os.Stderr, "%sPerforming TLS-S handshake (PSK-based mutual authentication)...", config.label)
		} else {
			fmt.Fprintf(os.Stderr, "%sPerforming TLS-S handshake...", config.label)
		}
		conn_tls = tls.Server(conn, tlsConfig)
	} else {
		tlsConfig.ServerName = *tlsSNI
		if config.key != "" && config.keyType == "PSK" {
			tlsConfig.Certificates = certs
			tlsConfig.VerifyPeerCertificate = misc.VerifyPeerCertificateByPSK(config.key)
			fmt.Fprintf(os.Stderr, "%sPerforming TLS-C handshake (PSK-based mutual authentication)...", config.label)
		} else {
			fmt.Fprintf(os.Stderr, "%sPerforming TLS-C handshake...", config.label)
		}
		conn_tls = tls.Client(conn, tlsConfig)
	}
	if err := conn_tls.HandshakeContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "failed: %v\n", err)
		return nil
	}
	fmt.Fprintf(os.Stderr, "completed.\n")
	return conn_tls
}

func do_DTLS(config *connectionConfig, conn net.Conn) net.Conn {
	// 支持的 CipherSuites（pion 这里和 crypto/tls 不同）
	allCiphers := []dtls.CipherSuiteID{
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}

	// DTLS 配置
	dtlsConfig := &dtls.Config{
		CipherSuites:         allCiphers,
		InsecureSkipVerify:   true, // 和 tls.Config 一样，跳过证书校验
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		FlightInterval:       2 * time.Second,
	}

	// DTLS Server / Client 模式
	var dtlsConn *dtls.Conn
	var err error
	timeout_sec := 20

	pktconn := easyp2p.NewPacketConnWrapper(conn, conn.RemoteAddr())

	intervalChange := make(chan time.Duration, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout_sec)*time.Second)
	defer cancel()
	// 开启NAT打洞， 首包是4秒后发出punch包
	startUDPKeepAlive(ctx, conn, []byte(*punchData), 4*time.Second, intervalChange)

	if !config.isClient {
		dtlsConfig.Certificates = config.certs
		if config.key != "" && config.keyType == "PSK" {
			dtlsConfig.ClientAuth = dtls.RequireAnyClientCert
			dtlsConfig.VerifyPeerCertificate = misc.VerifyPeerCertificateByPSK(config.key)
			fmt.Fprintf(os.Stderr, "%sPerforming DTLS-S handshake (PSK-based mutual authentication)...", config.label)
		} else {
			fmt.Fprintf(os.Stderr, "%sPerforming DTLS-S handshake...", config.label)
		}
		//dtls.Server 不会主动发包，startUDPKeepAlive4秒后发出punch包有助于P2P建立通信
		dtlsConn, err = dtls.Server(pktconn, conn.RemoteAddr(), dtlsConfig)
	} else {
		dtlsConfig.ServerName = *tlsSNI
		if config.key != "" && config.keyType == "PSK" {
			dtlsConfig.Certificates = config.certs
			dtlsConfig.VerifyPeerCertificate = misc.VerifyPeerCertificateByPSK(config.key)
			fmt.Fprintf(os.Stderr, "%sPerforming DTLS-C handshake (PSK-based mutual authentication)...", config.label)
		} else {
			fmt.Fprintf(os.Stderr, "%sPerforming DTLS-C handshake...", config.label)
		}
		//dtls.Client 会立刻发出hello包，dtls.Server
		dtlsConn, err = dtls.Client(pktconn, conn.RemoteAddr(), dtlsConfig)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "DTLS initialization failed: %v\n", err)
		return nil
	}

	// 超时控制通道
	timeoutChan := make(chan struct{})
	defer close(timeoutChan) // 确保通道最终被关闭

	// 超时检测协程
	go func() {
		select {
		case <-time.After(time.Duration(timeout_sec) * time.Second):
			// 超时后强制关闭连接
			cancel()
			time.Sleep(500 * time.Millisecond)
			dtlsConn.Close()
		case <-timeoutChan:
			// 正常完成握手，退出协程
			return
		}
	}()

	firstRefusedLogged := false
	for {
		if err = dtlsConn.HandshakeContext(ctx); err != nil {
			if easyp2p.IsConnRefused(err) {
				if !firstRefusedLogged {
					fmt.Fprintf(os.Stderr, "(ECONNREFUSED)...")
					firstRefusedLogged = true
				}
				time.Sleep(500 * time.Millisecond)
				continue
			}
			fmt.Fprintf(os.Stderr, "failed: %v\n", err)
			dtlsConn.Close()
			return nil
		}
		timeoutChan <- struct{}{}
		break
	}
	fmt.Fprintf(os.Stderr, "completed.\n")
	return dtlsConn
}

func createProxyClient(proxyProt, proxyAddr, proxyAuth string) (*ProxyClient, error) {
	if proxyAddr != "" {
		user, pass := "", ""
		if proxyAuth != "" {
			authParts := strings.SplitN(proxyAuth, ":", 2)
			if len(authParts) != 2 {
				return nil, fmt.Errorf("invalid auth format: expected user:pass")
			}
			user, pass = authParts[0], authParts[1]
		}

		switch proxyProt {
		case "", "5":
			client, err := NewProxyClient("socks5", proxyAddr, user, pass)
			if err != nil {
				return nil, fmt.Errorf("failed to create socks5 client: %w", err)
			}
			return client, nil
		case "connect":
			client, err := NewProxyClient("http", proxyAddr, user, pass)
			if err != nil {
				return nil, fmt.Errorf("failed to create http client: %w", err)
			}
			return client, nil
		default:
			return nil, fmt.Errorf("invalid proxy protocol: %s", proxyProt)
		}
	}

	// 没有代理时，返回默认的直连客户端
	client, err := NewProxyClient("", "", "", "")
	if err != nil {
		return nil, fmt.Errorf("failed to create direct client: %w", err)
	}
	return client, nil
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

func usage() {
	fmt.Fprintln(os.Stderr, "go-netcat v1.9.6")
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "    gonc [-x socks5_ip:port] [-auth user:pass] [-send path] [-tls] [-l] [-u] target_host target_port")
	fmt.Fprintln(os.Stderr, "         [-p2p sessionKey]")
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
	if *keepOpen && *proxyAddr != "" {
		fmt.Fprintf(os.Stderr, "-keep-open and -x cannot be used together\n")
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

	builtinApp := strings.TrimLeft(args[0], "-")
	if builtinApp == "app-mux" {
		app_mux_Config, err = AppMuxConfigByArgs(args[1:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error init %s config: %v\n", builtinApp, err)
			App_mux_usage()
			os.Exit(1)
		}
	} else if builtinApp == "app-s5s" {
		app_s5s_Config, err = AppS5SConfigByArgs(args[1:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error init %s config: %v\n", builtinApp, err)
			os.Exit(1)
		}
	} else if builtinApp == "app-pf" {
		app_pf_Config, err = AppPFConfigByArgs(args[1:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error init %s config: %v\n", builtinApp, err)
			os.Exit(1)
		}
	}
}

func main() {
	var err error
	flag.Parse()

	easyp2p.MQTTBrokerServers = parseMultiItems(*MQTTServers, true)
	easyp2p.STUNServers = parseMultiItems(*stunSrv, true)

	conflictCheck()

	if *runAppFileServ != "" {
		escapedPath := strings.ReplaceAll(*runAppFileServ, "\\", "/")
		*runCmd = fmt.Sprintf("-app-mux httpserver \"%s\"", escapedPath)
		if *MQTTWait == "" {
			*MQTTWait = "hello"
		}
		*progressEnabled = true
		*keepOpen = true
	} else if *runAppFileGet != "" {
		escapedPath := strings.ReplaceAll(*runAppFileGet, "\\", "/")
		*runCmd = fmt.Sprintf("-app-mux httpclient \"%s\"", escapedPath)
		if *appMuxListenOn != "" {
			muxLastListenAddress = *appMuxListenOn
		}
		if *MQTTPush == "" {
			*MQTTPush = "hello"
		}
		*keepOpen = true
	} else if *appMuxSocksMode {
		*runCmd = "-app-mux socks5"
		if *MQTTWait == "" {
			*MQTTWait = "hello"
		}
		*progressEnabled = true
		*keepOpen = true
	} else if *appMuxListenMode || *appMuxListenOn != "" {
		if *appMuxListenOn == "" {
			*appMuxListenOn = "0"
		}
		*runCmd = fmt.Sprintf("-app-mux -l %s", *appMuxListenOn)
		if *MQTTPush == "" {
			*MQTTPush = "hello"
		}
		*keepOpen = true
	}
	if *kcpEnabled || *kcpSEnabled {
		*udpProtocol = true
	}
	if *presharedKey == "." {
		*presharedKey, err = misc.GenerateSecureRandomString(22)
		if err != nil {
			panic(err)
		}
		fmt.Fprintf(os.Stderr, "%s\n", *presharedKey)
		os.Exit(1)
	}
	if *presharedKey != "" {
		if strings.HasPrefix(*presharedKey, "@") {
			*presharedKey, err = ReadPSKFile(*presharedKey)
			if err != nil {
				panic(err)
			}
		}
	}

	if *runCmd != "" {
		preinitBuiltinAppConfig()
	}

	var wg *sync.WaitGroup
	var done chan bool
	var conn net.Conn
	var network string
	var P2PSessionKey string
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

	host := ""
	port := ""
	args := flag.Args()
	if len(args) == 2 {
		host = args[0]
		port = args[1]
	} else if len(args) == 1 && *listenMode {
		port = args[0]
	} else if len(args) == 1 && !*listenMode && *useUNIXdomain {
		port = args[0]
	} else if len(args) == 0 && *listenMode && *localbind != "" {
		host, port, err = net.SplitHostPort(*localbind)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid local address %q: %v\n", *localbind, err)
			os.Exit(1)
		}
	} else if len(args) == 0 && *remoteAddr != "" {
		host, port, err = net.SplitHostPort(*remoteAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid remote address %q: %v\n", *remoteAddr, err)
			os.Exit(1)
		}
	} else if len(args) == 0 && (*autoP2P != "") {
		if *proxyAddr != "" {
			fmt.Fprintf(os.Stderr, "INFO: proxy is ignored with p2p\n")
			*proxyAddr = ""
		}
		*listenMode = false
		if *autoP2P != "" && !*udpProtocol {
			network = "any"
			P2PSessionKey = *autoP2P
			*tlsEnabled = true //-p2p 默认开启tls安全通信
		} else if *autoP2P != "" && *udpProtocol {
			P2PSessionKey = *autoP2P
			*tlsEnabled = true //-p2p 默认开启tls安全通信
			*kcpEnabled = true //需要kcp实现稳定传输
			*udpProtocol = true
			network = "udp"
		} else {
			os.Exit(1)
		}
		if *useIPv4 {
			network += "4"
		} else if *useIPv6 {
			network += "6"
		}
		if strings.HasPrefix(P2PSessionKey, "@") {
			P2PSessionKey, err = ReadPSKFile(P2PSessionKey)
			if err != nil {
				panic(err)
			}
		}
		if P2PSessionKey == "." {
			P2PSessionKey, err = misc.GenerateSecureRandomString(22)
			if err != nil {
				panic(err)
			}
			fmt.Fprintf(os.Stderr, "Keep this key secret! It is used to establish the secure P2P tunnel: %s\n", P2PSessionKey)
		} else if misc.IsWeakPassword(P2PSessionKey) {
			fmt.Fprintf(os.Stderr, "Weak password detected. Please use at least 8 characters and avoid common or repetitive patterns.\n")
			os.Exit(1)
		}
		*presharedKey = P2PSessionKey
	} else {
		usage()
		os.Exit(1)
	}

	if *tlsSNI == "" {
		if *listenMode {
			*tlsSNI = "localhost"
		} else {
			*tlsSNI = host
		}
	}

	connConfig, err = preinitConnectionConfig()
	if err != nil {
		panic(err)
	}

	if *useDNS != "" {
		setDns(*useDNS)
	}
	if isAndroid() {
		if *useDNS == "" {
			setDns("8.8.8.8:53")
		}
	}

	//p2p模式
	if P2PSessionKey != "" {
		// 创建进度统计
		stats_in := misc.NewProgressStats()
		stats_out := misc.NewProgressStats()
		if *progressEnabled {
			// 启动进度显示
			wg = &sync.WaitGroup{}
			done = make(chan bool)
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
		if *progressEnabled {
			done <- true
			wg.Wait()
		}
		return
	}

	proxyClient, err := createProxyClient(*proxyProt, *proxyAddr, *auth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error create proxy client: %v\n", err)
		os.Exit(1)
	}

	// 监听模式
	if *listenMode {
		if *proxyAddr == "" {
			if port == "0" {
				portInt, err := easyp2p.GetFreePort()
				if err != nil {
					panic(err)
				}
				port = strconv.Itoa(portInt)
			}
		}
		listenAddr := net.JoinHostPort(host, port)
		if *useUNIXdomain {
			listenAddr = port
			err := cleanupUnixSocket(port)
			if err != nil {
				panic(err)
			}
		}
		if *udpProtocol {
			// 绑定UDP地址
			addr, err := net.ResolveUDPAddr(network, listenAddr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error resolving UDP address: %v\n", err)
				os.Exit(1)
			}

			if *useSTUN {
				err = ShowPublicIP(network, addr.String())
				if err != nil {
					panic(err)
				}
				time.Sleep(1500 * time.Millisecond) //等待一会儿，避免立刻监听又收到stun服务器回复的udp包
			}

			uconn, err := net.ListenUDP(network, addr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error listening on UDP address: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Listening %s on %s\n", uconn.LocalAddr().Network(), uconn.LocalAddr().String())

			logDiscard := log.New(io.Discard, "", log.LstdFlags)
			usessListener, err := easyp2p.NewUDPCustomListener(uconn, logDiscard)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error NewUDPCustomListener: %v\n", err)
				os.Exit(1)
			}

			if *keepOpen {
				// 创建进度统计
				stats_in := misc.NewProgressStats()
				stats_out := misc.NewProgressStats()
				if *progressEnabled {
					// 启动进度显示
					wg = &sync.WaitGroup{}
					done = make(chan bool)
					showProgress(stats_in, stats_out, done, wg)
				}

				for {
					newSess, err := usessListener.Accept()
					if err != nil {
						if err == net.ErrClosed {
							fmt.Fprintf(os.Stderr, "UDPCustomListener accept failed: %v\n", err)
							os.Exit(1)
							return
						}
						continue
					}

					fmt.Fprintf(os.Stderr, "UDP session established from %s\n", newSess.RemoteAddr().String())
					go handleConnection(connConfig, newSess, stats_in, stats_out)
				}
			} else {
				// 只接受一个连接
				newSess, err := usessListener.Accept()
				if err != nil {
					fmt.Fprintf(os.Stderr, "UDPCustomListener accept failed: %v\n", err)
					os.Exit(1)
				}
				fmt.Fprintf(os.Stderr, "UDP session established from %s\n", newSess.RemoteAddr().String())
				conn = newSess
			}
		} else {
			var listener net.Listener

			if proxyClient.SupportBIND() {
				listener, err = proxyClient.dialer.Listen(network, listenAddr)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error listening on %s: %v\n", listenAddr, err)
					os.Exit(1)
				}
			} else {
				// TCP/unix listen
				lc := net.ListenConfig{}
				if *useSTUN {
					err = ShowPublicIP(network, listenAddr)
					if err != nil {
						panic(err)
					}
				}
				if *useSTUN {
					lc.Control = easyp2p.ControlTCP
				}
				listener, err = lc.Listen(context.Background(), network, listenAddr)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error listening on %s: %v\n", listenAddr, err)
					os.Exit(1)
				}
			}
			fmt.Fprintf(os.Stderr, "Listening %s on %s\n", listener.Addr().Network(), listener.Addr().String())

			if *keepOpen {
				// 创建进度统计
				stats_in := misc.NewProgressStats()
				stats_out := misc.NewProgressStats()
				if *progressEnabled {
					// 启动进度显示
					wg = &sync.WaitGroup{}
					done = make(chan bool)
					showProgress(stats_in, stats_out, done, wg)
				}
				defer listener.Close()
				for {
					conn, err = listener.Accept()
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error accepting connection: %v\n", err)
						time.Sleep(1 * time.Second)
						continue
					}
					if conn.LocalAddr().Network() == "unix" {
						fmt.Fprintf(os.Stderr, "Connection on %s received!\n", conn.LocalAddr().String())
					} else {
						fmt.Fprintf(os.Stderr, "Connected from: %s        \n", conn.RemoteAddr().String())
					}
					go handleConnection(connConfig, conn, stats_in, stats_out)
				}
			} else {
				conn, err = listener.Accept()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error accepting connection: %v\n", err)
					os.Exit((1))
				}
				listener.Close()
				if conn.LocalAddr().Network() == "unix" {
					fmt.Fprintf(os.Stderr, "Connection on %s received!\n", conn.LocalAddr().String())
				} else {
					fmt.Fprintf(os.Stderr, "Connected from: %s\n", conn.RemoteAddr().String())
				}
			}
		}
	} else {
		//主动连接模式

		// go func() {
		// 	log.Println(http.ListenAndServe("localhost:6060", nil))
		// }()

		var localAddr net.Addr
		var localTcpAddr *net.TCPAddr

		if *localbind != "" {
			switch {
			case strings.HasPrefix(network, "tcp"):
				localTcpAddr, err = net.ResolveTCPAddr(network, *localbind)
				if err != nil {
					panic(err)
				}
				localAddr = localTcpAddr
			case strings.HasPrefix(network, "udp"):
				localAddr, err = net.ResolveUDPAddr(network, *localbind)
				if err != nil {
					panic(err)
				}
			}
		}

		if *useSTUN {
			if *localbind == "" {
				panic("-stun need be with -bind while connecting")
			}
			err = ShowPublicIP(network, localAddr.String())
			if err != nil {
				panic(err)
			}
		}

		if *useUNIXdomain {
			// Unix域套接字
			conn, err = net.Dial("unix", port)
		} else {
			// TCP/UDP 连接
			if localAddr == nil {
				conn, err = proxyClient.DialTimeout(network, net.JoinHostPort(host, port), 20*time.Second)
			} else {
				dialer := &net.Dialer{
					LocalAddr: localAddr,
				}
				switch {
				case strings.HasPrefix(network, "tcp"):
					dialer.Control = easyp2p.ControlTCP
				case strings.HasPrefix(network, "udp"):
					dialer.Control = easyp2p.ControlUDP
				}
				conn, err = dialer.Dial(network, net.JoinHostPort(host, port))
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if strings.HasPrefix(conn.LocalAddr().Network(), "udp") {
			if *proxyAddr == "" {
				fmt.Fprintf(os.Stderr, "UDP ready for: %s\n", net.JoinHostPort(host, port))
			} else {
				fmt.Fprintf(os.Stderr, "UDP ready for: %s -> %s\n", *proxyAddr, net.JoinHostPort(host, port))
			}
		} else {
			if *proxyAddr == "" {
				fmt.Fprintf(os.Stderr, "Connected to: %s\n", conn.RemoteAddr().String())
			} else {
				fmt.Fprintf(os.Stderr, "Connected to: %s -> %s\n", conn.RemoteAddr().String(), net.JoinHostPort(host, port))
			}
		}
	}

	// 创建进度统计
	stats_in := misc.NewProgressStats()
	stats_out := misc.NewProgressStats()
	if *progressEnabled {
		wg = &sync.WaitGroup{}
		done = make(chan bool)
		showProgress(stats_in, stats_out, done, wg)
	}

	handleConnection(connConfig, conn, stats_in, stats_out)
	if *progressEnabled {
		done <- true
		wg.Wait()
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
			fmt.Fprintf(os.Stderr, "Read error: %v\n", err1)
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

type closeWriter interface {
	CloseWrite() error
}

type connectionConfig struct {
	label         string
	isClient      bool
	secureLayer   string //tls tls13 dtls ss
	certs         []tls.Certificate
	kcpWithUDP    bool
	kcpEncryption bool //是否开启kcp加密
	key           string
	keyType       string // ECDHE or PSK
}

func preinitConnectionConfig() (*connectionConfig, error) {
	config := &connectionConfig{}

	genCertForced := *presharedKey != ""
	config.certs = init_TLS(genCertForced)

	if *listenMode || *kcpSEnabled || *tlsServerMode {
		config.isClient = false
	} else {
		config.isClient = true
	}

	if *presharedKey != "" {
		config.keyType = "PSK"
		config.key = *presharedKey
	}

	if *udpProtocol {
		config.kcpWithUDP = isKCPEnabled()
		if isTLSEnabled() {
			config.secureLayer = "dtls"
		} else if config.kcpWithUDP && config.key != "" {
			config.kcpEncryption = true
		}
	} else {
		if isTLSEnabled() {
			if *tls10_forced {
				config.secureLayer = "tls10"
			} else if *tls11_forced {
				config.secureLayer = "tls11"
			} else if *tls12_forced {
				config.secureLayer = "tls12"
			} else if *tls13_forced {
				config.secureLayer = "tls13"
			} else {
				config.secureLayer = "tls"
			}
		} else if config.key != "" {
			config.secureLayer = "ss"
		}
	}

	return config, nil
}

type negotiatedConn struct {
	ctx        context.Context
	cancel     context.CancelFunc
	connLayers []net.Conn
	isUDP      bool
}

func (nconn *negotiatedConn) Close() error {
	if nconn.cancel != nil {
		nconn.cancel()
	}
	for _, c := range nconn.connLayers {
		c.Close()
	}
	nconn.connLayers = []net.Conn{}
	nconn.ctx = nil
	nconn.cancel = nil
	return nil
}

func (nconn *negotiatedConn) Read(b []byte) (int, error) {
	return nconn.connLayers[0].Read(b)
}

func (nconn *negotiatedConn) Write(b []byte) (int, error) {
	return nconn.connLayers[0].Write(b)
}

func (nconn *negotiatedConn) CloseWrite() error {
	if cw, ok := nconn.connLayers[0].(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nconn.connLayers[0].Close()
}

func (nconn *negotiatedConn) LocalAddr() net.Addr {
	return nconn.connLayers[0].LocalAddr()
}

func (nconn *negotiatedConn) RemoteAddr() net.Addr {
	return nconn.connLayers[0].RemoteAddr()
}

func (nconn *negotiatedConn) SetDeadline(t time.Time) error {
	return nconn.connLayers[0].SetDeadline(t)
}

func (nconn *negotiatedConn) SetReadDeadline(t time.Time) error {
	return nconn.connLayers[0].SetReadDeadline(t)
}

func (nconn *negotiatedConn) SetWriteDeadline(t time.Time) error {
	return nconn.connLayers[0].SetWriteDeadline(t)
}

func do_Negotiation(cfg *connectionConfig, rawconn net.Conn) (*negotiatedConn, error) {
	nconn := &negotiatedConn{
		connLayers: []net.Conn{rawconn},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		if nconn.cancel == nil {
			cancel()
			for i, c := range nconn.connLayers {
				if i != len(nconn.connLayers)-1 { // 最后一个连接是原始连接，发送错误时不关闭，还给调用者处置
					c.Close()
				}
			}
		}
	}()

	if strings.HasPrefix(rawconn.LocalAddr().Network(), "udp") {
		nconn.isUDP = true
		configUDPConn(rawconn)
	} else {
		configTCPKeepalive(rawconn)
	}

	switch {
	case strings.HasPrefix(cfg.secureLayer, "tls"):
		conn_tls := do_TLS(cfg, nconn.connLayers[0])
		if conn_tls == nil {
			return nil, fmt.Errorf("failed to establish TLS connection")
		}
		nconn.connLayers = append([]net.Conn{conn_tls}, nconn.connLayers...)
	case cfg.secureLayer == "dtls":
		conn_dtls := do_DTLS(cfg, nconn.connLayers[0])
		if conn_dtls == nil {
			return nil, fmt.Errorf("failed to establish DTLS connection")
		}
		nconn.connLayers = append([]net.Conn{conn_dtls}, nconn.connLayers...)
	case cfg.secureLayer == "ss":
		var key32 [32]byte
		if cfg.keyType == "ECDHE" {
			copy(key32[:], []byte(cfg.key))
			fmt.Fprintf(os.Stderr, "%sCommunication is encrypted(ECDHE) with AES.\n", cfg.label)
		} else if cfg.keyType == "PSK" {
			k, err := misc.DerivePSK(cfg.key)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%sFailed to derive key for secure stream: %v\n", cfg.label, err)
				return nil, err
			}
			copy(key32[:], k)
			fmt.Fprintf(os.Stderr, "%sCommunication is encrypted(PSK) with AES.\n", cfg.label)
		} else {
			fmt.Fprintf(os.Stderr, "%sMissing key type for secure stream\n", cfg.label)
			return nil, fmt.Errorf("missing key type for secure stream")
		}
		connss := misc.NewSecureStreamConn(nconn.connLayers[0], key32)
		nconn.connLayers = append([]net.Conn{connss}, nconn.connLayers...)
	default:
	}

	if nconn.isUDP {
		if cfg.kcpWithUDP {
			sess_kcp := do_KCP(ctx, cfg, nconn.connLayers[0], rawconn, 30*time.Second)
			if sess_kcp == nil {
				return nil, fmt.Errorf("failed to establish KCP session")
			}
			nconn.connLayers = append([]net.Conn{sess_kcp}, nconn.connLayers...)
		} else {
			pktconn := easyp2p.NewPacketConnWrapper(nconn.connLayers[0], nconn.connLayers[0].RemoteAddr())
			buconn := easyp2p.NewBoundUDPConn(pktconn, nconn.connLayers[0].RemoteAddr().String(), false)
			buconn.SetIdleTimeout(5 * time.Minute)
			nconn.connLayers = append([]net.Conn{buconn}, nconn.connLayers...)
		}
	}

	nconn.ctx = ctx
	nconn.cancel = cancel
	return nconn, nil
}

func handleNegotiatedConnection(nconn *negotiatedConn, stats_in, stats_out *misc.ProgressStats) {
	defer atomic.AddInt32(&goroutineConnectionCounter, -1)
	atomic.AddInt32(&goroutineConnectionCounter, 1)

	defer nconn.Close()

	conn := nconn.connLayers[0]

	var bufsize int = 32 * 1024
	blocksize := bufsize
	if nconn.isUDP {
		//往udp连接拷贝数据，如果源是文件，应该限制每次拷贝到udp包的大小
		blocksize = udpOutputBlockSize
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

		builtinApp := strings.TrimLeft(args[0], "-")
		if builtinApp == "app-mux" {
			pipeConn := misc.NewPipeConn(conn)
			input = pipeConn.In
			output = pipeConn.Out
			defer pipeConn.Close()
			go App_mux_main_withconfig(pipeConn, app_mux_Config)
		} else if builtinApp == "app-s5s" {
			pipeConn := misc.NewPipeConn(conn)
			input = pipeConn.In
			output = pipeConn.Out
			defer pipeConn.Close()
			go App_s5s_main_withconfig(pipeConn, app_s5s_Config)
		} else if builtinApp == "app-pf" {
			pipeConn := misc.NewPipeConn(conn)
			input = pipeConn.In
			output = pipeConn.Out
			defer pipeConn.Close()
			if strings.Contains(app_pf_Config.network, "udp") {
				//udp的端口转发，避免截断数据包，也不应该会粘包（pipeConn内部是net.Pipe()，它无内置缓冲区）
				blocksize = bufsize
			}
			go App_pf_main_withconfig(pipeConn, app_pf_Config)
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
				copyWithProgress(conn, input, blocksize, !nconn.isUDP, stats_out)
			} else {
				copyCharDeviceWithProgress(conn, input, stats_out)
			}
		} else {
			copyWithProgress(conn, input, blocksize, !nconn.isUDP, stats_out)
		}

		time.Sleep(1 * time.Second)
		// 关闭连接
		if tcpConn, ok := conn.(closeWriter); ok {
			tcpConn.CloseWrite()
		} else {
			conn.Close()
		}
	}()
	// 从连接读取并输出到输出
	go func() {
		defer wg.Done()
		defer close(inExited)

		copyWithProgress(output, conn, bufsize, !nconn.isUDP, stats_in)
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

	conn.Close()
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

func handleConnection(cfg *connectionConfig, conn net.Conn, stats_in, stats_out *misc.ProgressStats) {
	nconn, err := do_Negotiation(cfg, conn)
	if err != nil {
		conn.Close()
		return
	}
	handleNegotiatedConnection(nconn, stats_in, stats_out)
}

func configTCPKeepalive(conn net.Conn) {
	if *keepAlive > 0 {
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			ka := net.KeepAliveConfig{
				Enable:   true,
				Idle:     time.Duration(*keepAlive) * time.Second, // 空闲多久后开始探测
				Count:    9,                                       // 最多发几次探测包
				Interval: time.Duration(*keepAlive) * time.Second, // 探测包之间的间隔
			}
			tcpConn.SetKeepAliveConfig(ka)
		}
	}
}

func configUDPConn(conn net.Conn) {
	udpConn, ok := conn.(*net.UDPConn)
	if ok {
		udpConn.SetReadBuffer(512 * 1024)
		udpConn.SetWriteBuffer(512 * 1024)
	}
}

func createKCPBlockCrypt(passphrase string, salt []byte) (kcp.BlockCrypt, error) {
	// 使用 PBKDF2 派生 32 字节密钥
	key, err := pbkdf2.Key(sha1.New, passphrase, salt, 1024, 32)
	if err != nil {
		return nil, fmt.Errorf("pbkdf2 key derivation failed: %v", err)
	}

	// 使用派生密钥创建 AES 加密器
	blockCrypt, err := kcp.NewAESBlockCrypt(key)
	if err != nil {
		return nil, fmt.Errorf("kcp NewAESBlockCrypt failed: %v", err)
	}

	return blockCrypt, nil
}

func createKCPBlockCryptFromKey(key []byte) (kcp.BlockCrypt, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: expected 32, got %d", len(key))
	}
	blockCrypt, err := kcp.NewAESBlockCrypt(key[:]) // key[:] 转为 []byte
	if err != nil {
		return nil, fmt.Errorf("kcp NewAESBlockCrypt failed: %v", err)
	}
	return blockCrypt, nil
}

func isKCPEnabled() bool {
	return *udpProtocol && (*kcpEnabled || *kcpSEnabled)
}

func do_KCP(ctx context.Context, config *connectionConfig, conn, rawconn net.Conn, timeout time.Duration) net.Conn {
	var sess *kcp.UDPSession
	var err error
	var blockCrypt kcp.BlockCrypt
	if config.kcpEncryption {
		if config.keyType == "ECDHE" {
			blockCrypt, err = createKCPBlockCryptFromKey([]byte(config.key))
			if err != nil {
				fmt.Fprintf(os.Stderr, "%screateKCPBlockCryptFromKey failed: %v\n", config.label, err)
				return nil
			}
		} else if config.keyType == "PSK" {
			blockCrypt, err = createKCPBlockCrypt(config.key, []byte("1234567890abcdef"))
			if err != nil {
				fmt.Fprintf(os.Stderr, "%screateKCPBlockCrypt failed: %v\n", config.label, err)
				return nil
			}
		}
	}

	// 通知keepalive调整间隔
	intervalChange := make(chan time.Duration, 1)

	// 启动 keepalive
	startUDPKeepAlive(ctx, rawconn, []byte(*punchData), 2*time.Second, intervalChange)

	pktconn := easyp2p.NewPacketConnWrapper(conn, conn.RemoteAddr())
	buconn := easyp2p.NewBoundUDPConn(pktconn, conn.RemoteAddr().String(), false)
	buconn.SetIdleTimeout(time.Duration(easyp2p.UDPIdleTimeoutSecond) * time.Second)

	if !config.isClient {
		if blockCrypt == nil {
			fmt.Fprintf(os.Stderr, "%sPerforming KCP-S handshake...", config.label)
		} else {
			fmt.Fprintf(os.Stderr, "%sPerforming encrypted(%s) KCP-S handshake...", config.label, config.keyType)
		}
	} else {
		if blockCrypt == nil {
			fmt.Fprintf(os.Stderr, "%sPerforming KCP-C handshake...", config.label)
		} else {
			fmt.Fprintf(os.Stderr, "%sPerforming encrypted(%s) KCP-C handshake using...", config.label, config.keyType)
		}
	}
	sess, err = kcp.NewConn3(0, conn.RemoteAddr(), blockCrypt, 10, 3, buconn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "NewConn failed: %v\n", err)
		return nil
	}

	// 简单握手
	handshake := []byte("HELLO")
	_, err = sess.Write(handshake)
	if err != nil {
		fmt.Fprintf(os.Stderr, "send handshake failed: %v\n", err)
		return nil
	}

	// 设置握手超时
	sess.SetReadDeadline(time.Now().Add(timeout))

	buf := make([]byte, len(handshake))
	n, err := io.ReadFull(sess, buf)
	if err != nil || n != len(handshake) || !bytes.Equal(buf, handshake) {
		fmt.Fprintf(os.Stderr, "recv handshake failed: %v\n", err)
		return nil
	}
	fmt.Fprintf(os.Stderr, "completed.\n")

	// 取消超时（恢复成无超时）
	sess.SetReadDeadline(time.Time{})

	// 告诉keep alive协程，把间隔调成13秒
	select {
	case intervalChange <- 13 * time.Second:
	default:
	}

	sess.SetNoDelay(1, 10, 2, 1)
	sess.SetWindowSize(kcpWindowSize, kcpWindowSize)
	//kcp header 24字节SetMtu时就暗含其中。但实际发出包可能还多出28字节。根据情况把mtu再调小，防止超过udpOutputBlockSize
	mtu := udpOutputBlockSize - 8 // 8: fecHeaderSizePlus2
	if blockCrypt != nil {
		mtu -= 20 //20: nonceSize+crcSize
	}
	if strings.Contains(config.secureLayer, "tls") {
		mtu -= 60
	}
	sess.SetMtu(mtu)

	return sess
}

func startUDPKeepAlive(ctx context.Context, conn net.Conn, data []byte, initInterval time.Duration, intervalChange <-chan time.Duration) {
	go func() {
		keepAliveInterval := initInterval
		ticker := time.NewTicker(keepAliveInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case newInterval := <-intervalChange:
				ticker.Stop()
				keepAliveInterval = newInterval
				ticker = time.NewTicker(keepAliveInterval)
			case <-ticker.C:
				if _, err := conn.Write(data); err != nil {
					fmt.Fprintf(os.Stderr, "keepAlive send failed: %v\n", err)
					// 不退出，继续重试
				}
			}
		}
	}()
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

func do_P2P(network, sessionKey string) (*negotiatedConn, error) {
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
	config := connectionConfig{
		key:      sessionKey,
		keyType:  "PSK",
		certs:    connConfig.certs,
		isClient: connInfo.IsClient,
	}
	if strings.HasPrefix(conn.LocalAddr().Network(), "udp") {
		config.kcpWithUDP = true
		config.secureLayer = "dtls"
	} else {
		config.kcpWithUDP = false
		config.secureLayer = "tls13"
	}

	nconn, err := do_Negotiation(&config, conn)
	if err != nil {
		return nil, err
	}
	if nconn.isUDP {
		fmt.Fprintf(os.Stderr, "UDP ready for: %s|%s\n", conn.LocalAddr().String(), conn.RemoteAddr().String())
	} else {
		fmt.Fprintf(os.Stderr, "Connected to: %s\n", conn.RemoteAddr().String())
	}
	return nconn, nil
}

func do_P2P_multipath(network, sessionKey string, enableMP bool) (*negotiatedConn, error) {
	if !enableMP {
		return do_P2P(network, sessionKey)
	}
	//建立多个连接，例如包含UDP TCP TCP6几个会话，然后封装为哪个协议快用哪个，规避Qos
	return nil, fmt.Errorf("multipath not implemented yet")
}

func ReadPSKFile(filepath string) (string, error) {
	// 检查是否以@开头
	if !strings.HasPrefix(filepath, "@") {
		return filepath, nil // 如果不是文件路径，直接返回原内容
	}

	// 提取实际文件路径（去掉@符号）
	filename := strings.TrimPrefix(filepath, "@")

	// 打开文件
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// 读取第一行
	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		// 去除首尾空白字符和换行符
		line := strings.TrimSpace(scanner.Text())
		return line, nil
	}

	// 处理文件为空的情况
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", nil // 空文件返回空字符串
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
