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
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"gonc/misc"
	"gonc/pty"

	"github.com/pion/dtls/v3"
	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/net/proxy"
	"golang.org/x/term"
)

var (
	tls_cert_EC         *tls.Certificate = nil
	tls_cert_RSA        *tls.Certificate = nil
	sessionReady                         = false
	sessionSharedKey    []byte           = nil
	secureStreamEnabled                  = false
	// 定义命令行参数
	socks5Addr        = flag.String("s5", "", "ip:port (SOCKS5 proxy)")
	auth              = flag.String("auth", "", "user:password for SOCKS5 proxy")
	sendfile          = flag.String("sendfile", "", "path to file to send (optional)")
	tlsEnabled        = flag.Bool("tls", false, "Enable TLS connection")
	tlsServerMode     = flag.Bool("tlsserver", false, "force as TLS server while connecting")
	tls10_forced      = flag.Bool("tls10", false, "force negotiation to specify TLS version")
	tls11_forced      = flag.Bool("tls11", false, "force negotiation to specify TLS version")
	tls12_forced      = flag.Bool("tls12", false, "force negotiation to specify TLS version")
	tls13_forced      = flag.Bool("tls13", false, "force negotiation to specify TLS version")
	tlsECCertEnabled  = flag.Bool("tlsec", true, "enable TLS EC cert")
	tlsRSACertEnabled = flag.Bool("tlsrsa", false, "enable TLS RSA cert")
	tlsSNI            = flag.String("sni", "", "specify TLS SNI")
	presharedKey      = flag.String("psk", "", "Pre-shared key for deriving TLS certificate identity (anti-MITM); also key for TCP/KCP encryption")
	enableCRLF        = flag.Bool("C", false, "enable CRLF")
	listenMode        = flag.Bool("l", false, "listen mode")
	udpProtocol       = flag.Bool("u", false, "use UDP protocol")
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
	useTurn           = flag.Bool("turn", false, "use STUN to discover public IP")
	turnServer        = flag.String("turnsrv", "turn.cloudflare.com:3478", "turn server, others: stunserver2025.stunprotocol.org:3478 ; stun.l.google.com:19302 (UDP only)")
	peer              = flag.String("peer", "", "peer address to connect, will send a ping/SYN for NAT punching")
	appMux            = flag.Bool("app-mux", false, "a Stream Multiplexing based proxy app")
	keepAlive         = flag.Int("keepalive", 0, "none 0 will enable TCP keepalive feature")
	punchData         = flag.String("punchdata", "ping\n", "UDP punch payload")
	MQTTServer        = flag.String("mqttsrv", "tcp://broker.hivemq.com:1883", "MQTT server, others: tcp://broker.emqx.io:1883 ; tcp://test.mosquitto.org:1883")
	autoP2P           = flag.String("p2p", "", "P2P session key (or @file). Auto try UDP/TCP via NAT traversal")
	autoP2PKCP        = flag.String("p2p-kcp", "", "P2P session key, kcp over udp, will be retried up to 3 times upon failure.")
	autoP2PTCP        = flag.String("p2p-tcp", "", "P2P session key, tcp, will be retried up to 3 times upon failure.")
	autoP2PTCPSS      = flag.String("p2p-ss", "", "p2p-tcp + AES-CTR")
	MQTTWait          = flag.String("mqtt-wait", "", "wait for MQTT hello message before initiating P2P connection")
	MQTTPush          = flag.String("mqtt-push", "", "send MQTT hello message before initiating P2P connection")
	useIPv4           = flag.Bool("4", false, "Forces to use IPv4 addresses only")
	useIPv6           = flag.Bool("6", false, "Forces to use IPv4 addresses only")
)

func init() {
	flag.StringVar(localbind, "local", "", "ip:port (alias for -bind)")
	flag.StringVar(&misc.TopicExchange, "mqtt-nat-topic", misc.TopicExchange, "")
	flag.StringVar(&misc.TopicExchangeWait, "mqtt-wait-topic", misc.TopicExchangeWait, "")
	flag.IntVar(&misc.PunchingShortTTL, "punch-short-ttl", misc.PunchingShortTTL, "")
	flag.IntVar(&misc.PunchingBatchPortSize, "punch-batch", misc.PunchingBatchPortSize, "brutely guess, 0 is disabled")
}

func init_TLS(genCertForced bool) {
	var err error
	if isTLSEnabled() {
		if *listenMode || *kcpSEnabled {
			*tlsServerMode = true
		}
		if genCertForced || *tlsServerMode {
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
				tls_cert_EC, err = misc.GenerateECDSACertificate(*tlsSNI, *presharedKey)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error generating EC certificate: %v\n", err)
					os.Exit(1)
				}
			}
			if *tlsRSACertEnabled {
				fmt.Fprintf(os.Stderr, "Generating RSA cert...")
				tls_cert_RSA, err = misc.GenerateRSACertificate(*tlsSNI)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error generating RSA certificate: %v\n", err)
					os.Exit(1)
				}
			}
			fmt.Fprintf(os.Stderr, "completed.\n")

		}
	}
}

func isTLSEnabled() bool {
	return *tlsServerMode || *tlsEnabled || *tls10_forced || *tls11_forced || *tls12_forced || *tls13_forced
}

func do_TLS(conn net.Conn) net.Conn {
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
		MaxVersion:               tls.VersionTLS12, // 最大支持 TLSv1.2
		PreferServerCipherSuites: true,             // 优先使用服务器的密码套件
	}
	if *tls10_forced {
		tlsConfig.MinVersion = tls.VersionTLS10
		tlsConfig.MaxVersion = tls.VersionTLS10
	}
	if *tls11_forced {
		tlsConfig.MinVersion = tls.VersionTLS11
		tlsConfig.MaxVersion = tls.VersionTLS11
	}
	if *tls12_forced {
		tlsConfig.MinVersion = tls.VersionTLS12
		tlsConfig.MaxVersion = tls.VersionTLS12
	}
	if *tls13_forced {
		tlsConfig.MinVersion = 0x0304
		tlsConfig.MaxVersion = 0x0304
	}
	timeout_sec := 20
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout_sec)*time.Second)
	defer cancel()
	// 使用 TLS 握手
	var conn_tls *tls.Conn
	var certs []tls.Certificate

	if tls_cert_RSA != nil {
		certs = append(certs, *tls_cert_RSA)
	}
	if tls_cert_EC != nil {
		certs = append(certs, *tls_cert_EC)
	}
	if *tlsServerMode {
		tlsConfig.Certificates = certs
		if *presharedKey != "" {
			tlsConfig.ClientAuth = tls.RequireAnyClientCert
			tlsConfig.VerifyPeerCertificate = misc.VerifyPeerCertificateByPSK(*presharedKey)
			fmt.Fprintf(os.Stderr, "Performing TLS-S handshake (PSK-based mutual authentication)...")
		} else {
			fmt.Fprintf(os.Stderr, "Performing TLS-S handshake...")
		}
		conn_tls = tls.Server(conn, tlsConfig)
	} else {
		tlsConfig.ServerName = *tlsSNI
		if *presharedKey != "" {
			tlsConfig.Certificates = certs
			tlsConfig.VerifyPeerCertificate = misc.VerifyPeerCertificateByPSK(*presharedKey)
			fmt.Fprintf(os.Stderr, "Performing TLS-C handshake (PSK-based mutual authentication)...")
		} else {
			fmt.Fprintf(os.Stderr, "Performing TLS-C handshake...")
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

func do_DTLS(conn net.Conn) net.Conn {
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

	pktconn := misc.NewPacketConnWrapper(conn, conn.RemoteAddr())

	intervalChange := make(chan time.Duration, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout_sec)*time.Second)
	defer cancel()
	// 开启NAT打洞， 首包是4秒后发出punch包
	startUDPKeepAlive(ctx, conn, []byte(*punchData), 4*time.Second, intervalChange)

	var certs []tls.Certificate
	if tls_cert_RSA != nil {
		certs = append(certs, *tls_cert_RSA)
	}
	if tls_cert_EC != nil {
		certs = append(certs, *tls_cert_EC)
	}

	if *tlsServerMode {
		dtlsConfig.Certificates = certs
		if *presharedKey != "" {
			dtlsConfig.ClientAuth = dtls.RequireAnyClientCert
			dtlsConfig.VerifyPeerCertificate = misc.VerifyPeerCertificateByPSK(*presharedKey)
			fmt.Fprintf(os.Stderr, "Performing DTLS-S handshake (PSK-based mutual authentication)...")
		} else {
			fmt.Fprintf(os.Stderr, "Performing DTLS-S handshake...")
		}
		//dtls.Server 不会主动发包，startUDPKeepAlive4秒后发出punch包有助于P2P建立通信
		dtlsConn, err = dtls.Server(pktconn, conn.RemoteAddr(), dtlsConfig)
	} else {
		dtlsConfig.ServerName = *tlsSNI
		if *presharedKey != "" {
			dtlsConfig.Certificates = certs
			dtlsConfig.VerifyPeerCertificate = misc.VerifyPeerCertificateByPSK(*presharedKey)
			fmt.Fprintf(os.Stderr, "Performing DTLS-C handshake (PSK-based mutual authentication)...")
		} else {
			fmt.Fprintf(os.Stderr, "Performing DTLS-C handshake...")
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
			if misc.IsConnRefused(err) {
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

func createDialer() proxy.Dialer {
	var err error
	// 如果指定了socks5代理
	if *socks5Addr != "" {
		// 设置SOCKS5代理
		var socks5Dialer proxy.Dialer
		if *auth != "" {
			// 如果指定了认证信息
			authParts := strings.SplitN(*auth, ":", 2)
			if len(authParts) != 2 {
				fmt.Fprintf(os.Stderr, "Invalid auth format. Expected user:pass\n")
				os.Exit(1)
			}

			// 创建SOCKS5代理客户端并进行认证
			socks5Dialer, err = proxy.SOCKS5("tcp", *socks5Addr, &proxy.Auth{
				User:     authParts[0],
				Password: authParts[1],
			}, proxy.Direct)
		} else {
			// 不使用认证
			socks5Dialer, err = proxy.SOCKS5("tcp", *socks5Addr, nil, proxy.Direct)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Create socks5 client failed: %v\n", err)
			os.Exit(1)
		}

		return socks5Dialer
	} else {
		return &net.Dialer{}
	}
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
					fmt.Fprintf(os.Stderr,
						"IN: %s (%d bytes), %s/s | OUT: %s (%d bytes), %s/s | %02d:%02d:%02d        \r",
						misc.FormatBytes(in.TotalBytes), in.TotalBytes, misc.FormatBytes(int64(in.SpeedBps)),
						misc.FormatBytes(out.TotalBytes), out.TotalBytes, misc.FormatBytes(int64(out.SpeedBps)),
						h, m, s,
					)
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
	fmt.Fprintln(os.Stderr, "go-netcat v1.6beta")
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "    gonc [-s5 socks5_ip:port] [-auth user:pass] [-sendfile path] [-tls] [-l] [-u] target_host target_port")
	fmt.Fprintln(os.Stderr, "         [-p2p sessionKey]")
	fmt.Fprintln(os.Stderr, "         [-h] for full help")
}

func main() {
	var err error
	flag.Parse()

	if *appMux {
		mux_main()
		return
	}

	if *sendfile != "" && *runCmd != "" {
		fmt.Fprintf(os.Stderr, "-sendfile and -exec cannot be used together\n")
		os.Exit(1)
	}
	if *enablePty && *enableCRLF {
		fmt.Fprintf(os.Stderr, "-pty and -C cannot be used together\n")
		os.Exit(1)
	}
	if *socks5Addr != "" && *localbind != "" {
		fmt.Fprintf(os.Stderr, "-bind and -s5 cannot be used together\n")
		os.Exit(1)
	}
	if *socks5Addr != "" && *udpProtocol {
		fmt.Fprintf(os.Stderr, "UDP over SOCKS5 is not supported\n")
		os.Exit(1)
	}
	if *localbind != "" && *listenMode {
		fmt.Fprintf(os.Stderr, "-bind and -l cannot be used together\n")
		os.Exit(1)
	}
	if *autoP2P != "" && (*autoP2PKCP != "" || *autoP2PTCP != "" || *autoP2PTCPSS != "") {
		fmt.Fprintf(os.Stderr, "-p2p and (-p2p-kcp, -p2p-tcp, -p2p-ss) cannot be used together\n")
		os.Exit(1)
	}
	if *presharedKey != "" && *tlsRSACertEnabled {
		fmt.Fprintf(os.Stderr, "-psk and -tlsrsa cannot be used together\n")
		os.Exit(1)
	}
	if *useIPv4 && *useIPv6 {
		fmt.Fprintf(os.Stderr, "-4 and -6 cannot be used together\n")
		os.Exit(1)
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
		secureStreamEnabled = true
		if strings.HasPrefix(*presharedKey, "@") {
			*presharedKey, err = ReadPSKFile(*presharedKey)
			if err != nil {
				panic(err)
			}
		}
	}

	var wg *sync.WaitGroup
	var done chan bool
	var conn net.Conn
	var network string
	var P2PSessionKey string
	var tryDiffNetwork bool
	if *udpProtocol {
		network = "udp"
	} else {
		network = "tcp"
	}
	if *useIPv4 {
		network += "4"
	} else if *useIPv6 {
		network += "6"
	}

	host := ""
	port := ""
	args := flag.Args()
	if len(args) == 2 {
		host = args[0]
		port = args[1]
	} else if len(args) == 1 && *listenMode {
		port = args[0]
	} else if len(args) == 0 && *remoteAddr != "" {
		host, port, err = net.SplitHostPort(*remoteAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid remote address %q: %v\n", *remoteAddr, err)
			os.Exit(1)
		}
	} else if len(args) == 0 && (*autoP2P != "" || *autoP2PKCP != "" || *autoP2PTCP != "" || *autoP2PTCPSS != "") {
		*listenMode = false
		if *autoP2P != "" {
			network = "any"
			P2PSessionKey = *autoP2P
			tryDiffNetwork = true
			*tlsEnabled = true //-p2p 默认开启tls安全通信
		} else if *autoP2PKCP != "" {
			tryDiffNetwork = false
			P2PSessionKey = *autoP2PKCP
			*kcpEnabled = true
			*udpProtocol = true
			network = "udp"
			// if *tlsServerMode || *kcpSEnabled {
			// 	misc.DebugServerRole = "S"
			// } else {
			// 	misc.DebugServerRole = "C"
			// }
		} else if *autoP2PTCP != "" {
			tryDiffNetwork = false
			P2PSessionKey = *autoP2PTCP
			*udpProtocol = false
			network = "tcp"
		} else if *autoP2PTCPSS != "" {
			tryDiffNetwork = false
			P2PSessionKey = *autoP2PTCPSS
			*udpProtocol = false
			secureStreamEnabled = true
			network = "tcp"
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

	genCertForced := *presharedKey != ""
	init_TLS(genCertForced)

	if P2PSessionKey != "" {
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
				conn, err = do_P2P_multistuns(network, P2PSessionKey, tryDiffNetwork)
				if err != nil {
					fmt.Fprintf(os.Stderr, "P2P failed: %v\n", err)
					time.Sleep(10 * time.Second)
					continue
				}
				handleConnection(conn, stats_in, stats_out)
				time.Sleep(2 * time.Second)
			}
		} else {
			conn, err = do_P2P_multistuns(network, P2PSessionKey, tryDiffNetwork)
			if err != nil {
				fmt.Fprintf(os.Stderr, "P2P failed: %v\n", err)
				os.Exit(1)
			}
			if tryDiffNetwork {
				network = conn.LocalAddr().Network()
			}
		}
	}

	dialer := createDialer()

	if *listenMode {
		// 监听模式
		listenAddr := net.JoinHostPort(host, port)
		if *udpProtocol {
			// 绑定UDP地址
			addr, err := net.ResolveUDPAddr(network, listenAddr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error resolving UDP address: %v\n", err)
				os.Exit(1)
			}

			if *useTurn {
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
			configUDPConn(uconn)
			fmt.Fprintf(os.Stderr, "Listening UDP on %s\n", uconn.LocalAddr().String())

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
					fmt.Fprintf(os.Stderr, "Waiting for initial UDP packet to establish session...\n")
					uconn.SetReadDeadline(time.Time{})
					buconn := misc.NewBoundUDPConn(uconn, "", true)
					if err = buconn.WaitAndLockRemote(); err != nil {
						fmt.Fprintf(os.Stderr, "ReadFromUDP failed: %v\n", err)
						os.Exit(1)
					}
					fmt.Fprintf(os.Stderr, "Received a UDP packet from %s\n", buconn.RemoteAddr().String())

					handleConnection(buconn, stats_in, stats_out)
					time.Sleep(1 * time.Second)
				}
			} else {
				if *peer != "" {
					peerIP, startPort, endPort := parsePeerAddressRange(*peer)
					data := []byte(*punchData)
					for port := startPort; port <= endPort; port++ {
						addrStr := net.JoinHostPort(peerIP, strconv.Itoa(port))
						peerAddr, err := net.ResolveUDPAddr(network, addrStr)
						if err != nil {
							fmt.Fprintf(os.Stderr, "Invalid peer address %s: %v\n", addrStr, err)
							continue
						}
						_, err = uconn.WriteToUDP(data, peerAddr)
						if err != nil {
							fmt.Fprintf(os.Stderr, "Failed to send punch packet to %s: %v\n", addrStr, err)
						}
					}
				}
				buconn := misc.NewBoundUDPConn(uconn, "", false)
				if err = buconn.WaitAndLockRemote(); err != nil {
					fmt.Fprintf(os.Stderr, "ReadFromUDP failed: %v\n", err)
					os.Exit(1)
				}
				fmt.Fprintf(os.Stderr, "Received first UDP packet from %s\n", buconn.RemoteAddr().String())
				conn = buconn
			}
		} else {
			//TCP listen
			var listener net.Listener
			var stopSynTrigger bool = false
			lc := net.ListenConfig{}
			if *peer != "" || *useTurn {
				lc.Control = misc.ControlTCP
			}
			listener, err = lc.Listen(context.Background(), network, listenAddr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error listening on %s: %v\n", listenAddr, err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Listening TCP on %s\n", listener.Addr().String())
			if *useTurn {
				err = ShowPublicIP(network, listener.Addr().String())
				if err != nil {
					panic(err)
				}
			}

			if *peer != "" {
				// 发起 outbound TCP SYN，触发 NAT 映射
				laddr, _ := net.ResolveTCPAddr(network, listener.Addr().String())

				go func() {
					for !stopSynTrigger {
						d := net.Dialer{
							LocalAddr: laddr,
							Timeout:   20 * time.Millisecond,
							Control:   misc.ControlTCPTTL, //小ttl，通常到不了对端
						}

						peerIP, startPort, endPort := parsePeerAddressRange(*peer)
						for port := startPort; port <= endPort; port++ {
							addrStr := net.JoinHostPort(peerIP, strconv.Itoa(port))
							peerAddr, err := net.ResolveTCPAddr(network, addrStr)
							if err != nil {
								fmt.Fprintf(os.Stderr, "Invalid peer address %s: %v\n", addrStr, err)
								continue
							}
							pc, err := d.Dial(network, peerAddr.String())
							if err == nil {
								if tcpCon, ok := conn.(*net.TCPConn); ok {
									tcpCon.SetLinger(0)
								}
								pc.Close()
							}
							fmt.Fprintf(os.Stderr, "Sent a TCP SYN(%s->%s) to trigger NAT mapping\n", laddr.String(), peerAddr.String())
							if !stopSynTrigger {
								time.Sleep(2 * time.Second)
							}
						}
					}
				}()

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
				defer listener.Close()
				for {
					conn, err = listener.Accept()
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error accepting connection: %v\n", err)
						continue
					}
					stopSynTrigger = true
					fmt.Fprintf(os.Stderr, "Connected from: %s        \n", conn.RemoteAddr().String())
					go handleConnection(conn, stats_in, stats_out)
				}
			} else {
				conn, err = listener.Accept()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error accepting connection: %v\n", err)
					os.Exit((1))
				}
				listener.Close()
				stopSynTrigger = true
				fmt.Fprintf(os.Stderr, "Connected from: %s\n", conn.RemoteAddr().String())
			}
		}
	} else if conn == nil {
		//主动连接模式
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

		if *useTurn {
			if *localbind == "" {
				panic("-turn need be with -bind while connecting")
			}
			err = ShowPublicIP(network, localAddr.String())
			if err != nil {
				panic(err)
			}
		}

		if strings.HasPrefix(host, "/") || port == "unix" {
			// Unix域套接字
			conn, err = net.Dial("unix", host)
		} else {
			// TCP/UDP 连接
			if localAddr == nil {
				conn, err = dialer.Dial(network, net.JoinHostPort(host, port))
			} else {
				dialer := &net.Dialer{
					LocalAddr: localAddr,
				}
				switch {
				case strings.HasPrefix(network, "tcp"):
					dialer.Control = misc.ControlTCP
				case strings.HasPrefix(network, "udp"):
					dialer.Control = misc.ControlUDP
				}
				conn, err = dialer.Dial(network, net.JoinHostPort(host, port))
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if strings.HasPrefix(network, "udp") {
			configUDPConn(conn)
			fmt.Fprintf(os.Stderr, "UDP socket ready for: %s\n", conn.RemoteAddr().String())
		} else {
			fmt.Fprintf(os.Stderr, "Connected to: %s\n", net.JoinHostPort(host, port))
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

	handleConnection(conn, stats_in, stats_out)
	if *progressEnabled {
		done <- true
		wg.Wait()
	}
}

// 新增的copyWithProgress函数用于在数据传输时显示进度
func copyWithProgress(dst io.Writer, src io.Reader, blocksize int, stats *misc.ProgressStats) {
	buf := make([]byte, blocksize)
	var n int
	var err, err1 error
	for {
		n, err1 = src.Read(buf)
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

		stats.Update(int64(n))
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
			stats.Update(int64(n))
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

func handleConnection(conn net.Conn, stats_in, stats_out *misc.ProgressStats) {
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	configTCPKeepalive(conn)

	// 如果启用 TLS，优先使用TLS作为安全加密层
	if isTLSEnabled() {
		if *udpProtocol {
			conn_dtls := do_DTLS(conn)
			if conn_dtls == nil {
				return
			}
			defer conn_dtls.Close()
			conn = conn_dtls
		} else {
			conn_tls := do_TLS(conn)
			if conn_tls == nil {
				return
			}
			defer conn_tls.Close()
			conn = conn_tls
		}
	}

	if isKCPEnabled() {
		sess_kcp := do_KCP(ctx, conn, 30*time.Second)
		if sess_kcp == nil {
			return
		}
		defer sess_kcp.Close()
		conn = sess_kcp
	}

	//如果没有TLS和KCP协议，-psk的密钥将直接对会话流进行加密，UDP由于非稳定传输NewSecureStreamConn不支持
	if secureStreamEnabled && !isTLSEnabled() && !*udpProtocol {
		var key32 [32]byte
		if sessionSharedKey != nil {
			copy(key32[:], sessionSharedKey)
			fmt.Fprintf(os.Stderr, "Communication is encrypted(ECDHE) with AES.\n")
		} else if *presharedKey != "" {
			k, err := misc.DerivePSK(*presharedKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to derive key for secure stream\n")
				return
			}
			copy(key32[:], k)
			fmt.Fprintf(os.Stderr, "Communication is encrypted(PSK) with AES.\n")
		} else {
			fmt.Fprintf(os.Stderr, "Missing key for secure stream\n")
			return
		}
		conn = misc.NewSecureStreamConn(conn, key32)
	}

	if !sessionReady {
		stats_in.ResetStart()
		stats_out.ResetStart()
		sessionReady = true
	}

	var input io.ReadCloser
	var output io.WriteCloser
	var binaryMode = true
	var cmd *exec.Cmd
	var err error
	var blocksize int = 32 * 1024
	if strings.HasPrefix(conn.LocalAddr().Network(), "udp") {
		blocksize = 1320
	}

	if *sendfile != "" {
		// 如果指定了 sendfile 参数，发送指定的文件
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
		output = os.Stdout
	} else if *runCmd != "" {
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

		if strings.TrimPrefix(args[0], "-") == "app-mux" {
			Appp_mux_main(conn, args[1:])
			return
		} else {

			// 创建命令
			cmd = exec.Command(args[0], args[1:]...)

			if *enablePty {
				ptmx, err := pty.Start(cmd)
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

	} else {
		// 使用标准输入输出
		input = os.Stdin
		output = os.Stdout
		binaryMode = false
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
		if err == nil && info.Mode()&os.ModeCharDevice != 0 && !binaryMode {
			if *enablePty {
				term_oldstat, err = term.MakeRaw(int(os.Stdin.Fd()))
				if err != nil {
					fmt.Fprintf(os.Stderr, "MakeRaw error: %v\n", err)
					return
				}
				defer term.Restore(int(os.Stdin.Fd()), term_oldstat)
				copyWithProgress(conn, input, blocksize, stats_out)
			} else {
				copyCharDeviceWithProgress(conn, input, stats_out)
			}
		} else {
			copyWithProgress(conn, input, blocksize, stats_out)
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

		copyWithProgress(output, conn, blocksize, stats_in)
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

func do_KCP(ctx context.Context, conn net.Conn, timeout time.Duration) net.Conn {
	var sess *kcp.UDPSession
	var err error
	var blockCrypt kcp.BlockCrypt
	var keyType = ""
	//如果已经有TLS加密了，则不再给KCP配置加密
	if sessionSharedKey != nil && !isTLSEnabled() {
		blockCrypt, err = createKCPBlockCryptFromKey(sessionSharedKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "createKCPBlockCryptFromKey failed: %v\n", err)
			return nil
		}
		keyType = "ECDHE"
	} else if *presharedKey != "" && !isTLSEnabled() {
		blockCrypt, err = createKCPBlockCrypt(*presharedKey, []byte("1234567890abcdef"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "createKCPBlockCrypt failed: %v\n", err)
			return nil
		}
		keyType = "PSK"
	}

	// 通知keepalive调整间隔
	intervalChange := make(chan time.Duration, 1)

	// 启动 keepalive
	startUDPKeepAlive(ctx, conn, []byte(*punchData), 2*time.Second, intervalChange)

	pktconn := misc.NewPacketConnWrapper(conn, conn.RemoteAddr())
	if *listenMode || *kcpSEnabled {
		if blockCrypt == nil {
			fmt.Fprintf(os.Stderr, "Performing KCP-S handshake...")
		} else {
			fmt.Fprintf(os.Stderr, "Performing encrypted(%s) KCP-S handshake...", keyType)
		}
		listener, err := kcp.ServeConn(blockCrypt, 10, 3, pktconn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ServeConn failed: %v\n", err)
			return nil
		}
		listener.SetDeadline(time.Now().Add(timeout))

		sessChan := make(chan *kcp.UDPSession, 1)
		errChan := make(chan error, 1)

		go func() {
			for {
				s, e := listener.AcceptKCP()
				if e != nil {
					if misc.IsConnRefused(e) {
						continue
					}
					errChan <- e
					return
				}
				sessChan <- s
				return
			}

		}()

		select {
		case sess = <-sessChan:
		case err = <-errChan:
			fmt.Fprintf(os.Stderr, "AcceptKCP failed: %v\n", err)
			return nil
		case <-time.After(timeout):
			fmt.Fprintf(os.Stderr, "timeout\n")
			return nil
		}
	} else {
		if blockCrypt == nil {
			fmt.Fprintf(os.Stderr, "Performing KCP-C handshake...")
		} else {
			fmt.Fprintf(os.Stderr, "Performing encrypted(%s) KCP-C handshake using...", keyType)
		}
		sess, err = kcp.NewConn(conn.RemoteAddr().String(), blockCrypt, 10, 3, pktconn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "NewConn failed: %v\n", err)
			return nil
		}
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

	// 告诉keep alive协程，把间隔调成15秒
	select {
	case intervalChange <- 15 * time.Second:
	default:
	}

	sess.SetNoDelay(1, 10, 2, 1)
	sess.SetWindowSize(512, 512)
	sess.SetMtu(1400)

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
	_, nata, err := misc.GetPublicIP(network, bind, *turnServer, 3*time.Second)
	if err == nil {
		fmt.Fprintf(os.Stderr, "Public Address: %s\n", nata)
	}

	return err
}

func Mqtt_ensure_ready(sessionKey string) error {
	var msg string
	var err error

	if *MQTTWait != "" {
		msg, err = misc.MqttWait(sessionKey, *MQTTServer, 10*time.Minute)
		if err != nil {
			return fmt.Errorf("mqtt-wait: %v", err)
		}
		if msg != *MQTTWait {
			return fmt.Errorf("mqtt-wait: not the expected message")
		}
	}

	if *MQTTPush != "" {
		err = misc.MqttPush(*MQTTPush, sessionKey, *MQTTServer)
		if err != nil {
			return fmt.Errorf("mqtt-push: %v", err)
		}
	}
	return nil
}

func do_P2P_multistuns(network, sessionKey string, tryDiffNetwork bool) (net.Conn, error) {
	if len(*turnServer) == 0 {
		return nil, fmt.Errorf("empty stunservers list")
	}

	var lastErr error
	stunsServers := strings.Split(*turnServer, ",")
	for _, stun := range stunsServers {
		stun = strings.TrimSpace(stun)
		if stun == "" {
			continue
		}

		conn, err := do_P2P(network, sessionKey, stun, tryDiffNetwork)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		if len(stunsServers) == 1 {
			return nil, lastErr
		}
		return nil, fmt.Errorf("all STUN servers failed, last error: %w", lastErr)
	}
	return nil, fmt.Errorf("no valid STUN servers provided")
}

func do_P2P(network, sessionKey, stunServer string, tryDiffNetwork bool) (net.Conn, error) {
	var err, err2 error
	var conn net.Conn
	var isRoleClient bool

	if tryDiffNetwork {
		err = Mqtt_ensure_ready(sessionKey)
		if err != nil {
			return nil, err
		}
		conn, isRoleClient, err = misc.Easy_P2P(network, sessionKey, stunServer, *MQTTServer)
		if err != nil {
			return nil, err
		}

		if strings.HasPrefix(conn.LocalAddr().Network(), "udp") {
			*udpProtocol = true
			if isRoleClient {
				*kcpSEnabled = false
				*kcpEnabled = true
			} else {
				*kcpSEnabled = true
				*kcpEnabled = false
			}
		} else {
			*udpProtocol = false
			*kcpSEnabled = false
			*kcpEnabled = false
		}
		*tlsEnabled = true
		if isTLSEnabled() {
			*tlsServerMode = !isRoleClient
		}
	} else if strings.HasPrefix(network, "udp") {
		err = Mqtt_ensure_ready(sessionKey)
		if err != nil {
			return nil, err
		}
		if network == "udp6" {
			conn, isRoleClient, sessionSharedKey, err = misc.Auto_P2P_UDP_NAT_Traversal(network, sessionKey, stunServer, *MQTTServer, true, 2)
			if err != nil {
				return nil, err
			}
		} else if network == "udp4" {
			conn, isRoleClient, sessionSharedKey, err = misc.Auto_P2P_UDP_NAT_Traversal(network, sessionKey, stunServer, *MQTTServer, true, 4)
			if err != nil {
				return nil, err
			}
		} else {
			conn, isRoleClient, sessionSharedKey, err = misc.Auto_P2P_UDP_NAT_Traversal("udp6", sessionKey, stunServer, *MQTTServer, true, 2)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
				conn, isRoleClient, sessionSharedKey, err2 = misc.Auto_P2P_UDP_NAT_Traversal("udp4", sessionKey, stunServer, *MQTTServer, true, 4)
				if err2 != nil {
					//返回udp4的err
					return nil, err
				}
			}
		}

		*udpProtocol = true
		if isRoleClient {
			//client mode
			*kcpSEnabled = false
			*kcpEnabled = true
		} else {
			*kcpSEnabled = true
			*kcpEnabled = false
		}
		if isTLSEnabled() {
			*tlsServerMode = !isRoleClient
		}
	} else if strings.HasPrefix(network, "tcp") {
		err = Mqtt_ensure_ready(sessionKey)
		if err != nil {
			return nil, err
		}
		if network == "tcp6" {
			conn, isRoleClient, sessionSharedKey, err = misc.Auto_P2P_TCP_NAT_Traversal(network, sessionKey, stunServer, *MQTTServer, secureStreamEnabled, 2)
			if err != nil {
				return nil, err
			}
		} else if network == "tcp4" {
			conn, isRoleClient, sessionSharedKey, err = misc.Auto_P2P_TCP_NAT_Traversal(network, sessionKey, stunServer, *MQTTServer, secureStreamEnabled, 4)
			if err != nil {
				return nil, err
			}
		} else {
			conn, isRoleClient, sessionSharedKey, err = misc.Auto_P2P_TCP_NAT_Traversal("tcp6", sessionKey, stunServer, *MQTTServer, secureStreamEnabled, 2)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
				conn, isRoleClient, sessionSharedKey, err2 = misc.Auto_P2P_TCP_NAT_Traversal("tcp4", sessionKey, stunServer, *MQTTServer, secureStreamEnabled, 4)
				if err2 != nil {
					//返回tcp4的err
					return nil, err
				}
			}
		}
		if secureStreamEnabled {
			if sessionSharedKey == nil || len(sessionSharedKey) != 32 {
				conn.Close()
				return nil, fmt.Errorf("expect a 32 bytes session key")
			}
		}
		*udpProtocol = false
		*kcpSEnabled = false
		*kcpEnabled = false
		if isTLSEnabled() {
			*tlsServerMode = !isRoleClient
		}
	} else {
		return nil, fmt.Errorf("unexpected p2p mode")
	}

	if conn != nil {
		if strings.HasPrefix(network, "udp") {
			configUDPConn(conn)
			fmt.Fprintf(os.Stderr, "UDP socket ready for: %s\n", conn.RemoteAddr().String())
		} else {
			fmt.Fprintf(os.Stderr, "Connected to: %s\n", conn.RemoteAddr().String())
		}
	}

	return conn, nil
}

func parsePeerAddressRange(peer string) (host string, startPort, endPort int) {
	host, portPart, err := net.SplitHostPort(peer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid peer address: %v\n", err)
		os.Exit(1)
	}

	if strings.Contains(portPart, "-") {
		ports := strings.SplitN(portPart, "-", 2)
		startPort, err = strconv.Atoi(ports[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid start port: %v\n", err)
			os.Exit(1)
		}
		endPort, err = strconv.Atoi(ports[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid end port: %v\n", err)
			os.Exit(1)
		}
		if startPort > endPort {
			fmt.Fprintf(os.Stderr, "Start port greater than end port\n")
			os.Exit(1)
		}
	} else {
		startPort, err = strconv.Atoi(portPart)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid port: %v\n", err)
			os.Exit(1)
		}
		endPort = startPort
	}

	return host, startPort, endPort
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
