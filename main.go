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
	"strings"
	"time"
	"unicode"

	"gonc/misc"
	"gonc/pty"

	"github.com/pion/dtls/v2"
	"github.com/pion/stun"
	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/net/proxy"
	"golang.org/x/term"
)

var (
	tls_cert *tls.Certificate = nil
	// 定义命令行参数
	socks5Addr       = flag.String("s5", "", "ip:port (SOCKS5 proxy)")
	auth             = flag.String("auth", "", "user:password for SOCKS5 proxy; preshared key for kcp")
	sendfile         = flag.String("sendfile", "", "path to file to send (optional)")
	tlsEnabled       = flag.Bool("tls", false, "Enable TLS connection")
	tlsServerMode    = flag.Bool("tlsserver", false, "force as TLS server while connecting")
	tls10_forced     = flag.Bool("tls10", false, "force negotiation to specify TLS version")
	tls11_forced     = flag.Bool("tls11", false, "force negotiation to specify TLS version")
	tls12_forced     = flag.Bool("tls12", false, "force negotiation to specify TLS version")
	tls13_forced     = flag.Bool("tls13", false, "force negotiation to specify TLS version")
	tlsSNI           = flag.String("sni", "", "specify TLS SNI")
	enableCRLF       = flag.Bool("C", false, "enable CRLF")
	listenMode       = flag.Bool("l", false, "listen mode")
	udpProtocol      = flag.Bool("u", false, "use UDP protocol")
	kcpEnabled       = flag.Bool("kcp", false, "use UDP+KCP protocol, -u can be omitted")
	localbind        = flag.String("bind", "", "ip:port")
	showSendProgress = flag.Bool("outprogress", false, "show transfer progress")
	showRecvProgress = flag.Bool("inprogress", false, "show transfer progress")
	runCmd           = flag.String("exec", "", "runs a command for each connection")
	mergeStderr      = flag.Bool("stderr", false, "when -exec, Merge stderr into stdout ")
	keepOpen         = flag.Bool("keep-open", false, "keep listening after client disconnects")
	enablePty        = flag.Bool("pty", false, "<-exec> will run in a pseudo-terminal, and put the terminal into raw mode")
	term_oldstat     *term.State
	useTurn          = flag.Bool("turn", false, "use STUN to discover public IP")
	turnServer       = flag.String("turnsrv", "turn.cloudflare.com:3478", "turn server")
	peer             = flag.String("peer", "", "peer address to connect, will send a ping/SYN for NAT punching")
	appMux           = flag.Bool("app-mux", false, "a Stream Multiplexing based proxy app")
	keepAlive        = flag.Int("keepalive", 0, "none 0 will enable TCP keepalive feature")
	punchData        = flag.String("punchdata", "ping\n", "UDP punch payload")
)

func init_TLS() {
	var err error
	if *tlsServerMode || *listenMode {
		if isTLSEnabled() {
			fmt.Fprintf(os.Stderr, "Generating certificate...\n")
			tls_cert, err = misc.GenerateCertificate(*tlsSNI)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error generating certificate: %v\n", err)
				os.Exit(1)
			}
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

	// 创建 TLS 配置，支持 SSL3 以及至少 TLSv1
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
	// 使用 TLS 握手
	var conn_tls *tls.Conn
	if *listenMode || *tlsServerMode {
		tlsConfig.Certificates = []tls.Certificate{*tls_cert}
		conn_tls = tls.Server(conn, tlsConfig)
	} else {
		tlsConfig.ServerName = *tlsSNI
		conn_tls = tls.Client(conn, tlsConfig)
	}
	if err := conn_tls.Handshake(); err != nil {
		fmt.Fprintf(os.Stderr, "TLS Handshake failed: %v\n", err)
		return nil
	}
	fmt.Fprintf(os.Stderr, "TLS Handshake completed.\n")
	return conn_tls
}

func do_DTLS(conn net.Conn) net.Conn {
	// 支持的 CipherSuites（pion 这里和 crypto/tls 不同）
	allCiphers := []dtls.CipherSuiteID{
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		dtls.TLS_PSK_WITH_AES_128_CCM,
	}

	// DTLS 配置
	dtlsConfig := &dtls.Config{
		CipherSuites:         allCiphers,
		InsecureSkipVerify:   true, // 和 tls.Config 一样，跳过证书校验
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	}

	// DTLS Server / Client 模式
	var dtlsConn *dtls.Conn
	var err error
	if *listenMode || *tlsServerMode {
		dtlsConfig.Certificates = []tls.Certificate{*tls_cert}
		dtlsConn, err = dtls.Server(conn, dtlsConfig)
	} else {
		dtlsConn, err = dtls.Client(conn, dtlsConfig)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "DTLS Handshake failed: %v\n", err)
		return nil
	}

	fmt.Fprintf(os.Stderr, "DTLS Handshake completed.\n")
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

func showProgress(stats_in, stats_out *misc.ProgressStats) *time.Ticker {
	// 启动进度显示
	ticker := time.NewTicker(1000 * time.Millisecond)
	go func() {
		for range ticker.C {
			if *showSendProgress {
				fmt.Fprintf(os.Stderr, "%s        \r", stats_out.String(false))
			}
			if *showRecvProgress {
				fmt.Fprintf(os.Stderr, "%s        \r", stats_in.String(false))
			}
		}
	}()
	return ticker
}

func usage() {
	fmt.Fprintln(os.Stderr, "go-netcat v1.2")
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "    gonc [-s5 socks5_ip:port] [-auth user:pass] [-sendfile path] [-tls] [-l] [-u] target_host target_port")
}

func main() {

	flag.Parse()

	if *appMux {
		mux_main()
		return
	}

	// 获取目标地址和端口
	host := ""
	port := ""
	args := flag.Args()
	if len(args) == 2 {
		host = args[0]
		port = args[1]
		if *tlsSNI == "" {
			*tlsSNI = host
		}
	} else if len(args) == 1 && *listenMode {
		port = args[0]
		if *tlsSNI == "" {
			*tlsSNI = "localhost"
		}
	} else {
		usage()
		os.Exit(1)
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
	if *kcpEnabled {
		*udpProtocol = true
	}

	var err error

	init_TLS()

	dialer := createDialer()

	var conn net.Conn

	if *listenMode {
		// 监听模式
		listenAddr := net.JoinHostPort(host, port)
		if *udpProtocol {
			// 绑定UDP地址
			addr, err := net.ResolveUDPAddr("udp", listenAddr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error resolving UDP address: %v\n", err)
				os.Exit(1)
			}

			if *useTurn {
				err = getPublicIP("udp", addr.String(), 3*time.Second)
				if err != nil {
					panic(err)
				}
			}

			uconn, err := net.ListenUDP("udp", addr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error listening on UDP address: %v\n", err)
				os.Exit(1)
			}
			configUDPConn(uconn)
			fmt.Fprintf(os.Stderr, "Listening UDP on %s\n", uconn.LocalAddr().String())
			if *peer != "" {
				peerAddr, err := net.ResolveUDPAddr("udp", *peer)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Invalid peer address: %v\n", err)
					os.Exit(1)
				}

				data := []byte(*punchData)
				_, err = uconn.WriteToUDP(data, peerAddr)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to send punch packet: %v\n", err)
					os.Exit(1)
				} else {
					fmt.Fprintf(os.Stderr, "Sent punch packet to %s\n", peerAddr.String())
				}
			}
			uaddr, err := misc.PeekSourceAddr(uconn)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to peek first packet: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Received first UDP packet from %s\n", uaddr.String())

			conn = misc.NewBoundUDPConn(uconn, uaddr)
		} else {
			var listener net.Listener
			var stopSynTrigger bool = false
			lc := net.ListenConfig{}
			if *peer != "" || *useTurn {
				lc.Control = misc.ControlTCP
			}
			listener, err = lc.Listen(context.Background(), "tcp", listenAddr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error listening on %s: %v\n", listenAddr, err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Listening TCP on %s\n", listener.Addr().String())
			if *useTurn {
				err = getPublicIP("tcp", listener.Addr().String(), 3*time.Second)
				if err != nil {
					panic(err)
				}
			}

			if *peer != "" {
				// 发起一次 outbound TCP SYN，触发 NAT 映射
				laddr, _ := net.ResolveTCPAddr("tcp", listener.Addr().String())
				raddr, err := net.ResolveTCPAddr("tcp", *peer)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error resolving %s: %v\n", *peer, err)
					os.Exit(1)
				}

				go func() {

					for !stopSynTrigger {
						d := net.Dialer{
							LocalAddr: laddr,
							Timeout:   20 * time.Millisecond,
							Control:   misc.ControlTCP,
						}
						pc, err := d.Dial("tcp", raddr.String())
						if err == nil {
							if tcpCon, ok := conn.(*net.TCPConn); ok {
								tcpCon.SetLinger(0)
							}
							pc.Close()
						}
						fmt.Fprintf(os.Stderr, "Sent a TCP SYN(%s->%s) to trigger NAT mapping\n", laddr.String(), raddr.String())
						if !stopSynTrigger {
							time.Sleep(2 * time.Second)
						}
					}
				}()

			}

			if *keepOpen {
				// 创建进度统计
				stats_in := misc.NewProgressStats()
				stats_out := misc.NewProgressStats()
				// 启动进度显示
				showProgress(stats_in, stats_out)

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
	} else {
		//主动连接模式
		var localAddr net.Addr
		var network string
		if *udpProtocol {
			network = "udp"
		} else {
			network = "tcp"
		}

		if *localbind != "" {
			if *udpProtocol {
				localAddr, err = net.ResolveUDPAddr("udp", *localbind)
			} else {
				localAddr, err = net.ResolveTCPAddr("tcp", *localbind)
			}
			if err != nil {
				panic(err)
			}
		}

		if *useTurn {
			if *localbind == "" {
				panic("-turn need be with -bind while connecting")
			}
			err = getPublicIP(network, localAddr.String(), 3*time.Second)
			if err != nil {
				panic(err)
			}
		}

		if strings.HasPrefix(host, "/") || port == "unix" {
			// Unix域套接字
			conn, err = net.Dial("unix", host)
		} else {
			// TCP连接
			if localAddr == nil {
				conn, err = dialer.Dial(network, net.JoinHostPort(host, port))
			} else {
				dialer := &net.Dialer{
					LocalAddr: localAddr,
				}
				switch network {
				case "tcp":
					dialer.Control = misc.ControlTCP
				case "udp":
					dialer.Control = misc.ControlUDP
				}
				conn, err = dialer.Dial(network, net.JoinHostPort(host, port))
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		configUDPConn(conn)
		fmt.Fprintf(os.Stderr, "Connected to: %s\n", net.JoinHostPort(host, port))
	}

	// 创建进度统计
	stats_in := misc.NewProgressStats()
	stats_out := misc.NewProgressStats()

	// 启动进度显示
	ticker := showProgress(stats_in, stats_out)
	handleConnection(conn, stats_in, stats_out)
	ticker.Stop()
	if *showSendProgress {
		fmt.Fprintf(os.Stderr, "%s\n", stats_out.String(true))
	}
	if *showRecvProgress {
		fmt.Fprintf(os.Stderr, "%s\n", stats_in.String(true))
	}
}

// 发送文件并输出传输速度
func sendFile(filepath string, conn net.Conn, stats *misc.ProgressStats) {
	var file io.ReadCloser
	var err, err1 error
	var n int
	if filepath == "/dev/zero" || filepath == "/dev/urandom" {
		file, err = misc.NewPseudoDevice(filepath)
	} else {
		file, err = os.Open(filepath)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	// 使用自定义复制函数以便更新统计信息
	var bufsize = 32 * 1024
	if conn.LocalAddr().Network() == "udp" {
		bufsize = 1320
	}
	buf := make([]byte, bufsize)
	for {
		n, err1 = file.Read(buf)
		if err1 != nil && err1 != io.EOF {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err1)
			break
		}
		if n == 0 {
			break
		}

		_, err = conn.Write(buf[:n])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error sending data: %v\n", err)
			break
		}

		stats.Update(int64(n))
		if err1 == io.EOF {
			break
		}
	}
}

// 新增的copyWithProgress函数用于在数据传输时显示进度
func copyWithProgress(dst io.Writer, src io.Reader, stats *misc.ProgressStats) {
	buf := make([]byte, 32*1024)
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

		// 注意：line读到的可能是 "\r\n" 或 "\n"，都要统一处理
		line = strings.TrimRight(line, "\r\n") // 去掉任何结尾的 \r 或 \n
		if *enableCRLF {
			line += "\r\n" // 统一加上 CRLF
		} else {
			line += "\n"
		}

		n, err = writer.WriteString(line)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Write error: %v\n", err)
			break
		}
		writer.Flush()
		stats.Update(int64(n))

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

	configKeepalive(conn)

	// 如果启用 TLS，进行 TLS 握手
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

	if *kcpEnabled {
		sess_kcp := do_KCP(conn)
		if sess_kcp == nil {
			return
		}
		defer sess_kcp.Close()
		conn = sess_kcp
	}

	// 如果指定了 sendfile 参数，发送指定的文件
	if *sendfile != "" {
		sendFile(*sendfile, conn, stats_out)
		time.Sleep(1 * time.Second)
		// 关闭连接
		if tcpConn, ok := conn.(closeWriter); ok {
			tcpConn.CloseWrite()
		} else {
			conn.Close()
		}
		return
	}

	var input io.Reader
	var output io.WriteCloser
	var cmd *exec.Cmd

	if *runCmd != "" {
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

		// 创建命令
		cmd = exec.Command(args[0], args[1:]...)

		if *enablePty {
			ptmx, err := pty.Start(cmd)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to start pty: %v", err)
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

		go func() {
			copyWithProgress(conn, input, stats_out)
			time.Sleep(1 * time.Second)
			// 关闭连接
			if tcpConn, ok := conn.(closeWriter); ok {
				tcpConn.CloseWrite()
			} else {
				conn.Close()
			}
		}()

	} else {
		// 使用标准输入输出
		input = os.Stdin
		output = os.Stdout

		go func() {
			info, err := os.Stdin.Stat()
			if err == nil && info.Mode()&os.ModeCharDevice != 0 {
				if *enablePty {
					term_oldstat, err = term.MakeRaw(int(os.Stdin.Fd()))
					if err != nil {
						fmt.Fprintf(os.Stderr, "MakeRaw error: %v\n", err)
						return
					}
					defer term.Restore(int(os.Stdin.Fd()), term_oldstat)
					copyWithProgress(conn, input, stats_out)
				} else {
					copyCharDeviceWithProgress(conn, input, stats_out)
				}
			} else {
				copyWithProgress(conn, input, stats_out)
			}

			time.Sleep(1 * time.Second)
			// 关闭连接
			if tcpConn, ok := conn.(closeWriter); ok {
				tcpConn.CloseWrite()
			} else {
				conn.Close()
			}
		}()
	}

	// 从连接读取并输出到输出
	copyWithProgress(output, conn, stats_in)
	time.Sleep(1 * time.Second)
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

func getPublicIP(network, bind string, timeout time.Duration) (err error) {

	var laddr net.Addr

	switch network {
	case "tcp":
		laddr, err = net.ResolveTCPAddr("tcp", bind)
		if err != nil {
			return fmt.Errorf("resolve local tcp addr failed: %v", err)
		}
	case "udp":
		laddr, err = net.ResolveUDPAddr("udp", bind)
		if err != nil {
			return fmt.Errorf("resolve local udp addr failed: %v", err)
		}
	default:
		return fmt.Errorf("unsupported network: %s", network)
	}

	d := &net.Dialer{
		LocalAddr: laddr,
		Timeout:   timeout,
	}

	switch network {
	case "tcp":
		d.Control = misc.ControlTCP
	case "udp":
		d.Control = misc.ControlUDP
	}

	conn, err := d.Dial(network, *turnServer)
	if err != nil {
		return fmt.Errorf("STUN dial failed: %v", err)
	}

	c, err := stun.NewClient(conn)
	if err != nil {
		conn.Close()
		return fmt.Errorf("STUN NewClient failed: %v", err)
	}

	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	var xorAddr stun.XORMappedAddress
	var err2 error
	if err := c.Do(message, func(res stun.Event) {
		if res.Error != nil {
			err2 = fmt.Errorf("STUN error: %v", res.Error)
			return
		}
		// 解析XOR-MAPPED-ADDRESS属性
		if err := xorAddr.GetFrom(res.Message); err != nil {
			err2 = fmt.Errorf("failed to get XOR-MAPPED-ADDRESS: %v", err)
			return
		}
	}); err != nil {
		return fmt.Errorf("STUN Do failed: %v", err)
	}
	if err2 != nil {
		return err2
	}

	//fmt.Fprintf(os.Stderr, "Local  Address: %s\n", conn.LocalAddr().String())
	fmt.Fprintf(os.Stderr, "Public Address: %s\n", xorAddr.String())

	//tcp不关闭连接，保持连接有助于NAT穿透，如果有连接关闭了可能NAT打开的洞也关闭
	if network == "tcp" {
		go func() {
			buf := make([]byte, 1)
			_, _ = conn.Read(buf)
			c.Close()
		}()
	} else {
		c.Close()
	}

	return nil
}

func configKeepalive(conn net.Conn) {
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

func do_KCP(conn net.Conn) net.Conn {
	var sess *kcp.UDPSession
	var err error
	var blockCrypt kcp.BlockCrypt

	if *auth != "" {
		blockCrypt, err = createKCPBlockCrypt(*auth, []byte("1234567890abcdef"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "createKCPBlockCrypt failed: %v\n", err)
			return nil
		}
	}

	pktconn := misc.NewPacketConnWrapper(conn, conn.RemoteAddr())
	if *listenMode {
		listener, err := kcp.ServeConn(blockCrypt, 10, 3, pktconn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "kcp ServeConn failed: %v\n", err)
			return nil
		}

		sess, err = listener.AcceptKCP()
		if err != nil {
			fmt.Fprintf(os.Stderr, "AcceptKCP failed: %v\n", err)
			return nil
		}
		buf := make([]byte, 1)
		n, err := sess.Read(buf)
		if err != nil || n != 1 || buf[0] != '\n' {
			fmt.Fprintf(os.Stderr, "kcp NewConn Handshake failed: %v\n", err)
			return nil
		}

		fmt.Fprintf(os.Stderr, "New KCP connection from %s\n", sess.RemoteAddr())
	} else {
		sess, err = kcp.NewConn(conn.RemoteAddr().String(), blockCrypt, 10, 3, pktconn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "kcp NewConn failed: %v\n", err)
			return nil
		}
		_, err := sess.Write([]byte("\n"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "kcp NewConn Handshake failed: %v\n", err)
			return nil
		}
	}
	sess.SetNoDelay(1, 10, 2, 1)
	sess.SetWindowSize(512, 512)
	sess.SetMtu(1400)
	return sess
}
