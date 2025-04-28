package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode"

	"golang.org/x/net/proxy"
)

var (
	tls_cert *tls.Certificate = nil
	// 定义命令行参数
	socks5Addr       = flag.String("s5", "", "ip:port (SOCKS5 proxy)")
	auth             = flag.String("auth", "", "user:password (for SOCKS5 proxy)")
	sendfile         = flag.String("sendfile", "", "path to file to send (optional)")
	tlsEnabled       = flag.Bool("tls", false, "Enable TLS connection")
	tls10_forced     = flag.Bool("tls10", false, "")
	tls11_forced     = flag.Bool("tls11", false, "")
	tls12_forced     = flag.Bool("tls12", false, "")
	tls13_forced     = flag.Bool("tls13", false, "")
	tlsSNI           = flag.String("sni", "", "")
	enableCRLF       = flag.Bool("C", false, "enable CRLF")
	listenMode       = flag.Bool("l", false, "listen mode")
	udpProtocol      = flag.Bool("u", false, "use UDP protocol")
	localbind        = flag.String("bind", "", "ip:port")
	showSendProgress = flag.Bool("outprogress", false, "show transfer progress")
	showRecvProgress = flag.Bool("inprogress", false, "show transfer progress")
	runCmd           = flag.String("exec", "", "runs a command for each connection")
	mergeStderr      = flag.Bool("stderr", false, "when -exec, Merge stderr into stdout ")
	keepOpen         = flag.Bool("keep-open", false, "keep listening after client disconnects")
)

// 新增的进度统计和伪设备相关代码
type ProgressStats struct {
	startTime    time.Time
	totalBytes   int64
	lastBytes    int64     // 上次统计时的字节数
	lastTime     time.Time // 上次统计时间
	lastSpeed    float64   // 上次计算的速度（字节/秒）
	lastSpeedStr string
}

func NewProgressStats() *ProgressStats {
	now := time.Now()
	return &ProgressStats{
		startTime: now,
		lastTime:  now,
	}
}

func (p *ProgressStats) Update(n int64) {
	p.totalBytes += n
}

func (p *ProgressStats) String(final bool) string {
	now := time.Now()
	// 计算瞬时速度（最近一次间隔的速度）
	timeDiff := now.Sub(p.lastTime).Seconds()
	bytesDiff := p.totalBytes - p.lastBytes
	if final {
		timeDiff = now.Sub(p.startTime).Seconds()
		bytesDiff = p.totalBytes
	}

	var speed float64
	if timeDiff > 0 {
		speed = float64(bytesDiff) / timeDiff
		p.lastSpeed = speed // 保存最后一次计算的速度
	} else {
		speed = p.lastSpeed // 使用上次计算的速度
	}

	// 更新最后统计时间和字节数
	p.lastTime = now
	p.lastBytes = p.totalBytes

	// 计算总时间
	totalElapsed := now.Sub(p.startTime).Seconds()
	hours := int(totalElapsed) / 3600
	minutes := (int(totalElapsed) % 3600) / 60
	seconds := int(totalElapsed) % 60

	// 格式化输出
	sizeStr := formatBytes(p.totalBytes)
	speedStr := formatBytes(int64(speed)) + "/s"

	p.lastSpeedStr = fmt.Sprintf("%d bytes (%s) copied, %02d:%02d:%02d, %s",
		p.totalBytes, sizeStr, hours, minutes, seconds, speedStr)
	return p.lastSpeedStr
}

func formatBytes(bytes int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB"}
	value := float64(bytes)

	for _, unit := range units {
		if value < 1024.0 {
			return fmt.Sprintf("%.1f %s", value, unit)
		}
		value /= 1024.0
	}
	return fmt.Sprintf("%.1f YiB", value)
}

// 伪设备实现
type PseudoDevice struct {
	name string
}

func NewPseudoDevice(name string) (*PseudoDevice, error) {
	validDevices := map[string]bool{
		"/dev/zero":    true,
		"/dev/urandom": true,
		"/dev/null":    true,
	}
	if !validDevices[name] {
		return nil, fmt.Errorf("unknown device name")
	}
	return &PseudoDevice{name: name}, nil
}

func (d *PseudoDevice) Read(p []byte) (n int, err error) {
	switch d.name {
	case "/dev/zero":
		for i := range p {
			p[i] = 0
		}
		return len(p), nil
	case "/dev/urandom":
		return rand.Read(p)
	default:
		return 0, io.EOF
	}
}

func (d *PseudoDevice) Write(p []byte) (n int, err error) {
	if d.name == "/dev/null" {
		return len(p), nil
	}
	return 0, fmt.Errorf("device not writable")
}

func (d *PseudoDevice) Close() error {
	return nil
}

func generateCACertificate(sni string) ([]byte, []byte, error) {
	// 生成 RSA 密钥对
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}

	// 生成随机序列号
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	// 准备自签名证书模板
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   sni,
			Organization: []string{sni},
		},
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// 生成自签名 CA 证书
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	key := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return cert, key, nil
}

func generateCertificate(sni string) (*tls.Certificate, error) {
	ca_data, cakey_data, err := generateCACertificate(sni)
	if err != nil {
		return nil, err
	}
	caCertBlock, _ := pem.Decode(ca_data)
	caKeyBlock, _ := pem.Decode(cakey_data)
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, err
	}
	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	// // 生成 RSA 密钥对
	// privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	// if err != nil {
	// 	return nil, err
	// }
	// 直接使用 CA 证书的私钥，而不生成新的私钥
	privateKey := caKey

	// 生成随机序列号
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	// 创建证书
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: sni,
		},
		NotBefore:   time.Now().AddDate(-1, 0, 0),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{sni},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &privateKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// 将证书和私钥组合为 tls.Certificate
	certificate, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		return nil, err
	}

	return &certificate, nil
}

func do_TLS(conn net.Conn) net.Conn {
	// 创建 TLS 配置，支持 SSL3 以及至少 TLSv1
	tlsConfig := &tls.Config{
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
	if *listenMode {
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

func showProgress(stats_in, stats_out *ProgressStats) *time.Ticker {
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

type closeWriter interface {
	CloseWrite() error
}

func usage() {
	fmt.Println("go-netcat v1.0")
	fmt.Println("Usage:")
	fmt.Println("    gonc [-s5 socks5_ip:port] [-auth user:pass] [-sendfile path] [-tls] [-l] [-u] target_host target_port")
}

func main() {

	flag.Parse()

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

	// 如果指定了socks5代理
	var dialer proxy.Dialer
	if *socks5Addr != "" {
		// 设置SOCKS5代理
		var socks5Dialer proxy.Dialer
		var err error
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

		dialer = socks5Dialer
	} else {
		dialer = &net.Dialer{}
	}

	var conn net.Conn
	var err error

	// 监听模式
	if *listenMode {
		listenAddr := fmt.Sprintf("%s:%s", host, port)
		if *udpProtocol {
			// 绑定UDP地址
			addr, err := net.ResolveUDPAddr("udp", listenAddr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error resolving UDP address: %v\n", err)
				os.Exit(1)
			}

			conn, err = net.ListenUDP("udp", addr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error listening on UDP address: %v\n", err)
				os.Exit(1)
			}

		} else {
			if *tlsEnabled || *tls10_forced || *tls11_forced || *tls12_forced || *tls13_forced {
				fmt.Fprintf(os.Stderr, "Generating certificate...\n")
				tls_cert, err = generateCertificate(*tlsSNI)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error generating certificate: %v\n", err)
					os.Exit(1)
				}
			}

			listener, err := net.Listen("tcp", listenAddr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error listening on %s: %v\n", listenAddr, err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Listening on %s\n", listenAddr)

			if *keepOpen {
				// 创建进度统计
				stats_in := NewProgressStats()
				stats_out := NewProgressStats()
				// 启动进度显示
				showProgress(stats_in, stats_out)

				defer listener.Close()
				for {
					conn, err = listener.Accept()
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error accepting connection: %v\n", err)
						continue
					}
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
				fmt.Fprintf(os.Stderr, "Connected from: %s\n", conn.RemoteAddr().String())
			}
		}
	} else {
		var localAddr *net.TCPAddr
		if *localbind != "" {
			localAddr, err = net.ResolveTCPAddr("tcp", *localbind)
			if err != nil {
				panic(err)
			}
		}
		// 连接模式，使用UDP
		if *udpProtocol {
			// UDP 连接
			conn, err = net.Dial("udp", fmt.Sprintf("%s:%s", host, port))
		} else {
			if strings.HasPrefix(host, "/") || port == "unix" {
				// Unix域套接字
				conn, err = net.Dial("unix", host)
			} else {
				// TCP连接
				if localAddr == nil {
					conn, err = dialer.Dial("tcp", fmt.Sprintf("%s:%s", host, port))
				} else {
					dialer := &net.Dialer{
						LocalAddr: localAddr,
					}
					conn, err = dialer.Dial("tcp", fmt.Sprintf("%s:%s", host, port))
				}

			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Connected to: %s\n", fmt.Sprintf("%s:%s", host, port))
	}

	// 创建进度统计
	stats_in := NewProgressStats()
	stats_out := NewProgressStats()

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
func sendFile(filepath string, conn net.Conn, stats *ProgressStats) {
	var file io.ReadCloser
	var err error
	if filepath == "/dev/zero" || filepath == "/dev/urandom" {
		file, err = NewPseudoDevice(filepath)
	} else {
		file, err = os.Open(filepath)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	// 使用自定义复制函数以便更新统计信息
	buf := make([]byte, 32*1024)
	for {
		n, err := file.Read(buf)
		if err != nil && err != io.EOF {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
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
	}
}

// 新增的copyWithProgress函数用于在数据传输时显示进度
func copyWithProgress(dst io.Writer, src io.Reader, stats *ProgressStats) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if err != nil && err != io.EOF {
			fmt.Fprintf(os.Stderr, "Read error: %v\n", err)
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
	}
}

func copyCharDeviceWithProgress(dst io.Writer, src io.Reader, stats *ProgressStats) {

	reader := bufio.NewReader(src)
	writer := bufio.NewWriter(dst)

	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			fmt.Fprintf(os.Stderr, "Read error: %v\n", err)
			break
		}

		// 注意：line读到的可能是 "\r\n" 或 "\n"，都要统一处理
		line = strings.TrimRight(line, "\r\n") // 去掉任何结尾的 \r 或 \n
		if *enableCRLF {
			line += "\r\n" // 统一加上 CRLF
		} else {
			line += "\n"
		}

		n, err := writer.WriteString(line)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Write error: %v\n", err)
			break
		}
		writer.Flush()

		stats.Update(int64(n))

		if err == io.EOF {
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

	return args, nil
}

func handleConnection(conn net.Conn, stats_in, stats_out *ProgressStats) {
	// 如果启用 TLS，进行 TLS 握手
	if *tlsEnabled || *tls10_forced || *tls11_forced || *tls12_forced || *tls13_forced {
		conn_tls := do_TLS(conn)
		if conn_tls == nil {
			conn.Close()
			return
		}
		conn = conn_tls
	}

	// 如果指定了 sendfile 参数，发送指定的文件
	if *sendfile != "" {
		sendFile(*sendfile, conn, stats_out)
		conn.Close()
		return
	}

	var input io.Reader
	var output io.Writer
	var cmd *exec.Cmd

	if *runCmd != "" {
		// 分割命令和参数（支持带空格的参数）
		args, err := parseCommandLine(*runCmd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing command: %v\n", err)
			conn.Close()
			return
		}

		if len(args) == 0 {
			fmt.Fprintf(os.Stderr, "Empty command\n")
			conn.Close()
			return
		}

		// 创建命令
		cmd = exec.Command(args[0], args[1:]...)

		// 创建管道
		stdinPipe, err := cmd.StdinPipe()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating stdin pipe: %v\n", err)
			conn.Close()
			return
		}

		stdoutPipe, err := cmd.StdoutPipe()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating stdout pipe: %v\n", err)
			conn.Close()
			return
		}

		if *mergeStderr {
			cmd.Stderr = cmd.Stdout
		} else {
			cmd.Stderr = os.Stderr
		}

		// 启动命令
		if err := cmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Command start error: %v\n", err)
			conn.Close()
			return
		}

		// 设置输入输出为管道
		input = stdoutPipe
		output = stdinPipe

		// 命令退出后关闭连接
		go func() {
			cmd.Wait()
			if tcpConn, ok := conn.(closeWriter); ok {
				tcpConn.CloseWrite()
			}
			conn.Close()
		}()

		go copyWithProgress(conn, input, stats_out)
	} else {
		// 使用标准输入输出
		input = os.Stdin
		output = os.Stdout

		go func() {

			info, err := os.Stdin.Stat()
			if err == nil && info.Mode()&os.ModeCharDevice != 0 {
				copyCharDeviceWithProgress(conn, input, stats_out)
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
	// 如果使用了命令，等待命令结束
	if cmd != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}
}
