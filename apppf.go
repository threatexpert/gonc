package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/threatexpert/gonc/easyp2p"
	"github.com/threatexpert/gonc/misc"
)

type AppPFConfig struct {
	tlsEnabled   bool             // -tls (bool)
	cert         *tls.Certificate // 如果tlsEnabled是true，这个就需要用到
	network      string           // 默认是tcp，然而如果有参数-4 -6 -u -U，则可能是tcp4 tcp6 udp4 udp6 unix
	host, port   string           // 是最后 two args
	localAddr    string
	presharedKey string // -psk <psk-string>
	proxyProt    string // -X 代理协议，可能是 connect或5，或空
	proxyAddress string // -x 代理服务器地址 host:port
	proxyAuth    string // -auth 代理认证信息，格式为 username:password
}

// AppPFConfigByArgs 解析给定的 []string 参数，生成 AppPFConfig
func AppPFConfigByArgs(args []string) (*AppPFConfig, error) {
	config := &AppPFConfig{
		network: "tcp", // 默认值
	}

	// 创建一个自定义的 FlagSet，而不是使用全局的 flag.CommandLine
	// 设置 ContinueOnError 允许我们捕获错误而不是直接退出
	fs := flag.NewFlagSet("AppPFConfig", flag.ContinueOnError)

	// 定义标志变量，这些变量会绑定到 config 结构体中
	// 注意：对于布尔标志，我们可以直接使用 BoolVar 绑定到结构体字段
	// 对于其他类型，我们先定义一个临时变量，解析后再赋值给结构体
	fs.BoolVar(&config.tlsEnabled, "tls", false, "Enable TLS encryption")
	var is4, is6 bool
	fs.BoolVar(&is4, "4", false, "Use IPv4 (default is tcp)")
	fs.BoolVar(&is6, "6", false, "Use IPv6")
	var isUdp, isUnix bool // 为了避免与 -U 混淆，使用 isUdp, isUnix
	fs.BoolVar(&isUdp, "u", false, "UDP socket")
	fs.BoolVar(&isUnix, "U", false, "Use Unix socket")

	fs.StringVar(&config.presharedKey, "psk", "", "Use pre-shared key for TLS verification")
	fs.StringVar(&config.localAddr, "local", "", "Bind on address")
	fs.StringVar(&config.proxyProt, "X", "", `Proxy protocol. Supported protocols are "5" (SOCKS v.5) and "connect"`)
	fs.StringVar(&config.proxyAddress, "x", "", "ip:port for proxy address")
	fs.StringVar(&config.proxyAuth, "auth", "", "user:password for proxy")

	// 设置自定义的 Usage 函数，当用户传递无效参数或请求帮助时显示
	// 这里我们使用 App_pf_usage 函数的内容
	fs.Usage = func() {
		App_pf_usage_flagSet(fs) // 传递 fs，以便它能打印出定义好的标志
	}

	// 解析传入的 args 切片
	// 注意：我们假设 args 已经不包含程序名 (os.Args[0])，所以直接传入
	err := fs.Parse(args)
	if err != nil {
		return nil, err // 解析错误直接返回
	}

	// 验证代理协议值
	if config.proxyProt != "" && config.proxyProt != "5" && config.proxyProt != "connect" {
		return nil, fmt.Errorf("invalid proxy protocol: %s", config.proxyProt)
	}

	// 验证代理认证格式
	if config.proxyAuth != "" && !strings.Contains(config.proxyAuth, ":") {
		return nil, fmt.Errorf("invalid format for -auth, expected user:pass")
	}

	// 处理网络类型
	if isUdp {
		config.network = "udp"
	} else if isUnix {
		config.network = "unix"
	} // 否则保持默认 "tcp"

	if is4 {
		if strings.HasSuffix(config.network, "4") || strings.HasSuffix(config.network, "6") {
			return nil, fmt.Errorf("-4 and -6 cannot be used together or with -u/-U in a conflicting way")
		}
		config.network += "4"
	} else if is6 {
		if strings.HasSuffix(config.network, "4") || strings.HasSuffix(config.network, "6") {
			return nil, fmt.Errorf("-4 and -6 cannot be used together or with -u/-U in a conflicting way")
		}
		config.network += "6"
	}

	// 获取所有非标志参数（即位置参数）
	positionalArgs := fs.Args()

	// 处理 host/port 或 unix 路径
	if config.network == "unix" {
		if len(positionalArgs) != 1 {
			return nil, fmt.Errorf("expect one unix socket path for -U mode, got %d", len(positionalArgs))
		}
		config.port = positionalArgs[0] // 对于Unix，port字段存储路径
	} else {
		if len(positionalArgs) != 2 {
			return nil, fmt.Errorf("expect host and port for network type %s, got %d", config.network, len(positionalArgs))
		}
		config.host = positionalArgs[0]
		config.port = positionalArgs[1]
	}

	// 若启用 TLS 或 PSK，加载证书
	if config.tlsEnabled || config.presharedKey != "" {
		var err error
		config.cert, err = misc.GenerateECDSACertificate(config.host, config.presharedKey)
		if err != nil {
			return nil, fmt.Errorf("error generating EC certificate: %v", err)
		}
		// 如果PSK存在，即使没有显式-tls，也认为TLS enabled
		config.tlsEnabled = true
	}

	return config, nil
}

// App_pf_usage_flagSet 接受一个 *flag.FlagSet 参数，用于打印其默认用法信息
func App_pf_usage_flagSet(fs *flag.FlagSet) {
	fmt.Fprintln(os.Stderr, "-app-pf Usage: [options] <host> <port>")
	fmt.Fprintln(os.Stderr, "Or:    [options] -U <UNIX-domain-socket-path>")
	fmt.Fprintln(os.Stderr, "\nOptions:")
	fs.PrintDefaults() // 打印所有定义的标志及其默认值和说明
	fmt.Fprintln(os.Stderr, "\nExamples:")
	fmt.Fprintln(os.Stderr, "  -app-pf -4 -tls <host> <port>")
	fmt.Fprintln(os.Stderr, "  -app-pf -U <UNIX-domain>")
}

// Port Forwarding
func App_pf_main(conn net.Conn, args []string) {
	config, err := AppPFConfigByArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing app-pf args: %v\n", err)
		return
	}

	App_pf_main_withconfig(conn, config)
}

func App_pf_main_withconfig(conn net.Conn, config *AppPFConfig) {
	defer conn.Close()
	timeout_sec := 20
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout_sec)*time.Second)
	defer cancel()

	address := net.JoinHostPort(config.host, config.port)
	if config.network == "unix" {
		address = config.port
	}

	var localAddr net.Addr
	var err error
	var targetConn net.Conn
	if config.localAddr == "" {
		dialer, err := createProxyClient(config.proxyProt, config.proxyAddress, config.proxyAuth)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error createProxyClient: %v\n", err)
			return
		}
		targetConn, err = dialer.DialTimeout(config.network, address, 20*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error DialTimeout: %v\n", err)
			return
		}
	} else {
		switch {
		case strings.HasPrefix(config.network, "tcp"):
			localAddr, err = net.ResolveTCPAddr(config.network, config.localAddr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error ResolveTCPAddr: %v\n", err)
				return
			}
		case strings.HasPrefix(config.network, "udp"):
			localAddr, err = net.ResolveUDPAddr(config.network, config.localAddr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error ResolveUDPAddr: %v\n", err)
				return
			}
		}
		dialer := &net.Dialer{
			LocalAddr: localAddr,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		targetConn, err = dialer.DialContext(ctx, config.network, net.JoinHostPort(config.host, config.port))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error Dial: %v\n", err)
			return
		}
	}

	if config.tlsEnabled {
		var tlsconn net.Conn
		if strings.HasPrefix(config.network, "tcp") {
			tlsconn, err = pf_do_TLS(ctx, targetConn, config)
		} else {
			tlsconn, err = pf_do_DTLS(ctx, targetConn, config)
		}
		if err != nil {
			return
		}
		defer tlsconn.Close()
		targetConn = tlsconn
	}

	handleProxy(conn, targetConn)
}

func pf_do_TLS(ctx context.Context, conn net.Conn, config *AppPFConfig) (net.Conn, error) {
	// 创建 TLS 配置
	tlsConfig := &tls.Config{
		InsecureSkipVerify:       true,             // 忽略证书验证（可选）
		MinVersion:               tls.VersionTLS10, // 至少 TLSv1
		MaxVersion:               tls.VersionTLS13, // 最大支持 TLSv1.3
		PreferServerCipherSuites: true,             // 优先使用服务器的密码套件
	}

	var conn_tls *tls.Conn
	var certs []tls.Certificate

	if config.cert != nil {
		certs = append(certs, *config.cert)
	}

	tlsConfig.ServerName = config.host
	if config.presharedKey != "" {
		tlsConfig.Certificates = certs
		tlsConfig.VerifyPeerCertificate = misc.VerifyPeerCertificateByPSK(config.presharedKey)
	}
	conn_tls = tls.Client(conn, tlsConfig)

	if err := conn_tls.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return conn_tls, nil
}

func pf_do_DTLS(ctx context.Context, conn net.Conn, config *AppPFConfig) (net.Conn, error) {
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

	var dtlsConn *dtls.Conn
	var err error
	var certs []tls.Certificate

	if config.cert != nil {
		certs = append(certs, *config.cert)
	}

	pktconn := easyp2p.NewPacketConnWrapper(conn, conn.RemoteAddr())
	dtlsConfig.ServerName = config.host
	if config.presharedKey != "" {
		dtlsConfig.Certificates = certs
		dtlsConfig.VerifyPeerCertificate = misc.VerifyPeerCertificateByPSK(config.presharedKey)
	}
	dtlsConn, err = dtls.Client(pktconn, conn.RemoteAddr(), dtlsConfig)
	if err != nil {
		return nil, err
	}

	err = dtlsConn.HandshakeContext(ctx)
	if err != nil {
		dtlsConn.Close()
		return nil, err
	}

	return dtlsConn, nil
}
