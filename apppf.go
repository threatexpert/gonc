package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/threatexpert/gonc/misc"
)

type AppPFConfig struct {
	tlsEnabled   bool             // -tls (bool)
	cert         *tls.Certificate // 如果tlsEnabled是true，这个就需要用到
	network      string           // 默认是tcp，然而如果有参数-4 -6 -U，则可能是tcp4 tcp6 unix
	host, port   string           // 是最后 two args
	presharedKey string           // -psk <psk-string>
}

func AppPFConfigByArgs(args []string) (*AppPFConfig, error) {
	// 初始化配置，设置默认值
	config := &AppPFConfig{
		network: "tcp",
	}

	// 临时存储非标志参数，用于解析 host 和 port
	var positionalArgs []string

	// 遍历参数，解析标志和其对应的值
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-tls":
			config.tlsEnabled = true
		case "-4":
			config.network = "tcp4"
		case "-6":
			config.network = "tcp6"
		case "-U":
			config.network = "unix"
		case "-psk":
			if i+1 < len(args) {
				config.presharedKey = args[i+1]
				i++ // 跳过下一个参数，因为它已经被解析为 -psk 的值
			} else {
				return nil, fmt.Errorf("missing value for -psk")
			}
		default:
			if strings.HasPrefix(arg, "-") {
				return nil, fmt.Errorf("unknown argument: %s", arg)
			}
			positionalArgs = append(positionalArgs, arg)
		}
	}

	// 解析 host 和 port (或 unix socket 路径)
	if config.network == "unix" {
		if len(positionalArgs) != 1 {
			return nil, fmt.Errorf("wrong arguments: expect only one unix socket path for -U mode")
		}
		config.port = positionalArgs[len(positionalArgs)-1]
	} else {
		// 对于 TCP/TCP4/TCP6，需要 host 和 port
		if len(positionalArgs) != 2 {
			return nil, fmt.Errorf("wrong arguments: host and port are required for network type %s", config.network)
		}
		// host 是倒数第二个参数，port 是最后一个参数
		config.host = positionalArgs[len(positionalArgs)-2]
		config.port = positionalArgs[len(positionalArgs)-1]
	}

	if config.tlsEnabled || config.presharedKey != "" {
		var err error
		config.cert, err = misc.GenerateECDSACertificate(config.host, config.presharedKey)
		if err != nil {
			return nil, fmt.Errorf("error generating EC certificate: %v", err)
		}
		config.tlsEnabled = true
	}
	return config, nil
}

func App_pf_usage() {
	fmt.Fprintln(os.Stderr, "Usage: -app-pf [-tls] [-4|-6|-U] [-psk <psk-string>] <host> <port>")
	fmt.Fprintln(os.Stderr, "  -tls          Enable TLS encryption")
	fmt.Fprintln(os.Stderr, "  -4            Use IPv4 (default is tcp)")
	fmt.Fprintln(os.Stderr, "  -6            Use IPv6")
	fmt.Fprintln(os.Stderr, "  -U            Use Unix socket")
	fmt.Fprintln(os.Stderr, "  -psk <key>    Use pre-shared key for TLS verification")
	fmt.Fprintln(os.Stderr, "  <host>        Target host (ignored if using Unix socket)")
	fmt.Fprintln(os.Stderr, "  <port>        Target port (path if using Unix socket)")
	fmt.Fprintln(os.Stderr, "usage:")
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
	var d net.Dialer
	timeout_sec := 20
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout_sec)*time.Second)
	defer cancel()

	address := net.JoinHostPort(config.host, config.port)
	if config.network == "unix" {
		address = config.port
	}
	targetConn, err := d.DialContext(ctx, config.network, address)
	if err != nil {
		return
	}
	if config.tlsEnabled {
		tlsconn, err := pf_do_TLS(ctx, targetConn, config)
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
