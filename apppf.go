package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/threatexpert/gonc/misc"
)

type AppPFConfig struct {
	tlsEnabled   bool             // -tls (bool)
	cert         *tls.Certificate // 如果tlsEnabled是true，这个就需要用到
	network      string           // 默认是tcp，然而如果有参数-4 -6 -u -U，则可能是tcp4 tcp6 udp4 udp6 unix
	host, port   string           // 是最后 two args
	localbind    string
	presharedKey string // -psk <psk-string>
	proxyProt    string // -X 代理协议，可能是 connect或5，或空
	proxyAddress string // -x 代理服务器地址 host:port
	proxyAuth    string // -auth 代理认证信息，格式为 username:password
	kcpWithUDP   bool
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
	fs.BoolVar(&config.kcpWithUDP, "kcp", false, "KCP over udp")

	fs.StringVar(&config.presharedKey, "psk", "", "Pre-shared key for deriving TLS certificate identity (anti-MITM); also key for TCP/KCP encryption")
	fs.StringVar(&config.localbind, "local", "", "Set local bind address for outbound connections (format: ip)")
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

	if config.kcpWithUDP {
		isUdp = true
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

	if strings.HasPrefix(config.presharedKey, "@") {
		config.presharedKey, err = ReadPSKFile(config.presharedKey)
		if err != nil {
			return nil, fmt.Errorf("failed to read psk file: %v", err)
		}
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
	if config.tlsEnabled {
		var err error
		config.cert, err = misc.GenerateECDSACertificate(config.host, config.presharedKey)
		if err != nil {
			return nil, fmt.Errorf("error generating EC certificate: %v", err)
		}
	}

	return config, nil
}

// App_pf_usage_flagSet 接受一个 *flag.FlagSet 参数，用于打印其默认用法信息
func App_pf_usage_flagSet(fs *flag.FlagSet) {
	fmt.Fprintln(os.Stderr, ":pf Usage: [options] <host> <port>")
	fmt.Fprintln(os.Stderr, "Or:    [options] -U <UNIX-domain-socket-path>")
	fmt.Fprintln(os.Stderr, "\nOptions:")
	fs.PrintDefaults() // 打印所有定义的标志及其默认值和说明
	fmt.Fprintln(os.Stderr, "\nExamples:")
	fmt.Fprintln(os.Stderr, "  :pf -4 -tls <host> <port>")
	fmt.Fprintln(os.Stderr, "  :pf -U <UNIX-domain>")
}

// Port Forwarding
func App_pf_main(conn net.Conn, args []string) {
	config, err := AppPFConfigByArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing :pf args: %v\n", err)
		return
	}

	App_pf_main_withconfig(conn, config)
}

func App_pf_main_withconfig(conn net.Conn, config *AppPFConfig) {
	defer conn.Close()
	timeout_sec := 20

	address := net.JoinHostPort(config.host, config.port)
	if config.network == "unix" {
		address = config.port
	}

	var localAddr net.Addr
	var err error
	var targetConn net.Conn
	targetConfig := &connectionConfig{
		isClient: true,
	}
	if config.localbind == "" {
		dialer, err := createProxyClient(config.proxyProt, config.proxyAddress, config.proxyAuth)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error createProxyClient: %v\n", err)
			return
		}
		targetConn, err = dialer.DialTimeout(config.network, address, time.Duration(timeout_sec)*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error DialTimeout: %v\n", err)
			return
		}
	} else {
		switch {
		case strings.HasPrefix(config.network, "tcp"):
			localAddr, err = net.ResolveTCPAddr(config.network, net.JoinHostPort(config.localbind, "0"))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error ResolveTCPAddr: %v\n", err)
				return
			}
		case strings.HasPrefix(config.network, "udp"):
			localAddr, err = net.ResolveUDPAddr(config.network, net.JoinHostPort(config.localbind, "0"))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error ResolveUDPAddr: %v\n", err)
				return
			}
		}
		dialer := &net.Dialer{
			LocalAddr: localAddr,
		}
		ctx2, cancel2 := context.WithTimeout(context.Background(), time.Duration(timeout_sec)*time.Second)
		defer cancel2()
		targetConn, err = dialer.DialContext(ctx2, config.network, net.JoinHostPort(config.host, config.port))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error Dial: %v\n", err)
			return
		}
	}

	defer targetConn.Close()
	fmt.Fprintf(os.Stderr, "Connected to: %s\n", targetConn.RemoteAddr().String())

	if config.presharedKey != "" {
		targetConfig.keyType = "PSK"
		targetConfig.key = config.presharedKey
	}

	if config.tlsEnabled {
		targetConfig.certs = []tls.Certificate{*config.cert}
		targetConfig.tlsSNI = config.host
	}

	if strings.HasPrefix(config.network, "udp") {
		targetConfig.kcpWithUDP = config.kcpWithUDP
		if config.tlsEnabled {
			targetConfig.secureLayer = "dtls"
		} else if config.kcpWithUDP && config.presharedKey != "" {
			targetConfig.kcpEncryption = true
		} else if config.presharedKey != "" {
			targetConfig.secureLayer = "dss"
		}
	} else {
		if config.tlsEnabled {
			targetConfig.secureLayer = "tls"
		} else if config.presharedKey != "" {
			targetConfig.secureLayer = "ss"
		}
	}

	nconn, err := do_Negotiation(targetConfig, targetConn, io.Discard)
	if err == nil {
		defer nconn.Close()
		handleProxy(conn, nconn.connLayers[0])
	}
	fmt.Fprintf(os.Stderr, "Disconnected from: %s\n", targetConn.RemoteAddr().String())
}
