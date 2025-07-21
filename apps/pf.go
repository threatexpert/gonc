package apps

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

	"github.com/threatexpert/gonc/secure"
)

type AppPFConfig struct {
	TlsEnabled   bool             // -tls (bool)
	Cert         *tls.Certificate // 如果tlsEnabled是true，这个就需要用到
	Network      string           // 默认是tcp，然而如果有参数-4 -6 -u -U，则可能是tcp4 tcp6 udp4 udp6 unix
	Host, Port   string           // 是最后 two args
	Localbind    string
	PresharedKey string // -psk <psk-string>
	ProxyProt    string // -X 代理协议，可能是 connect或5，或空
	ProxyAddress string // -x 代理服务器地址 host:port
	ProxyAuth    string // -auth 代理认证信息，格式为 username:password
	KcpWithUDP   bool
}

// AppPFConfigByArgs 解析给定的 []string 参数，生成 AppPFConfig
func AppPFConfigByArgs(args []string) (*AppPFConfig, error) {
	config := &AppPFConfig{
		Network: "tcp", // 默认值
	}

	// 创建一个自定义的 FlagSet，而不是使用全局的 flag.CommandLine
	// 设置 ContinueOnError 允许我们捕获错误而不是直接退出
	fs := flag.NewFlagSet("AppPFConfig", flag.ContinueOnError)

	// 定义标志变量，这些变量会绑定到 config 结构体中
	// 注意：对于布尔标志，我们可以直接使用 BoolVar 绑定到结构体字段
	// 对于其他类型，我们先定义一个临时变量，解析后再赋值给结构体
	fs.BoolVar(&config.TlsEnabled, "tls", false, "Enable TLS encryption")
	var is4, is6 bool
	fs.BoolVar(&is4, "4", false, "Use IPv4 (default is tcp)")
	fs.BoolVar(&is6, "6", false, "Use IPv6")
	var isUdp, isUnix bool // 为了避免与 -U 混淆，使用 isUdp, isUnix
	fs.BoolVar(&isUdp, "u", false, "UDP socket")
	fs.BoolVar(&isUnix, "U", false, "Use Unix socket")
	fs.BoolVar(&config.KcpWithUDP, "kcp", false, "KCP over udp")

	fs.StringVar(&config.PresharedKey, "psk", "", "Pre-shared key for deriving TLS certificate identity (anti-MITM); also key for TCP/KCP encryption")
	fs.StringVar(&config.Localbind, "local", "", "Set local bind address for outbound connections (format: ip)")
	fs.StringVar(&config.ProxyProt, "X", "", `Proxy protocol. Supported protocols are "5" (SOCKS v.5) and "connect"`)
	fs.StringVar(&config.ProxyAddress, "x", "", "ip:port for proxy address")
	fs.StringVar(&config.ProxyAuth, "auth", "", "user:password for proxy")

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
	if config.ProxyProt != "" && config.ProxyProt != "5" && config.ProxyProt != "connect" {
		return nil, fmt.Errorf("invalid proxy protocol: %s", config.ProxyProt)
	}

	// 验证代理认证格式
	if config.ProxyAuth != "" && !strings.Contains(config.ProxyAuth, ":") {
		return nil, fmt.Errorf("invalid format for -auth, expected user:pass")
	}

	if config.KcpWithUDP {
		isUdp = true
	}

	// 处理网络类型
	if isUdp {
		config.Network = "udp"
	} else if isUnix {
		config.Network = "unix"
	} // 否则保持默认 "tcp"

	if is4 {
		if strings.HasSuffix(config.Network, "4") || strings.HasSuffix(config.Network, "6") {
			return nil, fmt.Errorf("-4 and -6 cannot be used together or with -u/-U in a conflicting way")
		}
		config.Network += "4"
	} else if is6 {
		if strings.HasSuffix(config.Network, "4") || strings.HasSuffix(config.Network, "6") {
			return nil, fmt.Errorf("-4 and -6 cannot be used together or with -u/-U in a conflicting way")
		}
		config.Network += "6"
	}

	if strings.HasPrefix(config.PresharedKey, "@") {
		config.PresharedKey, err = secure.ReadPSKFile(config.PresharedKey)
		if err != nil {
			return nil, fmt.Errorf("failed to read psk file: %v", err)
		}
	}

	// 获取所有非标志参数（即位置参数）
	positionalArgs := fs.Args()

	// 处理 host/port 或 unix 路径
	if config.Network == "unix" {
		if len(positionalArgs) != 1 {
			return nil, fmt.Errorf("expect one unix socket path for -U mode, got %d", len(positionalArgs))
		}
		config.Port = positionalArgs[0] // 对于Unix，port字段存储路径
	} else {
		if len(positionalArgs) != 2 {
			return nil, fmt.Errorf("expect host and port for network type %s, got %d", config.Network, len(positionalArgs))
		}
		config.Host = positionalArgs[0]
		config.Port = positionalArgs[1]
	}

	// 若启用 TLS 或 PSK，加载证书
	if config.TlsEnabled {
		var err error
		config.Cert, err = secure.GenerateECDSACertificate(config.Host, config.PresharedKey)
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

	address := net.JoinHostPort(config.Host, config.Port)
	if config.Network == "unix" {
		address = config.Port
	}

	var localAddr net.Addr
	var err error
	var targetConn net.Conn
	targetConfig := secure.NewNegotiationConfig()
	targetConfig.IsClient = true

	if config.Localbind == "" {
		dialer, err := CreateProxyClient(config.ProxyProt, config.ProxyAddress, config.ProxyAuth)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error CreateProxyClient: %v\n", err)
			return
		}
		targetConn, err = dialer.DialTimeout(config.Network, address, time.Duration(timeout_sec)*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error DialTimeout: %v\n", err)
			return
		}
	} else {
		switch {
		case strings.HasPrefix(config.Network, "tcp"):
			localAddr, err = net.ResolveTCPAddr(config.Network, net.JoinHostPort(config.Localbind, "0"))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error ResolveTCPAddr: %v\n", err)
				return
			}
		case strings.HasPrefix(config.Network, "udp"):
			localAddr, err = net.ResolveUDPAddr(config.Network, net.JoinHostPort(config.Localbind, "0"))
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
		targetConn, err = dialer.DialContext(ctx2, config.Network, net.JoinHostPort(config.Host, config.Port))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error Dial: %v\n", err)
			return
		}
	}

	defer targetConn.Close()
	fmt.Fprintf(os.Stderr, "Connected to: %s\n", targetConn.RemoteAddr().String())

	if config.PresharedKey != "" {
		targetConfig.KeyType = "PSK"
		targetConfig.Key = config.PresharedKey
	}

	if config.TlsEnabled {
		targetConfig.Certs = []tls.Certificate{*config.Cert}
		targetConfig.TlsSNI = config.Host
	}

	if strings.HasPrefix(config.Network, "udp") {
		targetConfig.KcpWithUDP = config.KcpWithUDP
		if config.TlsEnabled {
			targetConfig.SecureLayer = "dtls"
		} else if config.KcpWithUDP && config.PresharedKey != "" {
			targetConfig.KcpEncryption = true
		} else if config.PresharedKey != "" {
			targetConfig.SecureLayer = "dss"
		}
	} else {
		if config.TlsEnabled {
			targetConfig.SecureLayer = "tls"
		} else if config.PresharedKey != "" {
			targetConfig.SecureLayer = "ss"
		}
	}

	nconn, err := secure.DoNegotiation(targetConfig, targetConn, io.Discard)
	if err == nil {
		defer nconn.Close()
		handleProxy(conn, nconn.ConnLayers[0])
	}
	fmt.Fprintf(os.Stderr, "Disconnected from: %s\n", targetConn.RemoteAddr().String())
}
