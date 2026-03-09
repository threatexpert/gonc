package apps

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/threatexpert/gonc/v2/misc"
	"github.com/threatexpert/gonc/v2/netx"
	"github.com/threatexpert/gonc/v2/secure"
)

type Dialer interface {
	DialTimeout(network, address string, timeout time.Duration) (net.Conn, error)
	Listen(network, address string) (net.Listener, error)
}

type HttpConnectClient struct {
	Config *ProxyClientConfig
}

func NewHttpConnectClient(config *ProxyClientConfig) *HttpConnectClient {
	return &HttpConnectClient{
		Config: config,
	}
}

func getFullHttpHeader(conn net.Conn) (string, error) {
	result := ""
	for {
		line, err := netx.ReadString(conn, '\n', 4096)
		if err != nil {
			return "", fmt.Errorf("failed to read headers: %v", err)
		}
		result += line

		if line == "\r\n" || line == "\n" {
			break
		}
	}

	return result, nil
}

// DialTimeout 实现 HttpConnectClient 的拨号逻辑
func (c *HttpConnectClient) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	// 1. 连接HTTP代理服务器
	serverAddress := net.JoinHostPort(c.Config.ServerHost, c.Config.ServerPort)
	proxyConn, err := c.Config.dialToServer(timeout)
	if err != nil {
		return nil, fmt.Errorf("connect to HTTP proxy server %s failed: %w", serverAddress, err)
	}
	if IsSecureNegotiationNeeded(c.Config) {
		ntconfig := BuildNTConfigFromPCConfig(c.Config)
		nconn, err := secure.DoNegotiation(ntconfig, proxyConn, io.Discard)
		if err != nil {
			proxyConn.Close()
			return nil, fmt.Errorf("DoNegotiation to HTTP proxy server %s failed: %w", serverAddress, err)
		}
		proxyConn = nconn
	}

	// 2. 发送CONNECT请求
	connectReq := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: address}, // Use Opaque for CONNECT
		Host:   address,                   // Set Host header for CONNECT
		Header: make(http.Header),
	}
	if c.Config.User != "" && c.Config.Pass != "" {
		connectReq.SetBasicAuth(c.Config.User, c.Config.Pass)
	}
	proxyConn.SetDeadline(time.Now().Add(timeout))

	err = connectReq.Write(proxyConn)
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("write HTTP CONNECT request(%s) failed: %w", serverAddress, err)
	}

	// 3. 读取HTTP代理服务器响应，不要直接bufio.NewReader(stringReader)，他可能读取过多数据并缓存在其内部
	//	需要使用自定义的getFullHttpHeader函数来确保仅仅读取完整的HTTP头部
	header, err := getFullHttpHeader(proxyConn)
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("read(%s) HTTP Header failed: %w", serverAddress, err)
	}
	stringReader := strings.NewReader(header)
	bufReader := bufio.NewReader(stringReader)
	resp, err := http.ReadResponse(bufReader, connectReq)
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("read(%s) HTTP CONNECT response failed: %w", serverAddress, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		proxyConn.Close()
		return nil, fmt.Errorf("HTTP CONNECT(%s) failed with status: %s", serverAddress, resp.Status)
	}
	proxyConn.SetDeadline(time.Time{})
	return proxyConn, nil
}

func (c *HttpConnectClient) Listen(network, address string) (net.Listener, error) {
	return nil, fmt.Errorf("N/A")
}

// ProxyClient 通用代理客户端
type ProxyClient struct {
	ProxyProt string
	Dialer    Dialer // 实际的拨号器
}

// NewProxyClient 构造函数
func NewProxyClient(config *ProxyClientConfig) (*ProxyClient, error) {
	proxyProtocol := ""
	if config != nil {
		proxyProtocol = config.Prot
	}
	pc := &ProxyClient{
		ProxyProt: proxyProtocol,
	}

	switch proxyProtocol {
	case "socks5":
		pc.Dialer = NewSocks5Client(config)
	case "http":
		pc.Dialer = NewHttpConnectClient(config)
	case "":
		pc.Dialer = &DirectDialer{}
	default:
		return nil, fmt.Errorf("unsupported proxy protocol: %s", proxyProtocol)
	}
	return pc, nil
}

type DirectDialer struct{}

// DialTimeout implements the Dialer interface for DirectDialer
func (d *DirectDialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, address, timeout)
}

func (c *DirectDialer) Listen(network, address string) (net.Listener, error) {
	return nil, fmt.Errorf("N/A")
}

// Dial 实现 ProxyClient 的拨号逻辑，委托给内部的 dialer
func (c *ProxyClient) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	if c.Dialer == nil {
		return nil, fmt.Errorf("proxy client not initialized, call NewProxyClient first")
	}
	return c.Dialer.DialTimeout(network, address, timeout)
}

func (c *ProxyClient) Listen(network, address string) (net.Listener, error) {
	if c.Dialer == nil {
		return nil, fmt.Errorf("proxy client not initialized")
	}
	return c.Dialer.Listen(network, address)
}

func (c *ProxyClient) SupportBIND() bool {
	// 目前仅 SOCKS5 支持 BIND
	return c.ProxyProt == "socks5"
}

type ProxyClientConfig struct {
	Logger           *log.Logger
	Prot, User, Pass string           //代理协议类型："socks5" 或 "http"
	TlsEnabled       bool             // -tls (bool)
	Cert             *tls.Certificate // 如果tlsEnabled是true，这个就需要用到
	Network          string           // 默认是tcp，然而如果有参数-4 -6 -u，则可能是tcp4 tcp6 udp4 udp6
	ServerHost       string
	ServerPort       string
	PresharedKey     string // -psk <psk-string>
	KcpWithUDP       bool
	UpstreamDialer   Dialer // 上游拨号器，用于链式代理。nil则使用net.DialTimeout直连
}

// dialToServer 通过上游拨号器（如果有）连接到代理服务器
func (c *ProxyClientConfig) dialToServer(timeout time.Duration) (net.Conn, error) {
	serverAddress := net.JoinHostPort(c.ServerHost, c.ServerPort)
	if c.UpstreamDialer != nil {
		return c.UpstreamDialer.DialTimeout(c.Network, serverAddress, timeout)
	}
	return net.DialTimeout(c.Network, serverAddress, timeout)
}

func BuildNTConfigFromPCConfig(config *ProxyClientConfig) *secure.NegotiationConfig {
	ntconfig := secure.NewNegotiationConfig()
	ntconfig.IsClient = true

	if config.PresharedKey != "" {
		ntconfig.KeyType = "PSK"
		ntconfig.Key = config.PresharedKey
	}

	if config.TlsEnabled {
		ntconfig.Certs = []tls.Certificate{*config.Cert}
		ntconfig.TlsSNI = config.ServerHost
	}

	if strings.HasPrefix(config.Network, "udp") {
		ntconfig.KcpWithUDP = config.KcpWithUDP
		if config.TlsEnabled {
			ntconfig.SecureLayer = "dtls"
		} else if config.KcpWithUDP && config.PresharedKey != "" {
			ntconfig.KcpEncryption = true
		} else if config.PresharedKey != "" {
			ntconfig.SecureLayer = "dss"
		}
	} else {
		if config.TlsEnabled {
			ntconfig.SecureLayer = "tls"
		} else if config.PresharedKey != "" {
			ntconfig.SecureLayer = "ss"
		}
	}
	return ntconfig
}

func IsSecureNegotiationNeeded(config *ProxyClientConfig) bool {
	return config.TlsEnabled || config.KcpWithUDP || config.PresharedKey != ""
}

func ProxyClientConfigByCommandline(logWriter io.Writer, proxyProt, auth, commandline string) (*ProxyClientConfig, error) {
	args, err := misc.ParseCommandLine(commandline)
	if err != nil {
		return nil, fmt.Errorf("parse command line failed: %v", err)
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("empty proxy args")
	}

	config, err := ProxyClientConfigByArgs(logWriter, args)
	if err != nil {
		return nil, err
	}

	switch proxyProt {
	case "", "5", "socks5":
		config.Prot = "socks5"
	case "connect", "http":
		config.Prot = "http"
	default:
		return nil, fmt.Errorf("invalid proxy protocol: %s", proxyProt)
	}

	if auth != "" {
		authParts := strings.SplitN(auth, ":", 2)
		if len(authParts) != 2 {
			return nil, fmt.Errorf("invalid auth format: expected user:pass")
		}
		config.User, config.Pass = authParts[0], authParts[1]
	}

	return config, nil
}

func ProxyClientConfigByArgs(logWriter io.Writer, args []string) (*ProxyClientConfig, error) {
	config := &ProxyClientConfig{
		Logger:  misc.NewLog(logWriter, "[:x] ", log.LstdFlags|log.Lmsgprefix),
		Network: "tcp", // 默认值
	}

	// 创建一个自定义的 FlagSet，而不是使用全局的 flag.CommandLine
	// 设置 ContinueOnError 允许我们捕获错误而不是直接退出
	fs := flag.NewFlagSet("ProxyClientConfig", flag.ContinueOnError)
	fs.SetOutput(logWriter)

	fs.BoolVar(&config.TlsEnabled, "tls", false, "Enable TLS encryption")
	var is4, is6 bool
	fs.BoolVar(&is4, "4", false, "Use IPv4 (default is tcp)")
	fs.BoolVar(&is6, "6", false, "Use IPv6")
	var isUdp bool
	fs.BoolVar(&isUdp, "u", false, "UDP socket")
	fs.BoolVar(&config.KcpWithUDP, "kcp", false, "KCP over udp")

	fs.StringVar(&config.PresharedKey, "psk", "", "Pre-shared key for deriving TLS certificate identity (anti-MITM); also key for TCP/KCP encryption")

	fs.Usage = func() {
		Proxy_usage_flagSet(fs) // 传递 fs，以便它能打印出定义好的标志
	}

	// 解析传入的 args 切片
	// 注意：我们假设 args 已经不包含程序名 (os.Args[0])，所以直接传入
	err := fs.Parse(args)
	if err != nil {
		return nil, err // 解析错误直接返回
	}

	if config.KcpWithUDP {
		isUdp = true
	}

	// 处理网络类型
	if isUdp {
		config.Network = "udp"
	}

	if is4 {
		config.Network += "4"
	} else if is6 {
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

	if len(positionalArgs) == 1 {
		if !strings.Contains(positionalArgs[0], ":") {
			return nil, fmt.Errorf("expect host:port, got %s", positionalArgs[0])
		}
		config.ServerHost, config.ServerPort, err = net.SplitHostPort(positionalArgs[0])
		if err != nil {
			return nil, fmt.Errorf("parse host:port failed: %v", err)
		}
	} else if len(positionalArgs) == 2 {
		config.ServerHost = positionalArgs[0]
		config.ServerPort = positionalArgs[1]
	} else {
		return nil, fmt.Errorf("expect host and port, got %d arg", len(positionalArgs))
	}

	// 若启用 TLS 或 PSK，加载证书
	if config.TlsEnabled {
		var err error
		config.Cert, err = secure.GenerateECDSACertificate(config.ServerHost, config.PresharedKey)
		if err != nil {
			return nil, fmt.Errorf("error generating EC certificate: %v", err)
		}
	}

	return config, nil
}

func Proxy_usage_flagSet(fs *flag.FlagSet) {
	fmt.Fprintln(fs.Output(), "-x Usage:")
	fmt.Fprintln(fs.Output(), "  Classic: [options] <host:port>")
	fmt.Fprintln(fs.Output(), "  Or:      [options]  <host> <port>")
	fmt.Fprintln(fs.Output(), "  URL:     <scheme>://[user:pass@]host:port[?psk=key]")
	fmt.Fprintln(fs.Output(), "  Chain:   <url1>,<url2>[,<url3>...]")
	fmt.Fprintln(fs.Output(), "\nClassic options:")
	fs.PrintDefaults()
	fmt.Fprintln(fs.Output(), "\nURL schemes: socks5, socks5s (socks5+tls), http (connect), https (connect+tls)")
	fmt.Fprintln(fs.Output(), "\nExamples:")
	fmt.Fprintln(fs.Output(), "  -x \"-tls -psk randomString <host:port>\"")
	fmt.Fprintln(fs.Output(), "  -x socks5://user:pass@1.1.1.1:1080")
	fmt.Fprintln(fs.Output(), "  -x socks5s://1.1.1.1:1080?psk=mykey")
	fmt.Fprintln(fs.Output(), "  -x \"socks5://1.1.1.1:1080,https://2.2.2.2:8080\"")
}

func CreateSocks5UDPClient(config *ProxyClientConfig) (net.PacketConn, error) {
	if config == nil {
		return nil, nil
	}
	if config.Prot == "" || config.ServerHost == "" {
		return nil, nil
	}
	if config.Prot != "socks5" {
		return nil, fmt.Errorf("only socks5 proxy is supported for UDP")
	}
	proxyClient, err := NewProxyClient(config)
	if err != nil {
		return nil, fmt.Errorf("error create proxy client: %v", err)
	}
	conn, err := proxyClient.DialTimeout("udp", ":0", 20*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect proxy server: %v", err)
	}
	packetConn, ok := conn.(net.PacketConn)
	if !ok {
		return nil, fmt.Errorf("failed to convert socks5 connection to PacketConn")
	}
	return packetConn, nil
}

// getProxyClient 获取代理客户端：优先使用预构建的链式代理，否则从 Config 构建
func getProxyClient(ncconfig *AppNetcatConfig) (*ProxyClient, error) {
	if ncconfig.arg_proxyc_Client != nil {
		return ncconfig.arg_proxyc_Client, nil
	}
	return NewProxyClient(ncconfig.arg_proxyc_Config)
}

// hasProxyConfig 检查是否配置了代理（包括单跳和链式）
func hasProxyConfig(ncconfig *AppNetcatConfig) bool {
	return ncconfig.arg_proxyc_Config != nil || ncconfig.arg_proxyc_Client != nil
}

// ParseProxyURL 解析 URL 格式的代理配置
// 支持的格式:
//
//	socks5://[user:pass@]host:port[?psk=key]
//	socks5s://[user:pass@]host:port[?psk=key]   (SOCKS5 + TLS)
//	http://[user:pass@]host:port[?psk=key]       (HTTP CONNECT)
//	https://[user:pass@]host:port[?psk=key]      (HTTP CONNECT + TLS)
func ParseProxyURL(logWriter io.Writer, rawURL string) (*ProxyClientConfig, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	config := &ProxyClientConfig{
		Logger:  misc.NewLog(logWriter, "[:x] ", log.LstdFlags|log.Lmsgprefix),
		Network: "tcp",
	}

	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "socks5":
		config.Prot = "socks5"
	case "socks5s":
		config.Prot = "socks5"
		config.TlsEnabled = true
	case "http", "connect":
		config.Prot = "http"
	case "https":
		config.Prot = "http"
		config.TlsEnabled = true
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", scheme)
	}

	if u.User != nil {
		config.User = u.User.Username()
		config.Pass, _ = u.User.Password()
	}

	config.ServerHost = u.Hostname()
	config.ServerPort = u.Port()
	if config.ServerHost == "" || config.ServerPort == "" {
		return nil, fmt.Errorf("proxy URL must include host and port: %s", rawURL)
	}

	// 解析 query 参数
	q := u.Query()
	if psk := q.Get("psk"); psk != "" {
		config.PresharedKey = psk
		if strings.HasPrefix(config.PresharedKey, "@") {
			config.PresharedKey, err = secure.ReadPSKFile(config.PresharedKey)
			if err != nil {
				return nil, fmt.Errorf("failed to read psk file: %v", err)
			}
		}
	}

	if config.TlsEnabled {
		config.Cert, err = secure.GenerateECDSACertificate(config.ServerHost, config.PresharedKey)
		if err != nil {
			return nil, fmt.Errorf("error generating EC certificate: %v", err)
		}
	}

	return config, nil
}

// splitProxyChain 按逗号分割代理链，但忽略 URL 中 userinfo 内的逗号
// URL 中密码含逗号时应使用 %2C 编码
func splitProxyChain(chain string) []string {
	var parts []string
	current := ""
	for i := 0; i < len(chain); i++ {
		if chain[i] == ',' {
			trimmed := strings.TrimSpace(current)
			if trimmed != "" {
				parts = append(parts, trimmed)
			}
			current = ""
		} else {
			current += string(chain[i])
		}
	}
	if trimmed := strings.TrimSpace(current); trimmed != "" {
		parts = append(parts, trimmed)
	}
	return parts
}

// IsProxyURLFormat 检测 -x 参数是否为 URL 格式
func IsProxyURLFormat(s string) bool {
	return strings.Contains(s, "://")
}

// ParseProxyChainURL 解析逗号分隔的代理链 URL，返回链式 ProxyClient
// 例如: "socks5://user:pass@1.1.1.1:1080,https://2.2.2.2:8080"
func ParseProxyChainURL(logWriter io.Writer, chain string) (*ProxyClient, error) {
	parts := splitProxyChain(chain)
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty proxy chain")
	}

	// 解析所有代理配置
	configs := make([]*ProxyClientConfig, 0, len(parts))
	for _, part := range parts {
		config, err := ParseProxyURL(logWriter, part)
		if err != nil {
			return nil, fmt.Errorf("parse proxy URL %q: %w", part, err)
		}
		configs = append(configs, config)
	}

	// 构建链式 dialer：从第一个代理开始，每个后续代理通过前一个代理连接
	var prevDialer Dialer
	for i, config := range configs {
		if i > 0 {
			config.UpstreamDialer = prevDialer
		}
		pc, err := NewProxyClient(config)
		if err != nil {
			return nil, fmt.Errorf("create proxy client for hop %d: %w", i+1, err)
		}
		prevDialer = pc
	}

	// 返回最后一个 ProxyClient（它内部已经链式嵌套了前面所有的代理）
	return prevDialer.(*ProxyClient), nil
}
