package apps

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	MagicDNServer = "gonc.cc"
)

type AppTPConfig struct {
	proxyConfig *ProxyClientConfig
	dialer      *ProxyClient
}

func AppTPConfigByArgs(args []string) (*AppTPConfig, error) {
	config := &AppTPConfig{}

	// 创建一个新的 FlagSet 实例
	fs := flag.NewFlagSet("AppTPConfig", flag.ContinueOnError)

	var protocol, proxyAddr, authString string

	fs.StringVar(&protocol, "X", "", "proxy_protocol. Supported protocols are “5” (SOCKS v.5) and “connect” (HTTPS proxy).  If the protocol is not specified, SOCKS version 5 is used.")
	fs.StringVar(&proxyAddr, "x", "", "\"ip:port\" for proxy_address")
	fs.StringVar(&authString, "auth", "", "user:password for proxy")

	// 设置自定义的 Usage 函数
	fs.Usage = func() {
		App_tp_usage_flagSet(fs)
	}

	// 解析传入的 args 切片
	err := fs.Parse(args)
	if err != nil {
		return nil, err // 解析错误直接返回
	}

	if proxyAddr == "" {
		return nil, fmt.Errorf("unknown proxy address, please use -x ip:port")
	}

	config.proxyConfig, err = ProxyClientConfigByCommandline(protocol, authString, proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("ProxyClientConfigByCommandline failed: %v", err)
	}

	config.dialer, err = NewProxyClient(config.proxyConfig)
	if err != nil {
		return nil, fmt.Errorf("NewProxyClient failed: %v", err)
	}

	return config, nil
}

func App_tp_usage_flagSet(fs *flag.FlagSet) {
	fmt.Fprintln(os.Stderr, ":tp Usage: [options]")
	fmt.Fprintln(os.Stderr, "\nOptions:")
	fs.PrintDefaults() // 打印所有定义的标志及其默认值和说明
	fmt.Fprintln(os.Stderr, "\nExample:")
	fmt.Fprintln(os.Stderr, "  :tp x.x.x.x:1080")
}

func App_tp_main_withconfig(conn net.Conn, config *AppTPConfig) {
	defer conn.Close()

	// Only accept 127.0.0.0/8
	rhost, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return
	}
	if !strings.HasPrefix(rhost, "127.") {
		fmt.Fprintf(os.Stderr, "Only accept from 127.0.0.0/8, client(%s) closed.\n", conn.RemoteAddr().String())
		return
	}
	magicTarget, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return
	}
	if magicTarget == "127.0.0.1" {
		return
	}
	targetHost, targetPort, err := DNSLookupMagicIP(magicTarget, true)
	if err != nil {
		fmt.Fprintln(os.Stderr, "DNSLookupMagicIP failed:", err)
		return
	}

	targetConn, err := config.dialer.Dialer.DialTimeout("tcp", net.JoinHostPort(targetHost, strconv.Itoa(targetPort)), 20*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "DialTimeout failed:", err)
		return
	}

	handleProxy(conn, targetConn)
}

// ipToken 例如 "127.4.5.6"
func DNSLookupMagicIP(ipToken string, allowPublicIP bool) (string, int, error) {
	// 验证并解析 IP
	parsed := net.ParseIP(ipToken)
	if parsed == nil || parsed.To4() == nil {
		return "", 0, fmt.Errorf("invalid ipToken: %s", ipToken)
	}
	b := parsed.To4()

	// 拼域名，比如 127.4.5.6.domain.io
	queryName := fmt.Sprintf("%d.%d.%d.%d.%s", b[0], b[1], b[2], b[3], MagicDNServer)

	// 系统默认 resolver 查询 TXT
	txtRecords, err := net.LookupTXT(queryName)
	if err != nil {
		return "", 0, fmt.Errorf("TXT lookup failed: %v", err)
	}
	if len(txtRecords) == 0 {
		return "", 0, fmt.Errorf("no TXT record found for %s", queryName)
	}

	// 假设 TXT 格式是 "ip:port"
	parts := strings.SplitN(txtRecords[0], ":", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid TXT format: %s", txtRecords[0])
	}

	host := parts[0]
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, fmt.Errorf("invalid port: %v", err)
	}

	if !allowPublicIP {
		parsedHost := net.ParseIP(host)
		if parsedHost == nil || !(parsedHost.IsPrivate() || parsedHost.IsLoopback()) {
			return "", 0, fmt.Errorf("public IPs are not allowed: %s", host)
		}
	}

	return host, port, nil
}
