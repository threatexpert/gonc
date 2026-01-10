package apps

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/threatexpert/gonc/v2/misc"
)

var (
	MagicDNServer = "gonc.cc"
)

type AppTPConfig struct {
	Logger      *log.Logger
	proxyConfig *ProxyClientConfig
	dialer      *ProxyClient
	allow       string
}

func AppTPConfigByArgs(logWriter io.Writer, args []string) (*AppTPConfig, error) {
	config := &AppTPConfig{
		Logger: misc.NewLog(logWriter, "[:tp] ", log.LstdFlags|log.Lmsgprefix),
	}

	// 创建一个新的 FlagSet 实例
	fs := flag.NewFlagSet("AppTPConfig", flag.ContinueOnError)
	fs.SetOutput(logWriter)

	var protocol, proxyAddr, authString string

	fs.StringVar(&protocol, "X", "", "proxy_protocol. Supported protocols are “5” (SOCKS v.5) and “connect” (HTTPS proxy).  If the protocol is not specified, SOCKS version 5 is used.")
	fs.StringVar(&proxyAddr, "x", "", "\"ip:port\" for proxy_address")
	fs.StringVar(&authString, "auth", "", "user:password for proxy")
	fs.StringVar(&config.allow, "allow", "private", "private|domain")

	// 设置自定义的 Usage 函数
	fs.Usage = func() {
		App_tp_usage_flagSet(fs)
	}

	// 解析传入的 args 切片
	err := fs.Parse(args)
	if err != nil {
		return nil, err // 解析错误直接返回
	}

	switch config.allow {
	case "private", "domain", "any":
	default:
		return nil, fmt.Errorf("invalid allow option: %s", config.allow)
	}

	if proxyAddr == "" {
		return nil, fmt.Errorf("unknown proxy address, please use -x ip:port")
	}

	config.proxyConfig, err = ProxyClientConfigByCommandline(logWriter, protocol, authString, proxyAddr)
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
	fmt.Fprintln(fs.Output(), ":tp Usage: [options]")
	fmt.Fprintln(fs.Output(), "\nOptions:")
	fs.PrintDefaults() // 打印所有定义的标志及其默认值和说明
	fmt.Fprintln(fs.Output(), "\nExample:")
	fmt.Fprintln(fs.Output(), "  :tp -x x.x.x.x:1080")
}

func App_tp_main_withconfig(conn net.Conn, config *AppTPConfig) {
	defer conn.Close()

	// Only accept 127.0.0.0/8
	rhost, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return
	}
	if !strings.HasPrefix(rhost, "127.") {
		config.Logger.Printf("Only accept from 127.0.0.0/8, client(%s) closed.\n", conn.RemoteAddr().String())
		return
	}
	magicTarget, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return
	}
	if magicTarget == "127.0.0.1" {
		return
	}
	allowPublicIP := false
	if config.allow == "domain" || config.allow == "any" {
		allowPublicIP = true
	}

	targetHost, targetPort, err := DNSLookupMagicIP(magicTarget, allowPublicIP)
	if err != nil {
		config.Logger.Println("DNSLookupMagicIP failed:", err)
		return
	}

	config.Logger.Printf("connecting %s:%d\n", targetHost, targetPort)

	targetConn, err := config.dialer.Dialer.DialTimeout("tcp", net.JoinHostPort(targetHost, strconv.Itoa(targetPort)), 20*time.Second)
	if err != nil {
		config.Logger.Println("DialTimeout failed:", err)
		return
	}

	bidirectionalCopy(conn, targetConn)
}

func IsValidABC0IP(ipStr string) (bool, string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, ""
	}

	ip = ip.To4()
	if ip == nil {
		return false, ""
	}

	// Check if the last octet is 0
	if ip[3] != 0 {
		return false, ""
	}

	abc := fmt.Sprintf("%d.%d.%d", ip[0], ip[1], ip[2])
	return true, abc
}

func ExtractBCDFrom127(ipStr string) (b int, cd int, err error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, 0, fmt.Errorf("invalid IP format")
	}
	ip = ip.To4()
	if ip == nil {
		return 0, 0, fmt.Errorf("not an IPv4 address")
	}

	if ip[0] != 127 {
		return 0, 0, fmt.Errorf("not a 127.x.x.x address")
	}

	b = int(ip[1])
	c := int(ip[2])
	d := int(ip[3])
	cd = c*256 + d

	return b, cd, nil
}

func DNSLookupMagicIP(ipToken string, allowPublicIP bool) (string, int, error) {

	// 验证并解析 IP
	parsed := net.ParseIP(ipToken)
	if parsed == nil || parsed.To4() == nil {
		return "", 0, fmt.Errorf("invalid ipToken: %s", ipToken)
	}
	b := parsed.To4()

	donotUsePublicMagicDNS, targetIpPref := IsValidABC0IP(MagicDNServer)
	if donotUsePublicMagicDNS {
		targetIpD, targetPort, err := ExtractBCDFrom127(ipToken)
		if err != nil {
			return "", 0, fmt.Errorf("invalid ipToken: %v", err)
		}
		return fmt.Sprintf("%s.%d", targetIpPref, targetIpD), targetPort, nil
	}

	// 拼域名，比如 127.4.5.6.domain.io
	queryName := fmt.Sprintf("%d.%d.%d.%d.%s", b[0], b[1], b[2], b[3], MagicDNServer)

	type result struct {
		host string
		port int
		err  error
	}

	results := make(chan result, 2)

	// 查询 TXT
	go func() {
		txtRecords, err := net.LookupTXT(queryName)
		if err != nil {
			results <- result{"", 0, err}
			return
		}
		if len(txtRecords) == 0 {
			results <- result{"", 0, fmt.Errorf("no TXT record found")}
			return
		}

		parts := strings.SplitN(txtRecords[0], ":", 2)
		if len(parts) != 2 {
			results <- result{"", 0, fmt.Errorf("invalid TXT format: %s", txtRecords[0])}
			return
		}

		host := parts[0]
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			results <- result{"", 0, fmt.Errorf("invalid port: %v", err)}
			return
		}

		results <- result{host, port, nil}
	}()

	// 查询 CNAME
	go func() {
		cname, err := net.LookupCNAME(queryName)
		if err != nil {
			results <- result{"", 0, err}
			return
		}

		// cname 返回通常带最后的点，去掉
		cname = strings.TrimSuffix(cname, ".")
		cname = strings.TrimSuffix(cname, MagicDNServer)
		cname = strings.TrimSuffix(cname, ".") // 确保去掉最后的点

		// 现在格式是 "host-port"， 或x-domain-port
		idx := strings.LastIndex(cname, "-")
		if idx == -1 {
			// 没有找到 '-'，直接返回原值，port为空
			results <- result{"", 0, fmt.Errorf("invalid CNAME format: %s", cname)}
			return
		}

		host, portStr := cname[:idx], cname[idx+1:]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			results <- result{"", 0, fmt.Errorf("invalid port: %v", err)}
			return
		}

		results <- result{host, port, nil}
	}()

	// 哪个先成功就用哪个
	for i := 0; i < 2; i++ {
		r := <-results
		if r.err == nil {
			if !allowPublicIP {
				parsedHost := net.ParseIP(r.host)
				if parsedHost == nil || !(parsedHost.IsPrivate() || parsedHost.IsLoopback()) {
					return "", 0, fmt.Errorf("public IPs are not allowed: %s", r.host)
				}
			}
			return r.host, r.port, nil
		}
	}

	return "", 0, fmt.Errorf("both TXT and CNAME lookups failed")
}
