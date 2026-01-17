package apps

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/threatexpert/gonc/v2/acl"
	"github.com/threatexpert/gonc/v2/misc"
	"github.com/threatexpert/gonc/v2/netx"
)

type AppS5SConfig struct {
	Logger        *log.Logger
	Username      string
	Password      string
	EnableConnect bool
	EnableUDP     bool
	EnableBind    bool
	Localbind     []string
	ServerIP      string
	AccessCtrl    *acl.ACL
	EnableSocks5  bool
	EnableHTTP    bool
}

// AppS5SConfigByArgs 解析给定的 []string 参数，生成 AppS5SConfig
func AppS5SConfigByArgs(logWriter io.Writer, args []string) (*AppS5SConfig, error) {
	config := &AppS5SConfig{
		Logger: misc.NewLog(logWriter, "[:s5s] ", log.LstdFlags|log.Lmsgprefix),
	}

	// 创建一个新的 FlagSet 实例
	fs := flag.NewFlagSet("AppS5SConfig", flag.ContinueOnError)
	fs.SetOutput(logWriter)

	var authString string // 用于接收 -auth 的值
	var localBind string
	fs.StringVar(&authString, "auth", "", "Username and password for SOCKS5 authentication (format: user:pass)")
	fs.BoolVar(&config.EnableConnect, "c", true, "Allow SOCKS5 CONNECT command")
	fs.BoolVar(&config.EnableBind, "b", false, "Allow SOCKS5 BIND command")
	fs.BoolVar(&config.EnableUDP, "u", false, "Allow SOCKS5 UDP ASSOCIATE command")
	fs.BoolVar(&config.EnableSocks5, "socks5", true, "Enable SOCKS5-PROXY")
	fs.BoolVar(&config.EnableHTTP, "http", false, "Enable HTTP-PROXY")
	fs.StringVar(&localBind, "local", "", "Set local bind address(es) for outbound connections, comma-separated (e.g. 10.0.0.12,2001:db8::1)")
	fs.StringVar(&config.ServerIP, "server-ip", "", "BIND/UDP ASSOCIATE uses this as server IP (format: ip)")

	// 设置自定义的 Usage 函数
	fs.Usage = func() {
		App_s5s_usage_flagSet(fs)
	}

	// 解析传入的 args 切片
	err := fs.Parse(args)
	if err != nil {
		return nil, err // 解析错误直接返回
	}

	// 检查是否有未解析的（非标志）参数
	if len(fs.Args()) > 0 {
		return nil, fmt.Errorf("unknown positional arguments: %v", fs.Args())
	}

	if localBind != "" {
		parts := strings.Split(localBind, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			config.Localbind = append(config.Localbind, p)
		}
	}

	// 如果 -auth 标志被提供
	if authString != "" {
		authParts := strings.SplitN(authString, ":", 2)
		if len(authParts) != 2 {
			return nil, fmt.Errorf("invalid auth format for -auth: %s. Expected user:pass", authString)
		}
		config.Username = authParts[0]
		config.Password = authParts[1]
	}

	return config, nil
}

// App_s5s_usage_flagSet 接受一个 *flag.FlagSet 参数，用于打印其默认用法信息
func App_s5s_usage_flagSet(fs *flag.FlagSet) {
	fmt.Fprintln(fs.Output(), ":s5s Usage: [options]")
	fmt.Fprintln(fs.Output(), "\nOptions:")
	fs.PrintDefaults() // 打印所有定义的标志及其默认值和说明
	fmt.Fprintln(fs.Output(), "\nExample:")
	fmt.Fprintln(fs.Output(), "  :s5s -auth user:password")
}

// stats_in, stats_out是为了针对UDP代理时，对UDP的流量进行统计。因为参数1的conn已经纳入统计了
func App_s5s_main_withconfig(conn net.Conn, keyingMaterial [32]byte, config *AppS5SConfig, stats_in, stats_out *misc.ProgressStats) {
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(25 * time.Second))

	bufConn := netx.NewBufferedConn(conn)
	head, err := bufConn.Reader.Peek(1)
	if err != nil {
		config.Logger.Printf("Peek from %s error : %v", conn.RemoteAddr(), err)
		return
	} else if len(head) == 0 {
		return
	}

	// 判断协议并分流
	if head[0] == 0x05 {
		if !config.EnableSocks5 {
			config.Logger.Printf("Denied %s, SOCKS5 proxy is disabled.", conn.RemoteAddr())
			return
		}
		handleSocks5Proxy(bufConn, keyingMaterial, config, stats_in, stats_out)
	} else {
		if !config.EnableHTTP {
			config.Logger.Printf("Denied %s, HTTP proxy is disabled.", conn.RemoteAddr())
			return
		}
		handleHTTPProxy(bufConn, config)
	}
}
