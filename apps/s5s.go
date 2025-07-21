package apps

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/threatexpert/gonc/v2/acl"
)

type AppS5SConfig struct {
	Username      string
	Password      string
	EnableConnect bool
	EnableUDP     bool
	EnableBind    bool
	Localbind     string
	AccessCtrl    *acl.ACL
}

// AppS5SConfigByArgs 解析给定的 []string 参数，生成 AppS5SConfig
func AppS5SConfigByArgs(args []string) (*AppS5SConfig, error) {
	config := &AppS5SConfig{}

	// 创建一个新的 FlagSet 实例
	fs := flag.NewFlagSet("AppS5SConfig", flag.ContinueOnError)

	var authString string // 用于接收 -auth 的值
	fs.StringVar(&authString, "auth", "", "Username and password for SOCKS5 authentication (format: user:pass)")
	fs.BoolVar(&config.EnableConnect, "c", true, "Allow SOCKS5 CONNECT command")
	fs.BoolVar(&config.EnableBind, "b", false, "Allow SOCKS5 BIND command")
	fs.BoolVar(&config.EnableUDP, "u", false, "Allow SOCKS5 UDP ASSOCIATE command")
	fs.StringVar(&config.Localbind, "local", "", "Set local bind address for outbound connections (format: ip)")

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
	fmt.Fprintln(os.Stderr, ":s5s Usage: [options]")
	fmt.Fprintln(os.Stderr, "\nOptions:")
	fs.PrintDefaults() // 打印所有定义的标志及其默认值和说明
	fmt.Fprintln(os.Stderr, "\nExample:")
	fmt.Fprintln(os.Stderr, "  :s5s -auth user:password")
}

func App_s5s_main_withconfig(conn net.Conn, config *AppS5SConfig) {
	defer conn.Close()

	s5config := Socks5ServerConfig{
		AuthenticateUser: nil,
	}
	if config.Username != "" || config.Password != "" {
		s5config.AuthenticateUser = func(username, password string) bool {
			return username == config.Username && password == config.Password
		}
	}
	log.Printf("New client connected from %s", conn.RemoteAddr())

	conn.SetReadDeadline(time.Now().Add(20 * time.Second))

	// 1. SOCKS5 握手
	err := handleSocks5Handshake(conn, s5config)
	if err != nil {
		log.Printf("SOCKS5 handshake failed for %s: %v", conn.RemoteAddr(), err)
		return
	}

	// 2. SOCKS5 请求 (TCP CONNECT 或 UDP ASSOCIATE)
	req, err := handleSocks5Request(conn)
	if err != nil {
		log.Printf("SOCKS5 request failed for %s: %v", conn.RemoteAddr(), err)
		return
	}

	conn.SetReadDeadline(time.Time{})

	if req.Command == "CONNECT" && config.EnableConnect {
		err = handleDirectTCPConnect(conn, req.Host, req.Port, config.Localbind, config.AccessCtrl)
		if err != nil {
			log.Printf("SOCKS5 TCP Connect failed for %s: %v", conn.RemoteAddr(), err)
		}
	} else if req.Command == "BIND" && config.EnableBind {
		err = handleTCPListen(conn, req.Host, req.Port)
		if err != nil {
			log.Printf("SOCKS5 TCP Listen failed for %s: %v", conn.RemoteAddr(), err)
		}
	} else if req.Command == "UDP" && config.EnableUDP {
		fakeTunnelC, fakeTunnelS := net.Pipe()
		var wg sync.WaitGroup
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer c.Close()
			handleSocks5ClientOnStream(c, config.Localbind, config.AccessCtrl)
		}(fakeTunnelS)

		err = handleUDPAssociateViaTunnel(conn, fakeTunnelC, req.Host, req.Port)
		if err != nil {
			log.Printf("SOCKS5 UDP Associate failed for %s: %v", conn.RemoteAddr(), err)
		}
		fakeTunnelC.Close()
		fakeTunnelS.Close()
		wg.Wait()
	} else {
		sendSocks5Response(conn, REP_COMMAND_NOT_SUPPORTED, "0.0.0.0", 0)
	}

	log.Printf("Disconnected from client %s (requested SOCKS5 command: %s).", conn.RemoteAddr(), req.Command)
}
