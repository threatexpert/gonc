package apps

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"github.com/threatexpert/gonc/v2/httpfileshare"
	"github.com/threatexpert/gonc/v2/misc"
)

// ==========================================
// Section 0: Custom Listener Implementation
// ==========================================

// ChannelListener 是一个自定义的 Listener，通过 Channel 接收连接
type ChannelListener struct {
	connCh  chan net.Conn
	closeCh chan struct{}
	addr    net.Addr
}

func NewChannelListener() *ChannelListener {
	return &ChannelListener{
		connCh:  make(chan net.Conn, 10), // 带缓冲，防止瞬时并发阻塞
		closeCh: make(chan struct{}),
		addr: &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 0, // 虚拟端口
		},
	}
}

// Accept 等待并返回下一个连接
func (l *ChannelListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.connCh:
		return c, nil
	case <-l.closeCh:
		return nil, net.ErrClosed
	}
}

// Close 关闭监听器
func (l *ChannelListener) Close() error {
	select {
	case <-l.closeCh:
		return nil // 已经关闭
	default:
		close(l.closeCh)
	}
	return nil
}

// Addr 返回虚拟地址
func (l *ChannelListener) Addr() net.Addr {
	return l.addr
}

// InjectConn 是我们自定义的方法，用于从外部注入连接
func (l *ChannelListener) InjectConn(c net.Conn) error {
	select {
	case l.connCh <- c:
		return nil
	case <-l.closeCh:
		return net.ErrClosed
	}
}

// ==========================================
// Section 1: Configuration & Flags
// ==========================================

type AppHttpServerConfig struct {
	Logger    *log.Logger
	RootPaths []string
	WebMode   bool

	// 内部状态
	server   *httpfileshare.Server // 假设这是一个 Struct 指针或 Interface
	listener *ChannelListener      // 保存监听器引用，以便注入连接

	// 使用 sync.Once 确保 server 只启动一次，线程安全且比 bool 更优雅
	startOnce sync.Once
}

func AppHttpServerConfigByArgs(logWriter io.Writer, args []string) (*AppHttpServerConfig, error) {
	config := &AppHttpServerConfig{
		Logger: misc.NewLog(logWriter, "[:httpserver] ", log.LstdFlags|log.Lmsgprefix),
	}
	fs := flag.NewFlagSet("AppHttpServerConfig", flag.ContinueOnError)
	fs.SetOutput(logWriter)

	// 支持的选项
	fs.BoolVar(&config.WebMode, "webmode", true, "Enable web mode")

	fs.Usage = func() {
		App_HttpServer_usage_flagSet(fs)
	}

	// 解析 flags
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	// === 方案 3：使用 positional args 作为 RootPaths ===
	paths := fs.Args()
	if len(paths) == 0 {
		paths = []string{"."} // 默认目录
	}
	config.RootPaths = paths

	err := validateRootPaths(config.RootPaths)
	if err != nil {
		return nil, err
	}

	// 初始化自定义 Listener
	ln := NewChannelListener()
	config.listener = ln

	srvcfg := httpfileshare.ServerConfig{
		RootPaths:    config.RootPaths,
		LoggerOutput: logWriter,
		EnableZstd:   true,
		Listener:     ln,
		WebMode:      config.WebMode,
	}

	srv, err := httpfileshare.NewServer(srvcfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create server: %w", err)
	}
	config.server = srv

	return config, nil
}

func App_HttpServer_usage_flagSet(fs *flag.FlagSet) {
	fmt.Fprintln(fs.Output(), ":httpserver Usage: [options]")
	fmt.Fprintln(fs.Output(), "\nOptions:")
	fs.PrintDefaults() // 打印所有定义的标志及其默认值和说明
	fmt.Fprintln(fs.Output(), "\nExample:")
	fmt.Fprintln(fs.Output(), "  :httpserver ./site ./assets")
}

// ==========================================
// Section 3: Main Logic
// ==========================================

func App_HttpServer_main_withconfig(conn net.Conn, config *AppHttpServerConfig) {
	// 1. 确保 Server 已经启动 (只执行一次)
	config.startOnce.Do(func() {
		go func() {
			config.Logger.Printf("Starting HTTP file server on virtual listener...")
			err := config.server.Start()
			if err != nil && !errors.Is(err, net.ErrClosed) {
				config.Logger.Printf("Server error: %v", err)
			}
		}()
	})

	// 2. 将外部连接注入到自定义监听器中
	// 这看起来像是把 conn "推" 给了 http server
	if config.listener != nil {
		err := config.listener.InjectConn(conn)
		if err != nil {
			config.Logger.Printf("Failed to inject connection: %v", err)
			conn.Close() // 如果注入失败，确保关闭连接
		} else {
			// config.Logger.Printf("Connection injected successfully")
		}
	} else {
		config.Logger.Printf("Error: Listener is not initialized")
		conn.Close()
	}
}

// --- Utils ---

func validateRootPaths(rootPaths []string) error {
	var bad []string

	for _, p := range rootPaths {
		if p == "" {
			bad = append(bad, "(empty path)")
			continue
		}

		if _, err := os.Stat(p); err != nil {
			bad = append(bad, fmt.Sprintf("%s (stat error: %v)", p, err))
		}
	}

	if len(bad) > 0 {
		// 拼接错误消息
		msg := "invalid RootPaths:\n"
		for _, b := range bad {
			msg += "  - " + b + "\n"
		}
		return errors.New(msg)
	}

	return nil
}
