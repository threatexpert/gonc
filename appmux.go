package main

import (
	"bytes"
	"flag"
	"fmt"
	"gonc/misc"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/xtaci/smux"
)

var (
	muxSessionMode       = flag.String("mux-mode", "stdio", "connect | listen | stdio")
	muxSessionAddress    = flag.String("mux-address", "", "host:port (for connect or listen mode)")
	muxEngine            = flag.String("mux-engine", "smux", "yamux | smux")
	httpServeDir         = "."
	muxLastListenAddress = ""
)

type MuxSessionConfig struct {
	Engine      string
	AppMode     string
	Host        string // for forward
	Port        string
	RootDir     string // for httpserver
	SessionConn net.Conn
}

type stdioConn struct{}

func (s *stdioConn) Read(p []byte) (int, error)         { return os.Stdin.Read(p) }
func (s *stdioConn) Write(p []byte) (int, error)        { return os.Stdout.Write(p) }
func (s *stdioConn) Close() error                       { return nil }
func (s *stdioConn) LocalAddr() net.Addr                { return dummyAddr("stdio") }
func (s *stdioConn) RemoteAddr() net.Addr               { return dummyAddr("stdio") }
func (s *stdioConn) SetDeadline(t time.Time) error      { return nil }
func (s *stdioConn) SetReadDeadline(t time.Time) error  { return nil }
func (s *stdioConn) SetWriteDeadline(t time.Time) error { return nil }

type dummyAddr string

func (d dummyAddr) Network() string { return string(d) }
func (d dummyAddr) String() string  { return string(d) }

type ChanError struct {
	id  int
	err error
}

type muxListener struct {
	session interface{}
}

func (m *muxListener) Accept() (net.Conn, error) {
	var stream net.Conn
	var err error

	switch s := m.session.(type) {
	case *yamux.Session:
		stream, err = s.Accept()
	case *smux.Session:
		stream, err = s.AcceptStream()
	default:
		return nil, fmt.Errorf("unknown session type")
	}
	if err != nil {
		return nil, err
	}

	return &streamWrapper{Conn: stream}, nil
}

func (m *muxListener) Close() error {
	switch s := m.session.(type) {
	case *yamux.Session:
		return s.Close()
	case *smux.Session:
		return s.Close()
	default:
		return fmt.Errorf("unknown session type")
	}
}

func (m *muxListener) Addr() net.Addr {
	return dummyAddr("mux")
}

type streamWrapper struct {
	net.Conn
}

func (s *streamWrapper) CloseWrite() error {
	// 对于 yamux/smux，没有真实的 CloseWrite，只能 Close()
	// 这样实现是为了让 proxy_copy 那边能继续收尾
	return s.Conn.Close()
}

// 实现 net.Conn 剩余方法：

func (s *streamWrapper) LocalAddr() net.Addr {
	return dummyAddr("local")
}

func (s *streamWrapper) RemoteAddr() net.Addr {
	return dummyAddr("remote")
}

func (s *streamWrapper) SetDeadline(t time.Time) error {
	return s.Conn.SetDeadline(t)
}

func (s *streamWrapper) SetReadDeadline(t time.Time) error {
	return s.Conn.SetReadDeadline(t)
}

func (s *streamWrapper) SetWriteDeadline(t time.Time) error {
	return s.Conn.SetWriteDeadline(t)
}

func proxy_copy(dst io.WriteCloser, src io.Reader, errCh chan<- ChanError, id int) {
	_, err := io.Copy(dst, src)
	if tcpConn, ok := dst.(closeWriter); ok {
		tcpConn.CloseWrite()
	}
	errCh <- ChanError{id: id, err: err}
}

func handleProxy(local io.ReadWriteCloser, stream io.ReadWriteCloser) {
	errCh := make(chan ChanError, 2)
	go proxy_copy(stream, local, errCh, 1)
	go proxy_copy(local, stream, errCh, 2)
	for i := 0; i < 2; i++ {
		<-errCh
	}
}

func mux_usage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "   -app-mux target_host target_port")
	fmt.Fprintln(os.Stderr, "   -app-mux socks5")
	fmt.Fprintln(os.Stderr, "   -app-mux httpserver <rootDir>")
	fmt.Fprintln(os.Stderr, "   -app-mux -l listen_port")
}

func mux_main() {
	appMode := ""
	host := ""
	port := ""
	args := flag.Args()
	if len(args) == 1 && *listenMode {
		port = args[0]
		appMode = "listen"
	} else if len(args) == 1 && args[0] == "socks5" {
		appMode = "socks5"
	} else if len(args) >= 1 && args[0] == "httpserver" {
		appMode = "httpserver"
		if len(args) > 1 {
			httpServeDir = args[1]
		}
	} else if len(args) == 2 {
		host = args[0]
		port = args[1]
		appMode = "forward"
	} else {
		mux_usage()
		os.Exit(1)
	}

	if *udpProtocol {
		fmt.Fprintf(os.Stderr, "-app-mux and -u cannot be used together\n")
		os.Exit(1)
	}
	if *runCmd != "" {
		fmt.Fprintf(os.Stderr, "-app-mux and -exec cannot be used together\n")
		os.Exit(1)
	}

	var sessionConn net.Conn
	var err error
	var localAddr net.Addr

	init_TLS(false)

	dialer := createClientDialer()

	switch *muxSessionMode {
	case "connect":
		if *muxSessionAddress == "" {
			fmt.Fprintln(os.Stderr, "Error: -mux-address required for connect mode")
			os.Exit(1)
		}
		if *localbind != "" {
			localAddr, err = net.ResolveTCPAddr("tcp", *localbind)
			if err != nil {
				panic(err)
			}
			d := &net.Dialer{
				LocalAddr: localAddr,
				Control:   misc.ControlTCP,
			}
			sessionConn, err = d.Dial("tcp", *muxSessionAddress)
		} else {
			sessionConn, err = dialer.Dial("tcp", *muxSessionAddress)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Connect failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "MUX Session: connected to", *muxSessionAddress)

	case "listen":
		*listenMode = true
		if *muxSessionAddress == "" {
			fmt.Fprintln(os.Stderr, "Error: -mux-address required for listen mode")
			os.Exit(1)
		}
		ln, err := net.Listen("tcp", *muxSessionAddress)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Listen failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "Session: listening on", *muxSessionAddress)
		sessionConn, err = ln.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Accept failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "MUX Session: accepted connection")

	case "stdio":
		sessionConn = &stdioConn{}
		fmt.Fprintln(os.Stderr, "MUX Session: using stdio")

	default:
		fmt.Fprintf(os.Stderr, "Unknown mux-mode: %s\n", *muxSessionMode)
		os.Exit(1)
	}

	configTCPKeepalive(sessionConn)
	if isTLSEnabled() {
		conn_tls := do_TLS(sessionConn)
		if conn_tls == nil {
			return
		}
		defer conn_tls.Close()
		sessionConn = conn_tls
	}

	cfg := MuxSessionConfig{
		Engine:      *muxEngine,
		AppMode:     appMode,
		Host:        host,
		Port:        port,
		RootDir:     httpServeDir,
		SessionConn: sessionConn,
	}
	err = handleMuxSession(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "app-mux: %v\n", err)
	}
}

func App_mux_main(conn net.Conn, args []string) {
	appMode := ""
	host := ""
	port := ""
	if len(args) == 2 && args[0] == "-l" {
		port = args[1]
		appMode = "listen"
	} else if len(args) == 1 && args[0] == "socks5" {
		appMode = "socks5"
	} else if len(args) >= 1 && args[0] == "httpserver" {
		appMode = "httpserver"
		if len(args) > 1 {
			httpServeDir = args[1]
		}
	} else if len(args) == 2 {
		host = args[0]
		port = args[1]
		appMode = "forward"
	} else {
		mux_usage()
		return
	}

	cfg := MuxSessionConfig{
		Engine:      *muxEngine,
		AppMode:     appMode,
		Host:        host,
		Port:        port,
		RootDir:     httpServeDir,
		SessionConn: conn,
	}

	err := handleMuxSession(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "app-mux: %v\n", err)
	}
}

func handleMuxSession(cfg MuxSessionConfig) error {
	switch cfg.AppMode {
	case "listen":
		return handleListenMode(cfg)
	case "forward":
		return handleForwardMode(cfg)
	case "socks5":
		return handleSocks5uMode(cfg)
	case "httpserver":
		return handleHTTPServerMode(cfg)
	default:
		return fmt.Errorf("unsupported app mode: %s", cfg.AppMode)
	}
}

func handleListenMode(cfg MuxSessionConfig) error {
	fmt.Fprintln(os.Stderr, "Waiting for app-mux handshake...")
	hello := make([]byte, 16)
	if _, err := io.ReadFull(cfg.SessionConn, hello); err != nil {
		return fmt.Errorf("mux read hello failed: %v", err)
	}
	peerMode := string(bytes.TrimRight(hello, "\x00"))

	var session interface{}
	var err error

	session, err = createMuxSession(cfg.Engine, cfg.SessionConn, true)
	if err != nil {
		return err
	}

	laddr := cfg.Port
	if muxLastListenAddress != "" {
		laddr = muxLastListenAddress
	}
	if !strings.Contains(laddr, ":") {
		laddr = "127.0.0.1:" + laddr
	}
	ln, err := net.Listen("tcp", laddr)
	if err != nil {
		return fmt.Errorf("listen failed: %v", err)
	}

	fmt.Fprintf(os.Stderr, "[%s] Listening on %s\n", peerMode, ln.Addr().String())
	if peerMode == "httpserver" {
		_, port, _ := net.SplitHostPort(ln.Addr().String())
		fmt.Fprintf(os.Stderr, "You can open http://127.0.0.1:%s in your browser\n", port)
	}
	if cfg.Port == "0" {
		muxLastListenAddress = ln.Addr().String()
	}

	// session health check
	var sessErr error
	go func() {
		for {
			if isSessionClosed(session) {
				sessErr = fmt.Errorf("mux session closed")
				ln.Close()
				return
			}
			time.Sleep(1 * time.Second)
		}
	}()
	//监测session的连接状态，对端不应该Open流，所以Accept返回可能是连接异常。
	go func() {
		var stream net.Conn
		var err error
		switch s := session.(type) {
		case *yamux.Session:
			stream, err = s.Accept()
		case *smux.Session:
			stream, err = s.AcceptStream()
		}
		sessErr = fmt.Errorf("mux session unexpected behavior: %v", err)
		if err == nil {
			stream.Close()
		}
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if sessErr != nil {
				return sessErr
			}
			return fmt.Errorf("listener accept failed: %v", err)
		}

		go func(c net.Conn) {
			defer c.Close()
			var stream net.Conn
			var err error
			switch s := session.(type) {
			case *yamux.Session:
				stream, err = s.Open()
			case *smux.Session:
				stream, err = s.OpenStream()
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, "mux Open failed:", err)
				return
			}
			streamWithCloseWrite := &streamWrapper{Conn: stream}
			defer streamWithCloseWrite.Close()
			if peerMode == "socks5" {
				handleSocks5uProxy(c, streamWithCloseWrite)
			} else {
				handleProxy(c, streamWithCloseWrite)
			}
		}(conn)
	}
}

func handleForwardMode(cfg MuxSessionConfig) error {
	if err := sendHello(cfg.SessionConn, cfg.AppMode); err != nil {
		return err
	}

	session, err := createMuxSession(cfg.Engine, cfg.SessionConn, false)
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "forward ready on mux")

	for {
		var stream net.Conn
		switch s := session.(type) {
		case *yamux.Session:
			stream, err = s.Accept()
		case *smux.Session:
			stream, err = s.AcceptStream()
		}
		if err != nil {
			return fmt.Errorf("accept mux stream failed: %v", err)
		}

		go func(s net.Conn) {
			defer s.Close()
			targetConn, err := net.Dial("tcp", net.JoinHostPort(cfg.Host, cfg.Port))
			if err != nil {
				fmt.Fprintln(os.Stderr, "Connect target failed:", err)
				return
			}
			defer targetConn.Close()
			handleProxy(s, targetConn)
		}(&streamWrapper{Conn: stream})
	}
}

func handleSocks5uMode(cfg MuxSessionConfig) error {
	if err := sendHello(cfg.SessionConn, cfg.AppMode); err != nil {
		return err
	}

	return handleSocks5uModeForRemote(cfg)
}

func handleHTTPServerMode(cfg MuxSessionConfig) error {
	if err := sendHello(cfg.SessionConn, cfg.AppMode); err != nil {
		return err
	}

	session, err := createMuxSession(cfg.Engine, cfg.SessionConn, false)
	if err != nil {
		return err
	}

	handler := createHTTPHandler(cfg.RootDir)

	fmt.Fprintln(os.Stderr, "httpserver ready on mux")

	for {
		var stream net.Conn
		switch s := session.(type) {
		case *yamux.Session:
			stream, err = s.Accept()
		case *smux.Session:
			stream, err = s.AcceptStream()
		}
		if err != nil {
			return fmt.Errorf("accept mux stream failed: %v", err)
		}

		go func(conn net.Conn) {
			defer conn.Close()
			listener := &singleConnListener{
				conn: conn,
				done: make(chan struct{}),
			}
			_ = http.Serve(listener, handler)
		}(&streamWrapper{Conn: stream})
	}
}

func sendHello(conn net.Conn, mode string) error {
	hello := make([]byte, 16)
	copy(hello, mode)
	_, err := conn.Write(hello)
	return err
}

func createMuxSession(engine string, conn net.Conn, isClient bool) (interface{}, error) {
	switch engine {
	case "yamux":
		if isClient {
			return yamux.Client(conn, nil)
		}
		return yamux.Server(conn, nil)
	case "smux":
		if isClient {
			return smux.Client(conn, nil)
		}
		return smux.Server(conn, nil)
	default:
		return nil, fmt.Errorf("unknown mux engine: %s", engine)
	}
}

func isSessionClosed(session interface{}) bool {
	switch s := session.(type) {
	case *yamux.Session:
		return s.IsClosed()
	case *smux.Session:
		return s.IsClosed()
	default:
		return true
	}
}

type singleConnListener struct {
	conn net.Conn
	done chan struct{}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.conn != nil {
		c := l.conn
		l.conn = nil
		return c, nil
	}
	<-l.done
	return nil, fmt.Errorf("listener closed")
}

func (l *singleConnListener) Close() error {
	close(l.done)
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return dummyAddr("stream")
}

// rootDir 是你希望暴露的目录，比如 "./public"
func createHTTPHandler(rootDir string) http.Handler {
	fs := http.FileServer(http.Dir(rootDir))
	return loggingMiddleware(http.StripPrefix("/", fs))
}

func loggingMiddleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		handler.ServeHTTP(w, r)
	})
}
