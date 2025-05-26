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

	"github.com/armon/go-socks5"
	"github.com/hashicorp/yamux"
	"github.com/xtaci/smux"
)

var (
	muxSessionMode    = flag.String("mux-mode", "stdio", "connect | listen | stdio")
	muxSessionAddress = flag.String("mux-address", "", "host:port (for connect or listen mode)")
	muxEngine         = flag.String("mux-engine", "smux", "yamux | smux")
	httpServeDir      = "."
)

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
	var stream io.ReadWriteCloser
	var err error

	switch s := m.session.(type) {
	case *yamux.Session:
		stream, err = s.Accept()
	case *smux.Session:
		stream, err = s.Accept()
	default:
		return nil, fmt.Errorf("unknown session type")
	}
	if err != nil {
		return nil, err
	}

	return &streamWrapper{ReadWriteCloser: stream}, nil
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
	io.ReadWriteCloser
}

func (s *streamWrapper) CloseWrite() error {
	// 对于 yamux/smux，没有真实的 CloseWrite，只能 Close()
	// 这样实现是为了让 proxy_copy 那边能继续收尾
	return s.Close()
}

// 实现 net.Conn 剩余方法：

func (s *streamWrapper) LocalAddr() net.Addr {
	return dummyAddr("local")
}

func (s *streamWrapper) RemoteAddr() net.Addr {
	return dummyAddr("remote")
}

func (s *streamWrapper) SetDeadline(t time.Time) error {
	// yamux/smux 的 Stream 一般不支持 deadline，这里可 no-op
	return nil
}

func (s *streamWrapper) SetReadDeadline(t time.Time) error {
	return nil
}

func (s *streamWrapper) SetWriteDeadline(t time.Time) error {
	return nil
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

	dialer := createDialer()

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
			dialer = &net.Dialer{
				LocalAddr: localAddr,
				Control:   misc.ControlTCP,
			}
		}
		sessionConn, err = dialer.Dial("tcp", *muxSessionAddress)
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

	if appMode == "listen" {
		fmt.Fprintln(os.Stderr, "Waiting for app-mux handshake...")
		hello := make([]byte, 16)
		if _, err := io.ReadFull(sessionConn, hello); err != nil {
			fmt.Fprintf(os.Stderr, "mux read hello failed: %v\n", err)
			os.Exit(1)
		}
		peer_mode := string(bytes.TrimRight(hello, "\x00"))
		if peer_mode != "socks5" && peer_mode != "forward" && peer_mode != "httpserver" {
			fmt.Fprintf(os.Stderr, "invalid peer mode: %q\n", peer_mode)
			os.Exit(1)
		}

		var session interface{}
		switch *muxEngine {
		case "yamux":
			session, err = yamux.Client(sessionConn, nil)
		case "smux":
			session, err = smux.Client(sessionConn, nil)
		default:
			fmt.Fprintf(os.Stderr, "Unknown mux-engine: %s\n", *muxEngine)
			os.Exit(1)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "mux client failed:", err)
			os.Exit(1)
		}

		laddr := port
		if !strings.Contains(laddr, ":") {
			laddr = "127.0.0.1:" + laddr
		}

		ln, err := net.Listen("tcp", laddr)
		if err != nil {
			log.Fatalf("listen failed: %v", err)
		}

		if peer_mode == "socks5" {
			fmt.Fprintln(os.Stderr, "[socks5] Listening on", ln.Addr().String())
		} else if peer_mode == "forward" {
			fmt.Fprintln(os.Stderr, "[forward] Listening on", ln.Addr().String())
		} else if peer_mode == "httpserver" {
			addr := ln.Addr().String()
			fmt.Fprintf(os.Stderr, "[httpserver] Serving files at %s\n", addr)
			// 提示用户如何访问
			_, port, _ := net.SplitHostPort(addr)
			fmt.Fprintf(os.Stderr, "You can open http://127.0.0.1:%s in your browser to browse or download files.\n", port)
		} else {
			fmt.Fprintf(os.Stderr, "invalid peer mode: %q\n", peer_mode)
			os.Exit(1)
		}

		go func() {
			for {
				if closed := isSessionClosed(session); closed {
					fmt.Fprintln(os.Stderr, "mux session closed")
					os.Exit(1)
				}
				time.Sleep(1 * time.Second)
			}
		}()

		for {
			conn, err := ln.Accept()
			if err != nil {
				fmt.Fprintln(os.Stderr, "Accept failed:", err)
				continue
			}
			go func(c net.Conn) {
				var stream io.ReadWriteCloser
				switch s := session.(type) {
				case *yamux.Session:
					stream, err = s.Open()
				case *smux.Session:
					stream, err = s.Open()
				default:
					err = fmt.Errorf("unknown mux session type")
				}
				if err != nil {
					fmt.Fprintln(os.Stderr, "mux Open failed:", err)
					c.Close()
					return
				}
				handleProxy(c, stream)
			}(conn)
		}

	} else {
		hello := make([]byte, 16)
		copy(hello, appMode)
		_, err = sessionConn.Write(hello)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mux write hello failed: %v\n", err)
			os.Exit(1)
		}

		var session interface{}
		switch *muxEngine {
		case "yamux":
			session, err = yamux.Server(sessionConn, nil)
		case "smux":
			session, err = smux.Server(sessionConn, nil)
		default:
			fmt.Fprintf(os.Stderr, "Unknown mux-engine: %s\n", *muxEngine)
			os.Exit(1)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "mux server failed:", err)
			os.Exit(1)
		}

		if appMode == "forward" {
			for {
				var stream io.ReadWriteCloser
				switch s := session.(type) {
				case *yamux.Session:
					stream, err = s.Accept()
				case *smux.Session:
					stream, err = s.Accept()
				default:
					err = fmt.Errorf("unknown mux session type")
				}
				if err != nil {
					fmt.Fprintln(os.Stderr, "Accept mux stream failed:", err)
					break
				}
				wrappedStream := &streamWrapper{ReadWriteCloser: stream}
				go func(s io.ReadWriteCloser) {
					defer s.Close()
					targetConn, err := net.Dial("tcp", net.JoinHostPort(host, port))
					if err != nil {
						fmt.Fprintln(os.Stderr, "Connect target failed:", err)
						return
					}
					defer targetConn.Close()
					handleProxy(s, targetConn)
				}(wrappedStream)
			}
		} else if appMode == "socks5" {
			logger := log.New(os.Stderr, "[socks5] ", log.LstdFlags)
			conf := &socks5.Config{Logger: logger}
			server, err := socks5.New(conf)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Create socks5 failed:", err)
				os.Exit(1)
			}
			fmt.Fprintln(os.Stderr, "SOCKS5 ready on mux")
			server.Serve(&muxListener{session})
		} else if appMode == "httpserver" {
			handler := createHTTPHandler(httpServeDir)

			for {
				var stream io.ReadWriteCloser
				switch s := session.(type) {
				case *yamux.Session:
					stream, err = s.Accept()
				case *smux.Session:
					stream, err = s.Accept()
				default:
					err = fmt.Errorf("unknown mux session type")
				}
				if err != nil {
					fmt.Fprintln(os.Stderr, "Accept mux stream failed:", err)
					break
				}
				wrappedStream := &streamWrapper{ReadWriteCloser: stream}

				go func(conn net.Conn) {
					defer conn.Close()
					listener := &singleConnListener{
						conn: conn,
						done: make(chan struct{}),
					}
					_ = http.Serve(listener, handler)
				}(wrappedStream)
			}
		}
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
