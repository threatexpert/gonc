package apps

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/threatexpert/gonc/v2/acl"
	"github.com/threatexpert/gonc/v2/misc"
	"github.com/threatexpert/gonc/v2/netx"
)

func handleSocks5Proxy(conn net.Conn, keyingMaterial [32]byte, config *AppS5SConfig, stats_in, stats_out *misc.ProgressStats) {
	defer conn.Close()

	s5config := Socks5uConfig{
		Logger:     config.Logger,
		Username:   config.Username,
		Password:   config.Password,
		ServerIP:   config.ServerIP,
		Localbind:  config.Localbind,
		AccessCtrl: config.AccessCtrl,
	}
	s5auth := &Socks5AuthConfig{
		AuthenticateUser: nil,
	}
	if config.Username != "" || config.Password != "" {
		s5auth.AuthenticateUser = func(username, password string) bool {
			return username == config.Username && password == config.Password
		}
	}

	conn.SetReadDeadline(time.Now().Add(20 * time.Second))

	// 1. SOCKS5 握手
	err := handleSocks5Handshake(conn, s5auth)
	if err != nil {
		config.Logger.Printf("SOCKS5 handshake failed for %s: %v", conn.RemoteAddr(), err)
		return
	}

	// 2. SOCKS5 请求 (TCP CONNECT 、BIND 或 UDP ASSOCIATE)
	req, err := handleSocks5Request(conn)
	if err != nil {
		config.Logger.Printf("SOCKS5 request failed for %s: %v", conn.RemoteAddr(), err)
		return
	}

	conn.SetReadDeadline(time.Time{})

	if req.Command == "CONNECT" && config.EnableConnect {
		err = handleDirectTCPConnect(&s5config, conn, req.Host, req.Port)
		if err != nil {
			config.Logger.Printf("SOCKS5 TCP Connect failed for %s: %v", conn.RemoteAddr(), err)
		}
	} else if req.Command == "BIND" && config.EnableBind {
		err = handleTCPListen(&s5config, conn, req.Host, req.Port)
		if err != nil {
			config.Logger.Printf("SOCKS5 TCP Listen failed for %s: %v", conn.RemoteAddr(), err)
		}
	} else if req.Command == "UDP" && config.EnableUDP {
		fakeTunnelC, rawS := net.Pipe()
		fakeTunnelS := misc.NewStatConn(rawS, stats_in, stats_out)
		var wg sync.WaitGroup
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer c.Close()
			handleSocks5ClientOnStream(&s5config, c)
		}(fakeTunnelS)

		err = handleUDPAssociateViaTunnel(&s5config, conn, keyingMaterial, fakeTunnelC, req.Host, req.Port)
		if err != nil {
			config.Logger.Printf("SOCKS5 UDP Associate failed for %s: %v", conn.RemoteAddr(), err)
		}
		fakeTunnelC.Close()
		fakeTunnelS.Close()
		wg.Wait()
	} else {
		sendSocks5Response(conn, REP_COMMAND_NOT_SUPPORTED, "0.0.0.0", 0)
	}

	config.Logger.Printf("Disconnected from client %s (requested SOCKS5 command: %s).", conn.RemoteAddr(), req.Command)
}

func handleHTTPProxy(conn *netx.BufferedConn, config *AppS5SConfig) error {
	req, err := handleHTTPProxyHandShake(conn, config.Username, config.Password)
	if err != nil {
		return err
	}

	if req.Method == http.MethodConnect {
		// HTTPS 隧道：建立连接后必须保持长连接进行双向转发
		return handleHTTPConnect(conn, req, config)
	}

	// 普通 HTTP
	return handleHTTPForwardSimple(conn, req, config)
}

func handleHTTPProxyHandShake(conn *netx.BufferedConn, username, password string) (*http.Request, error) {
	conn.SetReadDeadline(time.Now().Add(20 * time.Second))

	// 读取 HTTP 请求
	req, err := http.ReadRequest(conn.Reader)
	if err != nil {
		return nil, fmt.Errorf("read http request error: %w", err)
	}

	// 清除握手阶段的超时设置
	conn.SetReadDeadline(time.Time{})

	requiredAuth := ""
	if len(username) > 0 || len(password) > 0 {
		requiredAuth = fmt.Sprintf("%s:%s", username, password)
	}
	authField := req.Header.Get("Proxy-Authorization")
	if len(authField) == 0 {
		authField = req.Header.Get("Authorization")
	}
	if len(requiredAuth) > 0 {
		authOK := false
		if strings.HasPrefix(authField, "Basic ") {
			// Extract and decode the base64 encoded credentials
			encodedCredentials := strings.TrimPrefix(authField, "Basic ")
			encodedCredentials = strings.TrimSpace(encodedCredentials)
			decodedCredentials, err := base64.StdEncoding.DecodeString(encodedCredentials)
			if err != nil {
				return nil, fmt.Errorf("failed to decode Proxy-Authorization header: %v", err)
			}
			if string(decodedCredentials) == requiredAuth {
				authOK = true
			}
		}

		if !authOK {
			// Credentials do not match
			resp := &http.Response{
				StatusCode: http.StatusProxyAuthRequired,
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
			}
			resp.Header.Set("Proxy-Authenticate", `Basic realm="Restricted"`)
			resp.Write(conn)
			return nil, fmt.Errorf("proxy authentication failed for %s", conn.RemoteAddr())
		}
	}
	return req, nil
}

// handleHTTPForwardSimple 处理普通 HTTP 请求，不支持 Keep-Alive，并包含 ACL 和 Localbind 支持
func handleHTTPForwardSimple(clientConn net.Conn, req *http.Request, config *AppS5SConfig) error {
	// 1. URL 修正
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	// 2. 准备目标地址 (处理默认端口)
	// acl.ResolveAddrWithACL 通常需要 host:port 格式来正确解析（特别是如果是基于 ResolveTCPAddr）
	targetHost := req.URL.Hostname()
	targetPort := req.URL.Port()
	if targetPort == "" {
		targetPort = "80"
	}
	targetAddrStr := net.JoinHostPort(targetHost, targetPort)

	config.Logger.Printf("HTTP: %s->%s connecting...", clientConn.RemoteAddr().String(), targetAddrStr)
	defer config.Logger.Printf("HTTP: %s client disconnected.", clientConn.RemoteAddr().String())

	// 3. ACL 检查与地址解析 (逻辑复用自 handleHTTPConnect)
	// 使用 context 控制解析超时
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	resolvedAddr, isDenied, err := acl.ResolveAddrWithACL(ctx, config.AccessCtrl, "tcp", targetAddrStr)
	if err != nil {
		if isDenied {
			// 被 ACL 拒绝：返回 403 Forbidden
			clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			return fmt.Errorf("access denied by ACL for %s", targetAddrStr)
		}
		// 解析失败：返回 502 Bad Gateway
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return fmt.Errorf("resolve address failed: %w", err)
	}

	// 4. 定义自定义 Dialer (处理 Localbind)
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	// 如果配置了本地出口 IP，进行绑定
	if config.Localbind != "" {
		localAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(config.Localbind, "0"))
		if err != nil {
			clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return fmt.Errorf("resolve local bind address failed: %w", err)
		}
		dialer.LocalAddr = localAddr
	}

	// 5. 定义自定义 Transport
	// 我们在 DialContext 中使用已经经过 ACL 检查并解析好的 resolvedAddr
	tr := &http.Transport{
		// 强制短连接
		DisableKeepAlives: true,
		// 自定义拨号逻辑
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// 注意：这里忽略传入的 addr，直接使用上面 ACL 解析后的 resolvedAddr.String()
			// 这样既利用了 ACL 的解析结果，又防止了 DNS 重绑定攻击
			return dialer.DialContext(ctx, network, resolvedAddr.String())
		},
	}

	// 6. 强制短连接策略 (Simple & Brutal)
	req.Close = true
	req.Header.Set("Connection", "close")
	req.Header.Set("Proxy-Connection", "close")

	// 7. 删除逐跳头部
	delHopHeaders(req.Header)

	// 8. 发起请求 (使用自定义 Transport)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return fmt.Errorf("remote request failed: %w", err)
	}
	defer resp.Body.Close()

	// 9. 响应回写给客户端
	delHopHeaders(resp.Header)

	// 强制告诉客户端关闭连接
	resp.Header.Set("Connection", "close")
	resp.Close = true

	err = resp.Write(clientConn)
	if err != nil {
		return fmt.Errorf("write response failed: %w", err)
	}

	return nil
}

// 必须删除的头部，避免协议混乱
func delHopHeaders(header http.Header) {
	hopHeaders := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
		"Proxy-Connection",
	}
	for _, h := range hopHeaders {
		header.Del(h)
	}
}

func handleHTTPConnect(clientConn net.Conn, req *http.Request, config *AppS5SConfig) error {
	config.Logger.Printf("HTTP-CONNECT: %s->%s connecting...", clientConn.RemoteAddr().String(), req.Host)
	defer config.Logger.Printf("HTTP: %s client disconnected.", clientConn.RemoteAddr().String())

	dialer := &net.Dialer{}
	if config.Localbind != "" {
		localAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(config.Localbind, "0"))
		if err != nil {
			return err
		}
		dialer.LocalAddr = localAddr
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	resolvedAddr, isDenied, err := acl.ResolveAddrWithACL(ctx, config.AccessCtrl, "tcp", req.Host)
	if err != nil {
		if isDenied {
			clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		} else {
			clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		}
		return err
	}

	targetConn, err := dialer.DialContext(ctx, "tcp", resolvedAddr.String())
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return err
	}
	defer targetConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// 双向拷贝，直到一方断开
	bidirectionalCopy(clientConn, targetConn)
	return nil
}
