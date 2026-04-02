package apps

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/threatexpert/gonc/v2/acl"
	"github.com/threatexpert/gonc/v2/misc"
	"github.com/threatexpert/gonc/v2/netx"
	"github.com/threatexpert/gonc/v2/secure"
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

	reqTarget := net.JoinHostPort(req.Host, strconv.Itoa(req.Port))

	conn.SetReadDeadline(time.Time{})

	if req.Command == "CONNECT" && config.EnableConnect {
		err = handleDirectTCPConnect(&s5config, conn, req.Host, req.Port)
		if err != nil {
			config.Logger.Printf("SOCKS5 TCP Connect failed for %s->%s: %v", conn.RemoteAddr(), reqTarget, err)
		}
	} else if req.Command == "BIND" && config.EnableBind {
		err = handleTCPListen(&s5config, conn, req.Host, req.Port)
		if err != nil {
			config.Logger.Printf("SOCKS5 TCP Listen failed for %s->%s: %v", conn.RemoteAddr(), reqTarget, err)
		}
	} else if req.Command == "UDP" && config.EnableUDP {
		err = handleDirectUDPAssociate(&s5config, conn, keyingMaterial, stats_in, stats_out)
		if err != nil {
			config.Logger.Printf("SOCKS5 UDP Associate failed for %s: %v", conn.RemoteAddr(), err)
		}
	} else {
		sendSocks5Response(conn, REP_COMMAND_NOT_SUPPORTED, "0.0.0.0", 0)
	}

	config.Logger.Printf("Disconnected from client %s (requested SOCKS5 command: %s->%s).", conn.RemoteAddr(), req.Command, reqTarget)
}

func handleHTTPProxy(conn *netx.BufferedConn, config *AppS5SConfig) {
	req, err := handleHTTPProxyHandShake(conn, config.Username, config.Password)
	if err != nil {
		config.Logger.Printf("HTTP proxy handshake failed for %s: %v", conn.RemoteAddr(), err)
		return
	}

	if req.Method == http.MethodConnect {
		// HTTPS 隧道：建立连接后必须保持长连接进行双向转发
		err = handleHTTPConnect(conn, req, config)
		if err != nil {
			config.Logger.Printf("HTTP CONNECT failed for %s->%s: %v", conn.RemoteAddr(), req.Host, err)
			return
		}
		return
	}

	// 普通 HTTP
	err = handleHTTPForwardSimple(conn, req, config)
	if err != nil {
		config.Logger.Printf("HTTP CONNECT failed for %s->%s: %v", conn.RemoteAddr(), req.Host, err)
		return
	}
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

	lResolveAddr, rResolvedAddr, isDenied, err := acl.ResolveAddrWithACL(ctx, config.AccessCtrl, "tcp", config.Localbind, targetAddrStr)
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

	resolvedAddrStr := rResolvedAddr.String()
	if resolvedAddrStr != targetAddrStr {
		config.Logger.Printf("HTTP: %s->%s(%s) connecting...", clientConn.RemoteAddr().String(), targetAddrStr, resolvedAddrStr)
	}

	// 4. 定义自定义 Dialer (处理 Localbind)
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		LocalAddr: lResolveAddr,
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
			return dialer.DialContext(ctx, network, resolvedAddrStr)
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
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	lResolvedAddr, rResolvedAddr, isDenied, err := acl.ResolveAddrWithACL(ctx, config.AccessCtrl, "tcp", config.Localbind, req.Host)
	if err != nil {
		if isDenied {
			clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		} else {
			clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		}
		return err
	}
	dialer.LocalAddr = lResolvedAddr
	resolvedAddrStr := rResolvedAddr.String()

	if resolvedAddrStr != req.Host {
		config.Logger.Printf("HTTP-CONNECT: %s->%s(%s) connecting...", clientConn.RemoteAddr().String(), req.Host, resolvedAddrStr)
	}

	targetConn, err := dialer.DialContext(ctx, "tcp", resolvedAddrStr)
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

// handleDirectUDPAssociate 处理 standalone SOCKS5 服务器的 UDP ASSOCIATE 命令
// 不经过 tunnel/net.Pipe，直接在 clientUDP 和 targetUDP 之间转发
func handleDirectUDPAssociate(config *Socks5uConfig, clientConn net.Conn, keyingMaterial [32]byte, stats_in, stats_out *misc.ProgressStats) error {
	// 1. 创建面向客户端的 UDP 监听
	cliIP, _, _ := net.SplitHostPort(clientConn.LocalAddr().String())
	localUDPAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(cliIP, "0"))
	if err != nil {
		sendSocks5Response(clientConn, REP_GENERAL_SOCKS_SERVER_FAIL, "0.0.0.0", 0)
		return fmt.Errorf("resolve local UDP addr error: %w", err)
	}

	localUDPConn, err := net.ListenUDP("udp", localUDPAddr)
	if err != nil {
		sendSocks5Response(clientConn, REP_GENERAL_SOCKS_SERVER_FAIL, "0.0.0.0", 0)
		return fmt.Errorf("listen local UDP error: %w", err)
	}
	defer localUDPConn.Close()

	// 2. 创建面向目标的 UDP socket
	var remoteBindAddr *net.UDPAddr
	if len(config.Localbind) > 0 {
		remoteBindAddr, err = net.ResolveUDPAddr("udp", net.JoinHostPort(config.Localbind[0], "0"))
		if err != nil {
			sendSocks5Response(clientConn, REP_GENERAL_SOCKS_SERVER_FAIL, "0.0.0.0", 0)
			return fmt.Errorf("resolve remote bind addr error: %w", err)
		}
	}

	remoteUDPConn, err := net.ListenUDP("udp", remoteBindAddr)
	if err != nil {
		sendSocks5Response(clientConn, REP_GENERAL_SOCKS_SERVER_FAIL, "0.0.0.0", 0)
		return fmt.Errorf("listen remote UDP error: %w", err)
	}
	defer remoteUDPConn.Close()

	// 3. 回复 SOCKS5 客户端成功响应
	bindIP := config.ServerIP
	bindPort := localUDPConn.LocalAddr().(*net.UDPAddr).Port
	err = sendSocks5Response(clientConn, REP_SUCCEEDED, bindIP, bindPort)
	if err != nil {
		return fmt.Errorf("send UDP associate response error: %w", err)
	}

	config.Logger.Printf("UDP-Direct: local=%s, remote=%s", localUDPConn.LocalAddr(), remoteUDPConn.LocalAddr())

	// 4. 如果有加密密钥，包装面向客户端的 UDP socket
	var pktConnLocal net.PacketConn = localUDPConn
	if keyingMaterial != [32]byte{} {
		pktConnLocal, err = secure.NewSecureUDPConn(localUDPConn, keyingMaterial)
		if err != nil {
			return fmt.Errorf("create secure UDP conn error: %w", err)
		}
		defer pktConnLocal.Close()
	}

	// 5. 获取客户端 IP 用于安全校验
	clientAddr := clientConn.RemoteAddr()
	var clientIP net.IP
	switch a := clientAddr.(type) {
	case *net.TCPAddr:
		clientIP = a.IP
	case *net.UDPAddr:
		clientIP = a.IP
	}

	var clientActualUDPAddr *net.UDPAddr // 记录客户端的实际 UDP 源地址
	var wg sync.WaitGroup
	done := make(chan struct{})
	var once sync.Once
	closeDone := func() {
		once.Do(func() {
			close(done)
			pktConnLocal.Close()
			remoteUDPConn.Close()
			clientConn.Close()
		})
	}

	wg.Add(3)

	// Goroutine A: client UDP → 解析 SOCKS5 头 → target UDP
	go func() {
		defer wg.Done()
		defer closeDone()

		buf := make([]byte, 65535)
		var firstPacketLogged bool

		// 本地目标地址缓存，避免每包调用 ResolveAddrWithACL（内含 DialUDP 探测）
		type resolvedTarget struct {
			addr *net.UDPAddr
		}
		targetCache := make(map[string]*resolvedTarget) // key: "host:port"

		for {
			n, cliAddr, err := pktConnLocal.ReadFrom(buf)
			if err != nil {
				break
			}
			stats_in.Update(int64(n))

			cliUDPAddr, ok := cliAddr.(*net.UDPAddr)
			if !ok {
				continue
			}

			// 安全校验：只接受来自客户端 IP 的包
			if clientIP != nil && !cliUDPAddr.IP.Equal(clientIP) {
				continue
			}

			if clientActualUDPAddr == nil {
				clientActualUDPAddr = cliUDPAddr
				config.Logger.Printf("UDP: %s associated", clientActualUDPAddr)
			}

			// 解析 SOCKS5 UDP 报头
			if n < 10 {
				continue
			}
			frag := buf[2]
			atyp := buf[3]
			if frag != SOCKS5_UDP_FRAG {
				continue
			}

			var targetHost string
			var targetPort int
			var dataOffset int

			switch atyp {
			case ATYP_IPV4:
				if n < 10 {
					continue
				}
				targetHost = net.IPv4(buf[4], buf[5], buf[6], buf[7]).String()
				targetPort = int(buf[8])<<8 | int(buf[9])
				dataOffset = 10
			case ATYP_DOMAINNAME:
				domainLen := int(buf[4])
				if n < 5+domainLen+2 {
					continue
				}
				targetHost = string(buf[5 : 5+domainLen])
				targetPort = int(buf[5+domainLen])<<8 | int(buf[5+domainLen+1])
				dataOffset = 5 + domainLen + 2
			case ATYP_IPV6:
				if n < 22 {
					continue
				}
				targetHost = net.IP(buf[4 : 4+16]).String()
				targetPort = int(buf[20])<<8 | int(buf[21])
				dataOffset = 22
			default:
				continue
			}

			if !firstPacketLogged {
				firstPacketLogged = true
				config.Logger.Printf("UDP: first packet -> %s:%d", targetHost, targetPort)
			}

			// 查缓存，命中则直接发送，跳过 ResolveAddrWithACL（内含 DialUDP 探测）
			cacheKey := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
			cached, hit := targetCache[cacheKey]
			if !hit {
				_, targetAddr, isDenied, resolveErr := acl.ResolveAddrWithACL(context.Background(), config.AccessCtrl, "udp", config.Localbind, cacheKey)
				if resolveErr != nil {
					if isDenied {
						config.Logger.Printf("Denied UDP to %s:%d: %v", targetHost, targetPort, resolveErr)
					}
					// 解析失败也缓存（nil addr），避免重复尝试
					targetCache[cacheKey] = &resolvedTarget{addr: nil}
					continue
				}
				cached = &resolvedTarget{addr: targetAddr.(*net.UDPAddr)}
				targetCache[cacheKey] = cached
			}

			if cached.addr == nil {
				continue // 之前解析失败的目标
			}

			_, err = remoteUDPConn.WriteToUDP(buf[dataOffset:n], cached.addr)
			if err != nil {
				break
			}
		}
	}()

	// Goroutine B: target UDP → 构造 SOCKS5 头 → client UDP
	go func() {
		defer wg.Done()
		defer closeDone()

		// 预分配: [SOCKS5 头(最大22字节)][数据]
		frameBuf := make([]byte, 22+65535)
		respBuf := make([]byte, 65535)

		for {
			nResp, udpSrcAddr, err := remoteUDPConn.ReadFromUDP(respBuf)
			if err != nil {
				break
			}

			if clientActualUDPAddr == nil {
				continue
			}

			// 在 frameBuf 中构造 SOCKS5 UDP 响应
			frameBuf[0] = SOCKS5_UDP_RSV >> 8
			frameBuf[1] = SOCKS5_UDP_RSV & 0xFF // RSV
			frameBuf[2] = SOCKS5_UDP_FRAG       // FRAG
			off := 3

			if ipv4 := udpSrcAddr.IP.To4(); ipv4 != nil {
				frameBuf[off] = ATYP_IPV4
				off++
				off += copy(frameBuf[off:], ipv4)
			} else if ipv6 := udpSrcAddr.IP.To16(); ipv6 != nil {
				frameBuf[off] = ATYP_IPV6
				off++
				off += copy(frameBuf[off:], ipv6)
			} else {
				continue
			}

			frameBuf[off] = byte(udpSrcAddr.Port >> 8)
			frameBuf[off+1] = byte(udpSrcAddr.Port & 0xFF)
			off += 2

			off += copy(frameBuf[off:], respBuf[:nResp])

			_, err = pktConnLocal.WriteTo(frameBuf[:off], clientActualUDPAddr)
			if err != nil {
				break
			}
			stats_out.Update(int64(off))
		}
	}()

	// Goroutine C: 监控 TCP 控制连接断开
	go func() {
		defer wg.Done()
		defer closeDone()
		buf := make([]byte, 1)
		clientConn.Read(buf)
	}()

	<-done
	wg.Wait()
	return nil
}
