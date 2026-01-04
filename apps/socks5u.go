package apps

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/threatexpert/gonc/v2/acl"
	"github.com/threatexpert/gonc/v2/netx"
	"github.com/threatexpert/gonc/v2/secure"
)

// SOCKS5 协议常量
const (
	SOCKS5_VERSION = 0x05
	// 命令码
	CMD_CONNECT       = 0x01 // TCP CONNECT
	CMD_BIND          = 0x02 // TCP BIND
	CMD_UDP_ASSOCIATE = 0x03 // UDP ASSOCIATE

	// UDP 代理相关常量
	SOCKS5_UDP_RSV  = 0x0000 // Reserved bytes for SOCKS5 UDP header
	SOCKS5_UDP_FRAG = 0x00   // Fragment number for SOCKS5 UDP header (we don't support fragmentation)

	// 地址类型
	ATYP_IPV4       = 0x01
	ATYP_DOMAINNAME = 0x03
	ATYP_IPV6       = 0x04

	// 响应状态码
	REP_SUCCEEDED                  = 0x00
	REP_GENERAL_SOCKS_SERVER_FAIL  = 0x01
	REP_CONNECTION_NOT_ALLOWED     = 0x02
	REP_NETWORK_UNREACHABLE        = 0x03
	REP_HOST_UNREACHABLE           = 0x04
	REP_CONNECTION_REFUSED         = 0x05
	REP_TTL_EXPIRED                = 0x06
	REP_COMMAND_NOT_SUPPORTED      = 0x07
	REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08

	// 认证方法
	AUTH_NO_AUTH               = 0x00
	AUTH_USERNAME_PASSWORD     = 0x02
	AUTH_NO_ACCEPTABLE_METHODS = 0xFF
	// 用户名/密码认证状态
	AUTH_STATUS_SUCCESS byte = 0x00 // 认证成功
	AUTH_STATUS_FAILURE byte = 0x01 // 认证失败

	// 隧道请求前缀
	TUNNEL_REQ_TCP = "tcp://"
	TUNNEL_REQ_UDP = "udp://"
)

// Socks5AuthConfig 用于配置 SOCKS5 服务器的行为，包括认证
type Socks5AuthConfig struct {
	// AuthenticateUser 是一个函数，用于验证用户名和密码。
	// 如果配置为 nil，则表示服务器不要求用户密码认证。
	// 如果非 nil，服务器将要求客户端进行用户密码认证。
	AuthenticateUser func(username, password string) bool
}

type Socks5uConfig struct {
	Logger     *log.Logger
	Username   string
	Password   string
	ServerIP   string
	Localbind  string
	AccessCtrl *acl.ACL
}

type Socks5Request struct {
	Command string
	Host    string
	Port    int
}

const (
	ListenerIdleTimeout = 30 * time.Second // 监听器空闲超时时间（没人领连接就关闭）
)

// SharedListener 代表一个持久化的监听端口，专门为BIND命令设计，它可缓存BIND端口并发连入的连接，并提供给稍后请求BIND的客户端使用
type SharedListener struct {
	Ref        int32 // 引用计数
	Listener   net.Listener
	ConnQueue  chan net.Conn // 生产者-消费者队列
	LastActive time.Time     // 最后一次被客户端“触摸”的时间
	CloseOnce  sync.Once     // 确保只关闭一次
	QuitChan   chan struct{} // 通知后台协程退出
	Port       int           // 实际监听端口
	BindIP     string        // 监听IP
}

// BindManager 管理所有活跃的监听器
type BindManager struct {
	mu        sync.Mutex
	listeners map[string]*SharedListener // Key: "IP:Port"
}

// 全局管理器实例
var globalBindManager = &BindManager{
	listeners: make(map[string]*SharedListener),
}

// 获取或创建一个 SharedListener
func (m *BindManager) GetOrStartListener(ctx context.Context, bindIP string, reqPort int, logger *log.Logger) (*SharedListener, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := net.JoinHostPort(bindIP, strconv.Itoa(reqPort))

	// 1. 尝试查找现有的监听器 (仅当请求端口不为0时)
	if reqPort != 0 {
		if sl, exists := m.listeners[key]; exists {
			// 刷新活跃时间
			sl.LastActive = time.Now()
			atomic.AddInt32(&sl.Ref, 1)
			return sl, nil
		}
	}

	// 2. 如果没找到，或者请求端口是0，创建新的监听
	lc := net.ListenConfig{Control: netx.ControlTCP}
	addr := net.JoinHostPort(bindIP, ":0")
	if reqPort != 0 {
		addr = key
	}

	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	// 获取实际端口 (处理端口0的情况)
	realAddr := ln.Addr().(*net.TCPAddr)
	realKey := net.JoinHostPort(bindIP, strconv.Itoa(realAddr.Port))

	sl := &SharedListener{
		Ref:        1,
		Listener:   ln,
		ConnQueue:  make(chan net.Conn), // 大小为 0,
		LastActive: time.Now(),
		QuitChan:   make(chan struct{}),
		Port:       realAddr.Port,
		BindIP:     bindIP,
	}

	// 存入 Map
	m.listeners[realKey] = sl

	// 如果请求的是端口0，可能产生了一个新的key，需要确保以后能通过具体端口找到它
	// 但通常 Port 0 意味着“一次性”或“告知客户端新端口”，后续客户端会连这个新端口

	// 启动后台任务
	go sl.acceptLoop(logger)
	go sl.monitorLifecycle(m, realKey, logger)

	return sl, nil
}

// 后台接收连接循环 (生产者)
func (sl *SharedListener) acceptLoop(logger *log.Logger) {
	defer func() {
		// 退出时关闭 channel
		// 因为是无缓冲的，channel 里不可能有残留连接。
		close(sl.ConnQueue)
		sl.Listener.Close() // 确保物理监听关闭
	}()

	for {
		// 1. 阻塞等待内核的新连接
		// 如果这里阻塞太久，monitorLifecycle 会关闭 Listener，
		// 导致 Accept 返回 error，从而退出循环。
		conn, err := sl.Listener.Accept()
		if err != nil {
			select {
			case <-sl.QuitChan:
				return // 正常超时退出
			default:
				// 异常错误
				return
			}
		}

		// 2. 拿到连接了，必须递交给消费者
		// 我们利用 select 来实现“要么有人领走，要么超时关闭”
		select {
		case sl.ConnQueue <- conn:
			// 成功！有消费者（客户端 BIND 请求）拿走了连接
			// 继续循环去 Accept 下一个

		case <-sl.QuitChan:
			// 悲剧了：手里拿着个刚 Accept 的连接，但是管理器通知要关闭了
			// (比如超时时间到了，monitor 关闭了 QuitChan)
			conn.Close() // 销毁手里这个没送出去的连接
			return       // 退出协程
		}
	}
}

// 生命周期监控 (超时管理)
func (sl *SharedListener) monitorLifecycle(m *BindManager, mapKey string, logger *log.Logger) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sl.QuitChan:
			return
		case <-ticker.C:
			// 检查是否空闲超时
			if atomic.LoadInt32(&sl.Ref) == 0 && time.Since(sl.LastActive) > ListenerIdleTimeout {
				// 执行清理
				m.mu.Lock()
				// 二次确认，防止在获取锁期间被更新
				if time.Since(sl.LastActive) > ListenerIdleTimeout {
					if current, ok := m.listeners[mapKey]; ok && current == sl {
						delete(m.listeners, mapKey)
						sl.CloseOnce.Do(func() {
							close(sl.QuitChan)
							sl.Listener.Close()
						})
						logger.Printf("Closed idle BIND listener on %s", mapKey)
					}
				}
				m.mu.Unlock()
				return // 退出监控
			}
		}
	}
}

// sendSocks5AuthResponse 发送 SOCKS5 用户名/密码认证阶段的响应
func sendSocks5AuthResponse(conn net.Conn, status byte) error {
	_, err := conn.Write([]byte{0x01, status})
	return err
}

// handleSocks5Handshake 处理 SOCKS5 握手阶段
func handleSocks5Handshake(conn net.Conn, authconfig *Socks5AuthConfig) error {
	buf := make([]byte, 256)

	// 1. 读取 VER (版本) 和 NMETHODS (方法数量)
	_, err := io.ReadFull(conn, buf[:2])
	if err != nil {
		return fmt.Errorf("read VER and NMETHODS error: %w", err)
	}
	ver := buf[0]
	nMethods := int(buf[1])

	if ver != SOCKS5_VERSION {
		return fmt.Errorf("unsupported SOCKS version: %d", ver)
	}

	// 2. 读取客户端支持的 METHODS (认证方法列表)
	methodsBuf := make([]byte, nMethods)
	_, err = io.ReadFull(conn, methodsBuf)
	if err != nil {
		return fmt.Errorf("read METHODS error: %w", err)
	}

	// 3. 选择服务器偏好的认证方法
	var chosenMethod byte = 0xFF // 默认：无可用方法

	// 检查服务器是否要求认证
	if authconfig.AuthenticateUser != nil {
		// 服务器要求认证，优先选择 USERNAME/PASSWORD
		for _, method := range methodsBuf {
			if method == AUTH_USERNAME_PASSWORD {
				chosenMethod = AUTH_USERNAME_PASSWORD
				break
			}
		}
		if chosenMethod == 0xFF {
			// 客户端没有提供 USERNAME/PASSWORD 方法，但服务器要求认证
			// 发送 0xFF 回应表示没有可接受的方法
			_, writeErr := conn.Write([]byte{SOCKS5_VERSION, 0xFF})
			if writeErr != nil {
				return fmt.Errorf("failed to send no acceptable methods response: %w", writeErr)
			}
			return fmt.Errorf("authentication required by server, but client did not offer USERNAME/PASSWORD method")
		}
	} else {
		// 服务器不要求认证，优先选择 NO AUTHENTICATION REQUIRED
		for _, method := range methodsBuf {
			if method == AUTH_NO_AUTH {
				chosenMethod = AUTH_NO_AUTH
				break
			}
		}
		if chosenMethod == 0xFF {
			// 客户端没有提供 NO AUTHENTICATION REQUIRED 方法，但服务器不要求认证
			// 理论上客户端总会提供 0x00，但为了健壮性，如果没找到也报错
			_, writeErr := conn.Write([]byte{SOCKS5_VERSION, 0xFF})
			if writeErr != nil {
				return fmt.Errorf("failed to send no acceptable methods response: %w", writeErr)
			}
			return fmt.Errorf("no acceptable authentication methods offered by client (expected NO AUTHENTICATION REQUIRED)")
		}
	}

	// 4. 向客户端发送方法选择响应 (VER, CHOSEN_METHOD)
	_, err = conn.Write([]byte{SOCKS5_VERSION, chosenMethod})
	if err != nil {
		return fmt.Errorf("send method selection response error: %w", err)
	}

	// 5. 如果选择了 USERNAME/PASSWORD 认证，则进行认证子协商
	if chosenMethod == AUTH_USERNAME_PASSWORD {
		// 读取认证子协商的 VER (版本，应为 0x01)
		_, err := io.ReadFull(conn, buf[:1])
		if err != nil {
			return fmt.Errorf("read auth sub-negotiation VER error: %w", err)
		}
		authVer := buf[0]
		if authVer != 0x01 {
			sendSocks5AuthResponse(conn, AUTH_STATUS_FAILURE)
			return fmt.Errorf("unsupported authentication sub-negotiation version: %d", authVer)
		}

		// 读取 ULEN (用户名长度)
		_, err = io.ReadFull(conn, buf[:1])
		if err != nil {
			return fmt.Errorf("read ULEN error: %w", err)
		}
		uLen := int(buf[0])

		// 读取 UNAME (用户名)
		usernameBuf := make([]byte, uLen)
		_, err = io.ReadFull(conn, usernameBuf)
		if err != nil {
			return fmt.Errorf("read UNAME error: %w", err)
		}
		username := string(usernameBuf)

		// 读取 PLEN (密码长度)
		_, err = io.ReadFull(conn, buf[:1])
		if err != nil {
			return fmt.Errorf("read PLEN error: %w", err)
		}
		pLen := int(buf[0])

		// 读取 PASSWD (密码)
		passwordBuf := make([]byte, pLen)
		_, err = io.ReadFull(conn, passwordBuf)
		if err != nil {
			return fmt.Errorf("read PASSWD error: %w", err)
		}
		password := string(passwordBuf)

		// --- 执行用户认证逻辑 ---
		if !authconfig.AuthenticateUser(username, password) { // 使用配置中提供的认证函数
			sendSocks5AuthResponse(conn, AUTH_STATUS_FAILURE)
			return fmt.Errorf("authentication failed for user: %s", username)
		}

		// 认证成功，发送认证成功响应
		sendSocks5AuthResponse(conn, AUTH_STATUS_SUCCESS)
	}

	return nil
}

// handleSocks5Request 处理 SOCKS5 请求阶段
func handleSocks5Request(clientConn net.Conn) (*Socks5Request, error) {
	buf := make([]byte, 300)

	_, err := io.ReadFull(clientConn, buf[:4])
	if err != nil {
		return nil, fmt.Errorf("read VER, CMD, RSV, ATYP error: %w", err)
	}
	ver := buf[0]
	cmd := buf[1]
	// rsv := buf[2] // 0x00
	atyp := buf[3]

	if ver != SOCKS5_VERSION {
		return nil, fmt.Errorf("unsupported SOCKS version in request: %d", ver)
	}

	var host string
	var port int

	switch atyp {
	case ATYP_IPV4:
		_, err := io.ReadFull(clientConn, buf[:4])
		if err != nil {
			return nil, fmt.Errorf("read IPv4 address error: %w", err)
		}
		host = net.IPv4(buf[0], buf[1], buf[2], buf[3]).String()

		_, err = io.ReadFull(clientConn, buf[:2])
		if err != nil {
			return nil, fmt.Errorf("read port error: %w", err)
		}
		port = int(buf[0])<<8 | int(buf[1])
	case ATYP_DOMAINNAME:
		_, err := io.ReadFull(clientConn, buf[:1])
		if err != nil {
			return nil, fmt.Errorf("read domain length error: %w", err)
		}
		domainLen := int(buf[0])

		_, err = io.ReadFull(clientConn, buf[:domainLen])
		if err != nil {
			return nil, fmt.Errorf("read domain name error: %w", err)
		}
		host = string(buf[:domainLen])

		_, err = io.ReadFull(clientConn, buf[:2])
		if err != nil {
			return nil, fmt.Errorf("read port error: %w", err)
		}
		port = int(buf[0])<<8 | int(buf[1])
	case ATYP_IPV6:
		_, err := io.ReadFull(clientConn, buf[:16])
		if err != nil {
			return nil, fmt.Errorf("read IPv6 address error: %w", err)
		}
		host = net.IP(buf[:16]).String()

		_, err = io.ReadFull(clientConn, buf[:2])
		if err != nil {
			return nil, fmt.Errorf("read port error: %w", err)
		}
		port = int(buf[0])<<8 | int(buf[1])
	default:
		sendSocks5Response(clientConn, REP_ADDRESS_TYPE_NOT_SUPPORTED, "0.0.0.0", 0)
		return nil, fmt.Errorf("unsupported address type: %d", atyp)
	}

	switch cmd {
	case CMD_CONNECT:
		return &Socks5Request{
			Command: "CONNECT",
			Host:    host,
			Port:    port,
		}, nil
	case CMD_BIND:
		return &Socks5Request{
			Command: "BIND",
			Host:    host,
			Port:    port,
		}, nil
	case CMD_UDP_ASSOCIATE:
		return &Socks5Request{
			Command: "UDP",
			Host:    host,
			Port:    port,
		}, nil
	default:
		sendSocks5Response(clientConn, REP_COMMAND_NOT_SUPPORTED, "0.0.0.0", 0)
		return nil, fmt.Errorf("unsupported command: %d", cmd)
	}
}

// sendSocks5Response 发送 SOCKS5 响应
func sendSocks5Response(conn net.Conn, rep byte, bindAddr string, bindPort int) error {
	addr := net.ParseIP(bindAddr)
	var atyp byte
	var bndAddrBytes []byte

	if ipv4 := addr.To4(); ipv4 != nil {
		atyp = ATYP_IPV4
		bndAddrBytes = ipv4
	} else if ipv6 := addr.To16(); ipv6 != nil {
		atyp = ATYP_IPV6
		bndAddrBytes = ipv6
	} else {
		atyp = ATYP_IPV4
		bndAddrBytes = []byte{0, 0, 0, 0} // Default to 0.0.0.0 if cannot parse
	}

	resp := []byte{
		SOCKS5_VERSION,
		rep,  // REP
		0x00, // RSV
		atyp, // ATYP
	}
	resp = append(resp, bndAddrBytes...)
	resp = append(resp, byte(bindPort>>8), byte(bindPort&0xFF))

	_, err := conn.Write(resp)
	if err != nil {
		return fmt.Errorf("write SOCKS5 response error: %w", err)
	}
	return nil
}

// handleTCPConnectViaTunnel 处理 TCP CONNECT 命令并通过隧道转发
func handleTCPConnectViaTunnel(config *Socks5uConfig, clientConn net.Conn, tunnelStream net.Conn, transparent bool, targetHost string, targetPort int) error {
	// 发送代理请求给远端: "tcp://target_host:target_port\n"
	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	requestLine := fmt.Sprintf("%s%s\n", TUNNEL_REQ_TCP, targetAddr)
	_, err := tunnelStream.Write([]byte(requestLine))
	if err != nil {
		if !transparent {
			sendSocks5Response(clientConn, REP_GENERAL_SOCKS_SERVER_FAIL, "0.0.0.0", 0)
		}
		return fmt.Errorf("write tunnel request error: %w", err)
	}
	config.Logger.Printf("TCP: %s->%s connecting...", clientConn.RemoteAddr().String(), targetAddr)

	tunnelStream.SetReadDeadline(time.Now().Add(25 * time.Second))
	// 读取远端连接结果（例如 "OK\n" 或 "ERROR: reason\n"）
	responseLine, err := netx.ReadString(tunnelStream, '\n', 1024)
	if err != nil {
		config.Logger.Printf("%s->%s error: %v", clientConn.RemoteAddr().String(), targetAddr, err)
		if !transparent {
			sendSocks5Response(clientConn, REP_GENERAL_SOCKS_SERVER_FAIL, "0.0.0.0", 0)
		}
		return fmt.Errorf("read tunnel response error: %w", err)
	}
	responseLine = strings.TrimSpace(responseLine)

	if !strings.HasPrefix(responseLine, "OK") {
		config.Logger.Printf("%s->%s failed: %s", clientConn.RemoteAddr().String(), targetAddr, responseLine)
		if !transparent {
			sendSocks5Response(clientConn, REP_GENERAL_SOCKS_SERVER_FAIL, "0.0.0.0", 0) // 根据远端错误细化SOCKS5错误码
		}
		return fmt.Errorf("tunnel TCP connect failed: %s", responseLine)
	}

	// 成功响应SOCKS5客户端
	// 这里我们没有远端绑定的实际地址和端口，所以使用 0.0.0.0:0 或者客户端连接的源IP/端口
	// 根据SOCKS5协议，BND.ADDR和BND.PORT应该是服务器用于连接目标的地址/端口
	// 但在这里，连接目标在远端，所以我们通常返回代理服务器本身的地址（即 0.0.0.0:0 或本地监听地址）
	// 或者为了更严谨，可以要求远端在OK后回传其绑定的地址和端口。
	// 这里简化，返回 0.0.0.0:0
	if !transparent {
		sendSocks5Response(clientConn, REP_SUCCEEDED, "0.0.0.0", 0)
	}
	tunnelStream.SetReadDeadline(time.Time{})

	bidirectionalCopy(clientConn, tunnelStream)
	return nil
}

func handleHTTPConnectViaTunnel(config *Socks5uConfig, clientConn net.Conn, tunnelStream net.Conn, targetHost string, targetPort int) error {
	// 发送代理请求给远端: "tcp://target_host:target_port\n"
	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	requestLine := fmt.Sprintf("%s%s\n", TUNNEL_REQ_TCP, targetAddr)
	_, err := tunnelStream.Write([]byte(requestLine))
	if err != nil {
		// 发送失败，告诉 HTTP 客户端网关错误
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return fmt.Errorf("write tunnel request error: %w", err)
	}
	config.Logger.Printf("HTTP-CONNECT: %s->%s connecting...", clientConn.RemoteAddr().String(), targetAddr)

	tunnelStream.SetReadDeadline(time.Now().Add(25 * time.Second))
	// 读取远端连接结果（例如 "OK\n" 或 "ERROR: reason\n"）
	responseLine, err := netx.ReadString(tunnelStream, '\n', 1024)
	if err != nil {
		config.Logger.Printf("%s->%s tunnel read error: %v", clientConn.RemoteAddr().String(), targetAddr, err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return fmt.Errorf("read tunnel response error: %w", err)
	}
	responseLine = strings.TrimSpace(responseLine)

	if !strings.HasPrefix(responseLine, "OK") {
		config.Logger.Printf("%s->%s failed: %s", clientConn.RemoteAddr().String(), targetAddr, responseLine)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return fmt.Errorf("tunnel handshake failed: %s", responseLine)
	}

	// 4. 告诉 HTTP 客户端连接已建立 (关键步骤)
	// 浏览器收到这个 200 后，就会开始发送 TLS 握手包或原始 TCP 数据
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		return fmt.Errorf("send 200 OK failed: %w", err)
	}
	tunnelStream.SetReadDeadline(time.Time{})

	bidirectionalCopy(clientConn, tunnelStream)
	return nil
}

func handleHTTPRequestViaTunnel(config *Socks5uConfig, clientConn net.Conn, req *http.Request, tunnelConn net.Conn, targetHost string, targetPort int) error {

	bufTunnelStream := netx.NewBufferedConn(tunnelConn)

	// 发送代理请求给远端: "tcp://target_host:target_port\n"
	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	requestLine := fmt.Sprintf("%s%s\n", TUNNEL_REQ_TCP, targetAddr)
	_, err := bufTunnelStream.Write([]byte(requestLine))
	if err != nil {
		// 发送失败，告诉 HTTP 客户端网关错误
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return fmt.Errorf("write tunnel request error: %w", err)
	}
	config.Logger.Printf("HTTP-REQ: %s->%s connecting...", clientConn.RemoteAddr().String(), targetAddr)

	bufTunnelStream.SetReadDeadline(time.Now().Add(25 * time.Second))
	// 读取远端连接结果（例如 "OK\n" 或 "ERROR: reason\n"）
	responseLine, err := bufTunnelStream.Reader.ReadString('\n')
	if err != nil {
		config.Logger.Printf("%s->%s tunnel read error: %v", clientConn.RemoteAddr().String(), targetAddr, err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return fmt.Errorf("read tunnel response error: %w", err)
	}
	responseLine = strings.TrimSpace(responseLine)

	if !strings.HasPrefix(responseLine, "OK") {
		config.Logger.Printf("%s->%s failed: %s", clientConn.RemoteAddr().String(), targetAddr, responseLine)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return fmt.Errorf("tunnel handshake failed: %s", responseLine)
	}

	req.Close = true
	req.Header.Set("Connection", "close")
	req.Header.Set("Proxy-Connection", "close")

	// 7. 删除逐跳头部
	delHopHeaders(req.Header)

	// req.Write 会处理 Method, URL, Headers 和 Body 的写入
	if err := req.Write(bufTunnelStream); err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return fmt.Errorf("write request to tunnel failed: %w", err)
	}

	resp, err := http.ReadResponse(bufTunnelStream.Reader, req)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return fmt.Errorf("read response from tunnel failed: %w", err)
	}
	defer resp.Body.Close()

	// 9. 响应回写给客户端
	delHopHeaders(resp.Header)

	// 强制告诉客户端关闭连接
	resp.Header.Set("Connection", "close")
	resp.Close = true

	bufTunnelStream.SetReadDeadline(time.Time{})

	err = resp.Write(clientConn)
	if err != nil {
		return fmt.Errorf("write response failed: %w", err)
	}

	return nil
}

// handleUDPAssociateViaTunnel 处理 UDP ASSOCIATE 命令并通过隧道转发
func handleUDPAssociateViaTunnel(config *Socks5uConfig, clientConn net.Conn, keyingMaterial [32]byte, tunnelStream net.Conn, targetHost string, targetPort int) error {
	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	// 1. 本地 SOCKS5 服务器为客户端创建一个 UDP 监听端口
	//    客户端会将 UDP 数据包发送到这个本地端口
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
	defer localUDPConn.Close() // 确保本地 UDP 监听器关闭

	config.Logger.Printf("UDP-Associate-C: Using UDP socket: %s", localUDPConn.LocalAddr())

	//不指定具体serverIP时将告诉客户端0.0.0.0，因为服务器看不到自己真正的公网IP，localUDPConn.LocalAddr()可能会服务器的内网IP
	bindIP := config.ServerIP
	bindPort := localUDPConn.LocalAddr().(*net.UDPAddr).Port

	// 2. 回复 SOCKS5 客户端成功响应，告知其本地 UDP 转发的地址和端口
	err = sendSocks5Response(clientConn, REP_SUCCEEDED, bindIP, bindPort)
	if err != nil {
		return fmt.Errorf("send UDP associate response error: %w", err)
	}

	// 4. 发送 UDP 代理请求给远端: "udp://target_host:target_port\n"
	// 实际上，对于 UDP ASSOCIATE，客户端的 initial targetHost/Port 通常是 0.0.0.0:0
	// 真正的目标地址会在每个 UDP 包中携带。
	// 这里我们发送一个通用的 UDP 关联请求，告诉远端准备好接收 SOCKS5 UDP 数据报。
	requestLine := fmt.Sprintf("%s%s\n", TUNNEL_REQ_UDP, targetAddr) // 尽管targetHost/Port可能是0.0.0.0:0, 还是发过去
	_, err = tunnelStream.Write([]byte(requestLine))
	if err != nil {
		return fmt.Errorf("write tunnel request error: %w", err)
	}

	// 读取远端连接结果（例如 "OK\n" 或 "ERROR: reason\n"）
	responseLine, err := netx.ReadString(tunnelStream, '\n', 1024)
	if err != nil {
		return fmt.Errorf("read tunnel response error: %w", err)
	}
	responseLine = strings.TrimSpace(responseLine)

	if !strings.HasPrefix(responseLine, "OK") {
		config.Logger.Printf("Tunnel UDP associate failed: %s", responseLine)
		return fmt.Errorf("tunnel UDP associate failed: %s", responseLine)
	}

	// 用于同步客户端 TCP 连接关闭和本地 UDP 监听器关闭
	var wg sync.WaitGroup
	wg.Add(1)

	// 5. 启动一个 goroutine，等待客户端 TCP 连接关闭，然后关闭本地 UDP 监听和隧道流
	go func() {
		defer wg.Done()
		io.Copy(io.Discard, clientConn) // 仅读取直到EOF或错误
		localUDPConn.Close()            // 这会中断 UDP 转发循环
		tunnelStream.Close()            // 关闭隧道流
	}()

	// 6. 启动 UDP 数据转发：客户端本地 UDP <-> 隧道流
	// 这部分是关键：本地 SOCKS5 服务器接收客户端的 SOCKS5 UDP 包，然后通过隧道流转发到远端
	// 同时，接收远端通过隧道流返回的 SOCKS5 UDP 包，再转发给客户端。

	clientAddr := clientConn.RemoteAddr()
	if clientAddr == nil {
		return fmt.Errorf("get clientConn RemoteAddr error")
	}

	var clientIP net.IP
	switch a := clientAddr.(type) {
	case *net.TCPAddr:
		clientIP = a.IP
	case *net.UDPAddr:
		clientIP = a.IP
	default:
		return fmt.Errorf("unknown clientConn RemoteAddr type: %s", clientAddr.Network())
	}

	if keyingMaterial == [32]byte{} {
		handleLocalUDPToTunnel(config, localUDPConn, tunnelStream, clientIP)
	} else {
		localUDPConnSS, _ := secure.NewSecureUDPConn(localUDPConn, keyingMaterial)
		handleLocalUDPToTunnel(config, localUDPConnSS, tunnelStream, clientIP)
	}

	clientConn.Close()
	wg.Wait() // 等待 TCP 关闭 goroutine 结束
	return nil
}

// handleLocalUDPToTunnel 是运行在本地客户端
// 负责将本地 SOCKS5 客户端的 UDP 数据包封装并通过 tunnelStream 发送给远端
// 并接收远端封装的 UDP 响应，解封装后发回给客户端。
func handleLocalUDPToTunnel(config *Socks5uConfig, localUDPConn net.PacketConn, tunnelStream net.Conn, clientIP net.IP) {
	var clientActualUDPAddr *net.UDPAddr // 记录 SOCKS5 客户端的实际 UDP 源地址
	var once sync.Once                   // 确保只捕获一次客户端 UDP 地址

	ctxRoot, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()
	// 用于等待两个 goroutine 结束
	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: 从 localUDPConn 接收 SOCKS5 UDP 包，封装后发送到 tunnelStream
	go func(cancel context.CancelFunc) {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				config.Logger.Printf("Recovered from panic in localUDPConn to tunnelStream: %v", r)
			}
			cancel()
		}()

		buf := make([]byte, 65535)     // SOCKS5 UDP 数据包最大长度
		lengthBytes := make([]byte, 2) // 用于存储长度前缀

		for {
			// 设置读取超时，以便在 localUDPConn 关闭时能退出循环
			localUDPConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, cliAddr, err := localUDPConn.ReadFrom(buf) // 读取 SOCKS5 客户端发来的 UDP 数据报
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // 超时，继续等待
				}
				config.Logger.Printf("Error reading from local UDP for client %s: %v", clientIP, err)
				return // 非临时错误或连接关闭，退出 goroutine
			}
			cliUDPAddr := cliAddr.(*net.UDPAddr) // 确保类型转换正确

			// 确保只处理来自 SOCKS5 客户端 IP 的 UDP 包，增强安全性
			if clientIP != nil && !cliUDPAddr.IP.Equal(clientIP) {
				config.Logger.Printf("Received UDP packet from unexpected source: %s, expected: %s. Dropping.", cliUDPAddr.IP, clientIP)
				continue
			}

			// 首次收到客户端的 UDP 包时，保存其源地址
			once.Do(func() {
				clientActualUDPAddr = cliUDPAddr
				config.Logger.Printf("UDP: %s associated", clientActualUDPAddr)
			})

			// 封装数据包：[Length (2 bytes)] [SOCKS5 UDP Header + Data]
			// 确保数据包长度在 2 字节可表示的范围内
			if n > 65535 {
				config.Logger.Printf("UDP packet too large (%d bytes) for 2-byte length prefix. Dropping.", n)
				continue
			}
			binary.BigEndian.PutUint16(lengthBytes, uint16(n)) // 写入长度

			// 写入长度前缀
			_, err = tunnelStream.Write(lengthBytes)
			if err != nil {
				config.Logger.Printf("Error writing length prefix to tunnel stream: %v", err)
				return
			}
			// 写入完整的 SOCKS5 UDP 数据报
			_, err = tunnelStream.Write(buf[:n])
			if err != nil {
				config.Logger.Printf("Error writing SOCKS5 UDP packet to tunnel stream: %v", err)
				return
			}
		}
	}(cancelRoot)

	// Goroutine 2: 从 tunnelStream 接收封装的数据包，解封装后发送到 localUDPConn
	go func(cancel context.CancelFunc) {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				config.Logger.Printf("Recovered from panic in tunnelStream to localUDPConn: %v", r)
			}
			cancel()
		}()

		lengthBytes := make([]byte, 2)
		// 使用一个较大的缓冲区来接收完整的 UDP 包
		packetBuf := make([]byte, 65535)

		for {
			// 设置读取超时，以便在 tunnelStream 关闭时能退出循环
			tunnelStream.SetReadDeadline(time.Now().Add(5 * time.Second))

			// 1. 读取长度前缀
			_, err := io.ReadFull(tunnelStream, lengthBytes)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // 超时，继续等待
				}
				if err == io.EOF {
					config.Logger.Println("Tunnel stream closed from remote for UDP responses. Exiting.")
					return // 流关闭
				}
				config.Logger.Printf("Error reading length prefix from tunnel stream: %v", err)
				return // 非 EOF 错误，退出
			}

			packetLength := binary.BigEndian.Uint16(lengthBytes) // 解析长度

			if packetLength == 0 {
				config.Logger.Printf("Received zero-length UDP packet from tunnel. Skipping.")
				continue
			}
			if packetLength > uint16(len(packetBuf)) {
				config.Logger.Printf("Received too large UDP packet from tunnel (%d bytes). Dropping.", packetLength)
				// 尝试跳过这个无效包，但可能导致同步问题
				// 更好的做法是直接退出，因为这表明协议错误
				return
			}

			// 2. 根据长度读取完整的 SOCKS5 UDP 数据报
			_, err = io.ReadFull(tunnelStream, packetBuf[:packetLength])
			if err != nil {
				if err == io.EOF {
					config.Logger.Println("Tunnel stream closed from remote while reading UDP packet body. Exiting.")
				}
				config.Logger.Printf("Error reading UDP packet body from tunnel stream: %v", err)
				return // 错误，退出
			}

			// 3. 将 SOCKS5 UDP 数据报发送回 SOCKS5 客户端
			if clientActualUDPAddr == nil {
				config.Logger.Printf("Warning: Client's UDP address not yet known for sending responses. Dropping packet from tunnel.")
				continue // 客户端还没发过包，不知道往哪里回传
			}

			_, err = localUDPConn.WriteTo(packetBuf[:packetLength], clientActualUDPAddr)
			if err != nil {
				config.Logger.Printf("Error writing UDP response to client %s via local UDP: %v", clientActualUDPAddr, err)
				// 这里通常不直接 return，因为可能只是单个包发送失败，不影响后续包
				// 但如果错误是连接关闭，那也会在 ReadFromUDP 时检测到并退出
			}
		}
	}(cancelRoot)

	select {
	case <-ctxRoot.Done():
		localUDPConn.Close()
		tunnelStream.Close()
	default:
	}
	// 等待两个转发 goroutine 结束
	wg.Wait()
}

func handleDirectTCPConnect(config *Socks5uConfig, clientConn net.Conn, targetHost string, targetPort int) error {
	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
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

	resolvedAddr, isDenied, err := acl.ResolveAddrWithACL(ctx, config.AccessCtrl, "tcp", targetAddr)
	if err != nil {
		if isDenied {
			sendSocks5Response(clientConn, REP_CONNECTION_NOT_ALLOWED, "0.0.0.0", 0)
		} else {
			sendSocks5Response(clientConn, REP_GENERAL_SOCKS_SERVER_FAIL, "0.0.0.0", 0)
		}
		return err
	}

	config.Logger.Printf("TCP: %s->%s connecting...", clientConn.RemoteAddr(), targetAddr)
	targetConn, err := dialer.DialContext(ctx, "tcp", resolvedAddr.String())
	if err != nil {
		sendSocks5Response(clientConn, REP_GENERAL_SOCKS_SERVER_FAIL, "0.0.0.0", 0)
		return fmt.Errorf("tunnel TCP connect failed: %v", err)
	}
	sendSocks5Response(clientConn, REP_SUCCEEDED, "0.0.0.0", 0)
	bidirectionalCopy(clientConn, targetConn)
	return nil
}

func handleTCPListen(config *Socks5uConfig, clientConn net.Conn, targetHost string, targetPort int) error {
	// 1. 确定 BIND 的 IP 地址
	bindIP := targetHost
	if bindIP == "" {
		// 如果客户端没指定IP，通常沿用连接进来的本地IP
		local, ok := clientConn.LocalAddr().(*net.TCPAddr)
		if ok {
			bindIP = local.IP.String()
		}
	}

	// 2. 从管理器获取或创建监听器
	// 注意：这里没有把 clientConn 传进去，意味着任何知道端口的人可能都能连（SOCKS5标准如此）。
	// 如果需要隔离用户，可以在 GetOrStartListener key 中加入 config.Username
	sl, err := globalBindManager.GetOrStartListener(context.Background(), bindIP, targetPort, config.Logger)
	if err != nil {
		sendSocks5Response(clientConn, REP_GENERAL_SOCKS_SERVER_FAIL, "0.0.0.0", 0)
		return fmt.Errorf("manager get listener failed: %w", err)
	}

	var onceReleaseSL sync.Once
	releaseSL := func() {
		onceReleaseSL.Do(func() {
			atomic.AddInt32(&sl.Ref, -1)
		})
	}
	defer releaseSL()

	config.Logger.Printf("Client %s attached to BIND listener on %s:%d", clientConn.RemoteAddr(), sl.BindIP, sl.Port)

	// 3. 发送第一次响应 (Reply 1) - 告诉客户端我们在哪个端口监听
	// 即使是复用旧监听器，这里也必须再次告诉客户端监听端口
	err = sendSocks5Response(clientConn, REP_SUCCEEDED, config.ServerIP, sl.Port)
	if err != nil {
		return fmt.Errorf("send response 1 error: %w", err)
	}

	// 4. 等待连接接入 (消费者逻辑)
	var targetConn net.Conn

	// 创建一个用于监测 clientConn 断开的 channel
	clientClosed := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(1)

	// 监控 clientConn 是否异常
	clientConn.SetReadDeadline(time.Time{}) // 移除 deadline 避免干扰
	go func() {
		defer wg.Done()
		buf := make([]byte, 1)
		if _, err := clientConn.Read(buf); err == nil {
			// 正常读到数据，说明客户端发了不该发的数据，直接关闭
			clientConn.Close()
		}
		// 读到数据或发生错误，说明连接断开或异常
		close(clientClosed)
	}()

	select {
	case conn, ok := <-sl.ConnQueue:
		if !ok {
			// 这种情况一般是监听器被强制关闭了
			sendSocks5Response(clientConn, REP_GENERAL_SOCKS_SERVER_FAIL, "0.0.0.0", 0)
			return fmt.Errorf("listener closed unexpectedly")
		}
		targetConn = conn

	case <-clientClosed:
		// 客户端在等待期间断开了
		return fmt.Errorf("client connection closed while waiting")
	}

	sl.LastActive = time.Now()
	releaseSL()
	defer targetConn.Close()

	_ = clientConn.SetReadDeadline(time.Now())
	wg.Wait() // 等 goroutine 退出后继续
	_ = clientConn.SetReadDeadline(time.Time{})

	// 5. 发送第二次响应 (Reply 2) - 告诉客户端谁连上来了
	remoteAddr := targetConn.RemoteAddr()
	remote, ok := remoteAddr.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("failed cast remote addr")
	}

	err = sendSocks5Response(clientConn, REP_SUCCEEDED, remote.IP.String(), remote.Port)
	if err != nil {
		return fmt.Errorf("send response 2 error: %w", err)
	}

	// 注意：转发结束后，我们不关闭 Listener，只由 monitorLifecycle 去负责
	bidirectionalCopy(clientConn, targetConn)

	return nil
}

func ServeProxyOnTunnel(config *Socks5uConfig, conn net.Conn, keyingMaterial [32]byte, stream net.Conn, cmd, targetHost string, targetPort int) {
	/*
		conn 是本地应用接入的客户端连接
		stream 是通过mux申请下来的一个channel
		1、先通过 conn 完成代理握手和请求，得到客户端要代理的目的地址和端口；支持socks5（TCP/UDP）和HTTP代理
		2、将代理请求封装为自定义的代理协议格式 "tcp://target_host:target_port\n" 通过stream发送请求到远端
		3、等待stream反馈连接结果，再将结果反馈给 conn
	*/
	config.Logger.Printf("New client connected from %s", conn.RemoteAddr())
	var err error
	var httpreq *http.Request

	if cmd == "" {
		conn.SetReadDeadline(time.Now().Add(20 * time.Second))

		bufConn := netx.NewBufferedConn(conn)
		head, err := bufConn.Reader.Peek(1)
		if err != nil {
			config.Logger.Printf("Peek from %s error : %v", conn.RemoteAddr(), err)
			return
		} else if len(head) == 0 {
			return
		}

		// 判断协议并分流
		switch head[0] {
		case 0x05:
			// 1. SOCKS5 握手
			s5auth := Socks5AuthConfig{
				AuthenticateUser: nil,
			}
			if config.Username != "" || config.Password != "" {
				s5auth.AuthenticateUser = func(u, p string) bool {
					return u == config.Username && p == config.Password
				}
			}
			err = handleSocks5Handshake(bufConn, &s5auth)
			if err != nil {
				config.Logger.Printf("SOCKS5 handshake failed for %s: %v", conn.RemoteAddr(), err)
				return
			}

			// 2. SOCKS5 请求 (TCP CONNECT 或 UDP ASSOCIATE)
			req, err := handleSocks5Request(bufConn)
			if err != nil {
				config.Logger.Printf("SOCKS5 request failed for %s: %v", conn.RemoteAddr(), err)
				return
			}

			cmd = req.Command
			targetHost, targetPort = req.Host, req.Port
			conn = bufConn
		default:
			req, err := handleHTTPProxyHandShake(bufConn, config.Username, config.Password)
			if err != nil {
				config.Logger.Printf("HTTP handshake failed for %s: %v", conn.RemoteAddr(), err)
				return
			}
			if req.Method == http.MethodConnect {
				cmd = "HTTP-CONNECT"
				// 提取 Host 和 Port
				host, portStr, err := net.SplitHostPort(req.Host)
				if err != nil {
					// 如果只有域名没有端口，默认 443
					host = req.Host
					portStr = "443"
				}
				targetHost = host
				targetPort, _ = strconv.Atoi(portStr)
			} else {
				// 普通 HTTP 请求 (GET http://example.com/...)
				cmd = "HTTP-REQ"

				// 规范化 URL
				if req.URL.Scheme == "" {
					req.URL.Scheme = "http"
				}
				if req.URL.Host == "" {
					req.URL.Host = req.Host
				}

				targetHost = req.URL.Hostname()
				targetPortStr := req.URL.Port()
				if targetPortStr == "" {
					targetPortStr = "80"
				}
				targetPort, _ = strconv.Atoi(targetPortStr)
				httpreq = req
			}
			conn = bufConn
		}
		conn.SetReadDeadline(time.Time{})
	}

	switch cmd {
	case "CONNECT", "T-CONNECT":
		transparent := cmd == "T-CONNECT"
		err = handleTCPConnectViaTunnel(config, conn, stream, transparent, targetHost, targetPort)
	case "HTTP-CONNECT":
		err = handleHTTPConnectViaTunnel(config, conn, stream, targetHost, targetPort)
	case "HTTP-REQ":
		err = handleHTTPRequestViaTunnel(config, conn, httpreq, stream, targetHost, targetPort)
	case "UDP":
		err = handleUDPAssociateViaTunnel(config, conn, keyingMaterial, stream, targetHost, targetPort)
	default:
		config.Logger.Printf("Unsupported command: %s, from client %s ", cmd, conn.RemoteAddr())
		return
	}

	if err != nil {
		config.Logger.Printf("Proxy session %s->%s (%s) finished with error: %v",
			conn.RemoteAddr(), targetHost, cmd, err)
	} else {
		config.Logger.Printf("Proxy session %s->%s (%s) finished.",
			conn.RemoteAddr(), targetHost, cmd)
	}
}

// handleSocks5ClientOnMuxStream 处理每个通过 MuxSession 传入的 Stream
func handleSocks5ClientOnStream(config *Socks5uConfig, tunnelStream net.Conn) {
	defer tunnelStream.Close()

	// 读取流的第一个请求行
	requestLine, err := netx.ReadString(tunnelStream, '\n', 1024)
	if err != nil {
		config.Logger.Printf("Failed to read request line from mux stream: %v", err)
		return
	}
	requestLine = strings.TrimSpace(requestLine)

	if strings.HasPrefix(requestLine, TUNNEL_REQ_TCP) {
		targetAddr := strings.TrimPrefix(requestLine, TUNNEL_REQ_TCP)
		handleRemoteTCPConnect(config, tunnelStream, targetAddr)
	} else if strings.HasPrefix(requestLine, TUNNEL_REQ_UDP) {
		handleRemoteUDPAssociate(config, tunnelStream)
	} else {
		config.Logger.Printf("Unknown request type from mux stream: %s", requestLine)
		// 向流写入错误响应
		_, writeErr := tunnelStream.Write([]byte("ERROR: Unknown request type\n"))
		if writeErr != nil {
			config.Logger.Printf("Failed to write error response: %v", writeErr)
		}
		return
	}
}

// handleRemoteTCPConnect 处理远端 TCP CONNECT 代理
func handleRemoteTCPConnect(config *Socks5uConfig, tunnelStream net.Conn, targetAddr string) {
	config.Logger.Printf("TCP-Connect: %s", targetAddr)
	d := &net.Dialer{
		Timeout: 25 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if config.Localbind != "" {
		localAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(config.Localbind, "0"))
		if err != nil {
			config.Logger.Printf("Failed to ResolveTCPAddr: %v", err)
			tunnelStream.Write([]byte(fmt.Sprintf("ERROR: %v\n", err)))
			return
		}
		d.LocalAddr = localAddr
	}
	resolvedAddr, isDenied, err := acl.ResolveAddrWithACL(ctx, config.AccessCtrl, "tcp", targetAddr)
	if err != nil {
		if isDenied {
			config.Logger.Printf("Access control denied for target %s", targetAddr)
			tunnelStream.Write([]byte("ERROR: Access denied\n"))
		} else {
			tunnelStream.Write([]byte(fmt.Sprintf("ERROR: %v\n", err)))
		}
		return
	}

	targetConn, err := d.Dial("tcp", resolvedAddr.String())
	if err != nil {
		config.Logger.Printf("Failed to connect to target %s: %v", targetAddr, err)
		// 向流写入错误响应
		_, writeErr := tunnelStream.Write([]byte(fmt.Sprintf("ERROR: %v\n", err)))
		if writeErr != nil {
			config.Logger.Printf("Failed to write error response: %v", writeErr)
		}
		return
	}
	defer targetConn.Close()

	// 成功建立连接，向流写入 "OK\n"
	_, err = tunnelStream.Write([]byte("OK\n"))
	if err != nil {
		config.Logger.Printf("Failed to write OK response to mux stream: %v", err)
		return
	}
	// 双向数据转发：隧道流 <-> 目标连接
	bidirectionalCopy(targetConn, tunnelStream)
	config.Logger.Printf("TCP relay for %s ended.", targetAddr)
}

// handleRemoteUDPAssociate 是运行在远程的
// 它只创建一个 UDP socket (localUDPConn)，
// 所有从 tunnelStream 接收的 SOCKS5 UDP 数据报都通过这个 socket 发送出去，
// 并且所有从这个 socket 接收的 UDP 响应包都封装后通过 tunnelStream 传回本地代理。
func handleRemoteUDPAssociate(config *Socks5uConfig, tunnelStream net.Conn) {
	// 远端创建一个通用的 UDP socket，用于向任意目标发送和接收 UDP 包
	// 绑定到 0.0.0.0:0，让操作系统选择一个可用端口
	localAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(config.Localbind, "0"))
	if err != nil {
		tunnelStream.Write([]byte(fmt.Sprintf("ERROR: Failed to ResolveUDPAddr: %v\n", err)))
		return
	}

	remoteLocalUDPConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		config.Logger.Printf("Failed to listen on remote local UDP: %v", err)
		// 如果这里失败，需要向隧道流写回错误信息
		_, writeErr := tunnelStream.Write([]byte(fmt.Sprintf("ERROR: Failed to open remote UDP socket: %v\n", err)))
		if writeErr != nil {
			config.Logger.Printf("Failed to write error response: %v", writeErr)
		}
		return
	}
	defer remoteLocalUDPConn.Close() // 确保远端 UDP socket 关闭

	// 向隧道流发送 "OK\n" 响应，通知本地代理 UDP 关联成功
	_, err = tunnelStream.Write([]byte("OK\n"))
	if err != nil {
		config.Logger.Printf("Failed to write OK response for UDP Associate to mux stream: %v", err)
		return
	}
	config.Logger.Printf("UDP-Associate-S: Using UDP socket: %s", remoteLocalUDPConn.LocalAddr())

	var wg sync.WaitGroup // 用于等待两个并发的 UDP 转发 goroutine 结束
	wg.Add(2)
	ctxRoot, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()
	var once sync.Once

	// Goroutine 1: 从 tunnelStream 接收封装的 SOCKS5 UDP 数据报，解封装后发送到目标
	go func(cancel context.CancelFunc) {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				config.Logger.Printf("Recovered from panic in tunnelStream to remote UDP sender: %v", r)
			}
			cancel()
		}()

		lengthBytes := make([]byte, 2)
		packetBuf := make([]byte, 65535) // 用于接收完整的 SOCKS5 UDP 数据报

		for {
			// 设置读取超时，以便在 tunnelStream 关闭时能退出循环
			tunnelStream.SetReadDeadline(time.Now().Add(5 * time.Second))

			// 1. 读取长度前缀
			_, err := io.ReadFull(tunnelStream, lengthBytes)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // 超时，继续等待
				}
				if err == io.EOF {
					config.Logger.Println("Tunnel stream closed from local proxy. Ending UDP relay from stream.")
					// Stream 关闭，通知另一个 goroutine 也停止
					return // 流关闭，退出此 goroutine
				}
				config.Logger.Printf("Error reading length prefix from tunnel stream for UDP: %v", err)
				return // 非 EOF 错误，退出此 goroutine
			}

			packetLength := int(binary.BigEndian.Uint16(lengthBytes)) // 解析长度

			if packetLength == 0 {
				config.Logger.Printf("Received zero-length UDP packet from tunnel. Skipping.")
				continue
			}
			if packetLength > len(packetBuf) {
				config.Logger.Printf("Received too large UDP packet from tunnel (%d bytes). Dropping.", packetLength)
				return // 协议错误，退出此 goroutine
			}

			// 2. 根据长度读取完整的 SOCKS5 UDP 数据报
			_, err = io.ReadFull(tunnelStream, packetBuf[:packetLength])
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // 超时，继续等待
				}
				if err == io.EOF {
					config.Logger.Println("Tunnel stream closed from local proxy while reading UDP packet body. Exiting.")
				}
				config.Logger.Printf("Error reading UDP packet body from tunnel stream: %v", err)
				return // 错误，退出此 goroutine
			}

			// 3. 解析 SOCKS5 UDP 报头，获取目标地址和端口
			// (SOCKS5_UDP_RSV, SOCKS5_UDP_FRAG, ATYP, DST.ADDR, DST.PORT, DATA)
			if packetLength < 10 { // 最小 SOCKS5 UDP 报头大小
				config.Logger.Printf("Received malformed SOCKS5 UDP packet (too short): %d bytes. Dropping.", packetLength)
				continue
			}

			// rsv := packetBuf[0:2]
			frag := packetBuf[2]
			atyp := packetBuf[3]

			if frag != SOCKS5_UDP_FRAG {
				config.Logger.Printf("UDP fragmentation not supported by remote. Dropping fragmented packet.")
				continue
			}

			var targetHost string
			var targetPort int
			dataOffset := 0

			switch atyp {
			case ATYP_IPV4:
				if packetLength < 10 {
					continue
				}
				targetHost = net.IPv4(packetBuf[4], packetBuf[5], packetBuf[6], packetBuf[7]).String()
				targetPort = int(packetBuf[8])<<8 | int(packetBuf[9])
				dataOffset = 10
			case ATYP_DOMAINNAME:
				domainLen := int(packetBuf[4])
				if packetLength < 5+domainLen+2 {
					continue
				}
				targetHost = string(packetBuf[5 : 5+domainLen])
				targetPort = int(packetBuf[5+domainLen])<<8 | int(packetBuf[5+domainLen+1])
				dataOffset = 5 + domainLen + 2
			case ATYP_IPV6:
				if packetLength < 22 {
					continue
				}
				targetHost = net.IP(packetBuf[4 : 4+16]).String()
				targetPort = int(packetBuf[20])<<8 | int(packetBuf[21])
				dataOffset = 22
			default:
				config.Logger.Printf("Unsupported UDP address type in SOCKS5 UDP header from local: %d", atyp)
				continue
			}

			once.Do(func() {
				config.Logger.Printf("UDP: %s->%s (first outbound packet of session)", remoteLocalUDPConn.LocalAddr().String(), net.JoinHostPort(targetHost, strconv.Itoa(targetPort)))
			})

			targetAddr, isDenied, resolveErr := acl.ResolveAddrWithACL(context.Background(), config.AccessCtrl, "udp", net.JoinHostPort(targetHost, strconv.Itoa(targetPort)))
			if resolveErr != nil {
				if isDenied {
					config.Logger.Printf("Denied to resolve target UDP address %s:%d: %v", targetHost, targetPort, resolveErr)

				} else {
					config.Logger.Printf("Failed to resolve target UDP address %s:%d: %v", targetHost, targetPort, resolveErr)
				}
				continue
			}

			// 4. 将 SOCKS5 UDP 包中的 DATA 部分通过 remoteLocalUDPConn 发送给目标服务器
			_, err = remoteLocalUDPConn.WriteToUDP(packetBuf[dataOffset:packetLength], targetAddr.(*net.UDPAddr))
			if err != nil {
				config.Logger.Printf("Error writing UDP data to target %s: %v", targetAddr, err)
				// 这里通常不直接 return，因为可能只是单个包发送失败
				// 但如果错误是连接关闭，那也会在 ReadFromUDP/WriteToUDP 时检测到并退出
			}
		}
	}(cancelRoot)

	// Goroutine 2: 从 remoteLocalUDPConn 接收 UDP 响应，封装后通过 tunnelStream 传回本地代理
	wg.Add(1)
	go func(cancel context.CancelFunc) {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				config.Logger.Printf("Recovered from panic in remote UDP receiver: %v", r)
			}
			cancel()
		}()

		respBuf := make([]byte, 65535) // 用于接收 UDP 响应
		lengthBytes := make([]byte, 2) // 用于存储长度前缀

		for {
			// 设置读取超时，以便在 remoteLocalUDPConn 关闭时能退出循环
			remoteLocalUDPConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			nResp, udpSrcAddr, err := remoteLocalUDPConn.ReadFromUDP(respBuf) // 从实际目标接收 UDP 响应
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // 超时，继续等待
				}
				config.Logger.Printf("Error reading from remote local UDP: %v", err)
				return // 非临时错误或连接关闭，退出此 goroutine
			}

			// 1. 构建 SOCKS5 UDP 响应数据报 (封装原始源地址)
			// +----+------+------+----------+----------+----------+
			// | RSV| FRAG | ATYP | BND.ADDR | BND.PORT |   DATA   |
			// +----+------+------+----------+----------+----------+

			var respATYP byte
			var respAddrBytes []byte

			if ipv4 := udpSrcAddr.IP.To4(); ipv4 != nil {
				respATYP = ATYP_IPV4
				respAddrBytes = ipv4
			} else if ipv6 := udpSrcAddr.IP.To16(); ipv6 != nil {
				respATYP = ATYP_IPV6
				respAddrBytes = ipv6
			} else {
				config.Logger.Printf("Cannot determine ATYP for source IP %s. Skipping.", udpSrcAddr.IP)
				continue
			}

			// SOCKS5 UDP header itself
			socks5UdpHeader := []byte{
				SOCKS5_UDP_RSV >> 8, SOCKS5_UDP_RSV & 0xFF, // RSV
				SOCKS5_UDP_FRAG, // FRAG
				respATYP,        // ATYP
			}
			socks5UdpHeader = append(socks5UdpHeader, respAddrBytes...)                                     // BND.ADDR
			socks5UdpHeader = append(socks5UdpHeader, byte(udpSrcAddr.Port>>8), byte(udpSrcAddr.Port&0xFF)) // BND.PORT

			// 完整 SOCKS5 UDP 响应包（包含头和数据）
			fullSocks5UdpPacket := append(socks5UdpHeader, respBuf[:nResp]...)

			// 2. 添加长度前缀
			// 确保数据包长度在 2 字节可表示的范围内
			if len(fullSocks5UdpPacket) > 65535 {
				config.Logger.Printf("Response SOCKS5 UDP packet too large (%d bytes) for 2-byte length prefix. Dropping.", len(fullSocks5UdpPacket))
				continue
			}
			binary.BigEndian.PutUint16(lengthBytes, uint16(len(fullSocks5UdpPacket)))

			// 3. 将封装好的数据包写入隧道流，发回给本地 SOCKS5 代理
			_, err = tunnelStream.Write(lengthBytes)
			if err != nil {
				config.Logger.Printf("Error writing length prefix for UDP response to tunnel stream: %v", err)
				return // 写入失败，退出
			}
			_, err = tunnelStream.Write(fullSocks5UdpPacket)
			if err != nil {
				config.Logger.Printf("Error writing SOCKS5 UDP response to tunnel stream: %v", err)
				return // 写入失败，退出
			}
		}
	}(cancelRoot)

	select {
	case <-ctxRoot.Done():
		tunnelStream.Close()
		remoteLocalUDPConn.Close()
	default:
	}
	// 等待两个转发 goroutine 结束
	wg.Wait()
	config.Logger.Printf("Remote UDP associate for stream from %s ended.", tunnelStream)
}

// SOCKS5 客户端结构体
type Socks5Client struct {
	Config *ProxyClientConfig
}

// NewSocks5Client 创建一个新的 SOCKS5 客户端实例
func NewSocks5Client(config *ProxyClientConfig) *Socks5Client {
	return &Socks5Client{
		Config: config,
	}
}

// socks5Handshake 执行 SOCKS5 握手和认证
func (c *Socks5Client) socks5Handshake(conn net.Conn) error {
	// 1. 发送方法选择报文
	var methods []byte
	if c.Config.User != "" && c.Config.Pass != "" {
		methods = []byte{AUTH_USERNAME_PASSWORD} // 支持用户名/密码认证
	} else {
		methods = []byte{AUTH_NO_AUTH} // 只支持无认证
	}

	req := []byte{SOCKS5_VERSION, byte(len(methods))}
	req = append(req, methods...)
	_, err := conn.Write(req)
	if err != nil {
		return fmt.Errorf("send method selection error: %w", err)
	}

	// 2. 读取方法选择响应
	resp := make([]byte, 2)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		return fmt.Errorf("read method selection response error: %w", err)
	}
	if resp[0] != SOCKS5_VERSION {
		return fmt.Errorf("unsupported SOCKS version in handshake response: %d", resp[0])
	}
	chosenMethod := resp[1]

	if chosenMethod == AUTH_NO_ACCEPTABLE_METHODS {
		return fmt.Errorf("SOCKS5 server: no acceptable authentication methods")
	}

	// 3. 处理认证子协商
	if chosenMethod == AUTH_USERNAME_PASSWORD {
		if c.Config.User == "" || c.Config.Pass == "" {
			return fmt.Errorf("SOCKS5 server requires authentication, but no credentials provided")
		}

		// 发送用户名/密码认证报文
		// VER(1) | ULEN(1) | UNAME(ULEN) | PLEN(1) | PASSWD(PLEN)
		authReq := []byte{0x01} // Auth subnegotiation version
		authReq = append(authReq, byte(len(c.Config.User)))
		authReq = append(authReq, []byte(c.Config.User)...)
		authReq = append(authReq, byte(len(c.Config.Pass)))
		authReq = append(authReq, []byte(c.Config.Pass)...)

		_, err := conn.Write(authReq)
		if err != nil {
			return fmt.Errorf("send username/password auth request error: %w", err)
		}

		// 读取认证响应
		// VER(1) | STATUS(1)
		authResp := make([]byte, 2)
		_, err = io.ReadFull(conn, authResp)
		if err != nil {
			return fmt.Errorf("read username/password auth response error: %w", err)
		}
		if authResp[0] != 0x01 { // Auth subnegotiation version
			return fmt.Errorf("unsupported auth subnegotiation version: %d", authResp[0])
		}
		if authResp[1] != 0x00 { // Status: 0x00 for success
			return fmt.Errorf("username/password authentication failed: status %d", authResp[1])
		}
		c.Config.Logger.Println("SOCKS5 username/password authentication successful.")
	} else if chosenMethod != AUTH_NO_AUTH {
		return fmt.Errorf("unsupported authentication method chosen by server: %d", chosenMethod)
	}
	//config.Logger.Println("SOCKS5 handshake and authentication completed.")
	return nil
}

// sendSocks5RequestHeader 构建并发送 SOCKS5 请求头
func sendSocks5RequestHeader(conn net.Conn, cmd byte, host string, port int) ([]byte, error) {
	addrBytes, atyp, err := parseHostPortToSocksAddr(host)
	if err != nil {
		return nil, fmt.Errorf("parse host/port error: %w", err)
	}

	// SOCKS5 请求报文: VER CMD RSV ATYP DST.ADDR DST.PORT
	req := []byte{
		SOCKS5_VERSION,
		cmd,
		0x00, // RSV
		atyp, // ATYP
	}
	req = append(req, addrBytes...)
	req = append(req, byte(port>>8), byte(port&0xFF))

	_, err = conn.Write(req)
	if err != nil {
		return nil, fmt.Errorf("send SOCKS5 request header error: %w", err)
	}

	return req, nil
}

// readSocks5Response 读取并解析 SOCKS5 响应
func readSocks5Response(conn net.Conn) (*net.TCPAddr, error) {
	resp := make([]byte, 300)             // Sufficient for standard response
	_, err := io.ReadFull(conn, resp[:4]) // Read VER, REP, RSV, ATYP
	if err != nil {
		return nil, fmt.Errorf("read SOCKS5 response header error: %w", err)
	}
	if resp[0] != SOCKS5_VERSION {
		return nil, fmt.Errorf("unsupported SOCKS version in response: %d", resp[0])
	}
	if resp[1] != REP_SUCCEEDED {
		return nil, fmt.Errorf("SOCKS5 request failed: %s", socks5ReplyCodeToString(resp[1]))
	}

	atyp := resp[3]
	var bndIP net.IP
	var bndPort int
	offset := 4

	switch atyp {
	case ATYP_IPV4:
		_, err := io.ReadFull(conn, resp[offset:offset+4])
		if err != nil {
			return nil, fmt.Errorf("read BND.ADDR (IPv4) error: %w", err)
		}
		bndIP = net.IPv4(resp[offset], resp[offset+1], resp[offset+2], resp[offset+3])
		offset += 4

	case ATYP_DOMAINNAME: // For BND.ADDR, server typically returns IP, but protocol allows domain
		_, err := io.ReadFull(conn, resp[offset:offset+1])
		if err != nil {
			return nil, fmt.Errorf("read BND.ADDR (domain length) error: %w", err)
		}
		domainLen := int(resp[offset])
		if domainLen <= 0 || domainLen > 255 {
			return nil, fmt.Errorf("invalid domain length: %d", domainLen)
		}
		// 检查剩余空间，如果不足则扩容
		requiredSize := offset + 1 + domainLen + 2 // +2 是为了预留给后面的 Port
		if requiredSize > len(resp) {
			newResp := make([]byte, requiredSize)
			copy(newResp, resp)
			resp = newResp
		}
		_, err = io.ReadFull(conn, resp[offset+1:offset+1+domainLen])
		if err != nil {
			return nil, fmt.Errorf("read BND.ADDR (domain) error: %w", err)
		}
		bndIP = net.ParseIP(string(resp[offset+1 : offset+1+domainLen])) // Try parse as IP, if not, it's domain
		// if bndIP == nil {
		// 	log.Printf("Warning: SOCKS5 server returned domain for BND.ADDR: %s. Proceeding with best effort.", string(resp[offset+1:offset+1+domainLen]))
		// }
		offset += 1 + domainLen

	case ATYP_IPV6:
		_, err := io.ReadFull(conn, resp[offset:offset+16])
		if err != nil {
			return nil, fmt.Errorf("read BND.ADDR (IPv6) error: %w", err)
		}
		bndIP = resp[offset : offset+16]
		offset += 16
	default:
		return nil, fmt.Errorf("unsupported BND.ADDR type in SOCKS5 response: %d", atyp)
	}

	_, err = io.ReadFull(conn, resp[offset:offset+2])
	if err != nil {
		return nil, fmt.Errorf("read BND.PORT error: %w", err)
	}
	bndPort = int(resp[offset])<<8 | int(resp[offset+1])

	return &net.TCPAddr{IP: bndIP, Port: bndPort}, nil
}

// Dial 方法现在统一处理 TCP 和 UDP
func (c *Socks5Client) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address format: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	serverAddress := net.JoinHostPort(c.Config.ServerHost, c.Config.ServerPort)
	var ntconfig *secure.NegotiationConfig
	var keyingMaterial [32]byte
	if IsSecureNegotiationNeeded(c.Config) {
		// 和服务器这个tcp连接是需要安全协商的
		ntconfig = BuildNTConfigFromPCConfig(c.Config)
		if strings.HasPrefix(network, "udp") {
			// 那么 UDP 连接需要密钥材料交换
			// 以便后续的 UDP 数据包可以使用相同的密钥材料进行加密。
			ntconfig.ErrorOnFailKeyingMaterial = true
		}
	}

	socks5Conn, err := net.DialTimeout(c.Config.Network, serverAddress, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial SOCKS5 server %s error: %w", serverAddress, err)
	}
	if ntconfig != nil {
		nconn, err := secure.DoNegotiation(ntconfig, socks5Conn, io.Discard)
		if err != nil {
			socks5Conn.Close()
			return nil, fmt.Errorf("DoNegotiation to SOCKS5 proxy server failed: %w", err)
		}
		socks5Conn = nconn
		keyingMaterial = nconn.KeyingMaterial
	}

	switch network {
	case "tcp", "tcp4", "tcp6":
		socks5Conn.SetDeadline(time.Now().Add(timeout))
		if err := c.socks5Handshake(socks5Conn); err != nil {
			socks5Conn.Close()
			return nil, fmt.Errorf("SOCKS5 handshake failed: %w", err)
		}
		if _, err := sendSocks5RequestHeader(socks5Conn, CMD_CONNECT, host, port); err != nil {
			socks5Conn.Close()
			return nil, fmt.Errorf("send SOCKS5 CONNECT request error: %w", err)
		}
		if _, err := readSocks5Response(socks5Conn); err != nil {
			socks5Conn.Close()
			return nil, fmt.Errorf("read SOCKS5 CONNECT response error: %w", err)
		}
		socks5Conn.SetDeadline(time.Time{})
		//config.Logger.Printf("Successfully connected to %s via SOCKS5 TCP proxy.", address)
		return socks5Conn, nil

	case "udp", "udp4", "udp6":
		host, portStr, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("invalid address format: %w", err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %w", err)
		}

		// 1. TCP 控制连接
		serverTCPConn := socks5Conn
		// 设置超时时间
		serverTCPConn.SetDeadline(time.Now().Add(timeout))
		if err := c.socks5Handshake(serverTCPConn); err != nil {
			serverTCPConn.Close()
			return nil, fmt.Errorf("SOCKS5 handshake for UDP ASSOCIATE failed: %w", err)
		}

		// 2. 发送 UDP ASSOCIATE 请求 (DST.ADDR 和 DST.PORT 通常是 0.0.0.0:0, 但也可以指定)
		// 这里，我们将应用程序指定的 host/port 作为请求参数。
		_, err = sendSocks5RequestHeader(serverTCPConn, CMD_UDP_ASSOCIATE, host, port)
		if err != nil {
			serverTCPConn.Close()
			return nil, fmt.Errorf("send SOCKS5 UDP ASSOCIATE request error: %w", err)
		}

		// 3. 读取 UDP ASSOCIATE 响应，获取 SOCKS5 服务器返回的 UDP 绑定地址和端口
		var actualSocks5ServerUDPAddr net.IP // 用于存储实际服务器UDP地址
		var actualSocks5ServerUDPPort int    // 用于存储实际服务器UDP端口

		bindAddr, err := readSocks5Response(serverTCPConn)
		if err != nil {
			serverTCPConn.Close()
			return nil, fmt.Errorf("read SOCKS5 UDP ASSOCIATE response error: %w", err)
		}

		// 判断如果服务端给的地址是全0, 以及是否给了内网地址，客户端则用serverTCPConn.RemoteAddr()的地址
		if bindAddr.IP.IsUnspecified() || bindAddr.IP.IsPrivate() { // 检查是否是 0.0.0.0 或 ::
			// 获取 TCP 连接的对端地址，即 SOCKS5 服务器的 IP
			if tcpRemoteAddr, ok := serverTCPConn.RemoteAddr().(*net.TCPAddr); ok {
				actualSocks5ServerUDPAddr = tcpRemoteAddr.IP
				actualSocks5ServerUDPPort = bindAddr.Port // 端口用响应中的端口
			} else {
				// 理论上不会发生，但以防万一
				actualSocks5ServerUDPAddr = bindAddr.IP
				actualSocks5ServerUDPPort = bindAddr.Port
			}
		} else {
			// 服务器返回了具体的 IP 地址，直接使用
			actualSocks5ServerUDPAddr = bindAddr.IP
			actualSocks5ServerUDPPort = bindAddr.Port
		}

		// 4. 客户端本地 dialUDP 到 SOCKS5 服务器的 UDP 绑定地址
		var localUDPConn net.Conn
		localUDPConn, err = net.DialUDP("udp", nil, &net.UDPAddr{IP: actualSocks5ServerUDPAddr, Port: actualSocks5ServerUDPPort})
		if err != nil {
			serverTCPConn.Close()
			return nil, fmt.Errorf("dial local UDP to SOCKS5 server UDP address error: %w", err)
		}

		if keyingMaterial == [32]byte{} {
		} else {
			localUDPConn, _ = secure.NewSecurePacketConn(localUDPConn, keyingMaterial)
		}

		s5uPacketConn := &Socks5UDPPacketConn{
			client:        c,
			serverTCPConn: serverTCPConn,
			localUDPConn:  localUDPConn, // 这里的 localUDPConn 已经 Dial 到 SOCKS5 服务器的 UDP 地址了
		}
		wrapper, err := netx.NewConnFromPacketConn(s5uPacketConn, true, address)
		if err != nil {
			serverTCPConn.Close()
			return nil, fmt.Errorf("NewConnFromPacketConn(Socks5UDPPacketConn): %w", err)
		}

		serverTCPConn.SetDeadline(time.Time{})

		// 启动 goroutine 监听 TCP 控制连接的关闭，以便关闭 UDP 关联
		go func() {
			defer func() {
				if r := recover(); r != nil {
				}
			}()
			// io.Copy 阻塞直到 TCP 连接关闭或出错
			_, err := io.Copy(io.Discard, serverTCPConn)
			if err != nil && err != io.EOF {
			}
			wrapper.Close() // 当 TCP 控制连接关闭时，关闭整个 UDP 客户端关联
		}()

		//config.Logger.Printf("Successfully established SOCKS5 UDP proxy for %s. Using local UDP socket: %s", address, wrapper.LocalAddr())
		return wrapper, nil

	default:
		return nil, fmt.Errorf("unsupported network type: %s", network)
	}
}

func (c *Socks5Client) Listen(network, address string) (net.Listener, error) {
	bc, err := c.RemoteListen(network, address, 30*time.Second)
	if err != nil {
		return nil, err
	}

	return &socks5listener{
		boundConn:     bc,
		fakeLocalAddr: bc.LocalAddr().(*net.TCPAddr),
	}, nil
}

func (c *Socks5Client) RemoteListen(network, address string, timeout time.Duration) (*Socks5BindConn, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address format: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	serverAddress := net.JoinHostPort(c.Config.ServerHost, c.Config.ServerPort)
	var ntconfig *secure.NegotiationConfig
	if IsSecureNegotiationNeeded(c.Config) {
		ntconfig = BuildNTConfigFromPCConfig(c.Config)
	}

	socks5Conn, err := net.DialTimeout(c.Config.Network, serverAddress, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial SOCKS5 server %s error: %w", serverAddress, err)
	}
	if ntconfig != nil {
		nconn, err := secure.DoNegotiation(ntconfig, socks5Conn, io.Discard)
		if err != nil {
			socks5Conn.Close()
			return nil, fmt.Errorf("DoNegotiation to SOCKS5 proxy server failed: %w", err)
		}
		socks5Conn = nconn
	}

	switch network {
	case "tcp", "tcp4", "tcp6":
		socks5Conn.SetDeadline(time.Now().Add(timeout))
		if err := c.socks5Handshake(socks5Conn); err != nil {
			socks5Conn.Close()
			return nil, fmt.Errorf("SOCKS5 handshake failed: %w", err)
		}
		if _, err := sendSocks5RequestHeader(socks5Conn, CMD_BIND, host, port); err != nil {
			socks5Conn.Close()
			return nil, fmt.Errorf("send SOCKS5 BIND request error: %w", err)
		}
		remoteBindAddr, err := readSocks5Response(socks5Conn)
		if err != nil {
			socks5Conn.Close()
			return nil, fmt.Errorf("read SOCKS5 BIND response error: %w", err)
		}
		socks5Conn.SetDeadline(time.Time{})
		return &Socks5BindConn{
			Conn:          socks5Conn,
			fakeLocalAddr: remoteBindAddr,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported network type: %s", network)
	}
}

type Socks5BindConn struct {
	net.Conn                    // 原始连接（嵌入）
	fakeLocalAddr  *net.TCPAddr // BIND 返回的地址
	fakeRemoteAddr *net.TCPAddr // BIND 返回的地址
}

func (b *Socks5BindConn) LocalAddr() net.Addr {
	return b.fakeLocalAddr
}

func (b *Socks5BindConn) RemoteAddr() net.Addr {
	return b.fakeRemoteAddr
}

func (c *Socks5BindConn) Accept() (net.Conn, error) {
	remoteAcceptAddr, err := readSocks5Response(c)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("read SOCKS5 Accept response error: %w", err)
	}
	c.fakeRemoteAddr = remoteAcceptAddr
	return c, nil
}

type socks5listener struct {
	boundConn     *Socks5BindConn
	fakeLocalAddr *net.TCPAddr
}

// Accept waits for and returns the next connection to the listener.
func (l *socks5listener) Accept() (net.Conn, error) {
	return l.boundConn.Accept()
}

// Close closes the listener.
func (l *socks5listener) Close() error {
	return nil
}

// address returns the listener's network address.
func (l *socks5listener) Addr() net.Addr {
	return l.fakeLocalAddr
}

// parseHostPortToSocksAddr 辅助函数，将主机和端口转换为 SOCKS 地址字节和 ATYP
func parseHostPortToSocksAddr(host string) ([]byte, byte, error) {
	ip := net.ParseIP(host)
	if ipv4 := ip.To4(); ipv4 != nil {
		return ipv4, ATYP_IPV4, nil
	}
	if ipv6 := ip.To16(); ipv6 != nil {
		return ipv6, ATYP_IPV6, nil
	}

	// 域名
	if len(host) > 255 {
		return nil, 0, fmt.Errorf("domain name too long: %s", host)
	}
	addrBytes := make([]byte, 1+len(host))
	addrBytes[0] = byte(len(host))
	copy(addrBytes[1:], host)
	return addrBytes, ATYP_DOMAINNAME, nil
}

// socks5ReplyCodeToString 将 SOCKS5 响应码转换为可读字符串
func socks5ReplyCodeToString(code byte) string {
	switch code {
	case REP_SUCCEEDED:
		return "Succeeded"
	case REP_GENERAL_SOCKS_SERVER_FAIL:
		return "General SOCKS server failure"
	case REP_CONNECTION_NOT_ALLOWED:
		return "Connection not allowed by ruleset"
	case REP_NETWORK_UNREACHABLE:
		return "Network unreachable"
	case REP_HOST_UNREACHABLE:
		return "Host unreachable"
	case REP_CONNECTION_REFUSED:
		return "Connection refused"
	case REP_TTL_EXPIRED:
		return "TTL expired"
	case REP_COMMAND_NOT_SUPPORTED:
		return "Command not supported"
	case REP_ADDRESS_TYPE_NOT_SUPPORTED:
		return "Address type not supported"
	default:
		return fmt.Sprintf("Unknown error (%d)", code)
	}
}

// Socks5UDPPacketConn 包装器，实现 net.PacketConn 接口
type Socks5UDPPacketConn struct {
	// 客户端底层的 SOCKS5 客户端实例
	client *Socks5Client
	// 与 SOCKS5 服务器的 TCP 控制连接
	serverTCPConn net.Conn
	// 客户端本地 UDP 连接，它是一个已 Dial 到 SOCKS5 服务器 UDP 端口的 net.Conn
	// 它的底层类型是 *net.UDPConn
	localUDPConn net.Conn

	// 标记是否已关闭
	closed sync.Once
}

func (pc *Socks5UDPPacketConn) GetUDPAssociateAddr() net.Addr {
	return pc.localUDPConn.RemoteAddr()
}

// ReadFrom 从 SOCKS5 代理读取一个UDP包，实现 net.PacketConn 接口。
// 它调用 localUDPConn.Read() 获取SOCKS5响应，然后解析出真正的源地址。
func (pc *Socks5UDPPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	if pc.localUDPConn == nil {
		return 0, nil, net.ErrClosed
	}
	// 1. 从已连接的 localUDPConn 读取完整的 SOCKS5 UDP 响应报文。
	//    这会从 SOCKS5 服务器的 UDP 端口接收数据。
	respBuf := make([]byte, 65535)
	nResp, err := pc.localUDPConn.Read(respBuf) // 使用 Read() 是正确的
	if err != nil {
		return 0, nil, err
	}

	// 2. 解析 SOCKS5 UDP 响应报头以找出真正的源地址
	if nResp < 10 { // IPv4 的最小报头长度
		return 0, nil, fmt.Errorf("malformed SOCKS5 UDP response (too short): %d bytes", nResp)
	}

	resp_frag := respBuf[2]
	if resp_frag != 0x00 {
		pc.client.Config.Logger.Printf("Warning: SOCKS5 UDP response fragmented. Fragmentation is not supported.")
	}

	resp_atyp := respBuf[3]
	headerOffset := 4
	var sourceAddr net.Addr
	var sourcePort int

	switch resp_atyp {
	case ATYP_IPV4:
		if nResp < headerOffset+4+2 {
			return 0, nil, fmt.Errorf("malformed IPv4 SOCKS5 UDP response")
		}
		ip := net.IP(respBuf[headerOffset : headerOffset+4])
		headerOffset += 4
		sourcePort = int(respBuf[headerOffset])<<8 | int(respBuf[headerOffset+1])
		sourceAddr = &net.UDPAddr{IP: ip, Port: sourcePort}
		headerOffset += 2

	case ATYP_IPV6:
		if nResp < headerOffset+16+2 {
			return 0, nil, fmt.Errorf("malformed IPv6 SOCKS5 UDP response")
		}
		ip := net.IP(respBuf[headerOffset : headerOffset+16])
		headerOffset += 16
		sourcePort = int(respBuf[headerOffset])<<8 | int(respBuf[headerOffset+1])
		sourceAddr = &net.UDPAddr{IP: ip, Port: sourcePort}
		headerOffset += 2

	case ATYP_DOMAINNAME:
		if nResp < headerOffset+1 {
			return 0, nil, fmt.Errorf("malformed domain SOCKS5 UDP response (no length)")
		}
		domainLen := int(respBuf[headerOffset])
		headerOffset += 1
		if nResp < headerOffset+domainLen+2 {
			return 0, nil, fmt.Errorf("malformed domain SOCKS5 UDP response (short data)")
		}
		domain := string(respBuf[headerOffset : headerOffset+domainLen])
		headerOffset += domainLen
		sourcePort = int(respBuf[headerOffset])<<8 | int(respBuf[headerOffset+1])
		headerOffset += 2
		sourceAddr = &netx.NameUDPAddr{
			Net:     "name",
			Address: fmt.Sprintf("%s:%d", domain, sourcePort),
		}

	default:
		return 0, nil, fmt.Errorf("unsupported ATYP in SOCKS5 UDP response: %d", resp_atyp)
	}

	// 复制数据部分
	dataOffset := headerOffset
	dataLen := nResp - dataOffset
	if dataLen < 0 {
		return 0, nil, fmt.Errorf("invalid SOCKS5 UDP response data length")
	}
	if dataLen > len(b) {
		n = copy(b, respBuf[dataOffset:dataOffset+len(b)])
		//log.Printf("Warning: UDP response truncated. Packet size: %d, Buffer size: %d", dataLen, len(b))
	} else {
		n = copy(b, respBuf[dataOffset:nResp])
	}

	return n, sourceAddr, nil
}

// WriteTo 将一个UDP包通过SOCKS5代理发送到指定的目标地址addr，实现 net.PacketConn 接口。
// 它将用户数据封装在SOCKS5头部中，然后调用 localUDPConn.Write() 发送到SOCKS5服务器。
func (pc *Socks5UDPPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	if pc.localUDPConn == nil {
		return 0, net.ErrClosed
	}

	var (
		host    string
		port    int
		portStr string
	)

	switch a := addr.(type) {
	case *net.UDPAddr:
		host = a.IP.String()
		port = a.Port
	case *netx.NameUDPAddr: // 自己的类型
		host, portStr, err = net.SplitHostPort(a.Address)
		if err != nil {
			return 0, fmt.Errorf("invalid UDP target address: %w", err)
		}
		port, _ = strconv.Atoi(portStr)
	default:
		// fallback: try resolve (可能丢失域名)
		udpAddr, err := net.ResolveUDPAddr(addr.Network(), addr.String())
		if err != nil {
			return 0, fmt.Errorf("invalid or non-UDP target address: %w", err)
		}
		host = udpAddr.IP.String()
		port = udpAddr.Port
	}

	addrBytes, atyp, err := parseHostPortToSocksAddr(host)
	if err != nil {
		return 0, fmt.Errorf("failed to parse target host for SOCKS5 header: %w", err)
	}

	// 构建 SOCKS5 UDP 请求报头
	header := []byte{
		SOCKS5_UDP_RSV >> 8, SOCKS5_UDP_RSV & 0xFF, // RSV
		0x00, // FRAG
		atyp, // ATYP
	}
	header = append(header, addrBytes...)
	header = append(header, byte(port>>8), byte(port&0xFF))

	// 将SOCKS5头部和用户数据拼接
	fullPacket := append(header, b...)

	// 将完整的SOCKS5包写入已连接的UDP Conn，发往SOCKS5服务器。
	// 使用 Write() 是正确的。
	_, err = pc.localUDPConn.Write(fullPacket)
	if err != nil {
		return 0, err
	}

	// 返回写入的原始用户数据长度
	return len(b), nil
}

// Close 关闭连接
func (pc *Socks5UDPPacketConn) Close() error {
	var err error
	pc.closed.Do(func() {
		if pc.serverTCPConn != nil {
			err = pc.serverTCPConn.Close()
		}
		//remoteaddr := ""
		if pc.localUDPConn != nil {
			//remoteaddr = pc.localUDPConn.LocalAddr().String()
			// 如果 serverTCPConn.Close() 出错，这里的错误可能会覆盖它。
			// 在实际应用中可能需要更复杂的错误处理。
			closeErr := pc.localUDPConn.Close()
			if err == nil {
				err = closeErr
			}
		}
		//log.Println("Socks5UDPPacketConn closed(", remoteaddr, ").")
	})
	return err
}

// LocalAddr 返回本地地址
func (pc *Socks5UDPPacketConn) LocalAddr() net.Addr {
	if pc.localUDPConn != nil {
		return pc.localUDPConn.LocalAddr()
	}
	return nil
}

// SetDeadline, SetReadDeadline, SetWriteDeadline 直接代理到下层连接
func (pc *Socks5UDPPacketConn) SetDeadline(t time.Time) error {
	if pc.localUDPConn != nil {
		return pc.localUDPConn.SetDeadline(t)
	}
	return net.ErrClosed
}

func (pc *Socks5UDPPacketConn) SetReadDeadline(t time.Time) error {
	if pc.localUDPConn != nil {
		return pc.localUDPConn.SetReadDeadline(t)
	}
	return net.ErrClosed
}

func (pc *Socks5UDPPacketConn) SetWriteDeadline(t time.Time) error {
	if pc.localUDPConn != nil {
		return pc.localUDPConn.SetWriteDeadline(t)
	}
	return net.ErrClosed
}
