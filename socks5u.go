package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
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

// Socks5ServerConfig 用于配置 SOCKS5 服务器的行为，包括认证
type Socks5ServerConfig struct {
	// AuthenticateUser 是一个函数，用于验证用户名和密码。
	// 如果配置为 nil，则表示服务器不要求用户密码认证。
	// 如果非 nil，服务器将要求客户端进行用户密码认证。
	AuthenticateUser func(username, password string) bool
}

// sendSocks5AuthResponse 发送 SOCKS5 用户名/密码认证阶段的响应
func sendSocks5AuthResponse(conn net.Conn, status byte) error {
	_, err := conn.Write([]byte{0x01, status})
	return err
}

type Socks5Request struct {
	Command string
	Host    string
	Port    int
}

// handleSocks5Handshake 处理 SOCKS5 握手阶段
func handleSocks5Handshake(conn net.Conn, config Socks5ServerConfig) error {
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
	if config.AuthenticateUser != nil {
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
		if !config.AuthenticateUser(username, password) { // 使用配置中提供的认证函数
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
	buf := make([]byte, 256)

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
func handleTCPConnectViaTunnel(clientConn net.Conn, tunnelStream net.Conn, targetHost string, targetPort int) error {
	// 发送代理请求给远端: "tcp://target_host:target_port\n"
	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	requestLine := fmt.Sprintf("%s%s\n", TUNNEL_REQ_TCP, targetAddr)
	_, err := tunnelStream.Write([]byte(requestLine))
	if err != nil {
		sendSocks5Response(clientConn, REP_GENERAL_SOCKS_SERVER_FAIL, "0.0.0.0", 0)
		return fmt.Errorf("write tunnel request error: %w", err)
	}
	log.Printf("TCP: %s->%s connecting...", clientConn.RemoteAddr().String(), targetAddr)

	tunnelStream.SetReadDeadline(time.Now().Add(25 * time.Second))
	// 读取远端连接结果（例如 "OK\n" 或 "ERROR: reason\n"）
	responseLine, err := ReadString(tunnelStream, '\n')
	if err != nil {
		log.Printf("%s->%s error: %v", clientConn.RemoteAddr().String(), targetAddr, err)
		sendSocks5Response(clientConn, REP_GENERAL_SOCKS_SERVER_FAIL, "0.0.0.0", 0)
		return fmt.Errorf("read tunnel response error: %w", err)
	}
	responseLine = strings.TrimSpace(responseLine)

	if !strings.HasPrefix(responseLine, "OK") {
		log.Printf("%s->%s failed: %s", clientConn.RemoteAddr().String(), targetAddr, responseLine)
		sendSocks5Response(clientConn, REP_GENERAL_SOCKS_SERVER_FAIL, "0.0.0.0", 0) // 根据远端错误细化SOCKS5错误码
		return fmt.Errorf("tunnel TCP connect failed: %s", responseLine)
	}

	// 成功响应SOCKS5客户端
	// 这里我们没有远端绑定的实际地址和端口，所以使用 0.0.0.0:0 或者客户端连接的源IP/端口
	// 根据SOCKS5协议，BND.ADDR和BND.PORT应该是服务器用于连接目标的地址/端口
	// 但在这里，连接目标在远端，所以我们通常返回代理服务器本身的地址（即 0.0.0.0:0 或本地监听地址）
	// 或者为了更严谨，可以要求远端在OK后回传其绑定的地址和端口。
	// 这里简化，返回 0.0.0.0:0
	sendSocks5Response(clientConn, REP_SUCCEEDED, "0.0.0.0", 0)

	tunnelStream.SetReadDeadline(time.Time{})

	handleProxy(clientConn, tunnelStream)
	return nil
}

// handleUDPAssociateViaTunnel 处理 UDP ASSOCIATE 命令并通过隧道转发
func handleUDPAssociateViaTunnel(clientConn net.Conn, tunnelStream net.Conn, targetHost string, targetPort int) error {
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

	bindIP := localUDPConn.LocalAddr().(*net.UDPAddr).IP.String()
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
	responseLine, err := ReadString(tunnelStream, '\n')
	if err != nil {
		return fmt.Errorf("read tunnel response error: %w", err)
	}
	responseLine = strings.TrimSpace(responseLine)

	if !strings.HasPrefix(responseLine, "OK") {
		log.Printf("Tunnel UDP associate failed: %s", responseLine)
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
	handleLocalUDPToTunnel(localUDPConn, tunnelStream, clientConn.RemoteAddr().(*net.TCPAddr).IP)
	clientConn.Close()
	wg.Wait() // 等待 TCP 关闭 goroutine 结束
	return nil
}

// handleLocalUDPToTunnel 是运行在本地客户端
// 负责将本地 SOCKS5 客户端的 UDP 数据包封装并通过 tunnelStream 发送给远端
// 并接收远端封装的 UDP 响应，解封装后发回给客户端。
func handleLocalUDPToTunnel(localUDPConn *net.UDPConn, tunnelStream net.Conn, clientIP net.IP) {
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
				log.Printf("Recovered from panic in localUDPConn to tunnelStream: %v", r)
			}
			cancel()
		}()

		buf := make([]byte, 65535)     // SOCKS5 UDP 数据包最大长度
		lengthBytes := make([]byte, 2) // 用于存储长度前缀

		for {
			// 设置读取超时，以便在 localUDPConn 关闭时能退出循环
			localUDPConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, cliAddr, err := localUDPConn.ReadFromUDP(buf) // 读取 SOCKS5 客户端发来的 UDP 数据报
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // 超时，继续等待
				}
				log.Printf("Error reading from local UDP for client %s: %v", clientIP, err)
				return // 非临时错误或连接关闭，退出 goroutine
			}

			// 确保只处理来自 SOCKS5 客户端 IP 的 UDP 包，增强安全性
			if clientIP != nil && !cliAddr.IP.Equal(clientIP) {
				log.Printf("Received UDP packet from unexpected source: %s, expected: %s. Dropping.", cliAddr.IP, clientIP)
				continue
			}

			// 首次收到客户端的 UDP 包时，保存其源地址
			once.Do(func() {
				clientActualUDPAddr = cliAddr
				log.Printf("UDP: %s associated", clientActualUDPAddr)
			})

			// 封装数据包：[Length (2 bytes)] [SOCKS5 UDP Header + Data]
			// 确保数据包长度在 2 字节可表示的范围内
			if n > 65535 {
				log.Printf("UDP packet too large (%d bytes) for 2-byte length prefix. Dropping.", n)
				continue
			}
			binary.BigEndian.PutUint16(lengthBytes, uint16(n)) // 写入长度

			// 写入长度前缀
			_, err = tunnelStream.Write(lengthBytes)
			if err != nil {
				log.Printf("Error writing length prefix to tunnel stream: %v", err)
				return
			}
			// 写入完整的 SOCKS5 UDP 数据报
			_, err = tunnelStream.Write(buf[:n])
			if err != nil {
				log.Printf("Error writing SOCKS5 UDP packet to tunnel stream: %v", err)
				return
			}
		}
	}(cancelRoot)

	// Goroutine 2: 从 tunnelStream 接收封装的数据包，解封装后发送到 localUDPConn
	go func(cancel context.CancelFunc) {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Recovered from panic in tunnelStream to localUDPConn: %v", r)
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
					log.Println("Tunnel stream closed from remote for UDP responses. Exiting.")
					return // 流关闭
				}
				log.Printf("Error reading length prefix from tunnel stream: %v", err)
				return // 非 EOF 错误，退出
			}

			packetLength := binary.BigEndian.Uint16(lengthBytes) // 解析长度

			if packetLength == 0 {
				log.Printf("Received zero-length UDP packet from tunnel. Skipping.")
				continue
			}
			if packetLength > uint16(len(packetBuf)) {
				log.Printf("Received too large UDP packet from tunnel (%d bytes). Dropping.", packetLength)
				// 尝试跳过这个无效包，但可能导致同步问题
				// 更好的做法是直接退出，因为这表明协议错误
				return
			}

			// 2. 根据长度读取完整的 SOCKS5 UDP 数据报
			_, err = io.ReadFull(tunnelStream, packetBuf[:packetLength])
			if err != nil {
				if err == io.EOF {
					log.Println("Tunnel stream closed from remote while reading UDP packet body. Exiting.")
				}
				log.Printf("Error reading UDP packet body from tunnel stream: %v", err)
				return // 错误，退出
			}

			// 3. 将 SOCKS5 UDP 数据报发送回 SOCKS5 客户端
			if clientActualUDPAddr == nil {
				log.Printf("Warning: Client's UDP address not yet known for sending responses. Dropping packet from tunnel.")
				continue // 客户端还没发过包，不知道往哪里回传
			}

			_, err = localUDPConn.WriteToUDP(packetBuf[:packetLength], clientActualUDPAddr)
			if err != nil {
				log.Printf("Error writing UDP response to client %s via local UDP: %v", clientActualUDPAddr, err)
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

func handleDirectTCPConnect(clientConn net.Conn, targetHost string, targetPort int) error {

	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	targetConn, err := net.Dial("tcp", targetAddr)
	log.Printf("TCP: %s->%s connecting...", clientConn.RemoteAddr().String(), targetAddr)

	if err != nil {
		sendSocks5Response(clientConn, REP_GENERAL_SOCKS_SERVER_FAIL, "0.0.0.0", 0)
		return fmt.Errorf("tunnel TCP connect failed: %v", err)
	}
	sendSocks5Response(clientConn, REP_SUCCEEDED, "0.0.0.0", 0)
	handleProxy(clientConn, targetConn)
	return nil
}

func handleTCPListen(clientConn net.Conn, targetHost string, targetPort int) error {
	lc := net.ListenConfig{}
	if targetHost == "" {
		local, ok := clientConn.LocalAddr().(*net.TCPAddr)
		if ok {
			targetHost = local.IP.String()
		}
	}
	bindAddr := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	listener, err := lc.Listen(context.Background(), "tcp", bindAddr)
	if err != nil {
		sendSocks5Response(clientConn, REP_GENERAL_SOCKS_SERVER_FAIL, "0.0.0.0", 0)
		return fmt.Errorf("bind to %v failed: %w", bindAddr, err)
	}

	localAddr := listener.Addr()
	local, ok := localAddr.(*net.TCPAddr)
	if !ok {
		listener.Close()
		return fmt.Errorf("bind to %v failed: local address is %s://%s", bindAddr, localAddr.Network(), localAddr.String())
	}

	err = sendSocks5Response(clientConn, REP_SUCCEEDED, local.IP.String(), local.Port)
	if err != nil {
		return fmt.Errorf("send response error: %w", err)
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background()) // 控制 goroutine 正常退出
	wg.Add(1)

	// 监控 clientConn 是否异常
	go func() {
		defer wg.Done()
		buf := make([]byte, 1)
		for {
			// 设置1秒超时
			_ = clientConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			_, err := clientConn.Read(buf)

			if err != nil {
				// 检查是否是超时（非致命）
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					select {
					case <-ctx.Done():
						// 收到主线程通知，正常退出
						return
					default:
						// 超时但还要继续循环
						continue
					}
				}

				// 其他错误，说明连接断了或异常
				listener.Close() // 主动关闭 Accept
				return
			}

			// 如果读到数据（buf 非空），也认为异常
			listener.Close()
			return
		}
	}()

	// 阻塞等待连接
	conn, err := listener.Accept()
	cancel() // 通知 goroutine 正常退出
	if err != nil {
		listener.Close()
		sendSocks5Response(clientConn, REP_GENERAL_SOCKS_SERVER_FAIL, "0.0.0.0", 0)
		wg.Wait()
		return fmt.Errorf("accept failed: %w", err)
	}

	listener.Close()
	wg.Wait() // 等 goroutine 退出后继续
	_ = clientConn.SetReadDeadline(time.Time{})

	remoteAddr := conn.RemoteAddr()
	remote, ok := remoteAddr.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("failed: cast remote address to TCPAddr: %s://%s", remoteAddr.Network(), remoteAddr.String())
	}
	err = sendSocks5Response(clientConn, REP_SUCCEEDED, remote.IP.String(), remote.Port)
	if err != nil {
		return fmt.Errorf("send response error: %w", err)
	}
	handleProxy(clientConn, conn)
	return nil
}

func handleSocks5uProxy(conn net.Conn, stream net.Conn) {
	log.Printf("New client connected from %s", conn.RemoteAddr())

	conn.SetReadDeadline(time.Now().Add(20 * time.Second))

	// 1. SOCKS5 握手
	configNoAuth := Socks5ServerConfig{
		AuthenticateUser: nil, // 不要求认证
	}
	err := handleSocks5Handshake(conn, configNoAuth)
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

	if req.Command == "CONNECT" {
		err = handleTCPConnectViaTunnel(conn, stream, req.Host, req.Port)
		if err != nil {
			log.Printf("SOCKS5 TCP Connect failed for %s: %v", conn.RemoteAddr(), err)
			return
		}
	} else if req.Command == "UDP" {
		err = handleUDPAssociateViaTunnel(conn, stream, req.Host, req.Port)
		if err != nil {
			log.Printf("SOCKS5 UDP Associate failed for %s: %v", conn.RemoteAddr(), err)
			return
		}
	}

	log.Printf("Disconnected from client %s (requested SOCKS5 command: %s).", conn.RemoteAddr(), req.Command)
}

func ReadString(conn io.Reader, delim byte) (string, error) {
	var buf []byte
	tmp := make([]byte, 1)

	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[0])
			if tmp[0] == delim {
				return string(buf), nil
			}
		}

		if err != nil {
			if errors.Is(err, io.EOF) && len(buf) > 0 {
				return string(buf), nil
			}
			return "", err
		}
	}
}

// handleSocks5uModeForRemote 是远端服务器的入口函数
// 它将负责接收 MuxSession 连接，并接受和处理 Stream
func handleSocks5uModeForRemote(cfg MuxSessionConfig) error {
	// 假设 cfg.SessionConn 是远端服务器接受的原始连接
	// 例如：rawConn, err := listener.Accept()
	// session, err := smux.Server(rawConn, nil) // 创建服务器端的 smux 会话
	session, err := createMuxSession(cfg.Engine, cfg.SessionConn, true) // isServer=true
	if err != nil {
		return fmt.Errorf("create mux session failed: %v", err)
	}

	log.Printf("SOCKS5 tunnel server ready on mux session.")

	listener := &muxListener{session}

	// 循环接受新的 mux 流
	for {
		// Accept() 阻塞直到有新的客户端流到来
		stream, err := listener.Accept()
		if err != nil {
			if err == io.EOF {
				log.Println("Mux session closed. Exiting stream acceptance loop.")
				return nil
			}
			log.Printf("Failed to accept mux stream: %v", err)
			return err
		}
		go handleSocks5ClientOnStream(stream) // 为每个新流启动一个 goroutine 处理
	}
}

// handleSocks5ClientOnMuxStream 处理每个通过 MuxSession 传入的 Stream
func handleSocks5ClientOnStream(tunnelStream net.Conn) {
	defer tunnelStream.Close()

	// 读取流的第一个请求行
	requestLine, err := ReadString(tunnelStream, '\n')
	if err != nil {
		log.Printf("Failed to read request line from mux stream: %v", err)
		return
	}
	requestLine = strings.TrimSpace(requestLine)

	if strings.HasPrefix(requestLine, TUNNEL_REQ_TCP) {
		targetAddr := strings.TrimPrefix(requestLine, TUNNEL_REQ_TCP)
		handleRemoteTCPConnect(tunnelStream, targetAddr)
	} else if strings.HasPrefix(requestLine, TUNNEL_REQ_UDP) {
		handleRemoteUDPAssociate(tunnelStream)
	} else {
		log.Printf("Unknown request type from mux stream: %s", requestLine)
		// 向流写入错误响应
		_, writeErr := tunnelStream.Write([]byte("ERROR: Unknown request type\n"))
		if writeErr != nil {
			log.Printf("Failed to write error response: %v", writeErr)
		}
		return
	}
}

// handleRemoteTCPConnect 处理远端 TCP CONNECT 代理
func handleRemoteTCPConnect(tunnelStream net.Conn, targetAddr string) {
	log.Printf("TCP-Connect: %s", targetAddr)
	d := &net.Dialer{
		Timeout: 20 * time.Second,
	}
	targetConn, err := d.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", targetAddr, err)
		// 向流写入错误响应
		_, writeErr := tunnelStream.Write([]byte(fmt.Sprintf("ERROR: %v\n", err)))
		if writeErr != nil {
			log.Printf("Failed to write error response: %v", writeErr)
		}
		return
	}
	defer targetConn.Close()

	// 成功建立连接，向流写入 "OK\n"
	_, err = tunnelStream.Write([]byte("OK\n"))
	if err != nil {
		log.Printf("Failed to write OK response to mux stream: %v", err)
		return
	}
	// 双向数据转发：隧道流 <-> 目标连接
	handleProxy(targetConn, tunnelStream)
	log.Printf("TCP relay for %s ended.", targetAddr)
}

// handleRemoteUDPAssociate 是运行在远程的
// 它只创建一个 UDP socket (localUDPConn)，
// 所有从 tunnelStream 接收的 SOCKS5 UDP 数据报都通过这个 socket 发送出去，
// 并且所有从这个 socket 接收的 UDP 响应包都封装后通过 tunnelStream 传回本地代理。
func handleRemoteUDPAssociate(tunnelStream net.Conn) {
	// 远端创建一个通用的 UDP socket，用于向任意目标发送和接收 UDP 包
	// 绑定到 0.0.0.0:0，让操作系统选择一个可用端口
	remoteLocalUDPConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Printf("Failed to listen on remote local UDP: %v", err)
		// 如果这里失败，需要向隧道流写回错误信息
		_, writeErr := tunnelStream.Write([]byte(fmt.Sprintf("ERROR: Failed to open remote UDP socket: %v\n", err)))
		if writeErr != nil {
			log.Printf("Failed to write error response: %v", writeErr)
		}
		return
	}
	defer remoteLocalUDPConn.Close() // 确保远端 UDP socket 关闭

	// 向隧道流发送 "OK\n" 响应，通知本地代理 UDP 关联成功
	_, err = tunnelStream.Write([]byte("OK\n"))
	if err != nil {
		log.Printf("Failed to write OK response for UDP Associate to mux stream: %v", err)
		return
	}
	log.Printf("UDP-Associate: Using local UDP socket: %s", remoteLocalUDPConn.LocalAddr())

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
				log.Printf("Recovered from panic in tunnelStream to remote UDP sender: %v", r)
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
					log.Println("Tunnel stream closed from local proxy. Ending UDP relay from stream.")
					// Stream 关闭，通知另一个 goroutine 也停止
					return // 流关闭，退出此 goroutine
				}
				log.Printf("Error reading length prefix from tunnel stream for UDP: %v", err)
				return // 非 EOF 错误，退出此 goroutine
			}

			packetLength := int(binary.BigEndian.Uint16(lengthBytes)) // 解析长度

			if packetLength == 0 {
				log.Printf("Received zero-length UDP packet from tunnel. Skipping.")
				continue
			}
			if packetLength > len(packetBuf) {
				log.Printf("Received too large UDP packet from tunnel (%d bytes). Dropping.", packetLength)
				return // 协议错误，退出此 goroutine
			}

			// 2. 根据长度读取完整的 SOCKS5 UDP 数据报
			_, err = io.ReadFull(tunnelStream, packetBuf[:packetLength])
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // 超时，继续等待
				}
				if err == io.EOF {
					log.Println("Tunnel stream closed from local proxy while reading UDP packet body. Exiting.")
				}
				log.Printf("Error reading UDP packet body from tunnel stream: %v", err)
				return // 错误，退出此 goroutine
			}

			// 3. 解析 SOCKS5 UDP 报头，获取目标地址和端口
			// (SOCKS5_UDP_RSV, SOCKS5_UDP_FRAG, ATYP, DST.ADDR, DST.PORT, DATA)
			if packetLength < 10 { // 最小 SOCKS5 UDP 报头大小
				log.Printf("Received malformed SOCKS5 UDP packet (too short): %d bytes. Dropping.", packetLength)
				continue
			}

			// rsv := packetBuf[0:2]
			frag := packetBuf[2]
			atyp := packetBuf[3]

			if frag != SOCKS5_UDP_FRAG {
				log.Printf("UDP fragmentation not supported by remote. Dropping fragmented packet.")
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
				log.Printf("Unsupported UDP address type in SOCKS5 UDP header from local: %d", atyp)
				continue
			}

			once.Do(func() {
				log.Printf("UDP: %s->%s (first outbound packet of session)", remoteLocalUDPConn.LocalAddr().String(), net.JoinHostPort(targetHost, strconv.Itoa(targetPort)))
			})

			targetAddr, resolveErr := net.ResolveUDPAddr("udp", net.JoinHostPort(targetHost, strconv.Itoa(targetPort)))
			if resolveErr != nil {
				log.Printf("Failed to resolve target UDP address %s:%d: %v", targetHost, targetPort, resolveErr)
				continue
			}

			// 4. 将 SOCKS5 UDP 包中的 DATA 部分通过 remoteLocalUDPConn 发送给目标服务器
			_, err = remoteLocalUDPConn.WriteToUDP(packetBuf[dataOffset:packetLength], targetAddr)
			if err != nil {
				log.Printf("Error writing UDP data to target %s: %v", targetAddr, err)
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
				log.Printf("Recovered from panic in remote UDP receiver: %v", r)
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
				log.Printf("Error reading from remote local UDP: %v", err)
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
				log.Printf("Cannot determine ATYP for source IP %s. Skipping.", udpSrcAddr.IP)
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
				log.Printf("Response SOCKS5 UDP packet too large (%d bytes) for 2-byte length prefix. Dropping.", len(fullSocks5UdpPacket))
				continue
			}
			binary.BigEndian.PutUint16(lengthBytes, uint16(len(fullSocks5UdpPacket)))

			// 3. 将封装好的数据包写入隧道流，发回给本地 SOCKS5 代理
			_, err = tunnelStream.Write(lengthBytes)
			if err != nil {
				log.Printf("Error writing length prefix for UDP response to tunnel stream: %v", err)
				return // 写入失败，退出
			}
			_, err = tunnelStream.Write(fullSocks5UdpPacket)
			if err != nil {
				log.Printf("Error writing SOCKS5 UDP response to tunnel stream: %v", err)
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
	log.Printf("Remote UDP associate for stream from %s ended.", tunnelStream)
}

// SOCKS5 客户端结构体
type Socks5Client struct {
	Socks5Addr string // SOCKS5 服务器地址 (e.g., "127.0.0.1:1080")
	Username   string // 用户名 (可选)
	Password   string // 密码 (可选)
}

// NewSocks5Client 创建一个新的 SOCKS5 客户端实例
func NewSocks5Client(socks5Addr, username, password string) *Socks5Client {
	return &Socks5Client{
		Socks5Addr: socks5Addr,
		Username:   username,
		Password:   password,
	}
}

// socks5Handshake 执行 SOCKS5 握手和认证
func (c *Socks5Client) socks5Handshake(conn net.Conn) error {
	// 1. 发送方法选择报文
	var methods []byte
	if c.Username != "" && c.Password != "" {
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
		if c.Username == "" || c.Password == "" {
			return fmt.Errorf("SOCKS5 server requires authentication, but no credentials provided")
		}

		// 发送用户名/密码认证报文
		// VER(1) | ULEN(1) | UNAME(ULEN) | PLEN(1) | PASSWD(PLEN)
		authReq := []byte{0x01} // Auth subnegotiation version
		authReq = append(authReq, byte(len(c.Username)))
		authReq = append(authReq, []byte(c.Username)...)
		authReq = append(authReq, byte(len(c.Password)))
		authReq = append(authReq, []byte(c.Password)...)

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
		log.Println("SOCKS5 username/password authentication successful.")
	} else if chosenMethod != AUTH_NO_AUTH {
		return fmt.Errorf("unsupported authentication method chosen by server: %d", chosenMethod)
	}
	//log.Println("SOCKS5 handshake and authentication completed.")
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
	resp := make([]byte, 256)             // Sufficient for standard response
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
		_, err = io.ReadFull(conn, resp[offset+1:offset+1+domainLen])
		if err != nil {
			return nil, fmt.Errorf("read BND.ADDR (domain) error: %w", err)
		}
		bndIP = net.ParseIP(string(resp[offset+1 : offset+1+domainLen])) // Try parse as IP, if not, it's domain
		if bndIP == nil {
			log.Printf("Warning: SOCKS5 server returned domain for BND.ADDR: %s. Proceeding with best effort.", string(resp[offset+1:offset+1+domainLen]))
		}
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
	if c.Socks5Addr == "" {
		return net.DialTimeout(network, address, timeout)
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
		host, portStr, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("invalid address format: %w", err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %w", err)
		}

		socks5Conn, err := net.DialTimeout("tcp", c.Socks5Addr, timeout)
		if err != nil {
			return nil, fmt.Errorf("dial SOCKS5 server %s error: %w", c.Socks5Addr, err)
		}
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
		//log.Printf("Successfully connected to %s via SOCKS5 TCP proxy.", address)
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
		serverTCPConn, err := net.DialTimeout("tcp", c.Socks5Addr, timeout)
		if err != nil {
			return nil, fmt.Errorf("dial SOCKS5 server %s for UDP ASSOCIATE error: %w", c.Socks5Addr, err)
		}
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

		// 判断如果服务端给的地址是全0, 则用serverTCPConn.RemoteAddr()的地址
		if bindAddr.IP.IsUnspecified() { // 检查是否是 0.0.0.0 或 ::
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
		localUDPConn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: actualSocks5ServerUDPAddr, Port: actualSocks5ServerUDPPort})
		if err != nil {
			serverTCPConn.Close()
			return nil, fmt.Errorf("dial local UDP to SOCKS5 server UDP address error: %w", err)
		}

		// 初始化 UDPConnWrapper
		wrapper := &UDPConnWrapper{
			client:           c,
			serverTCPConn:    serverTCPConn,
			localUDPConn:     localUDPConn, // 这里的 localUDPConn 已经 Dial 到 SOCKS5 服务器的 UDP 地址了
			strTargetUDPAddr: address,      // 保存 Dial 时的最终目标地址
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

		//log.Printf("Successfully established SOCKS5 UDP proxy for %s. Using local UDP socket: %s", address, wrapper.LocalAddr())
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
	if c.Socks5Addr == "" {
		return nil, fmt.Errorf("empty server address")
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
		host, portStr, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("invalid address format: %w", err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %w", err)
		}

		socks5Conn, err := net.DialTimeout("tcp", c.Socks5Addr, timeout)
		if err != nil {
			return nil, fmt.Errorf("dial SOCKS5 server %s error: %w", c.Socks5Addr, err)
		}
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

// UDPConnWrapper 包装器，实现 net.Conn 接口，用于通过 SOCKS5 UDP 关联转发数据
type UDPConnWrapper struct {
	// 客户端底层的 SOCKS5 客户端实例
	client *Socks5Client
	// 与 SOCKS5 服务器的 TCP 控制连接
	serverTCPConn net.Conn
	// 客户端本地 UDP 监听，已 Dial 到 SOCKS5 服务器的 UDP 地址
	localUDPConn *net.UDPConn
	// 用户 Dial 时指定的最终 UDP 目标地址 (用于构建 SOCKS5 UDP 报头)
	strTargetUDPAddr  string
	targetUDPAddr     net.Addr
	onceRecv1stPacket sync.Once

	// 标记 UDPConnWrapper 是否已关闭
	closed         sync.Once
	lastPacketAddr string
}

// Read 从 UDPConnWrapper 中读取数据
func (u *UDPConnWrapper) Read(b []byte) (n int, err error) {
	// 1. 从 localUDPConn 读取完整的 SOCKS5 UDP 响应报文
	// 由于 localUDPConn 已 Dial 到 SOCKS5 服务器的 UDP 地址，
	// 其 Read 方法只会返回来自该地址的包。
	respBuf := make([]byte, 65535) // Buffer to receive full SOCKS5 UDP packet
	nResp, err := u.localUDPConn.Read(respBuf)
	if err != nil {
		return 0, fmt.Errorf("read from local UDP error: %w", err)
	}

	// 2. 解析 SOCKS5 UDP 响应报头
	if nResp < 10 { // Min SOCKS5 UDP header for IPv4
		return 0, fmt.Errorf("malformed SOCKS5 UDP response (too short): %d bytes", nResp)
	}

	// resp_rsv := respBuf[0:2]
	resp_frag := respBuf[2]
	resp_atyp := respBuf[3]
	if resp_frag != 0x00 {
		log.Printf("Warning: SOCKS5 UDP response fragmented. Not supported.")
	}

	responseOffset := 4
	var sourceIP net.IP
	var sourcePort int

	switch resp_atyp {
	case ATYP_IPV4:
		if nResp < responseOffset+4+2 {
			return 0, fmt.Errorf("malformed IPv4 SOCKS5 UDP response")
		}
		sourceIP = net.IPv4(respBuf[responseOffset], respBuf[responseOffset+1], respBuf[responseOffset+2], respBuf[responseOffset+3])
		responseOffset += 4
	case ATYP_IPV6:
		if nResp < responseOffset+16+2 {
			return 0, fmt.Errorf("malformed IPv6 SOCKS5 UDP response")
		}
		sourceIP = respBuf[responseOffset : responseOffset+16]
		responseOffset += 16
	case ATYP_DOMAINNAME:
		if nResp < responseOffset+1 {
			return 0, fmt.Errorf("malformed domain SOCKS5 UDP response (no length)")
		}
		domainLen := int(respBuf[responseOffset])
		responseOffset += 1
		if nResp < responseOffset+domainLen+2 {
			return 0, fmt.Errorf("malformed domain SOCKS5 UDP response (short data)")
		}
		sourceIP = net.ParseIP(string(respBuf[responseOffset : responseOffset+domainLen]))
		responseOffset += domainLen
	default:
		return 0, fmt.Errorf("unsupported ATYP in SOCKS5 UDP response: %d", resp_atyp)
	}
	sourcePort = int(respBuf[responseOffset])<<8 | int(respBuf[responseOffset+1])
	responseOffset += 2

	// 3. 将原始数据（剥离 SOCKS5 头部后的数据）复制到传入的 b 缓冲区
	dataLen := nResp - responseOffset
	if dataLen < 0 { // Should not happen with correct parsing
		return 0, fmt.Errorf("invalid SOCKS5 UDP response data length after parsing header")
	}
	if dataLen > len(b) {
		// 如果数据包大于用户提供的缓冲区，则截断
		n = copy(b, respBuf[responseOffset:responseOffset+len(b)])
		log.Printf("Warning: UDP response truncated. Packet size: %d, Buffer size: %d", dataLen, len(b))
	} else {
		n = copy(b, respBuf[responseOffset:nResp])
	}

	u.lastPacketAddr = net.JoinHostPort(sourceIP.String(), strconv.Itoa(sourcePort))
	if u.targetUDPAddr == nil {
		if resp_atyp != ATYP_DOMAINNAME {
			u.targetUDPAddr, _ = net.ResolveUDPAddr("udp", u.lastPacketAddr)
		}
	}
	u.onceRecv1stPacket.Do(func() {
		if u.targetUDPAddr != nil {
			log.Printf("UDP: %s<-%s (first inbound packet of session)", u.localUDPConn.LocalAddr().String(), u.targetUDPAddr.String())
		}
	})
	return n, nil
}

func (u *UDPConnWrapper) GetLastPacketRemoteAddr() string {
	return u.lastPacketAddr
}

// Write 将数据写入 UDPConnWrapper (内部会封装成 SOCKS5 UDP 数据报)
func (u *UDPConnWrapper) Write(b []byte) (n int, err error) {
	if u.localUDPConn == nil {
		return 0, fmt.Errorf("UDPConnWrapper is closed or not initialized")
	}
	targetAddr := ""
	if u.targetUDPAddr == nil {
		targetAddr = u.strTargetUDPAddr
	} else {
		targetAddr = u.targetUDPAddr.String()
	}
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return 0, fmt.Errorf("invalid target address: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf("invalid target port: %w", err)
	}

	addrBytes, atyp, err := parseHostPortToSocksAddr(host)
	if err != nil {
		return 0, fmt.Errorf("parse target host/port error: %w", err)
	}

	if atyp != ATYP_DOMAINNAME && u.targetUDPAddr == nil {
		u.targetUDPAddr, err = net.ResolveUDPAddr("udp", u.strTargetUDPAddr)
		if err != nil {
			return 0, fmt.Errorf("parse target host/port error: %w", err)
		}
	}

	// 构建 SOCKS5 UDP 数据报头
	socks5UdpHeader := []byte{
		SOCKS5_UDP_RSV >> 8, SOCKS5_UDP_RSV & 0xFF, // RSV
		0x00, // FRAG (Always 0 as we don't support fragmentation)
		atyp, // ATYP
	}
	socks5UdpHeader = append(socks5UdpHeader, addrBytes...)
	socks5UdpHeader = append(socks5UdpHeader, byte(port>>8), byte(port&0xFF))

	// 完整发送到 SOCKS5 服务器 UDP 端口的数据包
	fullUdpPacket := append(socks5UdpHeader, b...)

	// 通过已连接到 SOCKS5 服务器 UDP 地址的 localUDPConn 发送
	// localUDPConn 的 Write 方法会自动发送到 dialUDP 时绑定的远程地址
	_, err = u.localUDPConn.Write(fullUdpPacket) // 使用 Write 方法
	if err != nil {
		return 0, fmt.Errorf("send SOCKS5 UDP packet to server error: %w", err)
	}
	return len(b), nil // 返回写入的原始数据包长度
}

// Close 关闭 UDPConnWrapper，包括 TCP 控制连接和本地 UDP socket
func (u *UDPConnWrapper) Close() error {
	var err error
	u.closed.Do(func() {
		if u.serverTCPConn != nil {
			err = u.serverTCPConn.Close() // 关闭 TCP 控制连接
		}
		if u.localUDPConn != nil {
			err = u.localUDPConn.Close() // 关闭本地 UDP socket
		}
		// 不需要 u.wg.Wait()，因为不再有独立的 goroutine 需要等待
		log.Println("UDPConnWrapper closed.")
	})
	return err
}

// LocalAddr 返回本地 UDP socket 的地址
func (u *UDPConnWrapper) LocalAddr() net.Addr {
	if u.localUDPConn != nil {
		return u.localUDPConn.LocalAddr()
	}
	return nil
}

// RemoteAddr 返回 Dial 时指定的 UDP 目标地址
func (u *UDPConnWrapper) RemoteAddr() net.Addr {
	if u.targetUDPAddr != nil {
		return u.targetUDPAddr
	} else {
		return &net.UDPAddr{}
	}
}

// SetDeadline, SetReadDeadline, SetWriteDeadline 实现 net.Conn 接口
func (u *UDPConnWrapper) SetDeadline(t time.Time) error {
	if u.localUDPConn != nil {
		return u.localUDPConn.SetDeadline(t)
	}
	return nil
}
func (u *UDPConnWrapper) SetReadDeadline(t time.Time) error {
	if u.localUDPConn != nil {
		return u.localUDPConn.SetReadDeadline(t)
	}
	return nil
}
func (u *UDPConnWrapper) SetWriteDeadline(t time.Time) error {
	if u.localUDPConn != nil {
		return u.localUDPConn.SetWriteDeadline(t)
	}
	return nil
}

type AppS5SConfig struct {
	username string
	password string
}

// AppS5SConfigByArgs 解析给定的 []string 参数，生成 AppS5SConfig
func AppS5SConfigByArgs(args []string) (*AppS5SConfig, error) {
	config := &AppS5SConfig{}

	// 创建一个新的 FlagSet 实例
	fs := flag.NewFlagSet("AppS5SConfig", flag.ContinueOnError)

	var authString string // 用于接收 -auth 的值
	fs.StringVar(&authString, "auth", "", "Username and password for SOCKS5 authentication (format: user:pass)")

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
		config.username = authParts[0]
		config.password = authParts[1]
	}

	return config, nil
}

// App_s5s_usage_flagSet 接受一个 *flag.FlagSet 参数，用于打印其默认用法信息
func App_s5s_usage_flagSet(fs *flag.FlagSet) {
	fmt.Fprintln(os.Stderr, "-app-s5s Usage: [options]")
	fmt.Fprintln(os.Stderr, "\nOptions:")
	fs.PrintDefaults() // 打印所有定义的标志及其默认值和说明
	fmt.Fprintln(os.Stderr, "\nExample:")
	fmt.Fprintln(os.Stderr, "  -app-s5s -auth user:password")
}

func App_s5s_main_withconfig(conn net.Conn, config *AppS5SConfig) {
	defer conn.Close()

	s5config := Socks5ServerConfig{
		AuthenticateUser: nil,
	}
	if config.username != "" || config.password != "" {
		s5config.AuthenticateUser = func(username, password string) bool {
			return username == config.username && password == config.password
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

	if req.Command == "CONNECT" {
		err = handleDirectTCPConnect(conn, req.Host, req.Port)
		if err != nil {
			log.Printf("SOCKS5 TCP Connect failed for %s: %v", conn.RemoteAddr(), err)
		}
	} else if req.Command == "BIND" {
		err = handleTCPListen(conn, req.Host, req.Port)
		if err != nil {
			log.Printf("SOCKS5 TCP Listen failed for %s: %v", conn.RemoteAddr(), err)
		}
	} else if req.Command == "UDP" {
		fakeTunnelC, fakeTunnelS := net.Pipe()
		var wg sync.WaitGroup
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer c.Close()
			handleSocks5ClientOnStream(c)
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
