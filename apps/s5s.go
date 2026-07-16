package apps

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/threatexpert/gonc/v2/acl"
	"github.com/threatexpert/gonc/v2/misc"
	"github.com/threatexpert/gonc/v2/netx"
	"github.com/threatexpert/gonc/v2/secure"
)

// VERSION 1.1.0 (Refactored)

type AppS5SConfig struct {
	Logger         *log.Logger
	Username       string
	Password       string
	EnableConnect  bool
	EnableUDP      bool
	EnableBind     bool
	Localbind      []string
	ServerIP       string
	AccessCtrl     *acl.ACL
	EnableSocks5   bool
	EnableHTTP     bool
	UpstreamProxy  string
	UpstreamClient *ProxyClient
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
	fs.StringVar(&config.UpstreamProxy, "x", "", "Upstream proxy chain for TCP CONNECT only (URL format, comma-separated)")
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

	if config.UpstreamProxy != "" {
		localAddr, err := resolveS5SFirstHopLocalAddr(config.Localbind)
		if err != nil {
			return nil, fmt.Errorf("invalid -local for -x first hop: %w", err)
		}
		config.UpstreamClient, err = ParseProxyChainURLWithLocalAddr(logWriter, config.UpstreamProxy, localAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid upstream proxy chain: %w", err)
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
func resolveS5SFirstHopLocalAddr(localbind []string) (net.Addr, error) {
	for _, ip := range localbind {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		return net.ResolveTCPAddr("tcp", net.JoinHostPort(ip, "0"))
	}
	return nil, nil
}

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

type AppS5CConfig struct {
	*AppNetcatConfig
}

func AppS5CConfigByArgs(logWriter io.Writer, args []string) (*AppS5CConfig, error) {
	config := &AppS5CConfig{}

	var err error
	config.AppNetcatConfig, err = AppNetcatConfigByArgs(logWriter, ":s5c", args)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func IPFromAddr(addr net.Addr) (net.IP, error) {
	if addr == nil {
		return nil, errors.New("nil addr")
	}

	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP, nil
	case *net.TCPAddr:
		return a.IP, nil
	case *net.IPAddr:
		return a.IP, nil
	default:
		return nil, fmt.Errorf("unsupported addr type: %T", addr)
	}
}

// App_s5c_main_withconfig 客户端入口
func App_s5c_main_withconfig(connL net.Conn, keyingMaterial [32]byte, ncconfig *AppS5CConfig, stats_in, stats_out *misc.ProgressStats) int {
	defer connL.Close()

	var connR net.Conn
	var err error

	// 1. 初始化 ProxyClient
	proxyClient, err := NewProxyClient(ncconfig.arg_proxyc_Config)
	if err != nil {
		ncconfig.Logger.Printf("Error create proxy client: %v\n", err)
		return 1
	}

	// 2. 准备本地绑定地址 (如果有)
	var localAddr net.Addr
	if ncconfig.localbind != "" {
		switch {
		case strings.HasPrefix(ncconfig.network, "tcp"):
			localAddr, err = net.ResolveTCPAddr(ncconfig.network, ncconfig.localbind)
		case strings.HasPrefix(ncconfig.network, "udp"):
			localAddr, err = net.ResolveUDPAddr(ncconfig.network, ncconfig.localbind)
		}
		if err != nil {
			ncconfig.Logger.Printf("Error resolving address: %v\n", err)
			return 1
		}
	}

	// 3. 连接远程服务器 (connR)
	targetAddr := net.JoinHostPort(ncconfig.host, ncconfig.port)
	if localAddr == nil {
		dialTimeout := 20 * time.Second
		if ncconfig.dialreadTimeout != 0 {
			dialTimeout = time.Duration(ncconfig.dialreadTimeout) * time.Second
		}
		connR, err = proxyClient.DialTimeout(ncconfig.network, targetAddr, dialTimeout)
	} else {
		dialer := &net.Dialer{LocalAddr: localAddr}
		switch {
		case strings.HasPrefix(ncconfig.network, "tcp"):
			dialer.Control = netx.ControlTCP
		case strings.HasPrefix(ncconfig.network, "udp"):
			dialer.Control = netx.ControlUDP
		}
		if ncconfig.dialreadTimeout != 0 {
			dialer.Timeout = time.Duration(ncconfig.dialreadTimeout) * time.Second
		}
		connR, err = dialer.Dial(ncconfig.network, targetAddr)
	}

	if err != nil {
		ncconfig.Logger.Printf("Error: %v\n", err)
		return 1
	}
	defer connR.Close()

	// 4. 打印连接日志
	onTip := fmt.Sprintf("Connected to: %s", targetAddr)
	offTip := fmt.Sprintf("Disconnected from: %s", targetAddr)
	ncconfig.Logger.Printf("%s\n", onTip)
	if ncconfig.verboseWithTime {
		defer ncconfig.Logger.Printf("%s\n", offTip)
	}

	// 5. 执行安全协商 (加密握手)
	nconnR, err := secure.DoNegotiationContext(ncconfig.ctx, ncconfig.connConfig, connR, ncconfig.Logger)
	if err != nil {
		return 1
	}
	defer nconnR.Close()

	if ncconfig.remoteCall != "" {
		_, err = nconnR.Write([]byte(ncconfig.remoteCall + "\n"))
		if err != nil {
			ncconfig.Logger.Printf("Error Sending: %v\n", err)
			return 1
		}
	}

	if ncconfig.framedStdio {
		connL = netx.NewFramedConn(connL, connL)
		defer connL.Close()
	}

	// 设置握手阶段的超时
	connL.SetReadDeadline(time.Now().Add(25 * time.Second))
	nconnR.SetReadDeadline(time.Now().Add(25 * time.Second))

	// =========================================================================
	// SOCKS5 协议监控与分流
	// =========================================================================
	// 我们需要在这里手动处理 SOCKS5 的握手阶段，以便识别是 UDP 还是 TCP 请求

	buf := make([]byte, 512)

	// --- 第一阶段：SOCKS5 认证协商 ---
	// Client -> [VER, NMETHODS, METHODS...]
	n, err := connL.Read(buf)
	if err != nil {
		return 1
	}
	// 转发给服务器
	_, err = nconnR.Write(buf[:n])
	if err != nil {
		return 1
	}

	// Server -> [VER, METHOD]
	n, err = nconnR.Read(buf)
	if err != nil {
		return 1
	}

	method := buf[1] // 获取选定的认证方式
	// 转发给客户端
	_, err = connL.Write(buf[:n])
	if err != nil {
		return 1
	}

	// --- 关键修正：处理认证子协议 ---
	if method != 0x00 { //
		// 1. 读取客户端发的 Username/Password 报文
		n, err = connL.Read(buf)
		if err != nil {
			return 1
		}
		// 2. 转发给远程服务器
		nconnR.Write(buf[:n])
		// 3. 读取服务器返回的认证结果 (0x01 0x00 表示成功)
		n, err = nconnR.Read(buf)
		if err != nil {
			return 1
		}
		// 4. 转发回客户端
		connL.Write(buf[:n])
		// 只有认证通过后，客户端才会发送真正的 Request (CMD 0x03)
		if buf[1] != 0x00 {
			// 认证失败，将结果原样回传给客户端后断开
			return 1
		}
	}

	// --- 第二阶段：SOCKS5 请求 (Request) ---
	// Client -> [VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT]
	n, err = connL.Read(buf)
	if err != nil {
		return 1
	}

	// 解析 CMD (SOCKS5 的第二个字节是 Command, 0x01=CONNECT, 0x03=UDP ASSOCIATE)
	if n > 2 && buf[0] == 0x05 && buf[1] == 0x03 {
		// >>> 检测到 UDP ASSOCIATE 请求 <<<
		// 将 UDP 处理逻辑移交给专用函数，保持主函数整洁
		return handleUDPProxy(connL, keyingMaterial, nconnR, ncconfig, buf[:n], localAddr, stats_in, stats_out)
	}

	// >>> 非 UDP 请求 (如 CONNECT) <<<
	// 将读取的这部分 TCP 握手数据写入远程，然后进入标准转发模式
	_, err = nconnR.Write(buf[:n])
	if err != nil {
		return 1
	}

	// 7. 进入 TCP 双向转发 (Keep-Alive)
	// 恢复 Deadline，bidirectionalCopy 内部通常会处理心跳或长期连接
	connL.SetReadDeadline(time.Time{})
	nconnR.SetReadDeadline(time.Time{})

	bidirectionalCopy(connL, nconnR)
	return 0
}

// handleUDPProxy 处理 SOCKS5 UDP ASSOCIATE 逻辑
// 参数:
//
//	connL: 本地 TCP 连接
//	nconnR: 已经建立好加密通道的远程 TCP 连接
//	reqData: 已经从 connL 读取到的 SOCKS5 请求头数据
//	localBindAddr: 用于建立 UDP 连接的本地绑定地址（可为 nil）
func handleUDPProxy(connL net.Conn, keyingMaterial [32]byte, nconnR *secure.NegotiatedConn, ncconfig *AppS5CConfig, reqData []byte, localBindAddr net.Addr, stats_in, stats_out *misc.ProgressStats) int {
	ncconfig.Logger.Println("Detected SOCKS5 UDP ASSOCIATE request ...")

	// 1. 将请求原样转发给服务器 (因为需要服务器在远端准备 UDP 资源)
	_, err := nconnR.Write(reqData)
	if err != nil {
		return 1
	}

	// 2. 读取服务器的 SOCKS5 响应 (获取远端映射的 IP:Port)
	bindAddr, err := readSocks5Response(nconnR)
	if err != nil {
		return 1
	}

	// 解析服务器返回的地址，如果是私有 IP 或 0.0.0.0，则替换为 nconnR 的远程 IP
	bindAddrIP, _ := IPFromAddr(bindAddr)
	serverUDPAddr := &net.UDPAddr{IP: bindAddrIP, Port: bindAddr.Port}

	if serverUDPAddr.IP.IsUnspecified() || serverUDPAddr.IP.IsPrivate() {
		serverUDPAddr.IP, _ = IPFromAddr(nconnR.RemoteAddr())
	}

	// 3. 准备本地 UDP 监听 (模拟服务器行为，接收客户端的 UDP 包)
	localIP, _ := IPFromAddr(connL.LocalAddr())
	localUDPConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: localIP, Port: 0})
	if err != nil {
		ncconfig.Logger.Printf("Error starting local UDP: %v\n", err)
		return 1
	}
	defer localUDPConn.Close()

	// 获取本地监听的端口，用于告知客户端
	lAddr := localUDPConn.LocalAddr().(*net.UDPAddr)
	ncconfig.Logger.Printf("Local UDP listening at: %v, Forwarding to remote: %v\n", lAddr, serverUDPAddr)

	// 4. 构造 SOCKS5 回复包并发送给客户端
	// 构造标准 IPv4 回复: [05 00 00 01 IP(4) Port(2)]
	replyBuf := make([]byte, 10)
	replyBuf[0] = 5
	replyBuf[3] = 0x01 // 强制设为 IPv4
	copy(replyBuf[4:8], lAddr.IP.To4())
	binary.BigEndian.PutUint16(replyBuf[8:10], uint16(lAddr.Port))

	_, err = connL.Write(replyBuf)
	if err != nil {
		return 1
	}

	var pktConnLocal net.PacketConn
	var pktConnRemoteTalker net.PacketConn

	pktConnLocal = localUDPConn

	if keyingMaterial != [32]byte{} {
		pktConnLocal, err = secure.NewSecureUDPConn(localUDPConn, keyingMaterial)
		if err != nil {
			return 1
		}
		defer pktConnLocal.Close()
	}

	// 5. 建立加密的 UDP 发送通道 (用于与服务器通信)
	// 使用 ephemeral UDP socket
	bindIP, _ := IPFromAddr(localBindAddr)
	remoteTalkerUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindIP, Port: 0})
	if err != nil {
		return 1
	}
	defer remoteTalkerUDP.Close()

	pktConnRemoteTalker = remoteTalkerUDP

	if nconnR.KeyingMaterial != [32]byte{} {
		// 使用 nconnR 的密钥材料创建加密 UDP 连接
		pktConnRemoteTalker, err = secure.NewSecureUDPConn(remoteTalkerUDP, nconnR.KeyingMaterial)
		if err != nil {
			ncconfig.Logger.Printf("Error creating secure UDP: %v\n", err)
			return 1
		}
		defer pktConnRemoteTalker.Close()
	}

	// 6. 启动 UDP 数据转发循环
	// 记录客户端的地址，因为 SOCKS5 UDP Associate 通常是 1 对 1 的会话
	var clientAddr net.Addr

	// 用于监控 TCP 连接断开的信号
	done := make(chan struct{})
	var once sync.Once
	var wg sync.WaitGroup

	wg.Add(4)

	closeDone := func() {
		once.Do(func() {
			close(done)
			// 强制唤醒 ReadFrom
			_ = pktConnLocal.Close()
			_ = pktConnRemoteTalker.Close()
			connL.Close()
			nconnR.Close()
		})
	}
	// 开始转发数据， stats_in stats_out不涉及与socks5服务器间的流量统计

	// 协程 A: 本地 App (明文) -> pktConnLocal -> 加密 -> 服务器
	go func() {
		defer wg.Done()
		defer closeDone() // 任何一方退出，关闭 done
		udpBuf := make([]byte, 65535)
		for {
			rn, rAddr, err := pktConnLocal.ReadFrom(udpBuf)
			if err != nil {
				break
			}
			stats_in.Update(int64(rn))

			// 记录当前向我们要数据的客户端地址，以便回包时使用
			if clientAddr == nil {
				clientAddr = rAddr
			}

			// SOCKS5 UDP 数据包结构: [RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT DATA]
			// 我们不需要解析它，直接作为 payload 加密发送给服务器对应的 UDP 端口
			_, err = pktConnRemoteTalker.WriteTo(udpBuf[:rn], serverUDPAddr)
			if err != nil {
				break
			}
		}
	}()

	// 协程 B: 服务器 (加密) -> pktConnRemoteTalker -> 解密 -> pktConnLocal -> 本地 App
	go func() {
		defer wg.Done()
		defer closeDone()
		udpBuf := make([]byte, 65535)
		for {
			rn, _, err := pktConnRemoteTalker.ReadFrom(udpBuf)
			if err != nil {
				break
			}

			// 如果我们知道客户端是谁，就转发回去
			if clientAddr != nil {
				_, err = pktConnLocal.WriteTo(udpBuf[:rn], clientAddr)
				if err != nil {
					break
				}
				stats_out.Update(int64(rn))
			}

		}
	}()

	connL.SetReadDeadline(time.Time{})
	nconnR.SetReadDeadline(time.Time{})
	// 7. 保持 TCP 连接 (Keep-Alive)
	// 对于 UDP Associate，TCP 连接不应该有数据，或断开，异常意味着 UDP 会话结束
	waitTCP := func(c net.Conn) {
		defer wg.Done()
		defer closeDone()
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
		c.Close()
	}
	go waitTCP(connL)
	go waitTCP(nconnR)

	<-done
	wg.Wait()
	return 0
}
