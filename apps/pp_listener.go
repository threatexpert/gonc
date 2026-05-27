package apps

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/threatexpert/gonc/v2/netx"
)

const (
	// 上游不发头/慢/坏头时的最长容忍时间，避免 Accept loop 被单连接拖死。
	ppReadHeaderTimeout = 10 * time.Second
	// PROXY v1 单行 ASCII 上限，按 spec 是 107 字节。
	ppV1MaxLineLen = 107
)

// PPListener 在 Accept 中对每个连入 conn 解析并剥离 PROXY protocol（v1 或 v2）头部。
// 严格模式：上游不发头或头部非法直接关闭该连接（Accept 返回错误）。
//
// 用法：listener = NewPPListener(rawListener)
//
// 返回的 net.Conn 会把 RemoteAddr() / LocalAddr() 替换为 PROXY 头里宣告的真实地址，
// 使得所有后续基于 conn.RemoteAddr() 的代码（ACL / mux session / business logic）
// 自动看到真实客户端 IP。
type PPListener struct {
	net.Listener
}

func NewPPListener(inner net.Listener) net.Listener {
	return &PPListener{Listener: inner}
}

func (l *PPListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		wrapped, werr := wrapPPConn(c, ppReadHeaderTimeout)
		if werr != nil {
			// 严格模式：丢弃这条连接，让上层进入下一轮 Accept
			// 调用方通常希望 Accept loop 继续，所以不向上抛 error，
			// 否则一次坏头就把 listener 关掉了。
			_ = c.Close()
			continue
		}
		return wrapped, nil
	}
}

// ppConn override RemoteAddr/LocalAddr，其余方法透传给底层 conn。
type ppConn struct {
	net.Conn         // 已经把 PROXY 头字节消费/缓冲处理后的 conn
	remote   net.Addr
	local    net.Addr
}

func (c *ppConn) RemoteAddr() net.Addr { return c.remote }
func (c *ppConn) LocalAddr() net.Addr  { return c.local }

// wrapPPConn 读完 PROXY 头（v1 或 v2，自动识别），返回 *ppConn。
// timeout 控制读头的最长等待，避免无头/慢上游拖累整个 Accept loop。
func wrapPPConn(c net.Conn, timeout time.Duration) (net.Conn, error) {
	// 给读头部设个 deadline
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	defer c.SetReadDeadline(time.Time{})

	bc := netx.NewBufferedConn(c)

	// 先 peek 12 字节看 v2 magic。Peek 不会消费字节；
	// 如果不足 12 字节（例如客户端发了 6 字节就停了），Peek 会阻塞/超时。
	head, err := bc.Reader.Peek(12)
	if err != nil {
		return nil, fmt.Errorf("pp: read header prefix: %w", err)
	}

	// v2 路径：完全匹配 12 字节 magic
	if bytes.Equal(head, proxyV2Sig) {
		raw, src, dst, perr := ReadProxyV2Header(bc)
		_ = raw // 在 listener 侧不需要原样转发，丢弃即可
		if perr != nil {
			return nil, fmt.Errorf("pp v2 parse: %w", perr)
		}
		remote := pickRemoteAddr(c, src)
		local := pickLocalAddr(c, dst)
		return &ppConn{Conn: bc.DiscardAndUnwrap(), remote: remote, local: local}, nil
	}

	// v1 路径：以 ASCII "PROXY " 起头
	if len(head) >= 6 && string(head[:6]) == "PROXY " {
		src, dst, lineLen, perr := readProxyV1Line(bc)
		_ = lineLen
		if perr != nil {
			return nil, fmt.Errorf("pp v1 parse: %w", perr)
		}
		remote := pickRemoteAddr(c, src)
		local := pickLocalAddr(c, dst)
		return &ppConn{Conn: bc.DiscardAndUnwrap(), remote: remote, local: local}, nil
	}

	return nil, fmt.Errorf("pp: no PROXY protocol header from %s", c.RemoteAddr())
}

func pickRemoteAddr(c net.Conn, parsed *net.TCPAddr) net.Addr {
	if parsed == nil {
		return c.RemoteAddr() // v2 LOCAL 命令或 v1 UNKNOWN 时退回 TCP 对端
	}
	return parsed
}

func pickLocalAddr(c net.Conn, parsed *net.TCPAddr) net.Addr {
	if parsed == nil {
		return c.LocalAddr()
	}
	return parsed
}

// readProxyV1Line 读到 "\r\n" 为止，解析 PROXY v1 单行。返回 src/dst (UNKNOWN/解析失败时 nil)、消费字节数。
// 形式：
//   "PROXY TCP4 1.2.3.4 5.6.7.8 12345 80\r\n"
//   "PROXY TCP6 ::1 ::1 12345 80\r\n"
//   "PROXY UNKNOWN\r\n"   或   "PROXY UNKNOWN ...任意... \r\n"
func readProxyV1Line(bc *netx.BufferedConn) (src, dst *net.TCPAddr, n int, err error) {
	// 用 ReadSlice('\n') 拿到包含 \n 的整行
	line, rerr := bc.Reader.ReadSlice('\n')
	if rerr != nil {
		return nil, nil, 0, fmt.Errorf("read v1 line: %w", rerr)
	}
	if len(line) > ppV1MaxLineLen {
		return nil, nil, 0, fmt.Errorf("v1 line too long: %d", len(line))
	}
	n = len(line)
	// 去掉尾部 \r\n
	s := strings.TrimRight(string(line), "\r\n")
	if !strings.HasPrefix(s, "PROXY ") {
		return nil, nil, n, fmt.Errorf("v1 line bad prefix")
	}
	parts := strings.Fields(s)
	// "PROXY UNKNOWN[...任意]" → 仅返回 nil/nil
	if len(parts) >= 2 && parts[1] == "UNKNOWN" {
		return nil, nil, n, nil
	}
	// 标准格式: PROXY <fam> <src> <dst> <sport> <dport>
	if len(parts) != 6 {
		return nil, nil, n, fmt.Errorf("v1 line bad fields: %d", len(parts))
	}
	fam := parts[1]
	if fam != "TCP4" && fam != "TCP6" {
		return nil, nil, n, fmt.Errorf("v1 unsupported family: %s", fam)
	}
	srcIP := net.ParseIP(parts[2])
	dstIP := net.ParseIP(parts[3])
	if srcIP == nil || dstIP == nil {
		return nil, nil, n, fmt.Errorf("v1 invalid IP")
	}
	sp, err1 := strconv.Atoi(parts[4])
	dp, err2 := strconv.Atoi(parts[5])
	if err1 != nil || err2 != nil || sp <= 0 || sp > 65535 || dp <= 0 || dp > 65535 {
		return nil, nil, n, fmt.Errorf("v1 invalid port")
	}
	src = &net.TCPAddr{IP: srcIP, Port: sp}
	dst = &net.TCPAddr{IP: dstIP, Port: dp}
	return src, dst, n, nil
}
