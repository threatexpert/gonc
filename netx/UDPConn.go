package netx

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

type BoundUDPConn struct {
	conn           net.PacketConn
	connmu         sync.Mutex
	supportRebuild bool
	remoteAddr     net.Addr
	keepOpen       bool
	closeChan      chan struct{}
	closeOnce      sync.Once // 保护closeChan
	connCloseOnce  sync.Once // 保护底层连接
	firstPacket    []byte    // 缓存的首包
	lastPacketAddr string

	lastActiveTime time.Time     // 最后一次收到合法数据的时间
	idleTimeout    time.Duration // 超时时间，0表示不启用
}

// NewBoundUDPConn 创建连接，remoteAddr为nil时允许任意源地址
func NewBoundUDPConn(conn net.PacketConn, raddr string, keepOpen bool) *BoundUDPConn {
	var remoteAddr net.Addr
	if raddr != "" {
		host, _, err := net.SplitHostPort(raddr)
		if err == nil {
			ip := net.ParseIP(host)
			if ip != nil {
				remoteAddr, _ = net.ResolveUDPAddr("udp", raddr)
			} else {
				remoteAddr = &NameUDPAddr{
					Net:     "name",
					Address: raddr,
				}
			}
		}
	}
	return &BoundUDPConn{
		conn:       conn,
		remoteAddr: remoteAddr,
		keepOpen:   keepOpen,
		closeChan:  make(chan struct{}),
	}
}

// SetIdleTimeout 设置最大空闲时间，如果超过这个时间没收到数据，则Read返回错误
func (b *BoundUDPConn) SetIdleTimeout(timeout time.Duration) {
	b.idleTimeout = timeout
}

// SetRemoteAddr 动态设置目标地址
func (b *BoundUDPConn) SetRemoteAddr(addr string) error {
	udpaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	b.remoteAddr = udpaddr
	return nil
}

func (b *BoundUDPConn) GetLastPacketRemoteAddr() string {
	return b.lastPacketAddr
}

func (b *BoundUDPConn) SetSupportRebuild(support bool) {
	b.supportRebuild = support
}

func (b *BoundUDPConn) Rebuild() (*net.UDPConn, error) {
	b.connmu.Lock()
	defer b.connmu.Unlock()

	if b.conn == nil {
		return nil, fmt.Errorf("connection is nil, cannot rebuild")
	}

	localAddr := b.conn.LocalAddr().(*net.UDPAddr)
	nw := localAddr.Network()

	b.conn.Close()

	c, e := net.ListenUDP(nw, localAddr)
	if e != nil {
		return nil, e
	}

	b.conn = c
	return c, nil
}

func (b *BoundUDPConn) Read(p []byte) (int, error) {
	select {
	case <-b.closeChan:
		return 0, io.EOF
	default:
	}

	// 处理首包
	if b.firstPacket != nil {
		n := copy(p, b.firstPacket)
		b.firstPacket = nil
		b.lastActiveTime = time.Now()
		return n, nil
	}

	for {
		if b.supportRebuild {
			b.connmu.Lock()
			if b.conn == nil {
				b.connmu.Unlock()
				return 0, fmt.Errorf("invalid conn object")
			}
		}
		b.conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, addr, err := b.conn.ReadFrom(p)
		if b.supportRebuild {
			b.connmu.Unlock()
		}
		switch {
		case err == nil:
			addrValid := false
			udpAddr, ok := addr.(*net.UDPAddr)
			if !ok {
				nameAddr, ok := addr.(*NameUDPAddr)
				if !ok {
					return 0, fmt.Errorf("received address is not a *net.UDPAddr or *NameUDPAddr, it's a %T", addr)
				} else {
					//域名的地址，这里就只判断端口，因为可能域名被解析为IP了
					addrValid = b.remoteAddr == nil || isSamePort(nameAddr.String(), b.remoteAddr.String())
				}
			} else {
				addrValid = b.remoteAddr == nil || isSameUDPAddress(udpAddr, b.remoteAddr)
			}
			if addrValid {
				b.lastPacketAddr = addr.String()
				b.lastActiveTime = time.Now() // 更新最后活动时间
				return n, nil
			}
			continue

		case isTimeout(err):
			if b.idleTimeout > 0 && !b.lastActiveTime.IsZero() {
				if time.Since(b.lastActiveTime) > b.idleTimeout {
					return 0, fmt.Errorf("idle timeout: no data received for %s", b.idleTimeout)
				}
			}
			select {
			case <-b.closeChan:
				return 0, io.EOF
			default:
				continue
			}

		default:
			return 0, err
		}
	}
}

// Write 发送数据（线程安全版）
func (b *BoundUDPConn) Write(p []byte) (int, error) {
	if b.remoteAddr == nil {
		return 0, fmt.Errorf("remote address not set")
	}
	return b.conn.WriteTo(p, b.remoteAddr)
}

func (b *BoundUDPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = b.Read(p)
	if err == nil {
		return n, b.remoteAddr, err
	}
	return 0, nil, err
}

func (b *BoundUDPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if b.remoteAddr == nil {
		return 0, fmt.Errorf("remote address not set")
	}

	if !isSameUDPAddress(addr, b.remoteAddr) {
		return 0, fmt.Errorf("cannot write to %s, only bound to %s", addr.String(), b.remoteAddr.String())
	}

	return b.conn.WriteTo(p, b.remoteAddr)
}

// CloseWrite 半关闭（保持不变）
func (b *BoundUDPConn) CloseWrite() error {
	b.closeOnce.Do(func() {
		close(b.closeChan)
	})
	return nil
}

// Close 全关闭（保持不变）
func (b *BoundUDPConn) Close() error {
	b.CloseWrite()
	b.connCloseOnce.Do(func() {
		if !b.keepOpen {
			b.conn.Close()
		}
	})
	return nil
}

// LocalAddr 返回本地地址
func (b *BoundUDPConn) LocalAddr() net.Addr {
	b.connmu.Lock()
	defer b.connmu.Unlock()

	if b.conn == nil {
		return nil
	}
	return b.conn.LocalAddr()
}

// RemoteAddr 返回绑定的远端地址
func (b *BoundUDPConn) RemoteAddr() net.Addr {
	return b.remoteAddr
}

// SetDeadline 设置读写超时
func (b *BoundUDPConn) SetDeadline(t time.Time) error {
	return b.conn.SetDeadline(t)
}

// SetReadDeadline 设置读超时
func (b *BoundUDPConn) SetReadDeadline(t time.Time) error {
	return b.conn.SetReadDeadline(t)
}

// SetWriteDeadline 设置写超时
func (b *BoundUDPConn) SetWriteDeadline(t time.Time) error {
	return b.conn.SetWriteDeadline(t)
}

type PacketConnWrapper struct {
	conn  net.Conn
	raddr net.Addr
}

func NewPacketConnWrapper(c net.Conn, r net.Addr) *PacketConnWrapper {
	return &PacketConnWrapper{
		conn:  c,
		raddr: r,
	}
}

func (d *PacketConnWrapper) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := d.conn.Read(b)
	return n, d.raddr, err
}

func (d *PacketConnWrapper) WriteTo(b []byte, addr net.Addr) (int, error) {
	return d.conn.Write(b)
}

func (d *PacketConnWrapper) Close() error {
	return d.conn.Close()
}

func (d *PacketConnWrapper) LocalAddr() net.Addr {
	return d.conn.LocalAddr()
}

func (d *PacketConnWrapper) SetDeadline(t time.Time) error {
	return d.conn.SetDeadline(t)
}

func (d *PacketConnWrapper) SetReadDeadline(t time.Time) error {
	return d.conn.SetReadDeadline(t)
}

func (d *PacketConnWrapper) SetWriteDeadline(t time.Time) error {
	return d.conn.SetWriteDeadline(t)
}

// ConnFromPacketConn 将一个 net.PacketConn 适配为 net.Conn 接口。
// 它会将所有 Write 操作都发送到固定的远端地址。
type ConnFromPacketConn struct {
	net.PacketConn
	SupportNameUDPAddr bool
	updateNameUDPAddr  bool
	remoteAddr         net.Addr
}

// NewConnFromPacketConn 创建一个 net.Conn，其通信被绑定到一个固定的远端地址。
func NewConnFromPacketConn(pc net.PacketConn, supportNameUDPAddr bool, raddr string) (*ConnFromPacketConn, error) {
	conn := &ConnFromPacketConn{
		PacketConn: pc,
	}
	err := conn.Config(supportNameUDPAddr, raddr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (c *ConnFromPacketConn) Config(supportNameUDPAddr bool, raddr string) error {
	var remoteAddr net.Addr
	if raddr != "" {
		host, _, err := net.SplitHostPort(raddr)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		if ip != nil {
			remoteAddr, err = net.ResolveUDPAddr("udp", raddr)
			if err != nil {
				return err
			}
		} else if supportNameUDPAddr {
			remoteAddr = &NameUDPAddr{
				Net:     "name",
				Address: raddr,
			}
		} else {
			return fmt.Errorf("invalid remote address: %s", raddr)
		}
	}
	c.updateNameUDPAddr = false
	c.SupportNameUDPAddr = supportNameUDPAddr
	c.remoteAddr = remoteAddr
	return nil
}

// Read 从连接中读取数据。它会忽略数据包的来源地址。
func (c *ConnFromPacketConn) Read(b []byte) (int, error) {
	// 调用底层的 ReadFrom，但忽略返回的 addr
	n, a, err := c.PacketConn.ReadFrom(b)
	if err == nil {
		if c.SupportNameUDPAddr && !c.updateNameUDPAddr {
			//第一个回复包，把NameUDPAddr的地址更新一下
			c.remoteAddr = a
			c.updateNameUDPAddr = true
		}
	}
	return n, err
}

// Write 将数据写入到固定的远端地址。
func (c *ConnFromPacketConn) Write(b []byte) (int, error) {
	if c.remoteAddr == nil {
		return 0, fmt.Errorf("remote address not set")
	}
	return c.PacketConn.WriteTo(b, c.remoteAddr)
}

// RemoteAddr 返回固定的远端地址。
func (c *ConnFromPacketConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func isSameUDPAddress(addr1, addr2 net.Addr) bool {
	daddr1, ok1 := addr1.(*net.UDPAddr)
	daddr2, ok2 := addr2.(*net.UDPAddr)
	if ok1 && ok2 {
		if !(daddr2.IP.Equal(daddr1.IP) && daddr2.Port == daddr1.Port) {
			return false
		}
	} else if addr1.String() != addr2.String() {
		return false
	}
	return true
}

func isSamePort(a, b string) bool {
	_, portA, errA := net.SplitHostPort(a)
	_, portB, errB := net.SplitHostPort(b)
	if errA != nil || errB != nil {
		return false // 无法解析就视为不一致
	}
	return portA == portB
}

func IsConnRefused(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		var sysErr *os.SyscallError
		if errors.As(opErr.Err, &sysErr) {
			return sysErr.Err == syscall.ECONNREFUSED
		}
		// 有些系统直接是 syscall.Errno
		if errno, ok := opErr.Err.(syscall.Errno); ok {
			return errno == syscall.ECONNREFUSED
		}
	}
	return false
}

// 判断是否是超时错误
func isTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}

// newTimeoutError (保持不变)
type timeoutError struct {
	op      string
	timeout bool
}

func (e *timeoutError) Error() string {
	return e.op + ": i/o timeout"
}

func (e *timeoutError) Timeout() bool {
	return e.timeout
}

func (e *timeoutError) Temporary() bool {
	return true
}

func newTimeoutError(op string, isTimeout bool) error {
	return &timeoutError{op: op, timeout: isTimeout}
}

type NameUDPAddr struct {
	Net     string // "name"
	Address string
}

func (a *NameUDPAddr) Network() string {
	return a.Net
}

func (a *NameUDPAddr) String() string {
	return a.Address
}
