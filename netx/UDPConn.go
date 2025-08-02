package netx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

type BoundUDPConn struct {
	conn           net.PacketConn
	connmu         sync.Mutex
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

func (b *BoundUDPConn) Rebuild() (*net.UDPConn, error) {
	localAddr := b.LocalAddr().(*net.UDPAddr)
	nw := localAddr.Network()

	b.connmu.Lock()
	defer b.connmu.Unlock()

	b.conn.Close()
	c, e := net.ListenUDP(nw, localAddr)
	b.conn = c
	return c, e
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
		b.connmu.Lock()
		if b.conn == nil {
			b.connmu.Unlock()
			return 0, fmt.Errorf("invalid conn object")
		}
		b.conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, addr, err := b.conn.ReadFrom(p)
		b.connmu.Unlock()

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

// ============================================================================
// UDPCustomConn 和 UDPCustomDialer 的定义和方法与之前完全相同
// 为了简洁，这里省略了它们的完整实现，假设它们已经包含了 CustomLogger 字段
// 并在 NewUDPCustomDialer 和 UDPCustomConn 构造时传入了 logger。
// ============================================================================

// UDPCustomConn 结构体定义 (省略大部分方法实现，只保留需要注入logger的部分)
type UDPCustomConn struct {
	dialer        *UDPCustomDialer
	remoteAddr    net.Addr
	readCh        chan []byte
	writeCh       chan []byte
	closeOnce     sync.Once
	closed        chan struct{}
	deadlineMu    sync.RWMutex
	readDeadline  time.Time
	writeDeadline time.Time
	logger        *log.Logger // 添加日志器字段
	localIP       net.IP
	// 用于被动连接的标志，表示这个连接是由Accept创建的
	accepted bool
}

func (c *UDPCustomConn) Read(b []byte) (n int, err error) {
	c.deadlineMu.RLock()
	readTimeout := c.readDeadline
	c.deadlineMu.RUnlock()

	var timer *time.Timer
	var timeoutCh <-chan time.Time

	if !readTimeout.IsZero() {
		duration := time.Until(readTimeout)
		if duration <= 0 {
			return 0, newTimeoutError("read", true)
		}
		timer = time.NewTimer(duration)
		timeoutCh = timer.C
	}

	select {
	case data := <-c.readCh:
		if timer != nil {
			timer.Stop()
		}
		n = copy(b, data)
		return n, nil
	case <-c.closed:
		if timer != nil {
			timer.Stop()
		}
		//c.logger.Printf("Read from %s closed due to conn close.", c.RemoteAddr().String())
		return 0, net.ErrClosed
	case <-timeoutCh:
		//c.logger.Printf("Read from %s timed out.", c.RemoteAddr().String())
		return 0, newTimeoutError("read", true)
	}
}

func (c *UDPCustomConn) Write(b []byte) (n int, err error) {
	c.deadlineMu.RLock()
	writeTimeout := c.writeDeadline
	c.deadlineMu.RUnlock()

	var timer *time.Timer
	var timeoutCh <-chan time.Time

	if !writeTimeout.IsZero() {
		duration := time.Until(writeTimeout)
		if duration <= 0 {
			return 0, newTimeoutError("write", true)
		}
		timer = time.NewTimer(duration)
		timeoutCh = timer.C
	}
	dataCopy := make([]byte, len(b))
	copy(dataCopy, b)
	select {
	case c.writeCh <- dataCopy:
		if timer != nil {
			timer.Stop()
		}
		return len(dataCopy), nil
	case <-c.closed:
		if timer != nil {
			timer.Stop()
		}
		c.logger.Printf("Write to %s closed due to conn close.", c.RemoteAddr().String())
		return 0, net.ErrClosed
	case <-timeoutCh:
		c.logger.Printf("Write to %s timed out.", c.RemoteAddr().String())
		return 0, newTimeoutError("write", true)
	}
}

func (c *UDPCustomConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.dialer.removeConn(c.remoteAddr.String(), c)
		c.logger.Printf("Custom UDP Conn to %s closed.", c.remoteAddr.String())
	})
	return nil
}

// LocalAddr returns the local address for this logical connection.
// It uses the derived local IP and the shared listener's port.
func (c *UDPCustomConn) LocalAddr() net.Addr {
	listenerUDPAddr, ok := c.dialer.conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		// Fallback if type assertion fails (shouldn't happen with net.ListenUDP)
		return c.dialer.conn.LocalAddr()
	}

	// Simplified Zone logic:
	// Only consider Zone if both the listener's IP and the derived localIP are IPv6,
	// and the listener's address explicitly has a zone (e.g., [::]%eth0).
	// For most global IP usages (IPv4 or IPv6), Zone will remain empty, which is correct.
	var zone string
	if listenerUDPAddr.IP.To4() == nil && c.localIP.To4() == nil && listenerUDPAddr.Zone != "" {
		zone = listenerUDPAddr.Zone
	}

	return &net.UDPAddr{
		IP:   c.localIP,
		Port: listenerUDPAddr.Port,
		Zone: zone, // Use the determined zone
	}
}

func (c *UDPCustomConn) RemoteAddr() net.Addr { return c.remoteAddr }
func (c *UDPCustomConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}
func (c *UDPCustomConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.readDeadline = t
	return nil
}
func (c *UDPCustomConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.writeDeadline = t
	return nil
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

// UDPCustomDialer 结构体定义 (省略大部分方法实现，只保留需要注入logger的部分)
type UDPCustomDialer struct {
	conn              net.PacketConn
	ownConn           bool
	conns             map[string][]*UDPCustomConn
	mu                sync.RWMutex
	maxPacketSize     int
	closed            chan struct{}
	wg                sync.WaitGroup
	logger            *log.Logger // 添加日志器字段
	acceptCh          chan net.Conn
	listenerCloseOnce sync.Once
	recentlyClosed    map[string]time.Time
	cleanupTicker     *time.Ticker
}

// NewUDPCustomDialer 创建一个新的 UDPCustomDialer。
func NewUDPCustomDialer(localUDPConn net.PacketConn, ownConn bool, maxPacketSize int, logger *log.Logger) (*UDPCustomDialer, error) {
	if localUDPConn == nil {
		return nil, fmt.Errorf("localUDPConn cannot be nil")
	}

	d := &UDPCustomDialer{
		conn:           localUDPConn,
		ownConn:        ownConn,
		conns:          make(map[string][]*UDPCustomConn),
		maxPacketSize:  maxPacketSize,
		closed:         make(chan struct{}),
		logger:         logger,                 // 注入日志器
		acceptCh:       make(chan net.Conn, 5), // 缓冲接受连接的通道
		recentlyClosed: make(map[string]time.Time),
		cleanupTicker:  time.NewTicker(30 * time.Second),
	}

	d.wg.Add(1)
	go d.readLoop()
	go d.cleanupRecentlyClosedLoop()
	d.logger.Printf("UDPCustomDialer initialized on %s", localUDPConn.LocalAddr().String())
	return d, nil
}

func (d *UDPCustomDialer) DialUDP(network string, remoteAddr *net.UDPAddr) (net.Conn, error) {
	if network != "udp" && network != "udp4" && network != "udp6" {
		return nil, fmt.Errorf("unsupported network type: %s", network)
	}
	if remoteAddr == nil {
		return nil, fmt.Errorf("remote address cannot be nil")
	}

	select {
	case <-d.closed:
		d.logger.Printf("Dialer closed, cannot dial.")
		return nil, net.ErrClosed
	default:
	}

	// Step 1: Use net.Dial to determine the actual local IP that would be used
	tmpConn, err := net.Dial(network, remoteAddr.String())
	if err != nil {
		d.logger.Printf("Failed to establish dummy connection to %s to determine local IP: %v", remoteAddr, err)
		// Fallback: If we can't determine the specific local IP, use the listener's IP
		// This might still be [::] or 0.0.0.0 if the listener is wildcard.
		// Or, you could return an error here if precise local IP is critical.
		listenerAddr := d.conn.LocalAddr().(*net.UDPAddr)
		d.logger.Printf("Falling back to listener's IP (%s) for custom connection local address.", listenerAddr.IP)
		return nil, fmt.Errorf("failed to determine local IP for outgoing connection: %w", err)
	}
	defer tmpConn.Close() // Close the temporary connection immediately

	// Get the local IP from the temporary connection
	localIP := tmpConn.LocalAddr().(*net.UDPAddr).IP

	remoteAddrStr := remoteAddr.String()

	d.mu.Lock()
	defer d.mu.Unlock()

	newConn := &UDPCustomConn{
		dialer:     d,
		remoteAddr: remoteAddr,
		readCh:     make(chan []byte, 100),
		writeCh:    make(chan []byte, 100),
		closed:     make(chan struct{}),
		logger:     d.logger, // 注入日志器
		localIP:    localIP,
		accepted:   false, // 这是主动拨号建立的连接
	}

	d.conns[remoteAddrStr] = append(d.conns[remoteAddrStr], newConn)
	d.logger.Printf("New Custom UDP Conn created for %s. LocalAddr will be %s:%d. Total conns for %s: %d",
		remoteAddrStr, localIP, d.conn.LocalAddr().(*net.UDPAddr).Port, remoteAddrStr, len(d.conns[remoteAddrStr]))

	d.wg.Add(1)
	go d.writeLoop(newConn)

	return newConn, nil
}

func (d *UDPCustomDialer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	if network != "udp" && network != "udp4" && network != "udp6" {
		return nil, fmt.Errorf("unsupported network type: %s", network)
	}

	select {
	case <-ctx.Done():
		d.logger.Printf("DialContext cancelled or timed out before address resolution: %v", ctx.Err())
		return nil, ctx.Err()
	case <-d.closed:
		d.logger.Printf("Dialer closed, cannot DialContext.")
		return nil, net.ErrClosed
	default:
	}

	addrCh := make(chan *net.UDPAddr, 1)
	errCh := make(chan error, 1)

	go func() {
		resolvedAddr, resolveErr := net.ResolveUDPAddr(network, address)
		if resolveErr != nil {
			errCh <- fmt.Errorf("failed to resolve UDP address %s: %w", address, resolveErr)
			return
		}
		addrCh <- resolvedAddr
	}()

	var remoteAddr *net.UDPAddr
	select {
	case <-ctx.Done():
		d.logger.Printf("DialContext cancelled or timed out during address resolution: %v", ctx.Err())
		return nil, ctx.Err()
	case addr := <-addrCh:
		remoteAddr = addr
	case err := <-errCh:
		return nil, err
	}

	return d.DialUDP(network, remoteAddr)
}

func (d *UDPCustomDialer) readLoop() {
	defer d.wg.Done()
	buffer := make([]byte, d.maxPacketSize)
	for {
		select {
		case <-d.closed:
			d.logger.Printf("UDPCustomDialer readLoop stopping due to dialer closed.")
			return
		default:
		}

		d.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, remoteAddr, err := d.conn.ReadFrom(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				//d.logger.Printf("Read from UDP timeout, continuing.")
				continue
			}
			if isMessageSizeError(err) {
				continue
			}
			d.logger.Printf("Error reading from UDP: %v", err)
			return
		}

		remoteAddrStr := remoteAddr.String()
		//d.logger.Printf("Received %d bytes from %s on shared UDPConn.", n, remoteAddrStr)

		d.mu.RLock()
		connsToNotify := d.conns[remoteAddrStr]
		d.mu.RUnlock()

		if len(connsToNotify) > 0 {
			dataCopy := append([]byte(nil), buffer[:n]...)
			for _, conn := range connsToNotify {
				select {
				case conn.readCh <- dataCopy:
				case <-conn.closed:
					d.logger.Printf("Skipping closed conn %s for %s", conn.RemoteAddr().String(), remoteAddrStr)
				}
			}
		} else {

			if closedAt, ok := d.recentlyClosed[remoteAddrStr]; ok {
				if time.Since(closedAt) < 10*time.Second {
					d.logger.Printf("Ignoring packet from %s as connection was recently closed (%v ago).", remoteAddrStr, time.Since(closedAt))
					continue
				}
			}

			// **核心修改：当没有匹配的连接时，尝试被动建立一个连接**
			d.logger.Printf("No custom connections found for received data from %s. Attempting to accept a new connection.", remoteAddrStr)

			// 模拟 net.Dial 来获取 localIP，虽然对于被动连接，localIP 通常是 listener 的 IP
			// 但为了和DialUDP行为一致，我们仍然尝试获取一个“有效”的 localIP
			var localIP net.IP
			listenerAddr := d.conn.LocalAddr().(*net.UDPAddr)
			if listenerAddr != nil {
				localIP = listenerAddr.IP
			} else {
				// 极端情况下的fallback
				tmpConn, err := net.Dial("udp", remoteAddr.String())
				if err == nil {
					localIP = tmpConn.LocalAddr().(*net.UDPAddr).IP
					tmpConn.Close()
				} else {
					d.logger.Printf("Warning: Could not determine local IP for new incoming connection from %s, using empty IP.", remoteAddrStr)
				}
			}

			newAcceptedConn := &UDPCustomConn{
				dialer:     d,
				remoteAddr: remoteAddr,
				readCh:     make(chan []byte, 100),
				writeCh:    make(chan []byte, 100),
				closed:     make(chan struct{}),
				logger:     d.logger,
				localIP:    localIP,
				accepted:   true, // 标记为被动接受的连接
			}

			// 将接收到的第一个包发送给新的连接
			dataCopy := append([]byte(nil), buffer[:n]...)
			select {
			case newAcceptedConn.readCh <- dataCopy:
				d.mu.Lock()
				d.conns[remoteAddrStr] = append(d.conns[remoteAddrStr], newAcceptedConn)
				d.mu.Unlock()
				d.wg.Add(1)
				go d.writeLoop(newAcceptedConn)

				select {
				case <-d.closed:
					d.logger.Printf("Dialer closed while trying to send new accepted conn to acceptCh for %s.", remoteAddrStr)
					newAcceptedConn.Close() // 关闭新连接
				case d.acceptCh <- newAcceptedConn:
					d.logger.Printf("Accepted new Custom UDP Conn from %s. Total conns for %s: %d",
						remoteAddrStr, remoteAddrStr, len(d.conns[remoteAddrStr]))
				default:
					d.logger.Printf("Accept channel is full, dropping new accepted conn from %s. Data dropped.", remoteAddrStr)
					newAcceptedConn.Close() // 关闭新连接
				}
			case <-newAcceptedConn.closed:
				d.logger.Printf("New accepted conn from %s closed before receiving first packet.", remoteAddrStr)
			default:
				d.logger.Printf("Read channel for new accepted conn from %s is full, dropping first packet.", remoteAddrStr)
				newAcceptedConn.Close() // 关闭新连接
			}
		}
	}
}

func (d *UDPCustomDialer) writeLoop(c *UDPCustomConn) {
	defer d.wg.Done()
	for {
		select {
		case data := <-c.writeCh:
			_, err := d.conn.WriteTo(data, c.remoteAddr)
			if err != nil {
				d.logger.Printf("Error writing to UDP for %s: %v", c.remoteAddr.String(), err)
			} else {
				//d.logger.Printf("Sent %d bytes to %s from %s on shared UDPConn.",
				//	len(data), c.remoteAddr.String(), c.LocalAddr().String())
			}
		case <-c.closed:
			d.logger.Printf("UDPCustomConn writeLoop for %s stopping due to conn closed.", c.remoteAddr.String())
			return
		case <-d.closed:
			d.logger.Printf("UDPCustomConn writeLoop for %s stopping due to dialer closed.", c.remoteAddr.String())
			return
		}
	}
}

func (d *UDPCustomDialer) removeConn(remoteAddrStr string, connToRemove *UDPCustomConn) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if conns, ok := d.conns[remoteAddrStr]; ok {
		d.recentlyClosed[remoteAddrStr] = time.Now()
		var updatedConns []*UDPCustomConn
		for _, conn := range conns {
			if conn != connToRemove {
				updatedConns = append(updatedConns, conn)
			}
		}
		if len(updatedConns) > 0 {
			d.conns[remoteAddrStr] = updatedConns
		} else {
			delete(d.conns, remoteAddrStr)
		}
		d.logger.Printf("Removed custom conn for %s. Remaining conns for %s: %d",
			remoteAddrStr, remoteAddrStr, len(d.conns[remoteAddrStr]))
	}
}

func (d *UDPCustomDialer) Close() error {
	d.logger.Printf("Closing UDPCustomDialer...")
	select {
	case <-d.closed:
		return net.ErrClosed
	default:
	}

	d.listenerCloseOnce.Do(func() {
		close(d.closed)
	})

	d.mu.Lock()
	var allConns []*UDPCustomConn
	for _, conns := range d.conns {
		allConns = append(allConns, conns...)
	}
	d.conns = make(map[string][]*UDPCustomConn)
	d.mu.Unlock()

	// 此处已经释放锁了，所以不会死锁
	for _, conn := range allConns {
		conn.Close()
	}

	var err error
	if d.ownConn {
		err := d.conn.Close()
		if err != nil {
			d.logger.Printf("Error closing underlying UDPConn: %v", err)
		}
	}

	d.wg.Wait()

	for {
		select {
		case conn := <-d.acceptCh:
			conn.Close()
		default:
			goto END
		}
	}
END:
	d.logger.Printf("UDPCustomDialer closed successfully.")
	return err
}

func (d *UDPCustomDialer) cleanupRecentlyClosedLoop() {
	for {
		select {
		case <-d.cleanupTicker.C:
			now := time.Now()
			d.mu.Lock()
			for addr, t := range d.recentlyClosed {
				if now.Sub(t) > 10*time.Second {
					delete(d.recentlyClosed, addr)
				}
			}
			d.mu.Unlock()
		case <-d.closed:
			d.cleanupTicker.Stop()
			return
		}
	}
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

// UDPCustomListener 结构体，模仿 net.Listener
type UDPCustomListener struct {
	dialer *UDPCustomDialer
	addr   net.Addr
}

// NewUDPCustomListener 创建并返回一个 UDPCustomListener。
// localAddr 是监听地址，例如 "udp://:8080"
func NewUDPCustomListener(localUDPConn *net.UDPConn, logger *log.Logger) (*UDPCustomListener, error) {

	dialer, err := NewUDPCustomDialer(localUDPConn, false, 4096, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDPCustomDialer: %w", err)
	}

	return &UDPCustomListener{
		dialer: dialer,
		addr:   localUDPConn.LocalAddr(),
	}, nil
}

// Accept 实现了 net.Listener 接口的 Accept 方法。
// 它会阻塞直到有一个新的入站连接被建立。
func (l *UDPCustomListener) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-l.dialer.acceptCh:
		if !ok {
			// acceptCh 已关闭，表示监听器已关闭
			return nil, net.ErrClosed
		}
		l.dialer.logger.Printf("Accepted new incoming UDP connection from %s.", conn.RemoteAddr().String())
		return conn, nil
	case <-l.dialer.closed:
		return nil, net.ErrClosed
	}
}

// Close 实现了 net.Listener 接口的 Close 方法。
// 它关闭底层的 UDPCustomDialer 和 UDPConn。
func (l *UDPCustomListener) Close() error {
	l.dialer.logger.Printf("Closing UDPCustomListener on %s...", l.addr.String())
	err := l.dialer.Close()
	if err != nil {
		l.dialer.logger.Printf("Error closing UDPCustomDialer: %v", err)
	}
	l.dialer.logger.Printf("UDPCustomListener on %s closed.", l.addr.String())
	return err
}

// Addr 返回监听器的本地网络地址。
func (l *UDPCustomListener) Addr() net.Addr {
	return l.addr
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
