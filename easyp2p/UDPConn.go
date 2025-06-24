package easyp2p

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
	conn           *net.UDPConn
	remoteAddr     *net.UDPAddr
	keepOpen       bool
	closeChan      chan struct{}
	closeOnce      sync.Once // 保护closeChan
	connCloseOnce  sync.Once // 保护底层连接
	firstPacket    []byte    // 缓存的首包
	lastPacketAddr string
}

// NewBoundUDPConn 创建连接，remoteAddr为nil时允许任意源地址
func NewBoundUDPConn(conn *net.UDPConn, raddr string, keepOpen bool) *BoundUDPConn {
	var udpaddr *net.UDPAddr
	var err error
	if raddr != "" {
		udpaddr, err = net.ResolveUDPAddr("udp", raddr)
		if err != nil {
			return nil
		}
	}
	return &BoundUDPConn{
		conn:       conn,
		remoteAddr: udpaddr,
		keepOpen:   keepOpen,
		closeChan:  make(chan struct{}),
	}
}

// WaitAndLockRemote 阻塞接收首个包并锁定源地址
func (b *BoundUDPConn) WaitAndLockRemote() error {
	b.conn.SetReadDeadline(time.Time{})
	buf := make([]byte, 65507)
	n, addr, err := b.conn.ReadFromUDP(buf)
	if err != nil {
		return err
	}

	b.remoteAddr = addr
	b.firstPacket = buf[:n]
	return nil
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

func (b *BoundUDPConn) Read(p []byte) (int, error) {
	// 1. 检查关闭状态
	select {
	case <-b.closeChan:
		return 0, io.EOF
	default:
	}

	// 2. 返回缓存的第一个包
	if b.firstPacket != nil {
		n := copy(p, b.firstPacket)
		b.firstPacket = nil
		return n, nil
	}

	// 3. 正常读取流程
	for {
		b.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := b.conn.ReadFromUDP(p)

		switch {
		case err == nil:
			addrValid := b.remoteAddr == nil ||
				(addr.IP.Equal(b.remoteAddr.IP) && addr.Port == b.remoteAddr.Port)

			if addrValid {
				b.lastPacketAddr = addr.String()
				return n, nil
			}
			continue

		case isTimeout(err):
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
	return b.conn.WriteToUDP(p, b.remoteAddr)
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
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
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

	select {
	case c.writeCh <- b:
		if timer != nil {
			timer.Stop()
		}
		return len(b), nil
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

// UDPCustomDialer 结构体定义 (省略大部分方法实现，只保留需要注入logger的部分)
type UDPCustomDialer struct {
	conn          *net.UDPConn
	conns         map[string][]*UDPCustomConn
	mu            sync.RWMutex
	maxPacketSize int
	closed        chan struct{}
	wg            sync.WaitGroup
	logger        *log.Logger // 添加日志器字段
}

// NewUDPCustomDialer 创建一个新的 UDPCustomDialer。
func NewUDPCustomDialer(localUDPConn *net.UDPConn, maxPacketSize int, logger *log.Logger) (*UDPCustomDialer, error) {
	if localUDPConn == nil {
		return nil, fmt.Errorf("localUDPConn cannot be nil")
	}

	d := &UDPCustomDialer{
		conn:          localUDPConn,
		conns:         make(map[string][]*UDPCustomConn),
		maxPacketSize: maxPacketSize,
		closed:        make(chan struct{}),
		logger:        logger, // 注入日志器
	}

	d.wg.Add(1)
	go d.readLoop()
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
		n, remoteAddr, err := d.conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				//d.logger.Printf("Read from UDP timeout, continuing.")
				continue
			}
			if err.Error() == "use of closed network connection" {
				d.logger.Printf("Underlying UDP connection closed, stopping readLoop.")
				return
			}
			//d.logger.Printf("Error reading from UDP: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
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
				default:
					d.logger.Printf("Read channel for conn %s to %s is full, dropping packet.",
						conn.RemoteAddr().String(), remoteAddrStr)
				}
			}
		} else {
			d.logger.Printf("No custom connections found for received data from %s. Data dropped.", remoteAddrStr)
		}
	}
}

func (d *UDPCustomDialer) writeLoop(c *UDPCustomConn) {
	defer d.wg.Done()
	for {
		select {
		case data := <-c.writeCh:
			_, err := d.conn.WriteToUDP(data, c.remoteAddr.(*net.UDPAddr))
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

	close(d.closed)

	d.mu.Lock()
	for _, conns := range d.conns {
		for _, conn := range conns {
			conn.Close()
		}
	}
	d.conns = make(map[string][]*UDPCustomConn)
	d.mu.Unlock()

	err := d.conn.Close()
	if err != nil {
		d.logger.Printf("Error closing underlying UDPConn: %v", err)
	}

	d.wg.Wait()
	d.logger.Printf("UDPCustomDialer closed successfully.")
	return err
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
