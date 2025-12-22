package netx

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// 1. 内存池与引用计数 (核心优化: 零分配 + 1对多广播)
// ============================================================================

// bufferPool 复用底层数据存储 []byte
var bufferPool = sync.Pool{
	New: func() interface{} {
		// 默认分配 4KB，覆盖绝大多数 UDP MTU (通常 1500)
		// 如果你的应用场景涉及 Jumbo Frame，可以调整为 9000 或 65535
		return make([]byte, 4096)
	},
}

// packetPool 复用 RefPacket 结构体本身
var packetPool = sync.Pool{
	New: func() interface{} {
		return &RefPacket{}
	},
}

// RefPacket 包装原始 buffer 和引用计数
type RefPacket struct {
	data []byte // 有效数据切片 (slice of buf)
	buf  []byte // 原始 buffer (用于归还给 bufferPool)
	ref  int32  // 原子计数器
}

// Retain 增加引用计数 (原子操作)
func (p *RefPacket) Retain() {
	atomic.AddInt32(&p.ref, 1)
}

// Release 减少引用计数，归零时回收 (原子操作)
func (p *RefPacket) Release() {
	newRef := atomic.AddInt32(&p.ref, -1)
	if newRef == 0 {
		// 引用归零，回收资源
		if p.buf != nil {
			//lint:ignore SA6002 argument is a slice, but overhead is negligible compared to complexity
			bufferPool.Put(p.buf)
		}
		p.data = nil
		p.buf = nil
		// 回收结构体本身
		packetPool.Put(p)
	} else if newRef < 0 {
		panic("RefPacket: double free or logic error")
	}
}

// ============================================================================
// 2. UDPSessionConn 定义与实现
// ============================================================================

type UDPSessionConn struct {
	dialer        *UDPSessionDialer
	remoteAddr    net.Addr
	readCh        chan *RefPacket // 修改: 传递引用计数包
	closeOnce     sync.Once
	closed        chan struct{}
	deadlineMu    sync.RWMutex
	readDeadline  time.Time
	writeDeadline time.Time
	logger        *log.Logger
	localIP       net.IP
	accepted      bool
}

func (c *UDPSessionConn) Read(b []byte) (n int, err error) {
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
	case pkt := <-c.readCh:
		if timer != nil {
			timer.Stop()
		}
		// 拷贝数据到用户 buffer
		n = copy(b, pkt.data)

		// 关键: 消费完毕，释放引用。
		// 如果这是最后一个消费者，buffer 会被自动归还。
		pkt.Release()

		return n, nil

	case <-c.closed:
		if timer != nil {
			timer.Stop()
		}
		return 0, net.ErrClosed

	case <-timeoutCh:
		return 0, newTimeoutError("read", true)
	}
}

func (c *UDPSessionConn) Write(b []byte) (n int, err error) {
	c.deadlineMu.RLock()
	writeTimeout := c.writeDeadline
	c.deadlineMu.RUnlock()

	if !writeTimeout.IsZero() && time.Now().After(writeTimeout) {
		return 0, newTimeoutError("write", true)
	}

	// 优化: 直接调用底层 WriteTo，移除 writeLoop 和 Channel 瓶颈
	// net.PacketConn 是并发安全的
	n, err = c.dialer.conn.WriteTo(b, c.remoteAddr)
	if err != nil {
		// 可以根据需要添加详细日志
		// c.logger.Printf("Write error to %s: %v", c.remoteAddr, err)
		return 0, err
	}
	return n, nil
}

func (c *UDPSessionConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.dialer.removeConn(c.remoteAddr.String(), c)
		c.logger.Printf("Custom UDP Conn to %s closed.", c.remoteAddr.String())
	})
	return nil
}

func (c *UDPSessionConn) LocalAddr() net.Addr {
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

func (c *UDPSessionConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *UDPSessionConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}
func (c *UDPSessionConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.readDeadline = t
	return nil
}
func (c *UDPSessionConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.writeDeadline = t
	return nil
}

// ============================================================================
// 3. UDPSessionDialer 定义与实现
// ============================================================================

type UDPSessionDialer struct {
	conn              net.PacketConn
	ownConn           bool
	conns             map[string][]*UDPSessionConn
	mu                sync.RWMutex
	maxPacketSize     int
	closed            chan struct{}
	wg                sync.WaitGroup
	logger            *log.Logger
	acceptCh          chan net.Conn
	listenerCloseOnce sync.Once
	recentlyClosed    map[string]time.Time
	cleanupTicker     *time.Ticker
}

func NewUDPSessionDialer(localUDPConn net.PacketConn, ownConn bool, maxPacketSize int, logger *log.Logger) (*UDPSessionDialer, error) {
	if localUDPConn == nil {
		return nil, fmt.Errorf("localUDPConn cannot be nil")
	}

	d := &UDPSessionDialer{
		conn:          localUDPConn,
		ownConn:       ownConn,
		conns:         make(map[string][]*UDPSessionConn),
		maxPacketSize: maxPacketSize,
		closed:        make(chan struct{}),
		logger:        logger,
		// 优化: 增大 Accept 缓冲区，防止突发连接请求阻塞
		acceptCh:       make(chan net.Conn, 100),
		recentlyClosed: make(map[string]time.Time),
		cleanupTicker:  time.NewTicker(30 * time.Second),
	}

	d.wg.Add(1)
	go d.readLoop()
	go d.cleanupRecentlyClosedLoop()
	d.logger.Printf("UDPSessionDialer initialized on %s", localUDPConn.LocalAddr().String())
	return d, nil
}

func (d *UDPSessionDialer) DialUDP(network string, remoteAddr *net.UDPAddr) (net.Conn, error) {
	if network != "udp" && network != "udp4" && network != "udp6" {
		return nil, fmt.Errorf("unsupported network type: %s", network)
	}
	if remoteAddr == nil {
		return nil, fmt.Errorf("remote address cannot be nil")
	}

	select {
	case <-d.closed:
		return nil, net.ErrClosed
	default:
	}

	var localIP net.IP
	laddr := d.conn.LocalAddr()
	if udpAddr, ok := laddr.(*net.UDPAddr); ok {
		if !udpAddr.IP.IsUnspecified() {
			localIP = udpAddr.IP
		}
	}
	if localIP == nil {
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
		localIP = tmpConn.LocalAddr().(*net.UDPAddr).IP
	}

	remoteAddrStr := remoteAddr.String()
	d.mu.Lock()
	defer d.mu.Unlock()

	newConn := &UDPSessionConn{
		dialer:     d,
		remoteAddr: remoteAddr,
		// 优化: 增大读取 Channel 缓冲区，减少丢包概率
		readCh:   make(chan *RefPacket, 256),
		closed:   make(chan struct{}),
		logger:   d.logger,
		localIP:  localIP,
		accepted: false,
	}

	d.conns[remoteAddrStr] = append(d.conns[remoteAddrStr], newConn)
	d.logger.Printf("New Custom UDP Conn created for %s.", remoteAddrStr)

	// 不需要启动 writeLoop 了
	return newConn, nil
}

func (d *UDPSessionDialer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	// 保持原有的 DNS 解析逻辑不变
	if network != "udp" && network != "udp4" && network != "udp6" {
		return nil, fmt.Errorf("unsupported network type: %s", network)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.closed:
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

// readLoop 负责读取并分发数据包 (1对多逻辑核心)
func (d *UDPSessionDialer) readLoop() {
	defer d.wg.Done()

	for {
		// 1. 从 Pool 获取原始 Buffer
		buf := bufferPool.Get().([]byte)

		// 确保 buffer 容量足够，如果不足则重新分配 (防止复用到被裁剪过的小切片)
		if cap(buf) < d.maxPacketSize {
			//lint:ignore SA6002 argument is a slice, but overhead is negligible compared to complexity
			bufferPool.Put(buf) // 归还小的，避免浪费
			buf = make([]byte, d.maxPacketSize)
		} else {
			buf = buf[:d.maxPacketSize] // 重置 slice 长度
		}

		// 2. 阻塞读取 (移除 SetReadDeadline 轮询，性能极大提升)
		n, remoteAddr, err := d.conn.ReadFrom(buf)
		if err != nil {
			// 读取失败，必须归还 buffer
			//lint:ignore SA6002 argument is a slice, but overhead is negligible compared to complexity
			bufferPool.Put(buf)

			if isClosedError(err) {
				d.logger.Printf("UDPSessionDialer readLoop stopping due to connection close.")
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// 发生超时，检查一下是否 Dialer 已经关闭
				select {
				case <-d.closed:
					// Dialer 已关闭，这是我们故意触发的超时，直接退出
					return
				default:
					// 真正的网络超时（如果有设置的话），继续循环
					continue
				}
			}
			if isMessageSizeError(err) {
				continue
			}
			d.logger.Printf("Error reading from UDP: %v", err)
			return // 遇到严重错误退出
		}

		remoteAddrStr := remoteAddr.String()

		// 3. 包装成 RefPacket
		pkt := packetPool.Get().(*RefPacket)
		pkt.data = buf[:n]
		pkt.buf = buf
		pkt.ref = 1 // 初始引用为 1 (readLoop 持有)

		d.mu.RLock()
		connsToNotify := d.conns[remoteAddrStr]
		d.mu.RUnlock()

		if len(connsToNotify) > 0 {
			// ============================
			// 1 对 多 广播分发
			// ============================
			for _, conn := range connsToNotify {
				// 为目标连接增加引用计数
				pkt.Retain()

				select {
				case conn.readCh <- pkt:
					// 发送成功，Conn.Read 会负责 Release
				case <-conn.closed:
					// 连接已关闭，撤销刚才的 Retain
					pkt.Release()
				default:
					// 通道已满 (丢包)，撤销刚才的 Retain
					pkt.Release()
					// 可以在此加入丢包统计日志
				}
			}

			// 分发完成，释放 readLoop 持有的初始引用
			// 如果所有 conn 都接收了，ref > 0，等待消费
			// 如果所有 conn 都丢弃了，ref 归零，buffer 立即回收
			pkt.Release()

		} else {
			// 没有匹配的连接，尝试 Accept
			d.handleAccept(remoteAddr, pkt, remoteAddrStr)
		}
	}
}

// handleAccept 处理新连接接入
func (d *UDPSessionDialer) handleAccept(remoteAddr net.Addr, pkt *RefPacket, remoteAddrStr string) {
	// 检查最近关闭列表 (防止快速重连干扰)
	d.mu.Lock()
	if closedAt, ok := d.recentlyClosed[remoteAddrStr]; ok {
		if time.Since(closedAt) < 10*time.Second {
			d.mu.Unlock()
			pkt.Release() // 丢弃并回收
			return
		}
	}
	d.mu.Unlock()

	d.logger.Printf("Accepting new connection from %s", remoteAddrStr)

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

	// 创建新连接
	newAcceptedConn := &UDPSessionConn{
		dialer:     d,
		remoteAddr: remoteAddr,
		readCh:     make(chan *RefPacket, 256),
		closed:     make(chan struct{}),
		logger:     d.logger,
		localIP:    localIP,
		accepted:   true,
	}

	// 增加引用给新连接
	pkt.Retain()

	select {
	case newAcceptedConn.readCh <- pkt:
		// 成功放入 buffer，注册连接
		d.mu.Lock()
		d.conns[remoteAddrStr] = append(d.conns[remoteAddrStr], newAcceptedConn)
		d.mu.Unlock()

		select {
		case d.acceptCh <- newAcceptedConn:
			// 成功提交给 Accept()
		default:
			// Accept 队列满
			newAcceptedConn.Close()
			d.logger.Printf("Accept queue full, dropping conn from %s", remoteAddrStr)
		}
	default:
		// 新连接的 readCh 满 (极罕见)
		pkt.Release()
		newAcceptedConn.Close()
	}

	// 释放 readLoop 的持有引用
	pkt.Release()
}

func (d *UDPSessionDialer) removeConn(remoteAddrStr string, connToRemove *UDPSessionConn) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if conns, ok := d.conns[remoteAddrStr]; ok {
		// 记录关闭时间
		d.recentlyClosed[remoteAddrStr] = time.Now()

		var updatedConns []*UDPSessionConn
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
	}
}

func (d *UDPSessionDialer) Close() error {
	d.logger.Printf("Closing UDPSessionDialer...")
	select {
	case <-d.closed:
		return net.ErrClosed
	default:
	}

	d.listenerCloseOnce.Do(func() {
		close(d.closed)
	})

	// 关闭底层连接，这会强制中断 readLoop 的 ReadFrom
	var err error
	if d.ownConn {
		err = d.conn.Close()
	} else {
		// === 修改重点 ===
		// 如果是共享连接（如 Listener 传入的），我们不能关闭它，
		// 但必须打断 readLoop 的阻塞。
		// 设置一个“过去”的时间点，强制触发 ReadFrom 超时。
		d.conn.SetReadDeadline(time.Now())
	}

	// 等待 readLoop 退出
	d.wg.Wait()
	// 但通常 Listener 关闭意味着该端口不再接收数据，视具体需求而定。
	if !d.ownConn {
		d.conn.SetReadDeadline(time.Time{})
	}
	// 清理所有活跃连接
	d.mu.Lock()
	var allConns []*UDPSessionConn
	for _, conns := range d.conns {
		allConns = append(allConns, conns...)
	}
	d.conns = make(map[string][]*UDPSessionConn)
	d.mu.Unlock()

	for _, conn := range allConns {
		conn.Close()
	}

	// 清理 Accept 通道
	close(d.acceptCh)
	for conn := range d.acceptCh {
		conn.Close()
	}
	d.logger.Printf("UDPSessionDialer closed successfully.")
	return err
}

func (d *UDPSessionDialer) cleanupRecentlyClosedLoop() {
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

// 辅助函数：判断是否是 Socket 关闭错误
func isClosedError(err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	// 针对不同平台的额外检查
	return false
}

// ============================================================================
// 4. UDPSessionListener (包装器)
// ============================================================================

type UDPSessionListener struct {
	dialer *UDPSessionDialer
	addr   net.Addr
}

func NewUDPSessionListener(localUDPConn *net.UDPConn, maxPacketSize int, logger *log.Logger) (*UDPSessionListener, error) {
	dialer, err := NewUDPSessionDialer(localUDPConn, false, maxPacketSize, logger)
	if err != nil {
		return nil, err
	}
	return &UDPSessionListener{
		dialer: dialer,
		addr:   localUDPConn.LocalAddr(),
	}, nil
}

func (l *UDPSessionListener) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-l.dialer.acceptCh:
		if !ok {
			return nil, net.ErrClosed
		}
		return conn, nil
	case <-l.dialer.closed:
		return nil, net.ErrClosed
	}
}

func (l *UDPSessionListener) Close() error {
	return l.dialer.Close()
}

func (l *UDPSessionListener) Addr() net.Addr {
	return l.addr
}
