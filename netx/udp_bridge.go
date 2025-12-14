package netx

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// BridgeConn manages:
//   A <-> B  (virtual local UDP pipe)
//   A <-> C  (remote forwarder, replaceable)
//
// A and B are two UDP net.Conn objects created by this module.
// B will be passed to KCP as its underlying UDP conn.
// A forwards packets between B and C.

type BridgeConn struct {
	TotalTraffic uint64

	A net.Conn // internal pipe endpoint A
	B net.Conn // internal pipe endpoint B (given to KCP)

	mu sync.RWMutex
	C  net.Conn // external forwarder, replaceable

	closed chan struct{}
	ErrCh  chan error
}

// NewBridge creates A and B as connected UDP conns bound to random local addresses.
// A's remote addr == B.LocalAddr, B's remote addr == A.LocalAddr.
func NewBridge() (*BridgeConn, error) {
	// Step 1: create two UDP listeners to obtain local ports
	la, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, err
	}
	lb, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		la.Close()
		return nil, err
	}

	localA := la.LocalAddr().(*net.UDPAddr)
	localB := lb.LocalAddr().(*net.UDPAddr)

	// Step 2: close listeners; we only needed the ports
	la.Close()
	lb.Close()

	// Step 3: Dial A -> B using A's port
	dialerA := &net.Dialer{LocalAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: localA.Port}}
	A, err := dialerA.Dial("udp4", localB.String())
	if err != nil {
		return nil, err
	}

	// Step 4: Dial B -> A using B's port
	dialerB := &net.Dialer{LocalAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: localB.Port}}
	B, err := dialerB.Dial("udp4", localA.String())
	if err != nil {
		A.Close()
		return nil, err
	}

	bc := &BridgeConn{
		A:      A,
		B:      B,
		closed: make(chan struct{}),
		ErrCh:  make(chan error, 1),
	}

	// 启动 A -> C 的长运行循环 (因为 A 是固定的)
	go bc.loopAtoC()

	// 注意：不再启动全局 loopCtoA，因为 C 是动态的，改为在 SetForwarder 时启动专属 loop

	return bc, nil
}

// SetForwarder replaces C safely.
// It starts the loop for the new connection immediately.
// It signals the old connection to stop by setting a deadline, but does not wait for it to close.
func (bc *BridgeConn) SetForwarder(newC net.Conn) {
	var framedConn net.Conn
	if newC != nil {
		select {
		case <-bc.closed:
			// 如果 bridge 已经关闭，直接关闭新连接并返回
			newC.Close()
			return
		default:
		}
		if strings.HasPrefix(newC.LocalAddr().Network(), "udp") {
			framedConn = newC
		} else {
			framedConn = NewFramedConn(newC, newC)
		}
	}

	bc.mu.Lock()
	oldC := bc.C
	bc.C = framedConn
	bc.mu.Unlock()

	// 1. 如果有新连接，立即启动针对该连接的读取循环
	if framedConn != nil {
		go bc.runSpecificCtoA(framedConn)
	}

	// 2. 如果有旧连接，给它一个“踢出”信号
	// SetReadDeadline 是非阻塞的，它会立即使旧连接正在进行的 Read 操作返回 Timeout 错误。
	// 旧连接的 runSpecificCtoA 循环会捕获该错误并负责执行 Close()。
	if oldC != nil {
		oldC.SetReadDeadline(time.Now())
	}
}

// GetForwarderInfo returns the address information of the current forwarder C.
func (bc *BridgeConn) GetForwarderInfo() string {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	c := bc.C
	if c == nil {
		return "none"
	}
	return fmt.Sprintf("%s: %s / %s", c.LocalAddr().Network(), c.LocalAddr().String(), c.RemoteAddr().String())
}

// runSpecificCtoA reads from a specific instance of C and forwards to A.
// It manages the lifecycle (Close) of this specific connection c.
func (bc *BridgeConn) runSpecificCtoA(c net.Conn) {
	// 无论如何退出，都要确保关闭这个 C
	defer c.Close()

	buf := make([]byte, 65535)
	for {
		select {
		case <-bc.closed:
			return
		default:
		}

		// [修改] 移除循环内的 SetReadDeadline。
		// 我们允许连接长期空闲（Idle），直到 SetForwarder 显式调用 SetReadDeadline(Now) 来中断它。
		// 这样可以避免 10秒无数据就断开的问题。

		n, err := c.Read(buf)

		if err != nil {
			// 这里会捕获两种情况：
			// 1. SetForwarder 调用了 SetReadDeadline(time.Now()) -> 返回 Timeout error (这是我们要的切换信号)
			// 2. 真正的网络断开或错误
			// 无论哪种，都退出循环并关闭连接
			return
		}

		// 转发给 A
		_, err = bc.A.Write(buf[:n])
		if err != nil {
			// 如果 A 写入失败，说明内部管道坏了，这是致命错误
			select {
			case <-bc.closed:
				return
			default:
				select {
				case bc.ErrCh <- fmt.Errorf("A.Write fatal error: %w", err):
				default:
				}
				bc.Close() // 关闭整个 Bridge
				return
			}
		}

		atomic.AddUint64(&bc.TotalTraffic, uint64(n))
	}
}

// loopAtoC: packets from A -> forward to C
func (bc *BridgeConn) loopAtoC() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-bc.closed:
			return
		default:
		}

		// A 端的读取使用超时轮询机制，以便检查 bc.closed 状态
		bc.A.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := bc.A.Read(buf)
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			continue
		}
		if err != nil {
			// A 的读取错误是致命的
			select {
			case <-bc.closed:
				return
			default:
				select {
				case bc.ErrCh <- fmt.Errorf("A.Read fatal error: %w", err):
				default:
				}
				bc.Close()
				return
			}
		}

		// 获取当前的 C
		bc.mu.RLock()
		c := bc.C
		bc.mu.RUnlock()

		if c != nil {
			atomic.AddUint64(&bc.TotalTraffic, uint64(n))
			// 尝试写入 C
			_, err := c.Write(buf[:n])
			if err != nil {
				// C 的写入错误不再是致命的。
				// 因为 C 可能正在被轮转，或者旧的 C 刚刚关闭。
				// 我们只需要忽略这个包，等待新的 C 生效即可。
			}
		}
	}
}

// Close shuts down bridge and all conns
func (bc *BridgeConn) Close() {
	select {
	case <-bc.closed:
		return
	default:
		close(bc.closed)
	}

	bc.A.Close()
	bc.B.Close()

	bc.mu.Lock()
	if bc.C != nil {
		// 这里的 Close 会触发正在运行的 runSpecificCtoA 退出
		bc.C.Close()
		bc.C = nil
	}
	bc.mu.Unlock()
}
