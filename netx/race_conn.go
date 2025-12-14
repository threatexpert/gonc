package netx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DialContextFunc 定义用户传入的 Dial 函数签名
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// DialRace 是统一入口
// address 格式支持: "host:port?port2?port3"
// network 支持: "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6"
func DialRace(ctx context.Context, network string, address string, dialer DialContextFunc) (net.Conn, error) {
	// 1. 公共逻辑：解析地址
	host, ports, err := parseRaceAddress(address)
	if err != nil {
		return nil, err
	}

	// 2. 根据 network 类型分流
	// 如果是 TCP，走握手竞速
	if strings.Contains(network, "tcp") {
		return dialTCPRace(ctx, network, host, ports, dialer)
	}

	// 如果是 UDP，走报文竞速 (返回包装后的 Conn)
	return dialUDPRace(ctx, network, host, ports, dialer)
}

// parseRaceAddress 解析 "host:port?p2?p3"
func parseRaceAddress(address string) (host string, ports []string, err error) {
	parts := strings.Split(address, "?")
	baseAddr := parts[0]

	h, p, err := net.SplitHostPort(baseAddr)
	if err != nil {
		return "", nil, fmt.Errorf("invalid base address: %w", err)
	}

	ports = append(ports, p)
	if len(parts) > 1 {
		// 处理后续的 ?p2?p3
		extras := strings.Split(parts[1], "?")
		ports = append(ports, extras...)
	}
	return h, ports, nil
}

// ==========================================
// 策略 A: TCP 竞速 (Happy Eyeballs)
// ==========================================

func dialTCPRace(ctx context.Context, network, host string, ports []string, dialer DialContextFunc) (net.Conn, error) {
	// 创建一个可取消的上下文，一旦有一个成功，取消其他所有
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type dialRes struct {
		conn net.Conn
		err  error
	}
	ch := make(chan dialRes) // 无缓冲或小缓冲均可

	// 并发拨号
	for _, port := range ports {
		go func(p string) {
			target := net.JoinHostPort(host, p)
			conn, err := dialer(ctx, network, target)

			select {
			case ch <- dialRes{conn: conn, err: err}:
				// 结果发送成功
			case <-ctx.Done():
				// 如果上下文已结束（说明别人已经赢了，或者超时了）
				// 如果我们刚刚连上，必须关闭它，防止泄露
				if conn != nil {
					conn.Close()
				}
			}
		}(port)
	}

	var errs []error
	// 等待结果
	for i := 0; i < len(ports); i++ {
		select {
		case res := <-ch:
			if res.err == nil {
				// 成功！直接返回。
				// defer cancel() 会触发，通知其他正在尝试的 goroutine 停止
				return res.conn, nil
			}
			errs = append(errs, res.err)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return nil, fmt.Errorf("all tcp dials failed: %v", errs)
}

// ==========================================
// 策略 B: UDP 竞速 (RaceConn)
// ==========================================

func dialUDPRace(ctx context.Context, network, host string, ports []string, dialer DialContextFunc) (net.Conn, error) {
	var conns []net.Conn
	var lastErr error

	// 1. 建立所有底层 UDP Socket
	for _, p := range ports {
		target := net.JoinHostPort(host, p)
		c, err := dialer(ctx, network, target)
		if err != nil {
			lastErr = err
			continue
		}
		conns = append(conns, c)
	}

	if len(conns) == 0 {
		if lastErr != nil {
			return nil, fmt.Errorf("all udp dials failed, last error: %w", lastErr)
		}
		return nil, errors.New("no udp connections established")
	}

	// 2. 封装成 RaceConn
	cCtx, cCancel := context.WithCancel(context.Background())
	rc := &RaceConn{
		conns:       conns,
		winnerIndex: -1,
		readCh:      make(chan readResult, 100),
		ctx:         cCtx,
		cancel:      cCancel,
	}

	// 3. 启动监听
	rc.startReaders()

	return rc, nil
}

// RaceConn 是 UDP 竞速专用包装器
type RaceConn struct {
	winnerIndex int32 // 原子操作: -1 未定, >=0 为赢家索引
	conns       []net.Conn
	readCh      chan readResult // 读取数据汇聚通道
	closeOnce   sync.Once
	ctx         context.Context
	cancel      context.CancelFunc
}

type readResult struct {
	data []byte
	err  error
}

func (r *RaceConn) startReaders() {
	for i, conn := range r.conns {
		go func(index int32, c net.Conn) {
			defer c.Close()
			buf := make([]byte, 2048) // UDP MTU 安全大小
			for {
				select {
				case <-r.ctx.Done():
					return
				default:
				}

				n, err := c.Read(buf)
				if err != nil {
					// 只有赢家报错，或者还没赢家时报错才传给上层
					if r.ctx.Err() == nil {
						winner := atomic.LoadInt32(&r.winnerIndex)
						if winner == index || winner == -1 {
							select {
							case r.readCh <- readResult{err: err}:
							case <-r.ctx.Done():
							}
						}
					}
					return
				}

				// === 核心逻辑: 抢占赢家 ===
				if atomic.LoadInt32(&r.winnerIndex) == -1 {
					atomic.CompareAndSwapInt32(&r.winnerIndex, -1, index)
				}

				winner := atomic.LoadInt32(&r.winnerIndex)
				if winner == index {
					dataCopy := make([]byte, n)
					copy(dataCopy, buf[:n])
					select {
					case r.readCh <- readResult{data: dataCopy}:
					case <-r.ctx.Done():
						return
					}
				}
				// 非赢家数据直接丢弃
			}
		}(int32(i), conn)
	}
}

func (r *RaceConn) Read(b []byte) (n int, err error) {
	select {
	case res := <-r.readCh:
		if res.err != nil {
			return 0, res.err
		}
		copy(b, res.data)
		return len(res.data), nil
	case <-r.ctx.Done():
		return 0, net.ErrClosed
	}
}

func (r *RaceConn) Write(b []byte) (n int, err error) {
	winner := atomic.LoadInt32(&r.winnerIndex)

	// 已有赢家，单发
	if winner != -1 {
		return r.conns[winner].Write(b)
	}

	// 无赢家，群发
	successCount := 0
	var lastErr error
	for _, c := range r.conns {
		wn, werr := c.Write(b)
		if werr == nil {
			n = wn
			successCount++
		} else {
			lastErr = werr
		}
	}

	if successCount == 0 && lastErr != nil {
		return 0, lastErr
	}
	return n, nil
}

func (r *RaceConn) Close() error {
	var err error
	r.closeOnce.Do(func() {
		r.cancel() // 停止后台读取
		for _, c := range r.conns {
			if e := c.Close(); e != nil {
				err = e
			}
		}
	})
	return err
}

// RemoteAddr 动态返回赢家地址
func (r *RaceConn) RemoteAddr() net.Addr {
	winner := atomic.LoadInt32(&r.winnerIndex)
	if winner != -1 {
		return r.conns[winner].RemoteAddr()
	}
	return r.conns[0].RemoteAddr()
}

// LocalAddr 动态返回赢家本地地址
func (r *RaceConn) LocalAddr() net.Addr {
	winner := atomic.LoadInt32(&r.winnerIndex)
	if winner != -1 {
		return r.conns[winner].LocalAddr()
	}
	return r.conns[0].LocalAddr()
}

func (r *RaceConn) SetDeadline(t time.Time) error {
	for _, c := range r.conns {
		c.SetDeadline(t)
	}
	return nil
}

func (r *RaceConn) SetReadDeadline(t time.Time) error {
	for _, c := range r.conns {
		c.SetReadDeadline(t)
	}
	return nil
}

func (r *RaceConn) SetWriteDeadline(t time.Time) error {
	for _, c := range r.conns {
		c.SetWriteDeadline(t)
	}
	return nil
}
