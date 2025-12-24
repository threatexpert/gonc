package misc

import (
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"
)

type ProgressStats struct {
	totalBytes int64
	lastBytes  int64
	startTime  time.Time
	lastTime   time.Time
	lastSpeed  float64
}

type StatResult struct {
	TotalBytes int64
	SpeedBps   float64
}

func NewProgressStats() *ProgressStats {
	now := time.Now()
	return &ProgressStats{
		startTime: now,
		lastTime:  now,
	}
}

func (p *ProgressStats) ResetStart() {
	now := time.Now()
	p.startTime = now
	p.lastTime = now
}

func (p *ProgressStats) Update(n int64) {
	// 2. 使用原子操作累加，这是线程安全的
	atomic.AddInt64(&p.totalBytes, n)
}

func (p *ProgressStats) Stats(now time.Time, final bool) StatResult {
	// 3. 安全读取当前的总字节数
	// 即使 Update 正在并发写入，这里也能读到完整的最新值
	currentTotal := atomic.LoadInt64(&p.totalBytes)

	var timeDiff float64
	var bytesDiff int64

	if final {
		timeDiff = now.Sub(p.startTime).Seconds()
		bytesDiff = currentTotal // 使用读取到的原子值
	} else {
		timeDiff = now.Sub(p.lastTime).Seconds()
		bytesDiff = currentTotal - p.lastBytes // 使用读取到的原子值
	}

	var speed float64
	if timeDiff > 0 {
		speed = float64(bytesDiff) / timeDiff
		p.lastSpeed = speed
	} else {
		speed = p.lastSpeed
	}

	p.lastTime = now
	p.lastBytes = currentTotal // 更新 lastBytes

	return StatResult{
		TotalBytes: currentTotal,
		SpeedBps:   speed,
	}
}

func (p *ProgressStats) StartTime() time.Time {
	return p.startTime
}

type StatConn struct {
	net.Conn                // 嵌入接口，自动继承 Close, LocalAddr, SetDeadline 等方法
	Rx       *ProgressStats // 接收统计 (Read)
	Tx       *ProgressStats // 发送统计 (Write)
}

// 2. 拦截 Read 方法
func (sc *StatConn) Read(b []byte) (n int, err error) {
	n, err = sc.Conn.Read(b) // 调用原始连接的 Read
	if n > 0 {
		sc.Rx.Update(int64(n)) // 统计接收流量
	}
	return
}

// 3. 拦截 Write 方法
func (sc *StatConn) Write(b []byte) (n int, err error) {
	n, err = sc.Conn.Write(b) // 调用原始连接的 Write
	if n > 0 {
		sc.Tx.Update(int64(n)) // 统计发送流量
	}
	return
}

func NewStatConn(c net.Conn, stats_in, stats_out *ProgressStats) *StatConn {
	return &StatConn{
		Conn: c,
		Rx:   stats_in,
		Tx:   stats_out,
	}
}

func FormatBytes(bytes int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB"}
	value := float64(bytes)

	for _, unit := range units {
		if value < 1024.0 {
			return fmt.Sprintf("%.1f %s", value, unit)
		}
		value /= 1024.0
	}
	return fmt.Sprintf("%.1f YiB", value)
}

type PipeConn struct {
	net.Conn
	In, in   net.Conn
	Out, out net.Conn
}

func NewPipeConn(originalConn net.Conn) *PipeConn {
	a, b := net.Pipe()

	return &PipeConn{
		Conn: originalConn,
		in:   a,
		Out:  b,
		In:   b,
		out:  a,
	}
}

// 实现 net.Conn 接口
func (p *PipeConn) Read(b []byte) (n int, err error) {
	return p.in.Read(b)
}

func (p *PipeConn) Write(b []byte) (n int, err error) {
	return p.out.Write(b)
}

func (p *PipeConn) Close() error {
	p.Out.Close()
	p.out.Close()
	return nil
}

func (p *PipeConn) CloseWrite() error {
	if c, ok := p.out.(io.Closer); ok {
		c.Close()
	}
	return nil
}

// 保持其他方法（使用原始连接）
func (p *PipeConn) LocalAddr() net.Addr {
	return p.Conn.LocalAddr()
}
func (p *PipeConn) RemoteAddr() net.Addr {
	return p.Conn.RemoteAddr()
}
func (p *PipeConn) SetDeadline(t time.Time) error {
	err := p.in.SetDeadline(t)
	if err != nil {
		return err
	}
	err = p.out.SetDeadline(t)
	return err
}
func (p *PipeConn) SetReadDeadline(t time.Time) error {
	return p.in.SetReadDeadline(t)
}
func (p *PipeConn) SetWriteDeadline(t time.Time) error {
	return p.out.SetWriteDeadline(t)
}
