package misc

import (
	"fmt"
	"io"
	"net"
	"time"
)

type ProgressStats struct {
	startTime  time.Time
	totalBytes int64
	lastBytes  int64
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
	p.totalBytes += n
}

func (p *ProgressStats) Stats(now time.Time, final bool) StatResult {
	var timeDiff float64
	var bytesDiff int64

	if final {
		timeDiff = now.Sub(p.startTime).Seconds()
		bytesDiff = p.totalBytes
	} else {
		timeDiff = now.Sub(p.lastTime).Seconds()
		bytesDiff = p.totalBytes - p.lastBytes
	}

	var speed float64
	if timeDiff > 0 {
		speed = float64(bytesDiff) / timeDiff
		p.lastSpeed = speed
	} else {
		speed = p.lastSpeed
	}

	p.lastTime = now
	p.lastBytes = p.totalBytes

	return StatResult{
		TotalBytes: p.totalBytes,
		SpeedBps:   speed,
	}
}

func (p *ProgressStats) StartTime() time.Time {
	return p.startTime
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
