package netx

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

const maxFrameSize = 65535

type FramedConn struct {
	sessR          io.ReadCloser
	sessW          io.WriteCloser
	writeMu        sync.Mutex
	readMu         sync.Mutex
	readBuf        []byte // 用于存储上一次Read调用未读完的帧数据，这是结构体自身拥有的缓冲区
	readEOF        bool   // 是否收到 CloseWrite 帧
	writeClosed    bool   // 是否已发送过 CloseWrite
	writeCloseTime time.Time
	closeOnce      sync.Once
	closeErr       error
}

// 帧缓冲池（用于 write 和 read）
// 优化：直接存储 []byte 切片，而不是指向切片的指针 (*[]byte)，以避免不必要的指针间接层。
var framePool = sync.Pool{
	New: func() any {
		buf := make([]byte, 2+maxFrameSize)
		return &buf
	},
}

// NewFramedConn 将一个会话包装成一个带帧的全双工流
func NewFramedConn(r io.ReadCloser, w io.WriteCloser) *FramedConn {
	return &FramedConn{sessR: r, sessW: w}
}

// Write 将 p 的内容分块写入帧中，并重用缓冲区
func (c *FramedConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.writeClosed {
		return 0, net.ErrClosed
	}

	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxFrameSize {
			n = maxFrameSize
		}
		chunk := p[:n]

		// 从池中获取缓冲区
		bufPtr := framePool.Get().(*[]byte)
		frame := (*bufPtr)[:2+n] // 对缓冲区进行切片以匹配所需大小

		binary.LittleEndian.PutUint16(frame[:2], uint16(n))
		copy(frame[2:], chunk)

		_, err := c.sessW.Write(frame)

		// 将原始的指针放回池中，无额外分配
		framePool.Put(bufPtr)

		if err != nil {
			return total, err
		}
		p = p[n:]
		total += n
	}
	return total, nil
}

// Read 读取带帧的流数据，内部进行缓冲
// 修复了并发安全问题
func (c *FramedConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	// 1. 如果我们内部的缓冲区有遗留数据，优先从这里读取
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	// 2. 如果已经收到了EOF并且缓冲区也空了，则返回EOF
	if c.readEOF {
		return 0, io.EOF
	}

	// 3. 内部缓冲区已空，需要从底层连接读取一个新帧
	// 读取帧长度
	var lenBuf [2]byte
	if _, err := io.ReadFull(c.sessR, lenBuf[:]); err != nil {
		return 0, err
	}
	size := binary.LittleEndian.Uint16(lenBuf[:])

	// 4. 收到长度为0的帧，代表对方已经 CloseWrite
	if size == 0 {
		c.readEOF = true
		return 0, io.EOF
	}

	// 5. 从池中获取一个临时缓冲区来接收帧数据
	bufPtr := framePool.Get().(*[]byte)
	defer framePool.Put(bufPtr)

	frameData := (*bufPtr)[:size]
	_, err := io.ReadFull(c.sessR, frameData)
	if err != nil {
		return 0, err
	}

	// 6. 将帧数据拷贝到用户提供的p切片中
	n := copy(p, frameData)

	// 7. 如果p的空间不足以容纳整个帧，将剩余部分拷贝到我们自己的内部缓冲区 c.readBuf
	//    这是关键的修复：我们是“复制”数据，而不是让 c.readBuf 指向池中的内存。
	if n < len(frameData) {
		c.readBuf = append(c.readBuf[:0], frameData[n:]...)
	}

	return n, nil
}

// CloseWrite 发送一个长度为0的帧来通知远端EOF
func (c *FramedConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.writeClosed {
		return nil
	}
	c.writeClosed = true
	c.writeCloseTime = time.Now()
	// 发送一个2字节，值为0的帧
	_, err := c.sessW.Write([]byte{0x00, 0x00})
	return err
}

// Close 关闭双向连接
func (c *FramedConn) Close() error {
	c.closeOnce.Do(func() {
		_ = c.CloseWrite()
		const minWait = 1500 * time.Millisecond
		waited := time.Since(c.writeCloseTime)
		if waited < minWait {
			time.Sleep(minWait - waited)
		}
		c.closeErr = c.sessW.Close()
	})
	return c.closeErr
}

// --- standard net.Conn methods ---
func (c *FramedConn) LocalAddr() net.Addr {
	if conn, ok := c.sessW.(net.Conn); ok {
		return conn.LocalAddr()
	}
	return nil
}

func (c *FramedConn) RemoteAddr() net.Addr {
	if conn, ok := c.sessW.(net.Conn); ok {
		return conn.RemoteAddr()
	}
	return nil
}

func (c *FramedConn) SetDeadline(t time.Time) error {
	var err error
	if conn, ok := c.sessR.(net.Conn); ok {
		err = conn.SetDeadline(t)
		if err != nil {
			return err
		}
	}
	if conn, ok := c.sessW.(net.Conn); ok {
		err = conn.SetDeadline(t)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *FramedConn) SetReadDeadline(t time.Time) error {
	if conn, ok := c.sessR.(net.Conn); ok {
		return conn.SetReadDeadline(t)
	}
	return nil
}

func (c *FramedConn) SetWriteDeadline(t time.Time) error {
	if conn, ok := c.sessW.(net.Conn); ok {
		return conn.SetWriteDeadline(t)
	}
	return nil
}
