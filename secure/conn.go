package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	ivSize = aes.BlockSize
)

// 全局缓冲池，减少 GC 压力
var bufPool = sync.Pool{
	New: func() interface{} {
		// 分配足够大的 buffer，避免扩容
		// 32KB 通常足够应对大多数 TCP/UDP 包，如果不够会自动扩容或单独分配
		return make([]byte, 32*1024)
	},
}

// 获取 buffer
func getBuffer(size int) []byte {
	b := bufPool.Get().([]byte)
	if cap(b) < size {
		//lint:ignore SA6002 argument is a slice, but overhead is negligible compared to complexity
		bufPool.Put(b)
		return make([]byte, size)
	}
	return b[:size]
}

// 归还 buffer
func putBuffer(b []byte) {
	//lint:ignore SA6002 argument is a slice, but overhead is negligible compared to complexity
	bufPool.Put(b)
}

// --- SecureStreamConn ---

type SecureStreamConn struct {
	conn net.Conn
	key  [32]byte

	writeOnce sync.Once
	readOnce  sync.Once

	// 复用 Block，避免每次 Write/Read 都重新生成
	block cipher.Block

	encStream cipher.Stream
	decStream cipher.Stream

	bufIV [ivSize]byte
}

func NewSecureStreamConn(conn net.Conn, key [32]byte) (*SecureStreamConn, error) {
	// 提前初始化 Block，因为 Key 是不变的
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return &SecureStreamConn{
		conn:  conn,
		key:   key,
		block: block,
	}, nil
}

func (s *SecureStreamConn) Write(p []byte) (int, error) {
	var err error
	var firstWrite bool

	s.writeOnce.Do(func() {
		if _, err = rand.Read(s.bufIV[:]); err != nil {
			return
		}
		s.encStream = cipher.NewCTR(s.block, s.bufIV[:])
		firstWrite = true
	})

	if err != nil {
		return 0, err
	}

	if firstWrite {
		// 首次写：IV + Ciphertext
		// 优化：从池中获取 buffer，避免 append 产生的额外分配
		totalLen := ivSize + len(p)
		buf := getBuffer(totalLen)
		defer putBuffer(buf)

		// 1. 填入 IV
		copy(buf, s.bufIV[:])

		// 2. 加密并填入后续位置
		s.encStream.XORKeyStream(buf[ivSize:], p)

		// 3. 一次性发送
		if _, err := s.WriteFull(buf); err != nil {
			return 0, err
		}
		return len(p), nil
	}

	// 后续写：仅加密数据
	// 为了并发安全和不修改输入切片 p (如果 p 是共享的)，我们使用池化 buffer
	buf := getBuffer(len(p))
	defer putBuffer(buf)

	s.encStream.XORKeyStream(buf, p)
	return s.WriteFull(buf)
}

func (s *SecureStreamConn) WriteFull(data []byte) (int, error) {
	total := 0
	for total < len(data) {
		n, err := s.conn.Write(data[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func (s *SecureStreamConn) Read(p []byte) (int, error) {
	var err error
	s.readOnce.Do(func() {
		// 优化：直接读取到内部数组，无堆分配
		if _, err = io.ReadFull(s.conn, s.bufIV[:]); err != nil {
			return
		}
		s.decStream = cipher.NewCTR(s.block, s.bufIV[:])
	})

	if err != nil {
		return 0, err
	}

	n, err := s.conn.Read(p)
	if n > 0 && s.decStream != nil {
		// XORKeyStream 支持原地修改 (dst == src)
		s.decStream.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

func (s *SecureStreamConn) Close() error {
	return s.conn.Close()
}

func (s *SecureStreamConn) CloseWrite() error {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := s.conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return errors.New("CloseWrite not supported")
}

func (s *SecureStreamConn) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *SecureStreamConn) RemoteAddr() net.Addr               { return s.conn.RemoteAddr() }
func (s *SecureStreamConn) SetDeadline(t time.Time) error      { return s.conn.SetDeadline(t) }
func (s *SecureStreamConn) SetReadDeadline(t time.Time) error  { return s.conn.SetReadDeadline(t) }
func (s *SecureStreamConn) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }

// --- SecurePacketConn ---

type SecurePacketConn struct {
	conn  net.Conn
	key   [32]byte
	block cipher.Block // 优化：缓存 block
}

func NewSecurePacketConn(conn net.Conn, key [32]byte) (*SecurePacketConn, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return &SecurePacketConn{conn: conn, key: key, block: block}, nil
}

func (s *SecurePacketConn) Write(p []byte) (int, error) {
	// 优化：使用 buffer 池，避免 make 和 append
	totalLen := ivSize + len(p)
	buf := getBuffer(totalLen)
	defer putBuffer(buf)

	// 生成 IV (直接写入 buffer 头部)
	iv := buf[:ivSize]
	if _, err := rand.Read(iv); err != nil {
		return 0, err
	}

	// 加密
	stream := cipher.NewCTR(s.block, iv)
	stream.XORKeyStream(buf[ivSize:], p)

	// 写入底层连接
	_, err := s.conn.Write(buf)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *SecurePacketConn) Read(p []byte) (int, error) {
	if len(p) < ivSize {
		return 0, io.ErrShortBuffer
	}

DoRead:
	// 但如果底层 conn 是 TCP，Read 可能只读到半个包，这里通过 bufPool 优化性能
	// 但并未解决 TCP 粘包/半包的逻辑问题（假设调用者能保证边界或底层非流式）
	n, err := s.conn.Read(p)
	if err != nil {
		return 0, err
	}
	if n < ivSize {
		// 简单的丢弃策略
		goto DoRead
	}

	iv := p[:ivSize]
	ciphertext := p[ivSize:n]

	// 复用 Block，显著降低 CPU 消耗
	stream := cipher.NewCTR(s.block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	// 移动数据：将解密后的 payload 移到 p 的头部
	copy(p, ciphertext)
	return n - ivSize, nil
}

// net.Conn 接口透传
func (s *SecurePacketConn) Close() error                       { return s.conn.Close() }
func (s *SecurePacketConn) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *SecurePacketConn) RemoteAddr() net.Addr               { return s.conn.RemoteAddr() }
func (s *SecurePacketConn) SetDeadline(t time.Time) error      { return s.conn.SetDeadline(t) }
func (s *SecurePacketConn) SetReadDeadline(t time.Time) error  { return s.conn.SetReadDeadline(t) }
func (s *SecurePacketConn) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }

// --- SecureUDPConn ---

type SecureUDPConn struct {
	conn  *net.UDPConn
	key   [32]byte
	block cipher.Block // 优化：缓存 block
}

func NewSecureUDPConn(conn *net.UDPConn, key [32]byte) (*SecureUDPConn, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return &SecureUDPConn{conn: conn, key: key, block: block}, nil
}

func (s *SecureUDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	// 优化：Buffer 池
	totalLen := ivSize + len(p)
	buf := getBuffer(totalLen)
	defer putBuffer(buf)

	iv := buf[:ivSize]
	if _, err := rand.Read(iv); err != nil {
		return 0, err
	}

	stream := cipher.NewCTR(s.block, iv)
	stream.XORKeyStream(buf[ivSize:], p)

	n, err := s.conn.WriteTo(buf, addr)
	if err != nil {
		return 0, err
	}
	if n < ivSize {
		return 0, io.ErrShortWrite
	}
	return n - ivSize, nil
}

func (s *SecureUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	// 优化：UDP 读取需要一个临时 buffer 来接收 IV+Ciphertext
	// 因为 p 的大小可能只够存 payload，不够存 IV
	// 使用池化 buffer 避免每次 ReadFrom 都分配内存

	// 假设 UDP 包最大 64k (常规情况)
	tempBuf := getBuffer(65536)
	defer putBuffer(tempBuf)

DoRead:
	n, addr, err := s.conn.ReadFrom(tempBuf)
	if err != nil {
		return 0, nil, err
	}
	if n < ivSize {
		goto DoRead
	}

	iv := tempBuf[:ivSize]
	ciphertext := tempBuf[ivSize:n]

	// 检查用户提供的 p 是否足够大
	if len(p) < len(ciphertext) {
		return 0, nil, io.ErrShortBuffer
	}

	stream := cipher.NewCTR(s.block, iv)
	// 直接解密到用户的 p 中，实现零拷贝写入
	stream.XORKeyStream(p[:len(ciphertext)], ciphertext)

	return len(ciphertext), addr, nil
}

// net.PacketConn 接口透传
func (s *SecureUDPConn) Close() error                       { return s.conn.Close() }
func (s *SecureUDPConn) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *SecureUDPConn) SetDeadline(t time.Time) error      { return s.conn.SetDeadline(t) }
func (s *SecureUDPConn) SetReadDeadline(t time.Time) error  { return s.conn.SetReadDeadline(t) }
func (s *SecureUDPConn) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }
