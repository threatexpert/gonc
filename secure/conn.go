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

type SecureStreamConn struct {
	conn net.Conn
	key  [32]byte

	writeOnce sync.Once
	readOnce  sync.Once

	encStream cipher.Stream
	decStream cipher.Stream

	bufIV [ivSize]byte
}

// NewSecureStreamConn 创建一个支持流加密的连接，不预发送 IV，而是与首个数据拼接发送
func NewSecureStreamConn(conn net.Conn, key [32]byte) *SecureStreamConn {
	return &SecureStreamConn{
		conn: conn,
		key:  key,
	}
}

// Write 会在首次调用时拼接 IV 和密文发送
func (s *SecureStreamConn) Write(p []byte) (int, error) {
	var outBuf []byte
	var err error

	s.writeOnce.Do(func() {
		if _, err = rand.Read(s.bufIV[:]); err != nil {
			return
		}
		block, e := aes.NewCipher(s.key[:])
		if e != nil {
			err = e
			return
		}
		s.encStream = cipher.NewCTR(block, s.bufIV[:])

		// 首次写，拼接 IV + 加密数据
		ciphertext := make([]byte, len(p))
		s.encStream.XORKeyStream(ciphertext, p)
		outBuf = append(s.bufIV[:], ciphertext...)
	})

	if err != nil {
		return 0, err
	}

	// 首次写：发送拼接的 [IV|CIPHERTEXT]
	// 之后写：只发送加密数据
	if outBuf != nil {
		nw, err := s.WriteFull(outBuf)
		if err != nil {
			return 0, err
		}
		return nw - len(s.bufIV), nil
	}

	// 后续写：仅加密数据
	ciphertext := make([]byte, len(p))
	s.encStream.XORKeyStream(ciphertext, p)
	return s.WriteFull(ciphertext)
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

// Read 会在首次调用时读取 IV 并初始化解密流
func (s *SecureStreamConn) Read(p []byte) (int, error) {
	var err error

	s.readOnce.Do(func() {
		// 读取 IV
		if _, err = io.ReadFull(s.conn, s.bufIV[:]); err != nil {
			return
		}
		block, e := aes.NewCipher(s.key[:])
		if e != nil {
			err = e
			return
		}
		s.decStream = cipher.NewCTR(block, s.bufIV[:])
	})

	if err != nil {
		return 0, err
	}

	// 读取并解密
	n, err := s.conn.Read(p)
	if n > 0 && s.decStream != nil {
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

type SecurePacketConn struct {
	conn net.Conn
	key  [32]byte
}

func NewSecurePacketConn(conn net.Conn, key [32]byte) *SecurePacketConn {
	return &SecurePacketConn{
		conn: conn,
		key:  key,
	}
}

// Write 每次发送格式：[IV | Ciphertext]
func (s *SecurePacketConn) Write(p []byte) (int, error) {
	var iv [ivSize]byte
	if _, err := rand.Read(iv[:]); err != nil {
		return 0, err
	}

	block, err := aes.NewCipher(s.key[:])
	if err != nil {
		return 0, err
	}

	stream := cipher.NewCTR(block, iv[:])
	ciphertext := make([]byte, len(p))
	stream.XORKeyStream(ciphertext, p)

	packet := append(iv[:], ciphertext...)
	_, err = s.conn.Write(packet)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read 解析格式：[IV | Ciphertext]
func (s *SecurePacketConn) Read(p []byte) (int, error) {
	if len(p) < ivSize {
		return 0, io.ErrShortBuffer
	}

DoRead:
	// 直接读取进 p
	n, err := s.conn.Read(p)
	if err != nil {
		return 0, err
	}
	if n < ivSize {
		//drop
		goto DoRead
	}

	iv := p[:ivSize]
	ciphertext := p[ivSize:n]

	block, err := aes.NewCipher(s.key[:])
	if err != nil {
		return 0, err
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	// 将解密后的数据就地使用（p[ivSize:n] 已被就地解密）
	copy(p, ciphertext)

	return n - ivSize, nil
}

// 透传 Conn 接口
func (s *SecurePacketConn) Close() error                       { return s.conn.Close() }
func (s *SecurePacketConn) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *SecurePacketConn) RemoteAddr() net.Addr               { return s.conn.RemoteAddr() }
func (s *SecurePacketConn) SetDeadline(t time.Time) error      { return s.conn.SetDeadline(t) }
func (s *SecurePacketConn) SetReadDeadline(t time.Time) error  { return s.conn.SetReadDeadline(t) }
func (s *SecurePacketConn) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }
