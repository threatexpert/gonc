package misc

import (
	"errors"
	"fmt"
	"io"
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
