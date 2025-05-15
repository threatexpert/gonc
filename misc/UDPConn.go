package misc

import (
	"fmt"
	"net"
	"time"
)

type BoundUDPConn struct {
	conn       *net.UDPConn
	remoteAddr *net.UDPAddr
}

// NewBoundUDPConn 创建绑定目标地址的 UDP 封装
func NewBoundUDPConn(conn *net.UDPConn, remoteAddr *net.UDPAddr) *BoundUDPConn {
	return &BoundUDPConn{
		conn:       conn,
		remoteAddr: remoteAddr,
	}
}

// Write 会自动向 remoteAddr 发送数据
func (b *BoundUDPConn) Write(p []byte) (int, error) {
	if b.remoteAddr == nil {
		return 0, fmt.Errorf("remote address not set")
	}
	return b.conn.WriteToUDP(p, b.remoteAddr)
}

// Read 直接读取数据
func (b *BoundUDPConn) Read(p []byte) (int, error) {
	return b.conn.Read(p)
}

// Close 关闭底层连接
func (b *BoundUDPConn) Close() error {
	return b.conn.Close()
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
