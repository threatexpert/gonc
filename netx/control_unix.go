//go:build !windows

package netx

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func ControlTCP(network, address string, c syscall.RawConn) error {
	var err error
	c.Control(func(fd uintptr) {
		if err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			return
		}

		if err2 := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err2 != nil {
			return
		}

	})

	return err
}

func ControlUDP(network, address string, c syscall.RawConn) error {
	var err error
	c.Control(func(fd uintptr) {
		if err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			return
		}
	})

	return err
}

func SetUDPTTL(pconn net.PacketConn, ttl int) error {
	conn, ok := pconn.(*net.UDPConn)
	if !ok {
		return fmt.Errorf("expected *net.UDPConn, got %T", pconn)
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("get rawconn error: %v", err)
	}

	var sockErr error
	err = rawConn.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
	})
	if sockErr != nil {
		return sockErr
	}
	if err != nil {
		return err
	}
	return nil
}

// isMessageSizeError 检查是否为 "message too long" 错误 (Unix 版本)
func isMessageSizeError(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		var sysErr *os.SyscallError
		if errors.As(opErr.Err, &sysErr) {
			// 在类 Unix 系统上，检查 EMSGSIZE
			return sysErr.Err == unix.EMSGSIZE
		}
	}
	// 兼容旧的或一些特殊情况
	return errors.Is(err, syscall.EMSGSIZE)
}
