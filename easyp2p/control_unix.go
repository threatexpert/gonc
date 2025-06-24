//go:build !windows

package easyp2p

import (
	"fmt"
	"net"
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

func ControlTCPTTL(network, address string, c syscall.RawConn) error {
	var err error
	c.Control(func(fd uintptr) {
		if err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			return
		}
		if err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			return
		}
		if err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, PunchingShortTTL); err != nil {
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

func SetUDPTTL(conn *net.UDPConn, ttl int) error {
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
