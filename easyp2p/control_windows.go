package easyp2p

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

func ControlUDP(network, address string, c syscall.RawConn) (err error) {
	c.Control(func(fd uintptr) {
		if err = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1); err != nil {
			return
		}
	})

	return
}

var ControlTCP = ControlUDP

func SetUDPTTL(conn *net.UDPConn, ttl int) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("get rawconn error: %v", err)
	}

	var sockErr error
	err = rawConn.Control(func(fd uintptr) {
		sockErr = windows.SetsockoptInt(windows.Handle(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
	})
	if sockErr != nil {
		return sockErr
	}
	if err != nil {
		return err
	}
	return nil
}

func ControlTCPTTL(network, address string, c syscall.RawConn) (err error) {
	c.Control(func(fd uintptr) {
		if err = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1); err != nil {
			return
		}
		if err = windows.SetsockoptInt(windows.Handle(fd), syscall.IPPROTO_IP, syscall.IP_TTL, PunchingShortTTL); err != nil {
			return
		}
	})

	return
}
