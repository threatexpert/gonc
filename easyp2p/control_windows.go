package easyp2p

import (
	"errors"
	"fmt"
	"net"
	"os"
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

// isMessageSizeError checks for the "message too long" error on Windows.
func isMessageSizeError(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		var sysErr *os.SyscallError
		if errors.As(opErr.Err, &sysErr) {
			// On Windows, the error is WSAEMSGSIZE
			return sysErr.Err == windows.WSAEMSGSIZE
		}
	}
	return false
}
