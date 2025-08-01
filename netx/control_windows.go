package netx

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
