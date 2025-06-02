//go:build !windows

package misc

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
		if err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
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

func PeekSourceAddr(conn *net.UDPConn) (*net.UDPAddr, error) {
	// 获取 fd
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("get rawconn error: %v", err)
	}

	var srcAddr *net.UDPAddr
	var peekErr error

	err = rawConn.Read(func(fd uintptr) bool {
		if srcAddr != nil {
			return true
		}
		buf := make([]byte, 0xffff)
		n, sa, err := unix.Recvfrom(int(fd), buf, unix.MSG_PEEK)
		if err != nil {
			peekErr = fmt.Errorf("recvfrom peek error: %v", err)
			return false
		}
		if n == 0 {
			peekErr = fmt.Errorf("no data peeked")
			return false
		}

		switch sa := sa.(type) {
		case *unix.SockaddrInet4:
			srcAddr = &net.UDPAddr{
				IP:   sa.Addr[:],
				Port: sa.Port,
			}
		case *unix.SockaddrInet6:
			srcAddr = &net.UDPAddr{
				IP:   sa.Addr[:],
				Port: sa.Port,
				Zone: zoneToString(uint32(sa.ZoneId)),
			}
		default:
			peekErr = fmt.Errorf("unknown sockaddr type")
			return false
		}

		return true
	})
	// 优先返回已获取的地址
	if srcAddr != nil {
		return srcAddr, nil
	}

	if err != nil {
		return nil, fmt.Errorf("rawconn read error: %v", err)
	}
	if peekErr != nil {
		return nil, peekErr
	}

	return nil, fmt.Errorf("failed to peek source address")
}

func zoneToString(zoneId uint32) string {
	ifi, err := net.InterfaceByIndex(int(zoneId))
	if err != nil {
		return ""
	}
	return ifi.Name
}
