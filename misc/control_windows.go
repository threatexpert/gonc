package misc

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

func ControlUDP(network, address string, c syscall.RawConn) (err error) {
	c.Control(func(fd uintptr) {
		err = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
	})

	return
}

var ControlTCP = ControlUDP

func PeekSourceAddr(conn *net.UDPConn) (*net.UDPAddr, error) {
	// 获取底层 fd
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

		n, from, err := windows.Recvfrom(windows.Handle(fd), buf, windows.MSG_PEEK)
		if err != nil {
			peekErr = fmt.Errorf("recvfrom peek error: %v", err)
			return false
		}
		if n == 0 {
			peekErr = fmt.Errorf("no data peeked")
			return false
		}

		switch sa := from.(type) {
		case *windows.SockaddrInet4:
			srcAddr = &net.UDPAddr{
				IP:   sa.Addr[:],
				Port: sa.Port,
			}
		case *windows.SockaddrInet6:
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
