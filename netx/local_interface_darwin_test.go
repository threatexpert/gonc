package netx

import (
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"syscall"
)

func checkLocalSocketInterface(raw syscall.RawConn, ip net.IP, iface net.Interface) error {
	level, option := unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
	if ip.To4() != nil {
		level, option = unix.IPPROTO_IP, unix.IP_BOUND_IF
	}
	var index int
	var optionErr error
	if err := raw.Control(func(fd uintptr) { index, optionErr = unix.GetsockoptInt(int(fd), level, option) }); err != nil {
		return err
	}
	if optionErr != nil {
		return optionErr
	}
	if index != iface.Index {
		return fmt.Errorf("bound interface=%d, want %d", index, iface.Index)
	}
	return nil
}
