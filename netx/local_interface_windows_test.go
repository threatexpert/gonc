package netx

import (
	"fmt"
	"golang.org/x/sys/windows"
	"net"
	"syscall"
)

func checkLocalSocketInterface(raw syscall.RawConn, ip net.IP, iface net.Interface) error {
	level := windows.IPPROTO_IPV6
	if ip.To4() != nil {
		level = windows.IPPROTO_IP
	}
	var index int
	var optionErr error
	if err := raw.Control(func(fd uintptr) { index, optionErr = windows.GetsockoptInt(windows.Handle(fd), level, ipUnicastIF) }); err != nil {
		return err
	}
	if optionErr != nil {
		return optionErr
	}
	// Winsock returns host byte order for both options, unlike the IPv4 setter.
	if index != iface.Index {
		return fmt.Errorf("outgoing interface=%d, want %d", index, iface.Index)
	}
	return nil
}
