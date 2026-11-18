//go:build darwin

package netx

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// LocalAddrControl keeps explicitly source-bound sockets on their owning
// interface on macOS. A usable route in that interface scope is still required.
// Loopback and wildcard binds retain normal system routing.
func LocalAddrControl(local net.Addr, previous socketControl) socketControl {
	return localInterfaceControl(local, previous, bindLocalInterface)
}

func bindLocalInterface(conn syscall.RawConn, ip net.IP, zone string) error {
	index, err := localInterfaceIndex(ip, zone)
	if err != nil {
		return err
	}
	level, option := unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
	if ip.To4() != nil {
		level, option = unix.IPPROTO_IP, unix.IP_BOUND_IF
	}
	var optionErr error
	if err := conn.Control(func(fd uintptr) {
		optionErr = unix.SetsockoptInt(int(fd), level, option, index)
	}); err != nil {
		return err
	}
	if optionErr != nil {
		return fmt.Errorf("set bound interface %d: %w", index, optionErr)
	}
	return nil
}
