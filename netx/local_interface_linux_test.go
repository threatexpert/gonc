//go:build linux && !android

package netx

import (
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"syscall"
)

func checkLocalSocketInterface(raw syscall.RawConn, _ net.IP, iface net.Interface) error {
	var name string
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		name, optionErr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	}); err != nil {
		return err
	}
	if optionErr != nil {
		return optionErr
	}
	if name != iface.Name {
		return fmt.Errorf("bound interface=%q, want %q", name, iface.Name)
	}
	return nil
}
