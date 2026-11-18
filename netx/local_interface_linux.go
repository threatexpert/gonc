//go:build linux && !android

package netx

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func LocalAddrControl(local net.Addr, previous socketControl) socketControl {
	return localInterfaceControl(local, previous, bindLocalInterface)
}

func bindLocalInterface(conn syscall.RawConn, ip net.IP, zone string) error {
	index, err := localInterfaceIndex(ip, zone)
	if err != nil {
		return err
	}
	iface, err := net.InterfaceByIndex(index)
	if err != nil {
		return err
	}
	var optionErr error
	if err := conn.Control(func(fd uintptr) {
		optionErr = unix.BindToDevice(int(fd), iface.Name)
	}); err != nil {
		return err
	}
	if errors.Is(optionErr, unix.EPERM) || errors.Is(optionErr, unix.EACCES) {
		return fmt.Errorf("bind socket to %s: this kernel or network namespace requires CAP_NET_RAW: %w", iface.Name, optionErr)
	}
	if optionErr != nil {
		return fmt.Errorf("bind socket to %s: %w", iface.Name, optionErr)
	}
	return nil
}
