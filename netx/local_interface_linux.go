//go:build linux && !android

package netx

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

func LocalAddrControl(local net.Addr, previous socketControl) socketControl {
	return linuxSocketControl(local, previous, "")
}

// RegisterLinuxSocketBinder delegates sockets explicitly bound to this source IP.
// dns is nonempty only for a NewBoundResolver socket. The callback must finish
// configuring the socket before returning. Release removes only this registration.
func RegisterLinuxSocketBinder(ip, dnsServer string, bind func(syscall.RawConn, string) error) (release func()) {
	entry := &linuxBinder{bind: bind, dns: dnsServer}
	linuxBinders.Store(ip, entry)
	return func() { linuxBinders.CompareAndDelete(ip, entry) }
}

type linuxBinder struct {
	dns  string
	bind func(syscall.RawConn, string) error
}

var linuxBinders sync.Map

func init() {
	resolverSocketControl = func(local net.Addr, server string) socketControl {
		return linuxSocketControl(local, nil, server)
	}
}
func linuxSocketControl(local net.Addr, previous socketControl, dns string) socketControl {
	return localInterfaceControl(local, previous, func(c syscall.RawConn, ip net.IP, zone string) error {
		entry, ok := linuxBinders.Load(ip.String())
		if ok && dns != "" && dns == entry.(*linuxBinder).dns {
			return entry.(*linuxBinder).bind(c, dns)
		}
		err := bindLocalInterface(c, ip, zone)
		if ok && (errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES)) {
			return entry.(*linuxBinder).bind(c, "")
		}
		return err
	})
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
