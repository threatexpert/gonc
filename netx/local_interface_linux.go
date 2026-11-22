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

// RegisterLinuxSocketBinder delegates sockets explicitly bound to this IP or device.
// dns is nonempty only for a NewBoundResolver socket. The callback must finish
// configuring the socket before returning. Release removes only this registration.
func RegisterLinuxSocketBinder(source, dnsServer string, bind func(syscall.RawConn, string) error) (release func()) {
	return registerLinuxBinder(source, &linuxBinder{bind: bind, dns: dnsServer})
}

// RegisterLinuxProtectedSocketBinder configures every socket with the selected
// source before its first packet, even if ordinary device binding is permitted.
func RegisterLinuxProtectedSocketBinder(source, dnsServer string, bind func(syscall.RawConn, string) error) func() {
	return registerLinuxBinder(source, &linuxBinder{bind: bind, dns: dnsServer, required: true})
}

func registerLinuxBinder(source string, entry *linuxBinder) func() {
	linuxBinders.Store(source, entry)
	return func() { linuxBinders.CompareAndDelete(source, entry) }
}

type linuxBinder struct {
	required bool
	dns      string
	bind     func(syscall.RawConn, string) error
}

var linuxBinders sync.Map

func init() {
	resolverSocketControl = func(local net.Addr, server string) socketControl {
		return linuxSocketControl(local, nil, server)
	}
}

func linuxSocketControl(local net.Addr, previous socketControl, dns string) socketControl {
	return localInterfaceControl(local, previous, func(c syscall.RawConn, ip net.IP, zone string) error {
		return bindLinuxSocket(c, ip.String(), dns, func() error { return bindLocalInterface(c, ip, zone) })
	})
}

func bindNamedInterface(c syscall.RawConn, iface *net.Interface, network, dns string) error {
	return bindLinuxSocket(c, iface.Name, dns, func() error { return bindLinuxDevice(c, iface.Name) })
}

func bindLinuxSocket(c syscall.RawConn, key, dns string, direct func() error) error {
	entry, ok := linuxBinders.Load(key)
	if ok && dns != "" && dns == entry.(*linuxBinder).dns {
		return entry.(*linuxBinder).bind(c, dns)
	}
	if ok && entry.(*linuxBinder).required {
		return entry.(*linuxBinder).bind(c, "")
	}
	err := direct()
	if ok && (errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES)) {
		return entry.(*linuxBinder).bind(c, "")
	}
	return err
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
	return bindLinuxDevice(conn, iface.Name)
}

func bindLinuxDevice(conn syscall.RawConn, name string) error {
	var optionErr error
	if err := conn.Control(func(fd uintptr) {
		optionErr = unix.BindToDevice(int(fd), name)
	}); err != nil {
		return err
	}
	if errors.Is(optionErr, unix.EPERM) || errors.Is(optionErr, unix.EACCES) {
		return fmt.Errorf("bind socket to %s: this kernel or network namespace requires CAP_NET_RAW: %w", name, optionErr)
	}
	if optionErr != nil {
		return fmt.Errorf("bind socket to %s: %w", name, optionErr)
	}
	return nil
}
