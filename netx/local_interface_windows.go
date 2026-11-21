package netx

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

// Both Winsock UNICAST_IF options have value 31. IPv4 takes a network-order
// DWORD, whereas IPv6 takes a host-order DWORD.
const ipUnicastIF = 31

func LocalAddrControl(local net.Addr, previous socketControl) socketControl {
	return localInterfaceControl(local, previous, bindLocalInterface)
}

func bindLocalInterface(conn syscall.RawConn, ip net.IP, zone string) error {
	index, err := localInterfaceIndex(ip, zone)
	if err != nil {
		return err
	}
	return bindInterfaceIndex(conn, index, ip.To4() != nil)
}

func bindNamedInterface(conn syscall.RawConn, iface *net.Interface, network, _ string) error {
	return bindInterfaceIndex(conn, iface.Index, strings.HasSuffix(network, "4"))
}

func bindInterfaceIndex(conn syscall.RawConn, index int, ipv4 bool) error {
	var optionErr error
	if err := conn.Control(func(fd uintptr) {
		if ipv4 {
			var value [4]byte
			binary.BigEndian.PutUint32(value[:], uint32(index))
			optionErr = windows.SetsockoptInet4Addr(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIF, value)
		} else {
			optionErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, ipUnicastIF, index)
		}
	}); err != nil {
		return err
	}
	if optionErr != nil {
		return fmt.Errorf("set outgoing interface %d: %w", index, optionErr)
	}
	return nil
}
