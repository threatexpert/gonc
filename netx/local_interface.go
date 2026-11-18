package netx

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"syscall"
)

type socketControl = func(string, string, syscall.RawConn) error

// ListenUDP also constrains UDP sockets recreated by NAT traversal.
func ListenUDP(network string, local *net.UDPAddr) (*net.UDPConn, error) {
	control := LocalAddrControl(local, nil)
	if control == nil {
		return net.ListenUDP(network, local)
	}
	lc := net.ListenConfig{Control: control}
	conn, err := lc.ListenPacket(context.Background(), network, local.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}

func localInterfaceIndex(ip net.IP, zone string) (int, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return 0, err
	}
	return interfaceIndexForIP(ip, zone, interfaces, func(iface net.Interface) ([]net.Addr, error) { return iface.Addrs() })
}

// localInterfaceControl composes interface binding with existing socket options.
// Resolve the interface for every new socket: interface indexes and addresses can
// change while a persistent connection is retrying.
func localInterfaceControl(local net.Addr, previous socketControl, bind func(syscall.RawConn, net.IP, string) error) socketControl {
	var ip net.IP
	var zone string
	switch a := local.(type) {
	case *net.TCPAddr:
		if a != nil {
			ip, zone = a.IP, a.Zone
		}
	case *net.UDPAddr:
		if a != nil {
			ip, zone = a.IP, a.Zone
		}
	}
	if len(ip) == 0 || ip.IsUnspecified() || ip.IsLoopback() {
		return previous
	}
	ip = append(net.IP(nil), ip...)
	return func(network, address string, conn syscall.RawConn) error {
		if err := bind(conn, ip, zone); err != nil {
			return fmt.Errorf("bind local interface for %s: %w", local, err)
		}
		if previous != nil {
			return previous(network, address, conn)
		}
		return nil
	}
}

func interfaceIndexForIP(ip net.IP, zone string, interfaces []net.Interface, addrs func(net.Interface) ([]net.Addr, error)) (int, error) {
	index := 0
	for _, iface := range interfaces {
		if zone != "" && zone != iface.Name && zone != strconv.Itoa(iface.Index) {
			continue
		}
		addresses, err := addrs(iface)
		if err != nil {
			return 0, fmt.Errorf("read addresses of %s: %w", iface.Name, err)
		}
		for _, address := range addresses {
			var candidate net.IP
			switch a := address.(type) {
			case *net.IPNet:
				candidate = a.IP
			case *net.IPAddr:
				candidate = a.IP
			}
			if !ip.Equal(candidate) {
				continue
			}
			if index != 0 && index != iface.Index {
				return 0, fmt.Errorf("local IP %s belongs to multiple interfaces; specify an IPv6 zone where applicable", ip)
			}
			index = iface.Index
		}
	}
	if index == 0 {
		return 0, fmt.Errorf("no interface owns local IP %s (zone %q)", ip, zone)
	}
	return index, nil
}
