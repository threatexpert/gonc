package easyp2p

import (
	"context"
	"net"
	"net/netip"
	"syscall"

	"github.com/threatexpert/gonc/v2/netx"
)

// STUN-derived addresses are not an explicit -local request. Preserve normal
// routing and Linux privilege requirements when no source IP was requested.
func (s *P2PSessionContext) bindsLocalInterface() bool {
	if s == nil {
		return false
	}
	if s.localDevice != "" {
		return true
	}
	ip, err := netip.ParseAddr(s.LocalBindIP)
	return err == nil && !ip.IsUnspecified() && !ip.IsLoopback()
}

func (s *P2PSessionContext) localControl(local net.Addr, previous func(string, string, syscall.RawConn) error) func(string, string, syscall.RawConn) error {
	if !s.bindsLocalInterface() {
		return previous
	}
	if s.localDevice != "" {
		return netx.InterfaceControl(s.localDevice, previous)
	}
	return netx.LocalAddrControl(local, previous)
}

func (s *P2PSessionContext) listenUDP(network string, local *net.UDPAddr) (*net.UDPConn, error) {
	if !s.bindsLocalInterface() {
		return net.ListenUDP(network, local)
	}
	if s.localDevice != "" {
		return netx.ListenInterfaceUDP(context.Background(), network, local, s.localDevice)
	}
	return netx.ListenUDP(network, local)
}
