package netx

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

// TunnelNetwork configures only transport sockets created for one embedded
// tunnel. The host callback also applies any explicit interface constraint.
type TunnelNetwork struct {
	bind     func(syscall.RawConn) error
	resolver *net.Resolver
}

func NewTunnelNetwork(dns string, source string, bind func(syscall.RawConn) error) (*TunnelNetwork, error) {
	if _, err := netip.ParseAddrPort(dns); err != nil {
		return nil, fmt.Errorf("invalid tunnel DNS endpoint: %w", err)
	}
	if bind == nil {
		return nil, fmt.Errorf("missing tunnel socket control")
	}
	s := &TunnelNetwork{bind: bind}
	s.resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		local, err := SourceAddr(network, source)
		if err != nil {
			return nil, err
		}
		d := s.Dialer(local, nil)
		d.Timeout = 5 * time.Second
		return d.DialContext(ctx, network, dns)
	}}
	return s, nil
}

type tunnelNetworkKey struct{}

func WithTunnelNetwork(ctx context.Context, s *TunnelNetwork) context.Context {
	if s == nil {
		return ctx
	}
	return context.WithValue(ctx, tunnelNetworkKey{}, s)
}

func TunnelNetworkFrom(ctx context.Context) *TunnelNetwork {
	if ctx == nil {
		return nil
	}
	s, _ := ctx.Value(tunnelNetworkKey{}).(*TunnelNetwork)
	return s
}

func (s *TunnelNetwork) Control(previous socketControl) socketControl {
	return func(network, address string, raw syscall.RawConn) error {
		if err := s.bind(raw); err != nil {
			return err
		}
		if previous != nil {
			return previous(network, address, raw)
		}
		return nil
	}
}

func (s *TunnelNetwork) Dialer(local net.Addr, previous socketControl) *net.Dialer {
	if s == nil {
		return BoundDialer(local, previous)
	}
	if _, ok := local.(InterfaceAddr); ok {
		local = nil
	}
	return &net.Dialer{LocalAddr: local, Control: s.Control(previous), Resolver: s.resolver}
}

func (s *TunnelNetwork) ListenUDP(ctx context.Context, network string, local *net.UDPAddr) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: s.Control(nil)}
	addr := ":0"
	if local != nil {
		addr = local.String()
	}
	conn, err := lc.ListenPacket(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}

func (s *TunnelNetwork) resolveUDP(ctx context.Context, network, address string) (*net.UDPAddr, error) {
	if s == nil {
		return net.ResolveUDPAddr(network, address)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	n, err := net.LookupPort("udp", port)
	if err != nil {
		return nil, err
	}
	family := "ip" + strings.TrimPrefix(network, "udp")
	ips, err := s.resolver.LookupNetIP(ctx, family, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no %s addresses for %s", family, host)
	}
	return &net.UDPAddr{IP: ips[0].AsSlice(), Zone: ips[0].Zone(), Port: n}, nil
}
