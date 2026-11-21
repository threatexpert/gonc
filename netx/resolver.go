package netx

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// Linux supplies a distinct control hook so an embedder can identify bootstrap DNS.
var resolverSocketControl = func(local net.Addr, _ string) socketControl {
	return LocalAddrControl(local, nil)
}

// NewBoundResolver routes only this resolver's DNS sockets through the requested source IP or device.
// The DNS server must be an IP literal: bootstrapping it must not recurse into
// the system resolver (which may already depend on the disconnected VPN).
func NewBoundResolver(server, source string) (*net.Resolver, error) {
	server = strings.TrimSpace(server)
	if ip := net.ParseIP(strings.Trim(server, "[]")); ip != nil {
		server = net.JoinHostPort(ip.String(), "53")
	}
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		return nil, fmt.Errorf("invalid DNS server: %w", err)
	}
	if net.ParseIP(host) == nil {
		return nil, fmt.Errorf("DNS server must be an IP address")
	}
	if _, err := net.LookupPort("udp", port); err != nil {
		return nil, err
	}
	// Validate before publishing the process-wide resolver.
	udp, err := SourceAddr("udp", source)
	if err != nil {
		return nil, err
	}
	tcp := udp
	if addr, ok := udp.(*net.UDPAddr); ok {
		tcp = &net.TCPAddr{IP: addr.IP, Zone: addr.Zone}
	}
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		local := udp
		if strings.HasPrefix(network, "tcp") {
			local = tcp
		}
		d := net.Dialer{Timeout: 5 * time.Second}
		if dev, ok := local.(InterfaceAddr); ok {
			d.Control = deviceControl(string(dev), nil, server)
		} else {
			d.LocalAddr = local
			d.Control = resolverSocketControl(local, server)
		}
		return d.DialContext(ctx, network, server)
	}}, nil
}
