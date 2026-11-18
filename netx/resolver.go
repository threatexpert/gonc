package netx

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// NewBoundResolver routes only this resolver's DNS sockets through localIP.
// The DNS server must be an IP literal: bootstrapping it must not recurse into
// the system resolver (which may already depend on the disconnected VPN).
func NewBoundResolver(server, localIP string) (*net.Resolver, error) {
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
	localHost, zone, _ := strings.Cut(localIP, "%")
	local := net.ParseIP(localHost)
	if localIP != "" && local == nil {
		return nil, fmt.Errorf("invalid local DNS address %q", localIP)
	}
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second}
		if local != nil {
			if strings.HasPrefix(network, "udp") {
				d.LocalAddr = &net.UDPAddr{IP: local, Zone: zone}
			} else {
				d.LocalAddr = &net.TCPAddr{IP: local, Zone: zone}
			}
		}
		d.Control = LocalAddrControl(d.LocalAddr, nil)
		return d.DialContext(ctx, network, server)
	}}, nil
}
