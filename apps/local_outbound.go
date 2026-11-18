package apps

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/threatexpert/gonc/v2/netx"
)

// Auxiliary connections use the selected IP/interface, but allocate their own
// port instead of competing with the P2P/STUN socket's -local port.
func proxyLocalAddr(network, localIP string) (net.Addr, error) {
	if localIP == "" {
		return nil, nil
	}
	host, zone, _ := strings.Cut(localIP, "%")
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid local IP %q", localIP)
	}
	if strings.HasPrefix(network, "udp") {
		return &net.UDPAddr{IP: ip, Zone: zone}, nil
	}
	return &net.TCPAddr{IP: ip, Zone: zone}, nil
}

func newBoundHTTPClient(localIP string, timeout time.Duration) (*http.Client, func(), error) {
	local, err := proxyLocalAddr("tcp", localIP)
	if err != nil {
		return nil, nil, err
	}
	d := &net.Dialer{Timeout: timeout, LocalAddr: local, Control: netx.LocalAddrControl(local, nil)}
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         d.DialContext,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: timeout,
	}
	// Redirects and connections to an environment HTTP proxy use this same
	// bound transport. DNS continues to use the process default resolver.
	return &http.Client{Transport: tr, Timeout: timeout}, tr.CloseIdleConnections, nil
}
