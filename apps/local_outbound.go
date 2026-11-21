package apps

import (
	"net/http"
	"time"

	"github.com/threatexpert/gonc/v2/netx"
)

func newBoundHTTPClient(source string, timeout time.Duration) (*http.Client, func(), error) {
	local, err := netx.SourceAddr("tcp", source)
	if err != nil {
		return nil, nil, err
	}
	d := netx.BoundDialer(local, nil)
	d.Timeout = timeout
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
