package tunengine

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/xjasonlyu/tun2socks/v2/proxy"
	"github.com/xjasonlyu/tun2socks/v2/proxy/socks5"
)

// UpdateProxy changes the running engine's SOCKS5 endpoint without closing the
// TUN or restarting its stack. It accepts socks5://[user:pass@]host:port or
// host:port, including bracketed IPv6 addresses. It performs no network I/O;
// success means the new configuration was installed, not that it is reachable.
// Invalid configuration leaves the current proxy unchanged.
//
// Only subsequent proxy dials use the new object. Existing TCP connections,
// UDP associations, in-flight dials and deferred-TCP failure cache are unchanged.
// Updates are serialized with Start and Stop; a stopped engine returns
// ErrNotRunning. This function does not change OS routes or DNS.
func UpdateProxy(address string) error { return shared.UpdateProxy(address) }

func (c *controller) UpdateProxy(address string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return ErrNotRunning
	}
	p, err := newSOCKSProxy(address)
	if err != nil {
		return err
	}
	c.setProxy(p)
	return nil
}

func newSOCKSProxy(address string) (proxy.Proxy, error) {
	address = strings.TrimSpace(address)
	if !strings.Contains(address, "://") {
		address = "socks5://" + address
	}
	u, err := url.Parse(address)
	// Do not include the input URL in errors: it may contain credentials.
	if err != nil || u.Scheme != "socks5" || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("tunengine: expected a SOCKS5 host:port URL without path, query or fragment")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || strings.TrimSpace(host) == "" || strings.ContainsAny(host, " \t\r\n") {
		return nil, errors.New("tunengine: SOCKS5 host and port are required")
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return nil, errors.New("tunengine: SOCKS5 port must be between 1 and 65535")
	}
	user := u.User.Username()
	password, _ := u.User.Password()
	if len(user) > 255 || len(password) > 255 || (user == "" && password != "") {
		return nil, errors.New("tunengine: invalid SOCKS5 credentials")
	}
	return socks5.New(net.JoinHostPort(host, port), user, password)
}
