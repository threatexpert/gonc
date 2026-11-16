// Package tunengine wraps the process-wide tun2socks engine for desktop and
// mobile callers. It does not configure OS routes, DNS, permissions or FD tags.
// The gonc command-line entry point does not import this package.
package tunengine

import (
	"errors"
	"strings"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/engine"
)

const (
	DefaultSOCKSHandshakeTimeout = 30 * time.Second
	DefaultFailureCacheTTL       = 30 * time.Second
	DefaultFailureCacheCapacity  = 4096
)

// DeferredTCPConfig enables remote-first TCP handshakes. Zero fields use the
// shared defaults. Connecting to the proxy itself retains the fixed 5s timeout.
type DeferredTCPConfig struct {
	SOCKSHandshakeTimeout time.Duration
	FailureCacheTTL       time.Duration
	FailureCacheCapacity  int
}

// Config is independent of tun2socks's public types. A nil DeferredTCP keeps
// legacy TCP behavior. RejectIPv6 independently rejects captured IPv6 TCP/UDP.
type Config struct {
	Device      string
	Proxy       string
	MTU         int
	LogLevel    string
	DeferredTCP *DeferredTCPConfig
	RejectIPv6  bool
}

func (c Config) key() (*engine.Key, error) {
	if strings.TrimSpace(c.Device) == "" || strings.TrimSpace(c.Proxy) == "" {
		return nil, errors.New("tunengine: device and proxy are required")
	}
	if c.MTU < 0 {
		return nil, errors.New("tunengine: MTU must not be negative")
	}
	if c.MTU == 0 {
		c.MTU = 1400
	}
	if strings.TrimSpace(c.LogLevel) == "" {
		c.LogLevel = "warn"
	}
	k := &engine.Key{Device: c.Device, Proxy: c.Proxy, MTU: c.MTU, LogLevel: c.LogLevel, RejectIPv6: c.RejectIPv6}
	if c.DeferredTCP != nil {
		d := *c.DeferredTCP // Never change the caller's config.
		if d.SOCKSHandshakeTimeout < 0 || d.FailureCacheTTL < 0 || d.FailureCacheCapacity < 0 {
			return nil, errors.New("tunengine: deferred TCP settings must not be negative")
		}
		if d.SOCKSHandshakeTimeout == 0 {
			d.SOCKSHandshakeTimeout = DefaultSOCKSHandshakeTimeout
		}
		if d.FailureCacheTTL == 0 {
			d.FailureCacheTTL = DefaultFailureCacheTTL
		}
		if d.FailureCacheCapacity == 0 {
			d.FailureCacheCapacity = DefaultFailureCacheCapacity
		}
		k.TCPDeferredHandshake = true
		k.TCPSOCKSHandshakeTimeout = d.SOCKSHandshakeTimeout
		k.TCPFailureCacheTTL = d.FailureCacheTTL
		k.TCPFailureCacheCapacity = d.FailureCacheCapacity
	}
	return k, nil
}
