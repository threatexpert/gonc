package mobilegonc

import (
	"time"

	"github.com/xjasonlyu/tun2socks/v2/engine"
)

// Keep the mobile opt-in policy aligned with gonc-gui's desktop engine policy.
// The old entry point supplies false/false and retains the library defaults.
func tun2SocksKey(device, proxyURL string, mtu int, logLevel string, deferredTCP, rejectIPv6 bool) *engine.Key {
	key := &engine.Key{
		Device: device, Proxy: proxyURL, MTU: mtu, LogLevel: logLevel,
		TCPDeferredHandshake: deferredTCP, RejectIPv6: rejectIPv6,
	}
	if deferredTCP {
		key.TCPSOCKSHandshakeTimeout = 30 * time.Second
		key.TCPFailureCacheTTL = 30 * time.Second
		key.TCPFailureCacheCapacity = 4096
	}
	return key
}
