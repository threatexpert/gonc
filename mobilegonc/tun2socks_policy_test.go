package mobilegonc

import (
	"testing"
)

// Both gomobile-facing signatures remain available to existing/new APKs.
var _ func(int, string, string, int, string) error = StartTun2Socks
var _ func(int, string, string, int, string, bool, bool) error = StartTun2SocksWithPolicy

func TestTun2SocksPolicyModes(t *testing.T) {
	for _, deferred := range []bool{false, true} {
		for _, reject := range []bool{false, true} {
			key := tun2SocksConfig("fd://512", "socks5://127.0.0.1:1080", 1400, "warn", deferred, reject)
			if key.Device != "fd://512" || key.Proxy != "socks5://127.0.0.1:1080" || key.MTU != 1400 || key.LogLevel != "warn" {
				t.Fatalf("lost engine settings: %+v", key)
			}
			if (key.DeferredTCP != nil) != deferred || key.RejectIPv6 != reject {
				t.Fatalf("policy flags not independent: %+v", key)
			}
			if deferred && (key.DeferredTCP.ProxyHandshakeTimeout != 0 || key.DeferredTCP.FailureCacheTTL != 0 || key.DeferredTCP.FailureCacheCapacity != 0) {
				t.Fatalf("mobile should use shared defaults: %+v", key)
			}
		}
	}
}

func TestTun2SocksRecoveryDoesNotRetainRejection(t *testing.T) {
	first := tun2SocksConfig("fd://512", "socks5://127.0.0.1:1080", 1400, "warn", true, true)
	recovered := tun2SocksConfig("fd://513", "socks5://127.0.0.1:1080", 1400, "warn", true, false)
	if !first.RejectIPv6 || recovered.RejectIPv6 || recovered.DeferredTCP == nil {
		t.Fatal("reconnection mutated or retained the previous policy")
	}
}
