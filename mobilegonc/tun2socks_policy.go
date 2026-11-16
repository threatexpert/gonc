package mobilegonc

import "github.com/threatexpert/gonc/v2/tunengine"

// The old entry point supplies false/false. Shared defaults live in tunengine.
func tun2SocksConfig(device, proxyURL string, mtu int, logLevel string, deferredTCP, rejectIPv6 bool) tunengine.Config {
	config := tunengine.Config{
		Device: device, Proxy: proxyURL, MTU: mtu, LogLevel: logLevel,
		RejectIPv6: rejectIPv6,
	}
	if deferredTCP {
		config.DeferredTCP = &tunengine.DeferredTCPConfig{}
	}
	return config
}
