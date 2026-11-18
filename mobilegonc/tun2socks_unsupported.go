//go:build !android

package mobilegonc

import "fmt"

func StartTun2Socks(fd int, proxyURL string, deviceName string, mtu int, logLevel string) error {
	return fmt.Errorf("tun2socks is only supported on Android")
}

func StartTun2SocksWithPolicy(fd int, proxyURL string, deviceName string, mtu int, logLevel string, deferredTCP bool, rejectIPv6 bool) error {
	return fmt.Errorf("tun2socks is only supported on Android")
}

func StopTun2Socks() {}

func StopTun2SocksWithError() error { return nil }

func UpdateTun2SocksProxy(endpoint string) error {
	return fmt.Errorf("tun2socks is only supported on Android")
}
