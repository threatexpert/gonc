//go:build !android

package mobilegonc

import "fmt"

func StartTun2Socks(fd int, proxyURL string, deviceName string, mtu int, logLevel string) error {
	return fmt.Errorf("tun2socks is only supported on Android")
}

func StopTun2Socks() {}
