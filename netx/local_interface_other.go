//go:build !darwin && !windows && (!linux || android)

package netx

import (
	"fmt"
	"net"
	"syscall"
)

// LocalAddrControl leaves source binding unchanged on other platforms.
func LocalAddrControl(_ net.Addr, previous socketControl) socketControl { return previous }

func bindNamedInterface(syscall.RawConn, *net.Interface, string, string) error {
	return fmt.Errorf("binding by interface name is unsupported on this platform")
}
