//go:build !darwin && !windows && (!linux || android)

package netx

import "net"

// LocalAddrControl leaves source binding unchanged on other platforms.
func LocalAddrControl(_ net.Addr, previous socketControl) socketControl { return previous }
