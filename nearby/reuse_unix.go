//go:build !windows

package nearby

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// reuseControl lets several local sockets (for example two app instances)
// bind the discovery port; each receives every multicast datagram. BSD-derived
// systems such as macOS need SO_REUSEPORT for that in addition to SO_REUSEADDR.
func reuseControl(network, address string, c syscall.RawConn) error {
	var err error
	if cerr := c.Control(func(fd uintptr) {
		if err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			return
		}
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	}); cerr != nil {
		return cerr
	}
	return err
}
