package nearby

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// reuseControl lets several local sockets (for example two app instances)
// bind the discovery port; each receives every multicast datagram.
func reuseControl(network, address string, c syscall.RawConn) error {
	var err error
	if cerr := c.Control(func(fd uintptr) {
		err = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
	}); cerr != nil {
		return cerr
	}
	return err
}
