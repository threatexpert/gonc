//go:build linux && !android

package netx

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/threatexpert/gonc/v2/internal/testdns"
	"golang.org/x/sys/unix"
)

func checkLocalSocketInterface(raw syscall.RawConn, _ net.IP, iface net.Interface) error {
	var name string
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		name, optionErr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	}); err != nil {
		return err
	}
	if optionErr != nil {
		return optionErr
	}
	if name != iface.Name {
		return fmt.Errorf("bound interface=%q, want %q", name, iface.Name)
	}
	return nil
}

func TestNamedResolverDelegatesBothDNSTransports(t *testing.T) {
	dns := testdns.Start(t, [4]byte{192, 0, 2, 4}, true)
	var marked atomic.Int32
	release := RegisterLinuxSocketBinder("lo", dns.Address, func(raw syscall.RawConn, dest string) error {
		if dest != dns.Address {
			return fmt.Errorf("unexpected bypass DNS %q", dest)
		}
		marked.Add(1)
		return nil
	})
	defer release()
	resolver, err := NewBoundResolver(dns.Address, "lo")
	if err != nil {
		t.Fatal(err)
	}
	ips, err := resolver.LookupIP(context.Background(), "ip4", "gonc.test.")
	if err != nil || len(ips) != 1 || marked.Load() < 2 || dns.UDPQueries.Load() == 0 || dns.TCPQueries.Load() == 0 {
		t.Fatalf("ips=%v delegated=%d err=%v", ips, marked.Load(), err)
	}
}
