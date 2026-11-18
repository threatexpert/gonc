package netx

import (
	"context"
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/threatexpert/gonc/v2/internal/testdns"
)

func TestBoundResolverTCPFallback(t *testing.T) {
	before := net.DefaultResolver
	servers := []*testdns.Server{testdns.Start(t, [4]byte{127, 0, 0, 1}, false), testdns.Start(t, [4]byte{127, 0, 0, 2}, true)}
	var wg sync.WaitGroup
	for i, s := range servers {
		r, err := NewBoundResolver(s.Address, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				ips, err := r.LookupIP(ctx, "ip4", "same-host.invalid")
				cancel()
				want := net.IPv4(127, 0, 0, byte(i+1))
				if err != nil || (len(ips) != 1 || !ips[0].Equal(want)) {
					t.Errorf("resolver %d: %v %v", i, ips, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if net.DefaultResolver != before {
		t.Fatal("default resolver changed")
	}
	if servers[1].UDPQueries.Load() == 0 || servers[1].TCPQueries.Load() == 0 {
		t.Fatal("DNS TCP fallback was not exercised")
	}
}

func TestUDPSessionDialerUsesGlobalResolver(t *testing.T) {
	s := testdns.Start(t, [4]byte{127, 0, 0, 1}, false)
	r, err := NewBoundResolver(s.Address, "")
	if err != nil {
		t.Fatal(err)
	}
	before := net.DefaultResolver
	net.DefaultResolver = r
	defer func() { net.DefaultResolver = before }()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewUDPSessionDialer(pc, true, 4096, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	defer pc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "udp4", "stun.invalid:3478")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.RemoteAddr().String() != "127.0.0.1:3478" || s.UDPQueries.Load() == 0 {
		t.Fatalf("wrong resolution: %v", c.RemoteAddr())
	}
	cancel()
	if c, err := d.DialContext(ctx, "udp4", "stun.invalid:3478"); err == nil {
		c.Close()
		t.Fatal("cancellation ignored")
	}
}

func TestBoundResolverRejectsInvalidBootstrap(t *testing.T) {
	for _, server := range []string{"dns.invalid", "dns.invalid:53", "bad:port"} {
		if _, err := NewBoundResolver(server, ""); err == nil {
			t.Fatalf("accepted %q", server)
		}
	}
	for _, server := range []string{"8.8.8.8", "8.8.8.8:53", "2001:4860:4860::8888", "[2001:4860:4860::8888]:53"} {
		if _, err := NewBoundResolver(server, ""); err != nil {
			t.Fatalf("%s: %v", server, err)
		}
	}
}
