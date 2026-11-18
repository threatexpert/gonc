package apps

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/threatexpert/gonc/v2/internal/testdns"
)

func preserveGlobalDNS(t *testing.T) {
	t.Helper()
	before := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = before })
}

func TestDNSIsProcessWide(t *testing.T) {
	preserveGlobalDNS(t)
	a := testdns.Start(t, [4]byte{127, 0, 0, 1}, false)
	b := testdns.Start(t, [4]byte{127, 0, 0, 2}, false)
	for _, builtin := range []string{":nc", ":s5c"} {
		// Outer -dns retains the old final precedence over a nested -dns.
		c, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{"-dns", a.Address, "-e", builtin + " -dns " + b.Address + " child.invalid 80", "outer.invalid", "80"})
		if err != nil {
			t.Fatal(err)
		}
		child := c.app_nc_Config
		if builtin == ":s5c" {
			child = c.app_s5c_Config.AppNetcatConfig
		}
		client, err := getProxyClient(child)
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		_, port, _ := net.SplitHostPort(ln.Addr().String())
		conn, err := client.DialTimeout("tcp4", "child.invalid:"+port, time.Second)
		ln.Close()
		if err != nil {
			t.Fatal("nested command did not use global DNS", err)
		}
		conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", "unrelated.invalid")
		cancel()
		if err != nil || len(ips) != 1 || !ips[0].Equal(net.IPv4(127, 0, 0, 1)) {
			t.Fatalf("process lookup: %v %v", ips, err)
		}
	}
	// A later command changes the policy for the whole process. A command
	// without -dns leaves it in place instead of resetting to system DNS.
	if _, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{"-dns", b.Address, "outer.invalid", "80"}); err != nil {
		t.Fatal(err)
	}
	current := net.DefaultResolver
	if _, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{"outer.invalid", "80"}); err != nil {
		t.Fatal(err)
	}
	if net.DefaultResolver != current {
		t.Fatal("plain command reset process DNS")
	}
	ips, err := net.LookupIP("unrelated.invalid")
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.IPv4(127, 0, 0, 2)) {
		t.Fatalf("global change: %v %v", ips, err)
	}
}

func TestGlobalDNSBindsUDPAndTCP(t *testing.T) {
	preserveGlobalDNS(t)
	local := outboundTestIP(t)
	dns := testdns.Start(t, [4]byte{127, 0, 0, 1}, true)
	if err := setDns(dns.Address, local); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := net.DefaultResolver.LookupIP(ctx, "ip4", "fallback.invalid"); err != nil {
		t.Fatal(err)
	}
	if dns.UDPSource.Load() != local || dns.TCPSource.Load() != local {
		t.Fatalf("DNS sources UDP=%v TCP=%v, want %s", dns.UDPSource.Load(), dns.TCPSource.Load(), local)
	}
	before := net.DefaultResolver
	if err := setDns("not-an-ip", local); err == nil || net.DefaultResolver != before {
		t.Fatal("invalid DNS replaced process resolver")
	}
}
