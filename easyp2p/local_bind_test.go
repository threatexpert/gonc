package easyp2p

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"syscall"
	"testing"

	stun "github.com/pion/stun/v3"
)

func TestP2PDerivedSourceDoesNotEnableInterfaceConstraint(t *testing.T) {
	derived := &net.TCPAddr{IP: net.ParseIP("192.0.2.10")}
	for _, ip := range []string{"", "0.0.0.0", "::", "127.0.0.1", "::1"} {
		s := &P2PSessionContext{LocalBindIP: ip}
		if s.bindsLocalInterface() || s.localControl(derived, nil) != nil {
			t.Fatalf("implicit binding enabled for %q", ip)
		}
		want := errors.New("existing option")
		previous := func(string, string, syscall.RawConn) error { return want }
		if err := s.localControl(derived, previous)("tcp4", "", nil); !errors.Is(err, want) {
			t.Fatal(err)
		}
	}
}

func TestP2PExplicitSourceEnablesInterfaceConstraint(t *testing.T) {
	for _, ip := range []string{"192.0.2.10", "2001:db8::1", "fe80::1%en0"} {
		s := &P2PSessionContext{LocalBindIP: ip}
		if !s.bindsLocalInterface() {
			t.Fatalf("missing binding for %s", ip)
		}
		if runtime.GOOS == "darwin" || runtime.GOOS == "windows" || runtime.GOOS == "linux" {
			if s.localControl(&net.TCPAddr{IP: net.ParseIP("192.0.2.10")}, nil) == nil {
				t.Fatal("missing socket hook")
			}
		}
	}
}

func TestNamedLocalDiscoversBothUDPFamilies(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		t.Skip("desktop socket options")
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var device string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 && iface.Flags&net.FlagUp != 0 {
			device = iface.Name
			break
		}
	}
	if device == "" {
		t.Skip("no loopback device")
	}
	original := STUNServers
	STUNServers = nil
	t.Cleanup(func() { STUNServers = original })
	for _, server := range []struct{ network, addr, external string }{{"udp4", "127.0.0.1:0", "203.0.113.5"}, {"udp6", "[::1]:0", "2001:db8::5"}} {
		pc, err := net.ListenPacket(server.network, server.addr)
		if err != nil {
			t.Skipf("dual-stack loopback unavailable: %v", err)
		}
		t.Cleanup(func() { pc.Close() })
		STUNServers = append(STUNServers, "udp://"+pc.LocalAddr().String())
		go func() {
			var buf [1500]byte
			for {
				n, from, err := pc.ReadFrom(buf[:])
				if err != nil {
					return
				}
				req := stun.Message{Raw: buf[:n]}
				if req.Decode() != nil {
					continue
				}
				reply := stun.MustBuild(stun.NewTransactionIDSetter(req.TransactionID), stun.BindingSuccess, &stun.XORMappedAddress{IP: net.ParseIP(server.external), Port: 45678})
				pc.WriteTo(reply.Raw, from)
			}
		}()
	}
	for _, tc := range []struct {
		bind string
		v6   bool
	}{{device, true}, {"127.0.0.1:0", false}} {
		candidates, results, err := DetectNATAddressInfoContext(context.Background(), []string{"udp4", "udp6"}, tc.bind, nil, io.Discard)
		got := map[string]string{}
		for _, c := range candidates {
			host, _, e := net.SplitHostPort(c.Lan)
			if e != nil {
				t.Fatal(e)
			}
			got[c.Network] = host
		}
		if err != nil || got["udp4"] != "127.0.0.1" || (got["udp6"] == "::1") != tc.v6 {
			t.Fatalf("bind %q: candidates=%v results=%+v err=%v", tc.bind, got, results, err)
		}
	}
}
