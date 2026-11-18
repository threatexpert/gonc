package netx

import (
	"errors"
	"net"
	"syscall"
	"testing"
)

func TestLocalInterfaceControlPreservesOptionsAndFailsClosed(t *testing.T) {
	local := &net.TCPAddr{IP: net.ParseIP("192.0.2.10")}
	bindErr, optionErr := errors.New("interface disappeared"), errors.New("socket option failed")
	var calls []string
	var fail error
	control := localInterfaceControl(local, func(network, address string, _ syscall.RawConn) error {
		calls = append(calls, "options")
		if network != "tcp4" || address != "198.51.100.1:53" {
			t.Fatal("changed control arguments")
		}
		return optionErr
	}, func(_ syscall.RawConn, ip net.IP, zone string) error {
		calls = append(calls, "bind")
		if !ip.Equal(net.ParseIP("192.0.2.10")) || zone != "" {
			t.Fatal("changed local address")
		}
		return fail
	})
	if err := control("tcp4", "198.51.100.1:53", nil); !errors.Is(err, optionErr) {
		t.Fatal(err)
	}
	fail = bindErr
	if err := control("tcp4", "198.51.100.1:53", nil); !errors.Is(err, bindErr) {
		t.Fatal(err)
	}
	if len(calls) != 3 || calls[0] != "bind" || calls[1] != "options" || calls[2] != "bind" {
		t.Fatal(calls)
	}
}

func TestLocalInterfaceControlLeavesWildcardAndLoopbackAlone(t *testing.T) {
	for _, local := range []net.Addr{nil, (*net.TCPAddr)(nil), (*net.UDPAddr)(nil), &net.TCPAddr{}, &net.TCPAddr{IP: net.IPv4zero}, &net.UDPAddr{IP: net.IPv6zero}, &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}, &net.UDPAddr{IP: net.IPv6loopback}} {
		bind := func(syscall.RawConn, net.IP, string) error { t.Fatal("unexpected interface binding"); return nil }
		if got := localInterfaceControl(local, nil, bind); got != nil {
			t.Fatalf("non-nil control for %v", local)
		}
		called := false
		got := localInterfaceControl(local, func(string, string, syscall.RawConn) error { called = true; return nil }, bind)
		if err := got("tcp", "", nil); err != nil || !called {
			t.Fatal("lost existing socket options")
		}
	}
}

func TestInterfaceIndexForIP(t *testing.T) {
	interfaces := []net.Interface{{Index: 4, Name: "en0"}, {Index: 8, Name: "en1"}, {Index: 12, Name: "utun0"}}
	addresses := map[int][]net.Addr{
		4:  {&net.IPNet{IP: net.ParseIP("192.0.2.10")}, &net.IPAddr{IP: net.ParseIP("fe80::1")}},
		8:  {&net.IPAddr{IP: net.ParseIP("fe80::1")}},
		12: {&net.IPNet{IP: net.ParseIP("10.60.173.33")}},
	}
	lookup := func(i net.Interface) ([]net.Addr, error) { return addresses[i.Index], nil }
	for _, tc := range []struct {
		ip, zone string
		want     int
	}{
		{"192.0.2.10", "", 4}, {"fe80::1", "en0", 4}, {"fe80::1", "8", 8},
		{"fe80::1", "", 0}, {"192.0.2.10", "en1", 0}, {"192.0.2.99", "", 0},
	} {
		index, err := interfaceIndexForIP(net.ParseIP(tc.ip), tc.zone, interfaces, lookup)
		if index != tc.want || (err != nil) != (tc.want == 0) {
			t.Fatalf("%+v: index=%d err=%v", tc, index, err)
		}
	}
	// A new connection must discover a changed interface index rather than reuse it.
	interfaces[0].Index = 5
	addresses[5] = addresses[4]
	if index, err := interfaceIndexForIP(net.ParseIP("192.0.2.10"), "", interfaces, lookup); err != nil || index != 5 {
		t.Fatalf("%d %v", index, err)
	}
	want := errors.New("enumeration failed")
	if _, err := interfaceIndexForIP(net.ParseIP("192.0.2.10"), "", interfaces, func(net.Interface) ([]net.Addr, error) { return nil, want }); !errors.Is(err, want) {
		t.Fatal(err)
	}
}
