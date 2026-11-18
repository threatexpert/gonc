package easyp2p

import (
	"errors"
	"net"
	"runtime"
	"syscall"
	"testing"
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
