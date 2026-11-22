package netx

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
)

func TestTunnelSocketAndDNSControlIsScoped(t *testing.T) {
	denied := errors.New("test tunnel marker")
	calls := 0
	ordinary := net.DefaultResolver
	s, err := NewTunnelNetwork("127.0.0.1:53", "", func(syscall.RawConn) error { calls++; return denied })
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithTunnelNetwork(context.Background(), s)
	if TunnelNetworkFrom(ctx) != s || TunnelNetworkFrom(context.Background()) != nil {
		t.Fatal("network leaked outside tunnel context")
	}
	_, err = s.Dialer(nil, nil).Dial("tcp4", "127.0.0.1:1")
	if !errors.Is(err, denied) {
		t.Fatal(err)
	}
	for _, network := range []string{"udp4", "tcp4"} {
		_, err = s.resolver.Dial(ctx, network, "ignored")
		if !errors.Is(err, denied) {
			t.Fatal(err)
		}
	}
	_, err = s.ListenUDP(ctx, "udp4", &net.UDPAddr{IP: net.IPv4zero})
	if !errors.Is(err, denied) {
		t.Fatal(err)
	}
	local, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	c, err := TunnelNetworkFrom(context.Background()).Dialer(nil, nil).Dial("tcp4", local.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if calls != 4 || ordinary != net.DefaultResolver {
		t.Fatalf("calls=%d, process resolver changed=%v", calls, ordinary != net.DefaultResolver)
	}
}
