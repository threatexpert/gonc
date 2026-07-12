package secure

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestDoNegotiationContextCancelsTLSHandshake(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		cfg := NewNegotiationConfig()
		cfg.IsClient = true
		cfg.SecureLayer = "tls13"
		_, err := DoNegotiationContext(ctx, cfg, local, io.Discard)
		result <- err
	}()

	// Wait until the client has entered the handshake before canceling it.
	if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := peer.Read(buf); err != nil {
		t.Fatalf("TLS handshake did not start: %v", err)
	}
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context cancellation, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TLS negotiation did not stop after context cancellation")
	}
}

func TestDoNegotiationContextPreservesHandshakeError(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()

	go func() {
		buf := make([]byte, 4096)
		_, _ = peer.Read(buf)
		_, _ = peer.Write([]byte("not tls"))
		_ = peer.Close()
	}()

	cfg := NewNegotiationConfig()
	cfg.IsClient = true
	cfg.SecureLayer = "tls13"
	_, err := DoNegotiationContext(context.Background(), cfg, local, io.Discard)
	if err == nil {
		t.Fatal("expected TLS handshake failure")
	}
	if errors.Is(err, context.Canceled) {
		t.Fatalf("ordinary handshake failure was reported as cancellation: %v", err)
	}
}

func TestDoNegotiationContextLeavesEstablishedConnectionOpen(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cfg := NewNegotiationConfig()

	nconn, err := DoNegotiationContext(ctx, cfg, local, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer nconn.Close()

	cancel()

	want := []byte("still-open")
	readDone := make(chan []byte, 1)
	go func() {
		buf := make([]byte, len(want))
		if _, err := io.ReadFull(peer, buf); err != nil {
			readDone <- nil
			return
		}
		readDone <- buf
	}()

	if _, err := nconn.Write(want); err != nil {
		t.Fatalf("established connection closed with its parent context: %v", err)
	}

	select {
	case got := <-readDone:
		if !bytes.Equal(got, want) {
			t.Fatalf("peer read %q, want %q", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peer did not receive data after parent cancellation")
	}
}

func TestNegotiatedConnCloseCallsOnCloseOnce(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()

	cfg := NewNegotiationConfig()
	connCtx, cancelConn := context.WithCancel(context.Background())
	nconn := &NegotiatedConn{
		ctx:        connCtx,
		cancel:     cancelConn,
		Config:     cfg,
		TopLayer:   local,
		ConnStack:  []string{"tls13"},
		ConnLayers: []net.Conn{local},
	}
	callbackCount := 0
	nconn.AddOnClose(func() {
		callbackCount++
	})

	if err := nconn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := nconn.Close(); err != nil {
		t.Fatal(err)
	}
	if callbackCount != 1 {
		t.Fatalf("close callback ran %d times, want 1", callbackCount)
	}
	if nconn.OnClose != nil || nconn.ctx != nil || nconn.cancel != nil {
		t.Fatal("close did not clear callback and internal lifecycle fields")
	}
	if nconn.Config != cfg || nconn.TopLayer != local {
		t.Fatal("close cleared public connection metadata")
	}
	if len(nconn.ConnStack) != 1 || nconn.ConnStack[0] != "tls13" {
		t.Fatalf("close changed connection stack: %v", nconn.ConnStack)
	}
	if len(nconn.ConnLayers) != 1 || nconn.ConnLayers[0] != local {
		t.Fatalf("close changed connection layers: %v", nconn.ConnLayers)
	}
	select {
	case <-connCtx.Done():
	default:
		t.Fatal("close did not cancel the internal connection context")
	}
}

func TestDoNegotiationContextCancelsDTLSHandshake(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	local, err := net.DialUDP("udp4", nil, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		cfg := NewNegotiationConfig()
		cfg.IsClient = true
		cfg.SecureLayer = "dtls"
		_, err := DoNegotiationContext(ctx, cfg, local, io.Discard)
		result <- err
	}()

	if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	if _, _, err := peer.ReadFromUDP(buf); err != nil {
		t.Fatalf("DTLS handshake did not start: %v", err)
	}
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context cancellation, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("DTLS negotiation did not stop after context cancellation")
	}
}

func TestDoNegotiationContextKCPHandshakeUsesFullTimeout(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	local, err := net.DialUDP("udp4", nil, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}

	cfg := NewNegotiationConfig()
	cfg.IsClient = true
	cfg.KcpWithUDP = true
	cfg.ReadIdleTimeoutSecond = 1

	started := time.Now()
	_, err = DoNegotiationContext(context.Background(), cfg, local, io.Discard)
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("expected KCP handshake timeout")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
	if elapsed < 750*time.Millisecond {
		t.Fatalf("KCP handshake timed out too early after %s", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("KCP handshake timeout took too long: %s", elapsed)
	}
}

func TestDoNegotiationContextCancelsKCPHandshake(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	local, err := net.DialUDP("udp4", nil, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		cfg := NewNegotiationConfig()
		cfg.IsClient = true
		cfg.KcpWithUDP = true
		_, err := DoNegotiationContext(ctx, cfg, local, io.Discard)
		result <- err
	}()

	if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	if _, _, err := peer.ReadFromUDP(buf); err != nil {
		t.Fatalf("KCP handshake did not start: %v", err)
	}
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context cancellation, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("KCP negotiation did not stop after context cancellation")
	}
}
