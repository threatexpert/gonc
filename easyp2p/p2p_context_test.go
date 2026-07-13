package easyp2p

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type traversalResult struct {
	conn     net.Conn
	isClient bool
	err      error
}

type readyLogWriter struct {
	once  sync.Once
	ready chan struct{}
}

func TestDoAutoP2PEx2PreservesCancelCause(t *testing.T) {
	want := errors.New("candidate superseded")
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(want)

	_, _, err := Do_autoP2PEx2(ctx, []string{"tcp4"}, "", "context-cause-test", time.Second, true, nil, io.Discard, nil)
	if !errors.Is(err, want) {
		t.Fatalf("Do_autoP2PEx2 error = %v, want cancellation cause", err)
	}
}

func TestMQTTSignalExchangePreservesParentCancelCause(t *testing.T) {
	want := errors.New("candidate superseded")
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(want)

	signal := &MQTTSignalSession{}
	_, _, _, err := signal.exchange(ctx, EXMODE_waitOnly, "", "", "", "", time.Second, nil, mqttNoPreferredBroker)
	if !errors.Is(err, want) {
		t.Fatalf("MQTT exchange error = %v, want cancellation cause", err)
	}
}

func newReadyLogWriter() *readyLogWriter {
	return &readyLogWriter{ready: make(chan struct{})}
}

func (w *readyLogWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("Best Route")) {
		w.once.Do(func() {
			close(w.ready)
		})
	}
	return len(p), nil
}

func reserveTCPAddrPair(t *testing.T) (string, string) {
	t.Helper()

	first, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	second, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		first.Close()
		t.Fatal(err)
	}

	firstAddr := first.Addr().String()
	secondAddr := second.Addr().String()
	if err := first.Close(); err != nil {
		second.Close()
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	return firstAddr, secondAddr
}

func reserveUDPAddrPair(t *testing.T) (string, string) {
	t.Helper()

	first, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	second, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		first.Close()
		t.Fatal(err)
	}

	firstAddr := first.LocalAddr().String()
	secondAddr := second.LocalAddr().String()
	if err := first.Close(); err != nil {
		second.Close()
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	return firstAddr, secondAddr
}

func loopbackP2PInfo(localAddr, remoteAddr string) *P2PAddressInfo {
	return &P2PAddressInfo{
		Network:       "tcp4",
		LocalLAN:      localAddr,
		LocalNAT:      localAddr,
		LocalNATType:  "easy",
		RemoteLAN:     remoteAddr,
		RemoteNAT:     remoteAddr,
		RemoteNATType: "easy",
	}
}

func loopbackUDPP2PInfo(localAddr, remoteAddr string) *P2PAddressInfo {
	return &P2PAddressInfo{
		Network:       "udp4",
		LocalLAN:      localAddr,
		LocalNAT:      localAddr,
		LocalNATType:  "easy",
		RemoteLAN:     remoteAddr,
		RemoteNAT:     remoteAddr,
		RemoteNATType: "easy",
	}
}

func runTCPTraversal(ctx context.Context, info *P2PAddressInfo, logWriter io.Writer, result chan<- traversalResult) {
	conn, isClient, err := Auto_P2P_TCP_NAT_Traversal(
		ctx,
		"tcp4",
		"tcp-context-test",
		info,
		&P2PSessionContext{},
		0,
		logWriter,
	)
	result <- traversalResult{conn: conn, isClient: isClient, err: err}
}

func runUDPTraversal(ctx context.Context, info *P2PAddressInfo, logWriter io.Writer, result chan<- traversalResult) {
	conn, isClient, _, err := Auto_P2P_UDP_NAT_Traversal(
		ctx,
		"udp4",
		"udp-context-test",
		info,
		&P2PSessionContext{},
		0,
		nil,
		logWriter,
	)
	result <- traversalResult{conn: conn, isClient: isClient, err: err}
}

func TestAutoP2PUDPTraversalCancellationDuringPassiveDelay(t *testing.T) {
	t.Setenv("ROLE_DEBUG", "S")

	localAddr, remoteAddr := reserveUDPAddrPair(t)
	info := loopbackUDPP2PInfo(localAddr, remoteAddr)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan traversalResult, 1)
	ready := newReadyLogWriter()
	go runUDPTraversal(ctx, info, ready, result)

	select {
	case <-ready.ready:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("UDP traversal socket was not prepared")
	}

	time.Sleep(50 * time.Millisecond)
	started := time.Now()
	cancel()

	select {
	case got := <-result:
		if got.conn != nil {
			got.conn.Close()
			t.Fatal("canceled UDP traversal returned a connection")
		}
		if !errors.Is(got.err, context.Canceled) {
			t.Fatalf("expected context cancellation, got %v", got.err)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("UDP traversal cancellation took too long: %s", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("UDP traversal did not return after cancellation")
	}
}

func TestAutoP2PUDPTraversalSuccessfulConnectionTransfer(t *testing.T) {
	addrA, addrB := reserveUDPAddrPair(t)
	infoA := loopbackUDPP2PInfo(addrA, addrB)
	infoB := loopbackUDPP2PInfo(addrB, addrA)
	sessCtx := &P2PSessionContext{}

	aIsClient := SelectRole(infoA, sessCtx)
	bIsClient := SelectRole(infoB, sessCtx)
	if aIsClient == bIsClient {
		t.Fatal("loopback peers selected the same UDP traversal role")
	}

	serverInfo := infoA
	clientInfo := infoB
	if aIsClient {
		serverInfo = infoB
		clientInfo = infoA
	}

	serverResult := make(chan traversalResult, 1)
	serverReady := newReadyLogWriter()
	go runUDPTraversal(context.Background(), serverInfo, serverReady, serverResult)
	select {
	case <-serverReady.ready:
	case <-time.After(2 * time.Second):
		t.Fatal("server UDP traversal socket was not prepared")
	}

	clientResult := make(chan traversalResult, 1)
	go runUDPTraversal(context.Background(), clientInfo, io.Discard, clientResult)

	results := make([]traversalResult, 0, 2)
	for len(results) < 2 {
		select {
		case got := <-serverResult:
			results = append(results, got)
			serverResult = nil
		case got := <-clientResult:
			results = append(results, got)
			clientResult = nil
		case <-time.After(5 * time.Second):
			for _, got := range results {
				if got.conn != nil {
					got.conn.Close()
				}
			}
			t.Fatal("paired UDP traversal did not complete")
		}
	}

	for _, got := range results {
		if got.err != nil {
			for _, cleanup := range results {
				if cleanup.conn != nil {
					cleanup.conn.Close()
				}
			}
			t.Fatalf("paired UDP traversal failed: %v", got.err)
		}
		if got.conn == nil {
			t.Fatal("paired UDP traversal returned a nil connection")
		}
	}

	for _, got := range results {
		_ = got.conn.Close()
	}
}

func TestAutoP2PTCPTraversalCancellationClosesHandshakeCandidate(t *testing.T) {
	t.Setenv("ROLE_DEBUG", "S")

	localAddr, remoteAddr := reserveTCPAddrPair(t)
	info := loopbackP2PInfo(localAddr, remoteAddr)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan traversalResult, 1)
	ready := newReadyLogWriter()
	go runTCPTraversal(ctx, info, ready, result)

	select {
	case <-ready.ready:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("TCP traversal listener was not prepared")
	}

	peer, err := net.DialTimeout("tcp4", localAddr, time.Second)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer peer.Close()

	time.Sleep(50 * time.Millisecond)
	started := time.Now()
	cancel()

	select {
	case got := <-result:
		if got.conn != nil {
			got.conn.Close()
			t.Fatal("canceled traversal returned a connection")
		}
		if !errors.Is(got.err, context.Canceled) {
			t.Fatalf("expected context cancellation, got %v", got.err)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("TCP traversal cancellation took too long: %s", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TCP traversal did not return after cancellation")
	}

	if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := peer.Read(buf); err == nil {
		t.Fatal("handshake candidate remained open after cancellation")
	}
}

func TestAutoP2PTCPTraversalSuccessfulOwnershipTransfer(t *testing.T) {
	addrA, addrB := reserveTCPAddrPair(t)
	infoA := loopbackP2PInfo(addrA, addrB)
	infoB := loopbackP2PInfo(addrB, addrA)
	sessCtx := &P2PSessionContext{}

	aIsClient := SelectRole(infoA, sessCtx)
	bIsClient := SelectRole(infoB, sessCtx)
	if aIsClient == bIsClient {
		t.Fatal("loopback peers selected the same TCP traversal role")
	}

	serverInfo := infoA
	clientInfo := infoB
	if aIsClient {
		serverInfo = infoB
		clientInfo = infoA
	}

	serverResult := make(chan traversalResult, 1)
	serverReady := newReadyLogWriter()
	go runTCPTraversal(context.Background(), serverInfo, serverReady, serverResult)
	select {
	case <-serverReady.ready:
	case <-time.After(2 * time.Second):
		t.Fatal("server traversal listener was not prepared")
	}

	clientResult := make(chan traversalResult, 1)
	go runTCPTraversal(context.Background(), clientInfo, io.Discard, clientResult)

	results := make([]traversalResult, 0, 2)
	for len(results) < 2 {
		select {
		case got := <-serverResult:
			results = append(results, got)
			serverResult = nil
		case got := <-clientResult:
			results = append(results, got)
			clientResult = nil
		case <-time.After(5 * time.Second):
			for _, got := range results {
				if got.conn != nil {
					got.conn.Close()
				}
			}
			t.Fatal("paired TCP traversal did not complete")
		}
	}

	for _, got := range results {
		if got.err != nil {
			for _, cleanup := range results {
				if cleanup.conn != nil {
					cleanup.conn.Close()
				}
			}
			t.Fatalf("paired TCP traversal failed: %v", got.err)
		}
		if got.conn == nil {
			t.Fatal("paired TCP traversal returned a nil connection")
		}
	}

	for _, got := range results {
		_ = got.conn.Close()
	}
}
