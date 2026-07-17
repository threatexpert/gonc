package easyp2p

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	pionstun "github.com/pion/stun/v3"
)

func TestGetPublicIPsClosesSuccessfulTCPConnection(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for fake STUN server: %v", err)
	}
	defer listener.Close()

	originalServers := STUNServers
	STUNServers = []string{"tcp://" + listener.Addr().String()}
	t.Cleanup(func() { STUNServers = originalServers })

	peerClosed := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			peerClosed <- acceptErr
			return
		}
		defer conn.Close()

		header := make([]byte, 20)
		if _, readErr := io.ReadFull(conn, header); readErr != nil {
			peerClosed <- readErr
			return
		}
		body := make([]byte, int(binary.BigEndian.Uint16(header[2:4])))
		if _, readErr := io.ReadFull(conn, body); readErr != nil {
			peerClosed <- readErr
			return
		}
		request := &pionstun.Message{Raw: append(header, body...)}
		if decodeErr := request.Decode(); decodeErr != nil {
			peerClosed <- decodeErr
			return
		}
		response := pionstun.MustBuild(
			pionstun.NewTransactionIDSetter(request.TransactionID),
			pionstun.BindingSuccess,
			&pionstun.XORMappedAddress{IP: net.ParseIP("203.0.113.10"), Port: 45678},
		)
		if _, writeErr := conn.Write(response.Raw); writeErr != nil {
			peerClosed <- writeErr
			return
		}

		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		_, readErr := conn.Read(make([]byte, 1))
		peerClosed <- readErr
	}()

	results, err := GetPublicIPs("tcp4", ":0", 2*time.Second, false, nil)
	if err != nil {
		t.Fatalf("GetPublicIPs returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("GetPublicIPs returned %d results, want 1", len(results))
	}
	if results[0].Err != nil {
		t.Fatalf("GetPublicIPs result error: %v", results[0].Err)
	}
	if results[0].Nat != "203.0.113.10:45678" {
		t.Fatalf("GetPublicIPs returned NAT address %q", results[0].Nat)
	}

	select {
	case readErr := <-peerClosed:
		if readErr == nil {
			t.Fatal("STUN connection remained open after successful query")
		}
		if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
			t.Fatal("STUN connection was retained after successful query")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fake STUN server did not observe connection closure")
	}
}

func TestGetPublicIPsContextCancellationClosesTCPConnection(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for fake STUN server: %v", err)
	}
	defer listener.Close()

	originalServers := STUNServers
	STUNServers = []string{"tcp://" + listener.Addr().String()}
	t.Cleanup(func() { STUNServers = originalServers })

	requestReceived := make(chan struct{})
	peerClosed := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			peerClosed <- acceptErr
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		if _, readErr := conn.Read(buf); readErr != nil {
			peerClosed <- readErr
			return
		}
		close(requestReceived)
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		_, readErr := conn.Read(buf)
		peerClosed <- readErr
	}()

	cancelCause := errors.New("LAN path won")
	ctx, cancel := context.WithCancelCause(context.Background())
	result := make(chan error, 1)
	go func() {
		_, callErr := GetPublicIPsContext(ctx, "tcp4", ":0", 30*time.Second, false, nil)
		result <- callErr
	}()

	select {
	case <-requestReceived:
	case <-time.After(time.Second):
		t.Fatal("fake STUN server did not receive a request")
	}
	cancel(cancelCause)

	select {
	case callErr := <-result:
		if !errors.Is(callErr, cancelCause) {
			t.Fatalf("GetPublicIPsContext error = %v, want %v", callErr, cancelCause)
		}
	case <-time.After(time.Second):
		t.Fatal("GetPublicIPsContext did not return after cancellation")
	}

	select {
	case readErr := <-peerClosed:
		if readErr == nil {
			t.Fatal("fake STUN connection remained readable after cancellation")
		}
		if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
			t.Fatal("fake STUN connection was not closed after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("fake STUN server did not observe connection closure")
	}
}

func TestNATDiscoveryContextCancellationPropagates(t *testing.T) {
	cancelCause := errors.New("superseded by LAN")
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(cancelCause)

	t.Run("all public IPs", func(t *testing.T) {
		_, err := GetPublicIPsContext(ctx, "tcp4", ":0", 30*time.Second, false, nil)
		if !errors.Is(err, cancelCause) {
			t.Fatalf("GetPublicIPsContext error = %v, want %v", err, cancelCause)
		}
	})

	t.Run("multiple networks", func(t *testing.T) {
		_, err := GetNetworksPublicIPsContext(ctx, []string{"tcp4"}, ":0", 30*time.Second, nil)
		if !errors.Is(err, cancelCause) {
			t.Fatalf("GetNetworksPublicIPsContext error = %v, want %v", err, cancelCause)
		}
	})

	t.Run("address analysis", func(t *testing.T) {
		_, _, err := DetectNATAddressInfoContext(ctx, []string{"tcp4"}, ":0", nil, nil)
		if !errors.Is(err, cancelCause) {
			t.Fatalf("DetectNATAddressInfoContext error = %v, want %v", err, cancelCause)
		}
	})
}

func TestStunOne(t *testing.T) {
	timeout := 3 * time.Second
	results, err := GetPublicIPs("udp4", ":20000", timeout, false, nil)
	if err != nil {
		return
	}
	if len(results) == 0 {
		fmt.Println("No public IP addresses found or all attempts failed.")
	} else {
		fmt.Println("\n--- Public IP Results ---")
		for _, r := range results {
			fmt.Printf("StunServer: %s\n", STUNServers[r.Index])
			if r.Err != nil {
				fmt.Printf("    Error: %v\n", r.Err)
			} else {
				fmt.Printf("    Local IP: %s, NAT IP: %s\n", r.Local, r.Nat)
			}
		}
	}
}

func TestStunN(t *testing.T) {
	timeout := 30 * time.Second
	networkList := strings.Split("tcp6,tcp4,udp4", ",")
	allResults, err := GetNetworksPublicIPs(networkList, "", timeout, nil)
	if err != nil {
		fmt.Println("failed: ", err)
		return
	}

	fmt.Println("\n--- Public IP Results ---")
	for _, r := range allResults {
		srv := strings.TrimPrefix(STUNServers[r.Index], "udp://")
		srv = strings.TrimPrefix(srv, "tcp://")
		if r.Remote != "" {
			fmt.Printf("StunServer: %s://%s (%s)\n", r.Network, srv, r.Remote)
		} else {
			fmt.Printf("StunServer: %s://%s\n", r.Network, srv)
		}
		if r.Err == nil {
			fmt.Printf("    Local IP: %s, NAT IP: %s\n", r.Local, r.Nat)
		}
	}
}

func TestGetFreePort(t *testing.T) {
	port, err := GetFreePort()
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	tcpListener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatalf("failed to Listen port: %v", err)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}
	tcpListener.Close()
	udpConn.Close()
	fmt.Printf("done: port: %d\n", port)
}

// ======= 以下是测试数据生成 =======

func getSampleSTUNResults() []*STUNResult {
	return []*STUNResult{
		{Index: 0, Network: "udp4", Local: "192.168.50.192:30000", Nat: "120.230.80.76:9716"},
		{Index: 1, Network: "udp4", Local: "192.168.50.192:30000", Nat: "120.230.80.76:9716"},
		{Index: 2, Network: "udp4", Local: "192.168.50.192:30000", Nat: "120.230.80.76:9716"},

		{Index: 2, Network: "udp4", Local: "192.168.50.3:40000", Nat: "120.230.80.3:6666"},
		{Index: 2, Network: "udp4", Local: "192.168.50.3:40000", Nat: "120.230.80.3:6666"},

		{Index: 3, Network: "udp4", Local: "192.168.50.2:30000", Nat: "120.230.80.77:4441"},
		{Index: 4, Network: "udp4", Local: "192.168.50.2:30000", Nat: "120.230.80.77:4442"},
		{Index: 5, Network: "udp4", Local: "192.168.50.2:30000", Nat: "120.230.80.77:4443"},

		{Index: 6, Network: "tcp4", Local: "192.168.50.192:30000", Nat: "120.230.80.76:9715"},
		{Index: 7, Network: "tcp4", Local: "192.168.50.192:30000", Nat: "120.230.80.76:9715"},
		{Index: 8, Network: "tcp4", Local: "192.168.50.192:30000", Nat: "120.230.80.76:9715"},
		{Index: 9, Network: "tcp4", Local: "192.168.50.192:30000", Nat: "120.230.80.76:9715"},

		{Index: 10, Network: "tcp6", Local: "", Nat: "", Err: errDummy},
		{Index: 11, Network: "tcp6", Local: "[2409:8a55:6e1:e201:7921:b6af:9228:318f]:30000", Nat: "[2409:8a55:6e1:e201:7921:b6af:9228:318f]:30000"},
		{Index: 12, Network: "tcp6", Local: "[2409:8a55:6e1:e201:7921:b6af:9228:318f]:30000", Nat: "[2409:8a55:6e1:e201:7921:b6af:9228:318f]:30000"},
	}
}

var errDummy = func() error {
	return &customErr{"no response"}
}()

type customErr struct {
	msg string
}

func (e *customErr) Error() string {
	return e.msg
}

func TestAnalyzeSTUNResults(t *testing.T) {
	results := getSampleSTUNResults()
	analyzed := analyzeSTUNResults(results)

	expected := []AnalyzedStunResult{
		{
			NATType: "hard",
			Network: "udp4",
			LAN:     "192.168.50.3:40000",
			NAT:     "120.230.80.3:6666",
		},
		{
			NATType: "symm",
			Network: "udp4",
			LAN:     "192.168.50.2:30000",
			NAT:     "120.230.80.77:4441",
		},
		{
			NATType: "hard",
			Network: "udp4",
			LAN:     "192.168.50.192:30000",
			NAT:     "120.230.80.76:9716",
		},
		{
			NATType: "hard",
			Network: "udp4",
			LAN:     "192.168.50.192:30000",
			NAT:     "120.230.80.77:7717",
		},
		{
			NATType: "hard",
			Network: "tcp4",
			LAN:     "192.168.50.192:30000",
			NAT:     "120.230.80.76:9715",
		},
		{
			NATType: "easy",
			Network: "tcp6",
			LAN:     "[2409:8a55:6e1:e201:7921:b6af:9228:318f]:30000",
			NAT:     "[2409:8a55:6e1:e201:7921:b6af:9228:318f]:30000",
		},
	}

	// 转成 map[key]=result 方便比对顺序无关
	expectedMap := make(map[string]AnalyzedStunResult)
	for _, e := range expected {
		key := e.Network + "|" + e.NAT
		expectedMap[key] = e
	}

	for _, actual := range analyzed {
		key := actual.Network + "|" + actual.NAT
		expect, ok := expectedMap[key]
		if !ok {
			j, _ := json.MarshalIndent(actual, "", "  ")
			t.Errorf("unexpected result: %s", string(j))
			continue
		}
		if actual.NATType != expect.NATType {
			t.Errorf("mismatched type for %s: got %s, want %s", key, actual.NATType, expect.NATType)
		}
	}
}

func TestAnalyzeRealSTUNResults(t *testing.T) {
	timeout := 3 * time.Second
	networkList := strings.Split("tcp6,tcp4,udp4", ",")
	allResults, err := GetNetworksPublicIPs(networkList, "", timeout, nil)
	if err != nil {
		fmt.Println("failed: ", err)
		return
	}
	analyzed := analyzeSTUNResults(allResults)
	for _, item := range analyzed {
		fmt.Fprintf(os.Stderr, "nattype: %s\nnetwork: %s\nLan: %s\nNat: %s\n\n", item.NATType, item.Network, item.LAN, item.NAT)
	}
}
