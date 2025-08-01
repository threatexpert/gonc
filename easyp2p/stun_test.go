package easyp2p

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

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
		fmt.Printf("StunServer: %s://%s\n", r.Network, srv)
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
