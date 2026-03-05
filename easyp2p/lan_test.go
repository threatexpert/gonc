package easyp2p

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

func TestLanDeriveKey(t *testing.T) {
	k1 := lanDeriveKey("abc")
	k2 := lanDeriveKey("abc")
	k3 := lanDeriveKey("xyz")
	if string(k1) != string(k2) { t.Fatal("same") }
	if string(k1) == string(k3) { t.Fatal("diff") }
	if len(k1) != 32 { t.Fatal("32") }
}

func TestLanSessionID(t *testing.T) {
	a := lanDeriveSessionID("abc")
	b := lanDeriveSessionID("abc")
	c := lanDeriveSessionID("xyz")
	if a != b || a == c || a == "" { t.Fatal("sid") }
}

func TestLanHMAC(t *testing.T) {
	key := lanDeriveKey("test")
	m1 := lanHMAC(key, "B", "d1")
	m2 := lanHMAC(key, "B", "d1")
	m3 := lanHMAC(key, "B", "d2")
	if m1 != m2 || m1 == m3 { t.Fatal("hmac") }
	msg := &lanMsg{Magic: LANBeaconMagic, Type: "B", Payload: "d1", HMAC: m1}
	if !lanVerify(key, msg) { t.Fatal("verify ok") }
	msg.HMAC = "bad"
	if lanVerify(key, msg) { t.Fatal("verify bad") }
}

func TestLanEncodeDecode(t *testing.T) {
	key := lanDeriveKey("test")
	b := lanBeacon{SessionID: "sid", NonceA: "na", Transport: "udp"}
	data := lanEncode(key, lanMsgBeacon, b)
	m, err := lanDecode(key, data)
	if err != nil { t.Fatal(err) }
	if m.Type != lanMsgBeacon { t.Fatal("type") }
	var d lanBeacon
	if err := lanUnmarshal(m, &d); err != nil { t.Fatal(err) }
	if d.SessionID != "sid" || d.NonceA != "na" || d.Transport != "udp" { t.Fatal("fields") }
}

func TestLanDecodeWrongKey(t *testing.T) {
	data := lanEncode(lanDeriveKey("a"), lanMsgBeacon, lanBeacon{})
	if _, err := lanDecode(lanDeriveKey("b"), data); err == nil { t.Fatal("wrong key") }
}

func TestLanDecodeTampered(t *testing.T) {
	key := lanDeriveKey("test")
	data := lanEncode(key, lanMsgBeacon, lanBeacon{})
	var m lanMsg
	json.Unmarshal(data, &m)
	m.Payload += "X"
	tampered, _ := json.Marshal(m)
	if _, err := lanDecode(key, tampered); err == nil { t.Fatal("tampered") }
}

func TestNegotiateTransport(t *testing.T) {
	cases := [][3]string{
		{"udp", "udp", "udp"}, {"udp", "tcp", "udp"}, {"udp", "", "udp"},
		{"tcp", "udp", "udp"}, {"tcp", "tcp", "tcp"}, {"tcp", "", "tcp"},
		{"", "udp", "udp"}, {"", "tcp", "tcp"}, {"", "", "tcp"},
	}
	for _, c := range cases {
		if negotiateTransport(c[0], c[1]) != c[2] {
			t.Errorf("negotiate(%q,%q) want %q", c[0], c[1], c[2])
		}
	}
}

func TestSelfFilter(t *testing.T) {
	f := newSelfFilter()
	if f.IsSelf("a") { t.Fatal("not yet") }
	f.Add("a")
	if !f.IsSelf("a") { t.Fatal("should") }
	if f.IsSelf("b") { t.Fatal("b") }
}

func TestBestLocalIP(t *testing.T) {
	ip, err := bestLocalIPForRemote("192.168.1.1")
	if err != nil { t.Skipf("no route: %v", err) }
	if ip == "" { t.Fatal("empty") }
	t.Logf("best for 192.168.1.1: %s", ip)
}

func TestAddrToIP(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	if addrToIP(addr) != "192.168.1.100" { t.Fatal("udp addr") }
}

func TestMulticastSendRecv(t *testing.T) {
	mc, err := newLanMcast()
	if err != nil { t.Skipf("multicast: %v", err) }
	defer mc.Close()
	t.Logf("joined %d ifaces", len(mc.ifaces))
	testMsg := []byte("hello-mcast")
	mc.broadcast(testMsg)
	buf := make([]byte, 1024)
	mc.rawConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, _, err := mc.conn.ReadFrom(buf)
	if err != nil { t.Fatalf("recv: %v", err) }
	if string(buf[:n]) != string(testMsg) { t.Fatalf("got %q", buf[:n]) }
	t.Log("OK")
}

func TestDispatcher(t *testing.T) {
	mc, err := newLanMcast()
	if err != nil { t.Skipf("multicast: %v", err) }
	defer mc.Close()
	key := lanDeriveKey("disp-test")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	disp := newLanDispatcher()
	go disp.run(ctx, mc, key)
	// 发一个 beacon
	mc.broadcast(lanEncode(key, lanMsgBeacon, lanBeacon{SessionID: "test", NonceA: "n1"}))
	// 发一个 response
	mc.broadcast(lanEncode(key, lanMsgResponse, lanResponse{NonceA: "n1", NonceB: "n2"}))
	// 验证分发
	select {
	case pkt := <-disp.beaconCh:
		if pkt.msg.Type != lanMsgBeacon { t.Fatal("type") }
	case <-time.After(2 * time.Second):
		t.Fatal("beacon timeout")
	}
	select {
	case pkt := <-disp.responseCh:
		if pkt.msg.Type != lanMsgResponse { t.Fatal("type") }
	case <-time.After(2 * time.Second):
		t.Fatal("response timeout")
	}
}

func TestLANTransportFromConfig(t *testing.T) {
	if LANTransportFromConfig(true) != "udp" { t.Fatal("udp") }
	if LANTransportFromConfig(false) != "" { t.Fatal("empty") }
}

// ── 集成测试 ──

func TestLANDiscoverLoopback(t *testing.T) {
	if os.Getenv("TEST_LAN_DISCOVER") == "" { t.Skip("set TEST_LAN_DISCOVER=1") }
	ctx := context.Background()
	key := "test-lan-12345"
	type rp struct { r *LANDiscoverResult; err error }
	ch := make(chan rp, 2)
	go func() { r, e := LANDiscover(ctx, key, "", 15*time.Second, os.Stderr); ch <- rp{r, e} }()
	time.Sleep(300 * time.Millisecond)
	go func() { r, e := LANDiscover(ctx, key, "", 15*time.Second, os.Stderr); ch <- rp{r, e} }()
	r1 := <-ch; if r1.err != nil { t.Fatalf("n1: %v", r1.err) }; t.Logf("N1: %+v", r1.r)
	r2 := <-ch; if r2.err != nil { t.Fatalf("n2: %v", r2.err) }; t.Logf("N2: %+v", r2.r)
}

func TestLANDiscoverUDP(t *testing.T) {
	if os.Getenv("TEST_LAN_DISCOVER") == "" { t.Skip("set TEST_LAN_DISCOVER=1") }
	ctx := context.Background()
	key := "test-lan-udp"
	type rp struct { r *LANDiscoverResult; err error }
	ch := make(chan rp, 2)
	go func() { r, e := LANDiscover(ctx, key, "udp", 15*time.Second, os.Stderr); ch <- rp{r, e} }()
	time.Sleep(300 * time.Millisecond)
	go func() { r, e := LANDiscover(ctx, key, "", 15*time.Second, os.Stderr); ch <- rp{r, e} }()
	r1 := <-ch; if r1.err != nil { t.Fatalf("A: %v", r1.err) }
	r2 := <-ch; if r2.err != nil { t.Fatalf("B: %v", r2.err) }
	if r1.r.Transport != "udp" || r2.r.Transport != "udp" {
		t.Fatalf("both udp: %s %s", r1.r.Transport, r2.r.Transport)
	}
}

func TestMcastPortAvailable(t *testing.T) {
	addr := fmt.Sprintf("%s:%d", LANMulticastIP, LANMulticastPort)
	c, err := net.ListenPacket("udp4", addr)
	if err != nil { t.Skipf("port unavailable: %v", err) }
	c.Close()
}
