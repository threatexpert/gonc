package nearby

import (
	"bytes"
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func testIdentity(t *testing.T, name string) Identity {
	t.Helper()
	id, err := NewInstallationID()
	if err != nil {
		t.Fatal(err)
	}
	irk, err := NewIRK()
	if err != nil {
		t.Fatal(err)
	}
	return Identity{InstallationID: id, IRK: irk, Nickname: name, DeviceType: "desktop"}
}

func TestEncodeIsUnambiguous(t *testing.T) {
	a := encode([]byte("ab"), []byte("c"))
	b := encode([]byte("a"), []byte("bc"))
	if bytes.Equal(a, b) {
		t.Fatal("different field splits encode identically")
	}
}

func TestTagResolvesOnlyWithItsIRK(t *testing.T) {
	irk, _ := NewIRK()
	other, _ := NewIRK()
	tag, err := makeTag(irk)
	if err != nil {
		t.Fatal(err)
	}
	if !tagMatches(irk, tag) {
		t.Fatal("tag does not resolve with its own IRK")
	}
	if tagMatches(other, tag) {
		t.Fatal("tag resolves with a different IRK")
	}
	tag2, _ := makeTag(irk)
	if bytes.Equal(tag, tag2) {
		t.Fatal("two tags from the same IRK are identical")
	}
	tag[len(tag)-1] ^= 1
	if tagMatches(irk, tag) {
		t.Fatal("tampered tag still resolves")
	}
}

func TestSessionKeysMatchAndPassStrengthCheck(t *testing.T) {
	rec := PeerRecord{PairKey: bytes.Repeat([]byte{7}, 32), PairID: strings.Repeat("ab", 32)}
	nA, nB := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	k1, err := deriveSessionKeys(rec, "a", "b", nA, nB)
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := deriveSessionKeys(rec, "a", "b", nA, nB)
	if k1.transfer != k2.transfer || k1.control != k2.control {
		t.Fatal("session keys are not deterministic")
	}
	if k1.transfer == k1.control {
		t.Fatal("transfer and control keys are equal")
	}
	k3, _ := deriveSessionKeys(rec, "a", "b", nA, bytes.Repeat([]byte{3}, 32))
	if k3.transfer == k1.transfer {
		t.Fatal("a fresh nonce did not change the transfer key")
	}
	if !strings.HasPrefix(k1.transfer, "nb1-") || len(k1.transfer) < 40 {
		t.Fatalf("unexpected transfer key format %q", k1.transfer)
	}
}

// pairOverPipe runs both pairing roles over an in-memory connection.
func pairOverPipe(t *testing.T, decideA, decideB bool) (*Pairing, *Pairing) {
	t.Helper()
	a, b := testIdentity(t, "Alice"), testIdentity(t, "Bob")
	ca, cb := net.Pipe()
	tagA, _ := makeTag(a.IRK)
	tagB, _ := makeTag(b.IRK)
	closed := make(chan struct{})
	t.Cleanup(func() { close(closed); ca.Close(); cb.Close() })

	type result struct {
		p   *Pairing
		err error
	}
	bRes := make(chan result, 1)
	go func() {
		first, err := readMsg(cb)
		if err != nil {
			bRes <- result{nil, err}
			return
		}
		p, x, k, err := pairRespond(cb, first, b, tagB)
		bRes <- result{p, err}
		if err != nil {
			return
		}
		rec, err := runConfirmation(cb, p, x, k, b, closed)
		p.finish(rec, err)
	}()
	pA, xA, kA, err := pairInitiate(ca, a, 0, tagA, tagB)
	if err != nil {
		t.Fatal(err)
	}
	r := <-bRes
	if r.err != nil {
		t.Fatal(r.err)
	}
	pB := r.p
	go func() {
		rec, err := runConfirmation(ca, pA, xA, kA, a, closed)
		pA.finish(rec, err)
	}()
	if pA.Code != pB.Code || len(pA.Code) != 6 {
		t.Fatalf("codes differ or malformed: %q vs %q", pA.Code, pB.Code)
	}
	if pA.PeerName != "Bob" || pB.PeerName != "Alice" {
		t.Fatalf("peer names %q / %q", pA.PeerName, pB.PeerName)
	}
	pA.Confirm(decideA)
	pB.Confirm(decideB)
	for _, p := range []*Pairing{pA, pB} {
		select {
		case <-p.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("pairing did not finish")
		}
	}
	return pA, pB
}

func TestPairingSucceedsWhenBothConfirm(t *testing.T) {
	pA, pB := pairOverPipe(t, true, true)
	recA, errA := pA.Result()
	recB, errB := pB.Result()
	if errA != nil || errB != nil {
		t.Fatalf("pairing errors: %v / %v", errA, errB)
	}
	if !bytes.Equal(recA.PairKey, recB.PairKey) || recA.PairID != recB.PairID {
		t.Fatal("the two sides derived different pairing keys")
	}
	if recA.Nickname != "Bob" || recB.Nickname != "Alice" || !recA.valid() || !recB.valid() {
		t.Fatalf("unexpected records %+v / %+v", recA, recB)
	}
}

func TestPairingFailsWhenOneSideRejects(t *testing.T) {
	pA, pB := pairOverPipe(t, true, false)
	if _, err := pA.Result(); err == nil {
		t.Fatal("initiator paired although the responder rejected")
	}
	if _, err := pB.Result(); !errors.Is(err, ErrRejected) {
		t.Fatalf("responder error = %v, want ErrRejected", err)
	}
}

func TestRevealMustMatchCommitment(t *testing.T) {
	ctx := pairContext(make([]byte, 16), make([]byte, 32), make([]byte, 32))
	a, _ := newPairExchange(roleA, ctx)
	b, _ := newPairExchange(roleB, ctx)
	b.peerCommit = a.commit
	other, _ := newPairExchange(roleA, ctx)
	if err := b.acceptReveal(other.pub, other.nonce); err == nil {
		t.Fatal("accepted a reveal that does not match the commitment")
	}
	if err := b.acceptReveal(a.pub, a.nonce); err != nil {
		t.Fatalf("rejected a valid reveal: %v", err)
	}
}

type testHandler struct {
	mu        sync.Mutex
	devices   []Device
	pairings  chan *Pairing
	transfers chan *IncomingTransfer
}

func newTestHandler() *testHandler {
	return &testHandler{pairings: make(chan *Pairing, 4), transfers: make(chan *IncomingTransfer, 4)}
}

func (h *testHandler) DevicesChanged(d []Device) {
	h.mu.Lock()
	h.devices = d
	h.mu.Unlock()
}
func (h *testHandler) IncomingPairing(p *Pairing)           { h.pairings <- p }
func (h *testHandler) IncomingTransfer(t *IncomingTransfer) { h.transfers <- t }

func startTestService(t *testing.T, id Identity, port int, h Handler) *Service {
	t.Helper()
	s, err := Start(Config{Identity: id, Visible: true, Handler: h, DiscoveryPort: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func findDevice(s *Service, match func(Device) bool, timeout time.Duration) (Device, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, d := range s.Devices() {
			if match(d) {
				return d, true
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return Device{}, false
}

func waitDevice(t *testing.T, s *Service, match func(Device) bool) Device {
	t.Helper()
	d, ok := findDevice(s, match, 15*time.Second)
	if !ok {
		t.Fatalf("device not found; seen: %+v", s.Devices())
	}
	return d
}

// link makes each service see the other through AddAddress, which uses TCP
// only, so these tests do not depend on multicast being deliverable.
func link(t *testing.T, a, b *Service) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.AddAddress(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(b.Port()))); err != nil {
		t.Fatal(err)
	}
	if _, err := b.AddAddress(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(a.Port()))); err != nil {
		t.Fatal(err)
	}
}

func TestMulticastDiscovery(t *testing.T) {
	port := 40000 + rand.IntN(20000)
	a, b := testIdentity(t, "Alice"), testIdentity(t, "Bob")
	sa := startTestService(t, a, port, newTestHandler())
	startTestService(t, b, port, newTestHandler())
	if _, ok := findDevice(sa, func(d Device) bool { return d.Nickname == "Bob" }, 8*time.Second); !ok {
		t.Skip("multicast datagrams are not delivered on this host")
	}
}

func TestAddAddressRejectsInvisibleDevice(t *testing.T) {
	port := 40000 + rand.IntN(20000)
	sa := startTestService(t, testIdentity(t, "Alice"), port, newTestHandler())
	sb := startTestService(t, testIdentity(t, "Bob"), port, newTestHandler())
	sb.SetVisible(false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := sa.AddAddress(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(sb.Port()))); err == nil {
		t.Fatal("an invisible device answered a hello")
	}
	if _, err := sa.AddAddress(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(sa.Port()))); err == nil {
		t.Fatal("a device added itself")
	}
}

func TestDiscoveryPairingAndTransferSession(t *testing.T) {
	port := 40000 + rand.IntN(20000)
	a, b := testIdentity(t, "Alice"), testIdentity(t, "Bob")
	ha, hb := newTestHandler(), newTestHandler()
	sa := startTestService(t, a, port, ha)
	sb := startTestService(t, b, port, hb)
	link(t, sa, sb)

	devB := waitDevice(t, sa, func(d Device) bool { return d.Nickname == "Bob" })
	if devB.Paired {
		t.Fatal("unpaired device reported as paired")
	}
	if !strings.HasPrefix(devB.ID, "t-") {
		t.Fatalf("unpaired device ID %q leaks a stable identifier", devB.ID)
	}

	pA, err := sa.Pair(devB.ID)
	if err != nil {
		t.Fatal(err)
	}
	var pB *Pairing
	select {
	case pB = <-hb.pairings:
	case <-time.After(5 * time.Second):
		t.Fatal("responder never saw the pairing request")
	}
	if pA.Code != pB.Code {
		t.Fatalf("codes differ: %s vs %s", pA.Code, pB.Code)
	}
	pA.Confirm(true)
	pB.Confirm(true)
	<-pA.Done()
	<-pB.Done()
	if _, err := pA.Result(); err != nil {
		t.Fatal(err)
	}
	if _, err := pB.Result(); err != nil {
		t.Fatal(err)
	}

	paired := waitDevice(t, sa, func(d Device) bool { return d.PeerID == b.InstallationID && d.Verified })
	if paired.ID != "p-"+b.InstallationID {
		t.Fatalf("paired device ID = %q", paired.ID)
	}
	waitDevice(t, sb, func(d Device) bool { return d.PeerID == a.InstallationID && d.Verified })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := sa.OpenTransfer(ctx, paired.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	offer := OfferInfo{Port: 45678, Name: "Alice", LAN: true, Files: 3, Bytes: 9,
		Items: []OfferItem{{Name: "notes.txt", Size: 4}, {Name: "photos", Dir: true, Size: 5}, {Name: "\x00"}}}
	if err := out.Offer(offer); err != nil {
		t.Fatal(err)
	}
	var in *IncomingTransfer
	select {
	case in = <-hb.transfers:
	case <-time.After(5 * time.Second):
		t.Fatal("recipient never saw the offer")
	}
	if in.Passphrase != out.Passphrase {
		t.Fatal("sender and recipient derived different transfer passphrases")
	}
	if _, port, _ := net.SplitHostPort(in.SenderAddress); port != "45678" {
		t.Fatalf("sender address = %q", in.SenderAddress)
	}
	if in.PeerID != a.InstallationID || in.PeerName != "Alice" {
		t.Fatalf("incoming transfer peer %q %q", in.PeerID, in.PeerName)
	}
	if in.Files != 3 || in.Bytes != 9 || len(in.Items) != 2 || in.Items[1] != (OfferItem{Name: "photos", Dir: true, Size: 5}) {
		t.Fatalf("offer summary = %d files, %d bytes, %+v", in.Files, in.Bytes, in.Items)
	}
	if err := in.Accept(); err != nil {
		t.Fatal(err)
	}
	if ok, err := out.WaitResponse(ctx); err != nil || !ok {
		t.Fatalf("WaitResponse = %v, %v", ok, err)
	}
	if err := in.Finish(true, "3 files"); err != nil {
		t.Fatal(err)
	}
	if ok, msg, err := out.WaitFinished(ctx); err != nil || !ok || msg != "3 files" {
		t.Fatalf("WaitFinished = %v, %q, %v", ok, msg, err)
	}

	// A second session gets a fresh passphrase.
	out2, err := sa.OpenTransfer(ctx, paired.ID)
	if err != nil {
		t.Fatal(err)
	}
	if out2.Passphrase == out.Passphrase {
		t.Fatal("two sessions share a transfer passphrase")
	}
	out2.Cancel()

	// After B forgets A, A can no longer open sessions.
	sb.SetPeers(nil)
	if _, err := sa.OpenTransfer(ctx, paired.ID); !errors.Is(err, ErrNotPaired) {
		t.Fatalf("OpenTransfer after forget = %v, want ErrNotPaired", err)
	}
}

func TestSessionFailsWithMismatchedPairKey(t *testing.T) {
	port := 40000 + rand.IntN(20000)
	a, b := testIdentity(t, "Alice"), testIdentity(t, "Bob")
	pairID := strings.Repeat("cd", 32)
	recOfB := PeerRecord{InstallationID: b.InstallationID, IRK: b.IRK, PairKey: bytes.Repeat([]byte{1}, 32), PairID: pairID, Nickname: "Bob"}
	recOfA := PeerRecord{InstallationID: a.InstallationID, IRK: a.IRK, PairKey: bytes.Repeat([]byte{2}, 32), PairID: pairID, Nickname: "Alice"}
	sa, err := Start(Config{Identity: a, Peers: []PeerRecord{recOfB}, Visible: true, Handler: newTestHandler(), DiscoveryPort: port})
	if err != nil {
		t.Fatal(err)
	}
	defer sa.Close()
	sb, err := Start(Config{Identity: b, Peers: []PeerRecord{recOfA}, Visible: true, Handler: newTestHandler(), DiscoveryPort: port})
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close()
	link(t, sa, sb)

	dev := waitDevice(t, sa, func(d Device) bool { return d.PeerID == b.InstallationID })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := sa.OpenTransfer(ctx, dev.ID); !errors.Is(err, ErrVerification) {
		t.Fatalf("OpenTransfer with mismatched keys = %v, want ErrVerification", err)
	}
	time.Sleep(500 * time.Millisecond)
	for _, d := range sa.Devices() {
		if d.PeerID == b.InstallationID && d.Verified {
			t.Fatal("device with a mismatched key was marked verified")
		}
	}
}

// When only one side can reach the other by address (no multicast), pairing
// teaches the responder where the initiator is, so it can send back.
func TestOneSidedAddressBecomesMutualAfterPairing(t *testing.T) {
	port := 40000 + rand.IntN(20000)
	a, b := testIdentity(t, "Alice"), testIdentity(t, "Bob")
	ha, hb := newTestHandler(), newTestHandler()
	sa := startTestService(t, a, port, ha)
	sb := startTestService(t, b, port, hb)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	devB, err := sa.AddAddress(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(sb.Port())))
	if err != nil {
		t.Fatal(err)
	}
	pA, err := sa.Pair(devB.ID)
	if err != nil {
		t.Fatal(err)
	}
	pB := <-hb.pairings
	pA.Confirm(true)
	pB.Confirm(true)
	<-pA.Done()
	<-pB.Done()

	devA := waitDevice(t, sb, func(d Device) bool { return d.PeerID == a.InstallationID && d.Verified })
	out, err := sb.OpenTransfer(ctx, devA.ID)
	if err != nil {
		t.Fatalf("Bob could not open a session back to Alice: %v", err)
	}
	out.Cancel()
}
