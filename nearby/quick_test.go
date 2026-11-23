package nearby

import (
	"context"
	"errors"
	"math/rand/v2"
	"testing"
	"time"
)

func TestQuickSendWithoutPairing(t *testing.T) {
	port := 40000 + rand.IntN(20000)
	a, b := testIdentity(t, "Alice"), testIdentity(t, "Bob")
	hb := newTestHandler()
	sa := startTestService(t, a, port, newTestHandler())
	sb := startTestService(t, b, port, hb)
	sb.SetQuickReceive(true)
	link(t, sa, sb)

	bob := waitDevice(t, sa, func(d Device) bool { return d.Nickname == "Bob" && d.QuickReceive })
	if bob.Paired {
		t.Fatal("Bob is paired before any pairing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := sa.OpenQuickTransfer(ctx, bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if err := out.Offer(OfferInfo{Port: 45678, Name: "Alice", Files: 1, Bytes: 5, Items: []OfferItem{{Name: "a.txt", Size: 5}}}); err != nil {
		t.Fatal(err)
	}
	var in *IncomingTransfer
	select {
	case in = <-hb.transfers:
	case <-time.After(5 * time.Second):
		t.Fatal("recipient never saw the quick offer")
	}
	if in.Verified || in.PeerID != "" {
		t.Fatalf("quick offer verified=%v peer=%q, want unverified with no peer", in.Verified, in.PeerID)
	}
	if in.PeerName != "Alice" || in.Passphrase != out.Passphrase || in.Files != 1 {
		t.Fatalf("quick offer %q files=%d, passphrases match=%v", in.PeerName, in.Files, in.Passphrase == out.Passphrase)
	}
	if err := in.Accept(); err != nil {
		t.Fatal(err)
	}
	if ok, err := out.WaitResponse(ctx); err != nil || !ok {
		t.Fatalf("WaitResponse = %v, %v", ok, err)
	}
	in.Close()

	// Quick sends never create a pairing on either side.
	for _, d := range append(sa.Devices(), sb.Devices()...) {
		if d.Paired {
			t.Fatalf("quick send paired %q", d.Nickname)
		}
	}

	// A second quick session gets a different passphrase.
	out2, err := sa.OpenQuickTransfer(ctx, bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer out2.Close()
	if out2.Passphrase == out.Passphrase {
		t.Fatal("two quick sessions share a passphrase")
	}
}

func TestQuickSendRefusedWhenTurnedOff(t *testing.T) {
	port := 40000 + rand.IntN(20000)
	sa := startTestService(t, testIdentity(t, "Alice"), port, newTestHandler())
	sb := startTestService(t, testIdentity(t, "Bob"), port, newTestHandler())
	link(t, sa, sb)
	bob := waitDevice(t, sa, func(d Device) bool { return d.Nickname == "Bob" })
	if bob.QuickReceive {
		t.Fatal("Bob advertises quick receive while it is off")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := sa.OpenQuickTransfer(ctx, bob.ID); !errors.Is(err, ErrQuickRefused) {
		t.Fatalf("OpenQuickTransfer = %v, want ErrQuickRefused", err)
	}
}

func TestQuickKeysBindBothSides(t *testing.T) {
	first := &wireMsg{Tag: make([]byte, tagBytes), Target: make([]byte, tagBytes), Pub: []byte("pubA"), Nonce: []byte("nonceA")}
	k1, err := deriveQuickKeys([]byte("shared"), quickContext(first, []byte("pubB"), []byte("nonceB")))
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := deriveQuickKeys([]byte("shared"), quickContext(first, []byte("pubB"), []byte("nonceC")))
	if k1.transfer == k2.transfer || k1.control == k2.control {
		t.Fatal("quick keys do not depend on the responder's nonce")
	}
	if k1.transfer == k1.control {
		t.Fatal("control and transfer keys are equal")
	}
}
