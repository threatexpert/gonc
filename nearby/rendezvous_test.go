package nearby

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func testRecord() PeerRecord {
	return PeerRecord{PairKey: bytes.Repeat([]byte{9}, 32), PairID: strings.Repeat("ef", 32), InstallationID: strings.Repeat("ab", 16), IRK: bytes.Repeat([]byte{1}, 16)}
}

func TestKnockSignatureBindsEveryField(t *testing.T) {
	rec := testRecord()
	key, err := knockMACKey(rec)
	if err != nil {
		t.Fatal(err)
	}
	base := knockMsg{Kind: knockSession, Tag: bytes.Repeat([]byte{1}, 32), Target: bytes.Repeat([]byte{2}, 32), Nonce: bytes.Repeat([]byte{3}, 16)}
	mac := knockMAC(key, &base)
	for name, mutate := range map[string]func(k *knockMsg){
		"kind":   func(k *knockMsg) { k.Kind = knockPair },
		"tag":    func(k *knockMsg) { k.Tag = bytes.Repeat([]byte{4}, 32) },
		"target": func(k *knockMsg) { k.Target = bytes.Repeat([]byte{4}, 32) },
		"nonce":  func(k *knockMsg) { k.Nonce = bytes.Repeat([]byte{4}, 16) },
	} {
		k := base
		mutate(&k)
		if bytes.Equal(knockMAC(key, &k), mac) {
			t.Errorf("changing %s does not change the signature", name)
		}
	}
	other := testRecord()
	other.PairKey = bytes.Repeat([]byte{8}, 32)
	otherKey, _ := knockMACKey(other)
	if bytes.Equal(knockMAC(otherKey, &base), mac) {
		t.Fatal("a different pairing key produces the same signature")
	}
}

func TestRendezvousKeys(t *testing.T) {
	rec := testRecord()
	nonce, tagI, tagR := bytes.Repeat([]byte{3}, 16), bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	a, err := rendezvousKey(knockSession, &rec, nonce, tagI, tagR)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := rendezvousKey(knockSession, &rec, nonce, tagI, tagR)
	if a != b {
		t.Fatal("both sides would derive different session rendezvous keys")
	}
	pair, err := rendezvousKey(knockPair, nil, nonce, tagI, tagR)
	if err != nil {
		t.Fatal(err)
	}
	if pair == a {
		t.Fatal("pairing and session rendezvous keys are equal")
	}
	if _, err := rendezvousKey(knockSession, nil, nonce, tagI, tagR); err == nil {
		t.Fatal("a session rendezvous key was derived without a pairing")
	}
	fresh, _ := rendezvousKey(knockSession, &rec, bytes.Repeat([]byte{5}, 16), tagI, tagR)
	if fresh == a {
		t.Fatal("a new knock nonce did not change the rendezvous key")
	}
	for _, k := range []string{a, pair} {
		hasLetter := strings.ContainsAny(k, "abcdefghijklmnopqrstuvwxyz")
		hasDigit := strings.ContainsAny(k, "0123456789")
		if !hasLetter || !hasDigit || len(k) < 20 {
			t.Fatalf("rendezvous key %q would fail gonc's passphrase strength check", k)
		}
	}
}

func TestKnockGateAnswersEachKnockOnce(t *testing.T) {
	g := knockGate{seen: map[string]time.Time{}}
	n := bytes.Repeat([]byte{7}, 16)
	if !g.firstTime(n) {
		t.Fatal("first knock was rejected")
	}
	if g.firstTime(n) {
		t.Fatal("repeated knock was answered twice")
	}
	if !g.firstTime(bytes.Repeat([]byte{6}, 16)) {
		t.Fatal("a different knock was rejected")
	}
}

func TestPendingKnockFollowsDeviceAdvertisements(t *testing.T) {
	s := &Service{knocks: map[*pendingKnock]bool{}}
	s.knocks[&pendingKnock{deviceID: "p-x", data: []byte("knock-x")}] = true
	s.knocks[&pendingKnock{deviceID: "p-y", data: []byte("knock-y")}] = true
	got := s.pendingKnocksForLocked("p-x")
	if len(got) != 1 || string(got[0]) != "knock-x" {
		t.Fatalf("pending knocks for p-x = %q", got)
	}
}
