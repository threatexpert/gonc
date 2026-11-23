package nearby

import (
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"
)

func knockFrom(t *testing.T, kind string, target []byte) (*knockMsg, []byte) {
	t.Helper()
	irk, _ := NewIRK()
	tag, _ := makeTag(irk)
	nonce, _ := randomBytes(knockNonceBytes)
	k := &knockMsg{M: advertMagic, V: ProtocolVersion, K: knockKind, Kind: kind, Tag: tag, Target: target, Nonce: nonce}
	if kind == knockSession {
		k.MAC = make([]byte, knockMACBytes)
	}
	data, _ := json.Marshal(k)
	return k, data
}

func TestKnocksThatWillNotBeMetAreRefused(t *testing.T) {
	s, sent := quietService(t)
	s.handler = &testHandler{}
	src := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 30), Port: MulticastPort}

	for _, tc := range []struct{ kind, reason string }{
		{knockSession, refuseUnknown}, // a pairing this device forgot
		{knockQuick, refuseQuick},     // quick receive is off
	} {
		k, data := knockFrom(t, tc.kind, s.tag)
		s.handleKnock(data, src)
		p := next(sent, time.Second)
		if p == nil {
			t.Fatalf("%s knock was not refused", tc.kind)
		}
		var r knockMsg
		if err := json.Unmarshal(p, &r); err != nil || r.K != knockRefusedKind || r.Kind != tc.reason {
			t.Fatalf("%s knock answered with %s", tc.kind, p)
		}
		if string(r.Nonce) != string(k.Nonce) || string(r.Target) != string(k.Tag) {
			t.Fatalf("refusal does not name the knock it answers: %s", p)
		}
		if _, ok := parseAdvert(p); ok {
			t.Fatal("a refusal parses as an advertisement on older devices")
		}
	}

	// Knocks for another device get no answer.
	irk, _ := NewIRK()
	other, _ := makeTag(irk)
	_, data := knockFrom(t, knockSession, other)
	s.handleKnock(data, src)
	if p := next(sent, 200*time.Millisecond); p != nil {
		t.Fatalf("answered a knock for another device: %s", p)
	}
}

func TestRefusalIsAcceptedOnlyFromTheKnockedDevice(t *testing.T) {
	s := bareService(t)
	s.knocks = map[*pendingKnock]bool{}
	deviceAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 5), Port: MulticastPort}
	s.devices["p-desk"] = &deviceState{Device: Device{ID: "p-desk"}, src: deviceAddr}
	nonce, _ := randomBytes(knockNonceBytes)
	pk := &pendingKnock{deviceID: "p-desk", nonce: nonce, refused: make(chan string, 1)}
	s.knocks[pk] = true

	refusal := func(target, nonce []byte) []byte {
		data, _ := json.Marshal(&knockMsg{M: advertMagic, V: ProtocolVersion, K: knockRefusedKind, Kind: refuseUnknown, Target: target, Nonce: nonce})
		return data
	}
	otherNonce, _ := randomBytes(knockNonceBytes)
	stranger := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 66), Port: MulticastPort}
	s.handleKnockRefused(refusal(s.tag, nonce), stranger)
	s.handleKnockRefused(refusal(s.tag, otherNonce), deviceAddr)
	s.handleKnockRefused(refusal(make([]byte, tagBytes), nonce), deviceAddr)
	select {
	case r := <-pk.refused:
		t.Fatalf("accepted a refusal that does not match the knock (%s)", r)
	default:
	}

	s.handleKnockRefused(refusal(s.tag, nonce), &net.UDPAddr{IP: deviceAddr.IP, Port: 50000})
	select {
	case r := <-pk.refused:
		if r != refuseUnknown {
			t.Fatalf("refusal reason = %q", r)
		}
	default:
		t.Fatal("the knocked device's refusal was not accepted")
	}
}

// TestForgottenPairingFailsFast knocks for a session on a device that no
// longer has the pairing. The sender must report ErrNotPaired right away
// instead of waiting out the rendezvous window.
func TestForgottenPairingFailsFast(t *testing.T) {
	sender, toReceiver := quietService(t)
	receiver, toSender := quietService(t)
	receiver.handler = &testHandler{}
	sender.knocks = map[*pendingKnock]bool{}
	senderAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 40), Port: MulticastPort}
	receiverAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 41), Port: MulticastPort}
	stop := make(chan struct{})
	defer close(stop)
	relay := func(from chan []byte, to *Service, src net.Addr) {
		for {
			select {
			case p := <-from:
				to.handlePacket(packet{data: p, src: src})
			case <-stop:
				return
			}
		}
	}
	go relay(toReceiver, receiver, senderAddr)
	go relay(toSender, sender, receiverAddr)

	rec := testRecord()
	d := &deviceState{Device: Device{ID: "p-desk", Nickname: "Desk"}, tag: receiver.tag, src: receiverAddr}
	sender.devices[d.ID] = d
	ctx, cancel := sender.context(rendezvousWindow)
	defer cancel()
	start := time.Now()
	_, err := sender.knockAndMeet(ctx, d, knockSession, &rec, sender.tag)
	if !errors.Is(err, ErrNotPaired) {
		t.Fatalf("knock on a device that forgot the pairing returned %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("refusal took %v", elapsed)
	}
}
