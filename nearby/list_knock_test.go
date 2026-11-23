package nearby

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"testing"
	"time"
)

func bareService(t *testing.T) *Service {
	t.Helper()
	s := &Service{
		logger:        log.New(io.Discard, "", 0),
		self:          testIdentity(t, "Self"),
		peers:         map[string]PeerRecord{},
		devices:       map[string]*deviceState{},
		pairLimit:     newRateLimiter(pairsPerMinute, time.Minute),
		quickLimit:    newRateLimiter(quicksPerMinute, time.Minute),
		knockGate:     knockGate{seen: map[string]time.Time{}},
		rendezvousSem: make(chan struct{}), // full: knocks stop before a rendezvous
		directFailed:  map[string]time.Time{},
		closed:        make(chan struct{}),
	}
	if err := s.rotateTagLocked(); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRestartedDeviceReplacesItsOldEntry(t *testing.T) {
	s := bareService(t)
	irk, _ := NewIRK()
	oldTag, _ := makeTag(irk)
	irk2, _ := NewIRK() // a restart without pairing looks like a new device
	newTag, _ := makeTag(irk2)
	now := time.Now()
	s.observeLocked(&advert{Tag: oldTag, Name: "Laptop", Port: 19732}, "192.168.1.5", nil, now)
	s.observeLocked(&advert{Tag: newTag, Name: "Laptop", Port: 19732}, "192.168.1.5", nil, now)
	if len(s.devices) != 1 {
		t.Fatalf("device list has %d entries, want 1", len(s.devices))
	}
	// A restart that also changed the TCP port is matched by host and name.
	s.observeLocked(&advert{Tag: oldTag, Name: "Laptop", Port: 50111}, "192.168.1.5", nil, now)
	if len(s.devices) != 1 {
		t.Fatalf("device list has %d entries after a port change, want 1", len(s.devices))
	}
	// A different device on another host stays.
	otherIRK, _ := NewIRK()
	otherTag, _ := makeTag(otherIRK)
	s.observeLocked(&advert{Tag: otherTag, Name: "Laptop", Port: 19732}, "192.168.1.6", nil, now)
	if len(s.devices) != 2 {
		t.Fatalf("device list has %d entries, want 2", len(s.devices))
	}
}

func TestUnpairedAdvertDoesNotRemovePairedDevice(t *testing.T) {
	s := bareService(t)
	peer := testIdentity(t, "Phone")
	s.peers[peer.InstallationID] = PeerRecord{InstallationID: peer.InstallationID, IRK: peer.IRK, Nickname: "Phone"}
	pairedTag, _ := makeTag(peer.IRK)
	strangerIRK, _ := NewIRK()
	strangerTag, _ := makeTag(strangerIRK)
	now := time.Now()
	s.observeLocked(&advert{Tag: pairedTag, Name: "Phone", Port: 19732}, "192.168.1.7", nil, now)
	s.observeLocked(&advert{Tag: strangerTag, Name: "Phone", Port: 19732}, "192.168.1.7", nil, now)
	if _, ok := s.devices["p-"+peer.InstallationID]; !ok {
		t.Fatal("an unpaired advertisement removed the paired device")
	}
}

func TestRepeatedPairKnockCountsAsOneAttempt(t *testing.T) {
	s := bareService(t)
	s.handler = &testHandler{}
	src := &net.UDPAddr{IP: net.ParseIP("192.168.1.9"), Port: MulticastPort}
	knock := func() []byte {
		irk, _ := NewIRK()
		tag, _ := makeTag(irk)
		nonce, _ := randomBytes(knockNonceBytes)
		data, _ := json.Marshal(&knockMsg{M: advertMagic, V: ProtocolVersion, K: knockKind, Kind: knockPair, Tag: tag, Target: s.tag, Nonce: nonce})
		return data
	}
	first := knock()
	for i := 0; i < 10; i++ {
		s.handleKnock(first, src)
	}
	if got := len(s.pairLimit.events["knock:192.168.1.9"]); got != 1 {
		t.Fatalf("ten repeats of one knock counted as %d attempts", got)
	}
	// Retries after a cancelled pairing are new knocks and still get through.
	for i := 1; i < pairsPerMinute; i++ {
		s.handleKnock(knock(), src)
	}
	if got := len(s.pairLimit.events["knock:192.168.1.9"]); got != pairsPerMinute {
		t.Fatalf("%d distinct knocks counted as %d attempts", pairsPerMinute, got)
	}
}

func TestPairingMarksDeviceVerified(t *testing.T) {
	s := bareService(t)
	s.notifyCh = make(chan struct{}, 1)
	peer := testIdentity(t, "Desk")
	tag, _ := makeTag(peer.IRK)
	s.observeLocked(&advert{Tag: tag, Name: "Desk", Port: 19732}, "192.168.1.8", nil, time.Now())
	pairID := make([]byte, 16)
	s.addPeer(PeerRecord{InstallationID: peer.InstallationID, IRK: peer.IRK, PairKey: make([]byte, 32), PairID: "00112233445566778899aabbccddeeff"[:len(pairID)*2], Nickname: "Desk"})
	d, ok := s.devices["p-"+peer.InstallationID]
	if !ok || !d.Verified {
		t.Fatalf("paired device verified = %v (present %v)", ok && d.Verified, ok)
	}
	if _, verify, _ := s.observeLocked(&advert{Tag: tag, Name: "Desk", Port: 19732}, "192.168.1.8", nil, time.Now()); verify {
		t.Fatal("a device that just paired is verified again in the background")
	}
}

func TestQuickKnockFollowsReceiveSetting(t *testing.T) {
	s := bareService(t)
	s.handler = &testHandler{}
	src := &net.UDPAddr{IP: net.ParseIP("192.168.1.10"), Port: MulticastPort}
	knock := func() []byte {
		irk, _ := NewIRK()
		tag, _ := makeTag(irk)
		nonce, _ := randomBytes(knockNonceBytes)
		data, _ := json.Marshal(&knockMsg{M: advertMagic, V: ProtocolVersion, K: knockKind, Kind: knockQuick, Tag: tag, Target: s.tag, Nonce: nonce})
		return data
	}
	s.handleKnock(knock(), src)
	if got := len(s.quickLimit.events["knock:192.168.1.10"]); got != 0 {
		t.Fatalf("quick knock counted while quick receive is off (%d)", got)
	}
	s.quickReceive = true
	data := knock()
	s.handleKnock(data, src)
	s.handleKnock(data, src)
	if got := len(s.quickLimit.events["knock:192.168.1.10"]); got != 1 {
		t.Fatalf("quick knock counted %d times, want 1", got)
	}
}
