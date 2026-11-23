package nearby

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

// quietService is a bareService with discovery whose outgoing packets go
// to the returned channel instead of the network.
func quietService(t *testing.T) (*Service, chan []byte) {
	t.Helper()
	sent := make(chan []byte, 16)
	s := bareService(t)
	s.disc = &discovery{
		group: &net.UDPAddr{IP: net.ParseIP(MulticastGroup), Port: MulticastPort},
		sink: func(data []byte, _ net.Addr) {
			select {
			case sent <- append([]byte(nil), data...):
			default:
			}
		},
	}
	s.visible = true
	s.port = 19732
	s.paused = true
	s.answerLimit = newRateLimiter(100, time.Second)
	s.kickCh = make(chan struct{}, 1)
	s.notifyCh = make(chan struct{}, 1)
	return s, sent
}

// next returns the next packet sent within wait, or nil.
func next(sent chan []byte, wait time.Duration) []byte {
	select {
	case p := <-sent:
		return p
	case <-time.After(wait):
		return nil
	}
}

func TestPausedServiceDoesNotAnnounce(t *testing.T) {
	s, sent := quietService(t)
	done := make(chan struct{})
	go func() { defer close(done); s.announceLoop() }()
	defer func() { close(s.closed); <-done }()

	if p := next(sent, 2500*time.Millisecond); p != nil {
		t.Fatalf("paused service sent %s", p)
	}
	start := time.Now()
	s.SetDiscovering(true)
	p := next(sent, time.Second)
	if p == nil {
		t.Fatal("no announcement after discovery was turned on")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("first announcement took %v", elapsed)
	}
	if a, ok := parseAdvert(p); !ok || len(a.Tag) == 0 || !a.Q {
		t.Fatalf("unexpected announcement %s", p)
	}
	s.SetDiscovering(false)
	for next(sent, 50*time.Millisecond) != nil {
		// Drop anything sent before the change.
	}
	if p := next(sent, 2500*time.Millisecond); p != nil {
		t.Fatalf("service sent %s after discovery was turned off", p)
	}
}

func TestPausedServiceDoesNotAnswerQueries(t *testing.T) {
	s, sent := quietService(t)
	query, _ := json.Marshal(advert{M: advertMagic, V: ProtocolVersion, Q: true})
	src := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 20), Port: MulticastPort}

	s.handlePacket(packet{data: query, src: src})
	if p := next(sent, 300*time.Millisecond); p != nil {
		t.Fatalf("paused service answered with %s", p)
	}
	s.SetDiscovering(true)
	s.handlePacket(packet{data: query, src: src})
	if p := next(sent, time.Second); p == nil {
		t.Fatal("no answer after discovery was turned on")
	}
}
