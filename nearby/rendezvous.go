package nearby

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/threatexpert/gonc/v2/easyp2p"
)

// Connections between Nearby devices race two paths and keep the first that
// works:
//
//   - Direct: dial the device's advertised TCP port. Instant when the device
//     accepts inbound connections.
//   - Rendezvous: send a "knock" over the discovery channel, then both sides
//     run gonc's LAN discovery and TCP traversal with a key made for this one
//     attempt. Both sides beacon by multicast and answer by unicast, then
//     dial each other from their punch ports at the same time, so this works
//     when either side, or both, block unsolicited inbound connections.
//
// A firewalled device cannot receive multicast it did not ask for, but it
// does receive unicast replies to its own multicast for a short time. Every
// advertisement therefore asks for a reply, and a pending knock is sent as a
// unicast reply the moment the target's next advertisement arrives.

const (
	knockKind        = "knock"
	knockPair        = "pair"
	knockSession     = "session"
	knockQuick       = "quick"
	knockNonceBytes  = 16
	knockMACBytes    = 16
	knockRepeat      = 1 * time.Second
	directHeadStart  = 700 * time.Millisecond
	rendezvousWindow = 25 * time.Second
	maxRendezvous    = 4
	knockMemory      = 2 * time.Minute
	directFailMemory = 10 * time.Minute
)

type knockMsg struct {
	M      string `json:"m"`
	V      int    `json:"v"`
	K      string `json:"k"`
	Kind   string `json:"kind"`
	Tag    []byte `json:"tag"`
	Target []byte `json:"target"`
	Nonce  []byte `json:"nonce"`
	MAC    []byte `json:"mac,omitempty"`
}

func knockMACKey(rec PeerRecord) ([]byte, error) {
	pairID, err := hex.DecodeString(rec.PairID)
	if err != nil {
		return nil, err
	}
	prk, err := hkdf.Extract(sha256.New, rec.PairKey, pairID)
	if err != nil {
		return nil, err
	}
	return hkdfExpand(prk, encode([]byte(advertLabel), []byte("knock")), keyBytes)
}

func knockMAC(key []byte, k *knockMsg) []byte {
	return hmacSHA256(key, encode([]byte(advertLabel), []byte(knockKind), []byte(k.Kind), k.Tag, k.Target, k.Nonce))[:knockMACBytes]
}

// rendezvousKey is the gonc LAN session key for one knock. Between paired
// devices it derives from the pairing key, so only they can complete the
// rendezvous. For a first pairing it is public; the numeric comparison is
// what protects pairing, not the transport.
func rendezvousKey(kind string, rec *PeerRecord, nonce, tagI, tagR []byte) (string, error) {
	info := encode([]byte(advertLabel), []byte("rendezvous"), []byte(kind), nonce, tagI, tagR)
	if kind == knockSession {
		if rec == nil {
			return "", ErrNotPaired
		}
		pairID, err := hex.DecodeString(rec.PairID)
		if err != nil {
			return "", err
		}
		prk, err := hkdf.Extract(sha256.New, rec.PairKey, pairID)
		if err != nil {
			return "", err
		}
		k, err := hkdfExpand(prk, info, keyBytes)
		if err != nil {
			return "", err
		}
		return encodeKey("nbr1", k), nil
	}
	return encodeKey("nbp1", sha256Sum(info)), nil
}

// lanRendezvous runs gonc LAN discovery and TCP traversal with key.
func lanRendezvous(ctx context.Context, key string, logw io.Writer) (net.Conn, error) {
	info, err := easyp2p.EasyP2PLANOnInterface(ctx, key, "", rendezvousWindow, false, logw, "")
	if err != nil {
		return nil, err
	}
	if info == nil || len(info.Conns) == 0 || info.Conns[0] == nil {
		return nil, errors.New("nearby: rendezvous returned no connection")
	}
	for _, extra := range info.Conns[1:] {
		if extra != nil {
			_ = extra.Close()
		}
	}
	return info.Conns[0], nil
}

// loggerWriter adapts the service logger for gonc's LAN discovery output.
type loggerWriter struct{ s *Service }

func (w loggerWriter) Write(p []byte) (int, error) {
	if msg := strings.TrimSpace(string(p)); msg != "" {
		w.s.logf("%s", msg)
	}
	return len(p), nil
}

// pendingKnock is resent as a unicast reply to each advertisement from the
// target device until the connection attempt ends.
type pendingKnock struct {
	deviceID string
	data     []byte
}

type connectResult struct {
	conn net.Conn
	path string
	err  error
}

// connect opens a connection to device d for a pairing or a session. rec is
// required for sessions.
func (s *Service) connect(ctx context.Context, d *deviceState, kind string, rec *PeerRecord) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan connectResult, 2)
	started := 1
	began := time.Now()

	go func() {
		conn, err := dialDevice(ctx, d)
		s.mu.Lock()
		if err == nil {
			delete(s.directFailed, d.ID)
		} else if ctx.Err() == nil {
			s.directFailed[d.ID] = time.Now()
		}
		s.mu.Unlock()
		results <- connectResult{conn, "direct", err}
	}()

	s.mu.Lock()
	ownTag := append([]byte(nil), s.tag...)
	// When the direct path failed recently, knock right away instead of
	// giving it a head start.
	delay := directHeadStart
	if at, ok := s.directFailed[d.ID]; ok && time.Since(at) < directFailMemory {
		delay = 0
	}
	s.mu.Unlock()
	startRendezvous := func() {
		started++
		go func() {
			conn, err := s.knockAndMeet(ctx, d, kind, rec, ownTag)
			results <- connectResult{conn, "LAN rendezvous", err}
		}()
	}

	headStart := time.NewTimer(delay)
	defer headStart.Stop()
	var errs []error
	rendezvousStarted := false
	for received := 0; received < started; {
		select {
		case <-headStart.C:
			if !rendezvousStarted {
				rendezvousStarted = true
				startRendezvous()
			}
		case r := <-results:
			received++
			if r.err == nil {
				s.logf("connected to %s (%s) in %.1fs", d.Nickname, r.path, time.Since(began).Seconds())
				cancel()
				// Close a late second connection, if any.
				go func(pending int) {
					for i := 0; i < pending; i++ {
						if late := <-results; late.conn != nil {
							_ = late.conn.Close()
						}
					}
				}(started - received)
				return r.conn, nil
			}
			s.logf("%s to %s failed: %v", r.path, d.Nickname, r.err)
			errs = append(errs, fmt.Errorf("%s: %w", r.path, r.err))
			if !rendezvousStarted {
				rendezvousStarted = true
				startRendezvous()
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, errors.Join(errs...)
}

// knockAndMeet asks d to start a rendezvous and runs this side of it.
func (s *Service) knockAndMeet(ctx context.Context, d *deviceState, kind string, rec *PeerRecord, ownTag []byte) (net.Conn, error) {
	if len(d.tag) != tagBytes {
		return nil, errors.New("device has no advertisement to knock on")
	}
	nonce, err := randomBytes(knockNonceBytes)
	if err != nil {
		return nil, err
	}
	k := &knockMsg{M: advertMagic, V: ProtocolVersion, K: knockKind, Kind: kind, Tag: ownTag, Target: d.tag, Nonce: nonce}
	if kind == knockSession {
		macKey, err := knockMACKey(*rec)
		if err != nil {
			return nil, err
		}
		k.MAC = knockMAC(macKey, k)
	}
	key, err := rendezvousKey(kind, rec, nonce, ownTag, d.tag)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(k)
	if err != nil {
		return nil, err
	}

	pk := &pendingKnock{deviceID: d.ID, data: data}
	s.mu.Lock()
	s.knocks[pk] = true
	src := s.knockTargetLocked(d.ID)
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.knocks, pk)
		s.mu.Unlock()
	}()

	send := func(src net.Addr) {
		if s.disc == nil {
			return
		}
		s.disc.multicast(data)
		if src != nil {
			s.disc.unicast(data, src)
		}
	}
	s.logf("knocking on %s (%s)", d.Nickname, kind)
	send(src)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		ticker := time.NewTicker(knockRepeat)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.mu.Lock()
				src := s.knockTargetLocked(d.ID)
				s.mu.Unlock()
				send(src)
			}
		}
	}()
	return lanRendezvous(ctx, key, loggerWriter{s})
}

// knockTargetLocked returns where device id's advertisements come from.
func (s *Service) knockTargetLocked(id string) net.Addr {
	if d, ok := s.devices[id]; ok {
		return d.src
	}
	return nil
}

// pendingKnocksForLocked returns knocks waiting for device id, to send in
// reply to its advertisement. The reply leaves right after the device's own
// multicast, so its firewall treats it as a response.
func (s *Service) pendingKnocksForLocked(id string) [][]byte {
	var out [][]byte
	for pk := range s.knocks {
		if pk.deviceID == id {
			out = append(out, pk.data)
		}
	}
	return out
}

type knockGate struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// firstTime reports whether this knock nonce is new, remembering it.
func (g *knockGate) firstTime(nonce []byte) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	for k, t := range g.seen {
		if now.Sub(t) > knockMemory {
			delete(g.seen, k)
		}
	}
	key := string(nonce)
	if _, ok := g.seen[key]; ok {
		return false
	}
	if len(g.seen) > 256 {
		return false
	}
	g.seen[key] = now
	return true
}

// handleKnock answers a knock addressed to this device by running the other
// side of the rendezvous and serving the resulting connection like an
// accepted one.
func (s *Service) handleKnock(data []byte, src net.Addr) {
	var k knockMsg
	if err := json.Unmarshal(data, &k); err != nil || k.K != knockKind || k.V != ProtocolVersion {
		return
	}
	if len(k.Tag) != tagBytes || len(k.Target) != tagBytes || len(k.Nonce) != knockNonceBytes {
		return
	}
	host := ""
	if udp, ok := src.(*net.UDPAddr); ok {
		host = udp.IP.String()
	}
	s.mu.Lock()
	targetOK := s.isOwnTagLocked(k.Target)
	var rec *PeerRecord
	if r, ok := s.resolveLocked(k.Tag); ok {
		rec = &r
	}
	s.mu.Unlock()
	if !targetOK {
		return
	}
	switch k.Kind {
	case knockSession:
		if rec == nil {
			return
		}
		macKey, err := knockMACKey(*rec)
		if err != nil || !hmac.Equal(k.MAC, knockMAC(macKey, &k)) {
			s.logf("ignored a knock with a bad signature from %s", host)
			return
		}
	case knockPair:
		if s.handler == nil {
			return
		}
	case knockQuick:
		s.mu.Lock()
		on := s.quickReceive && s.handler != nil
		s.mu.Unlock()
		if !on {
			return
		}
	default:
		return
	}
	// A knock is repeated every second until it is answered, so drop
	// repeats before counting attempts. Counting repeats used up the
	// pairing allowance in a few seconds and silently ignored retries.
	if !s.knockGate.firstTime(k.Nonce) {
		return
	}
	if k.Kind == knockPair || k.Kind == knockQuick {
		// A busy device still meets the knock and answers "busy" over the
		// connection, so the other side fails fast instead of timing out.
		s.mu.Lock()
		limit := s.pairLimit
		if k.Kind == knockQuick {
			limit = s.quickLimit
		}
		allowed := limit.allow("knock:" + host)
		s.mu.Unlock()
		if !allowed {
			s.logf("ignored a %s request from %s: too many attempts in the last minute", k.Kind, host)
			return
		}
	}
	select {
	case s.rendezvousSem <- struct{}{}:
	default:
		s.logf("too many rendezvous in progress; ignored a knock from %s", host)
		return
	}
	name := host
	if rec != nil {
		name = rec.Nickname
	}
	s.logf("knock from %s (%s); meeting on the LAN", name, k.Kind)
	key, err := rendezvousKey(k.Kind, rec, k.Nonce, k.Tag, k.Target)
	if err != nil {
		<-s.rendezvousSem
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() { <-s.rendezvousSem }()
		ctx, cancel := s.context(rendezvousWindow + 5*time.Second)
		defer cancel()
		conn, err := lanRendezvous(ctx, key, loggerWriter{s})
		if err != nil {
			s.logf("rendezvous with %s failed: %v", name, err)
			return
		}
		s.serveConn(conn)
	}()
}
