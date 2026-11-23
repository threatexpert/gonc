package nearby

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

const (
	announceFast       = 1 * time.Second
	announceSlow       = 2 * time.Second
	fastPhase          = 5 * time.Second
	deviceExpiry       = 16 * time.Second
	tagRotation        = 15 * time.Minute
	interfaceRefresh   = 30 * time.Second
	maxDevices         = 64
	maxAddresses       = 4
	maxActiveConns     = 16
	connsPerMinute     = 120
	pairsPerMinute     = 6
	reverifyAfter      = 10 * time.Minute
	dialTimeout        = 3 * time.Second
	queryAnswerSpacing = 1 * time.Second
	// manualProbeInterval spaces TCP checks of saved addresses. Each check is
	// a connection the other device counts against its per-address limit.
	manualProbeInterval = 5 * time.Second
	// manualProbeSkip skips the check when the device was heard from by
	// other means more recently than this.
	manualProbeSkip = 4 * time.Second
)

// Config starts a Service.
type Config struct {
	Identity Identity
	Peers    []PeerRecord
	Visible  bool
	// QuickReceive lets unpaired devices offer files (each offer is still
	// shown to the user).
	QuickReceive bool
	// Paused starts the service without announcing itself; see
	// SetDiscovering.
	Paused  bool
	Handler Handler
	Logger  *log.Logger

	// DiscoveryPort overrides MulticastPort, for tests.
	DiscoveryPort int
	// ListenAddr is the TCP address for pairing and sessions; default ":0".
	ListenAddr string
}

type deviceState struct {
	Device
	tag []byte
	// src is where the device's advertisements come from (its discovery
	// send socket). Knocks are answered to it.
	src       net.Addr
	lastCheck time.Time
	verifying bool
}

// Service runs discovery, answers pairing and session requests, and opens
// sessions to paired devices.
type Service struct {
	handler Handler
	logger  *log.Logger

	mu        sync.Mutex
	self      Identity
	visible   bool
	peers     map[string]PeerRecord
	tag       []byte
	prevTag   []byte
	tagAt     time.Time
	devices   map[string]*deviceState
	fastUntil time.Time

	pairingBusy  bool
	incomingBusy bool
	quickReceive bool
	// paused stops announcing, answering queries and probing; see
	// SetDiscovering.
	paused      bool
	quickLimit  *rateLimiter
	activeConns int
	connLimit   *rateLimiter
	pairLimit   *rateLimiter
	answerLimit *rateLimiter

	// manual holds addresses the user entered; they are probed over TCP.
	manual map[string]bool

	ln        net.Listener
	disc      *discovery
	discErr   error
	port      int
	closed    chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
	notifyCh  chan struct{}
	kickCh    chan struct{}
	verifySem chan struct{}

	knocks        map[*pendingKnock]bool
	knockGate     knockGate
	rendezvousSem chan struct{}
	// directFailed records devices whose direct path failed recently, so
	// the next connection starts the rendezvous at once.
	directFailed map[string]time.Time
}

// Start begins discovery and listening. Close stops everything.
func Start(cfg Config) (*Service, error) {
	if !validInstallationID(cfg.Identity.InstallationID) {
		return nil, errors.New("nearby: invalid installation ID")
	}
	if len(cfg.Identity.IRK) != irkBytes {
		return nil, errors.New("nearby: invalid identity resolving key")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	s := &Service{
		handler:       cfg.Handler,
		logger:        logger,
		self:          cfg.Identity,
		visible:       cfg.Visible,
		peers:         map[string]PeerRecord{},
		devices:       map[string]*deviceState{},
		connLimit:     newRateLimiter(connsPerMinute, time.Minute),
		pairLimit:     newRateLimiter(pairsPerMinute, time.Minute),
		quickLimit:    newRateLimiter(quicksPerMinute, time.Minute),
		quickReceive:  cfg.QuickReceive,
		paused:        cfg.Paused,
		answerLimit:   newRateLimiter(1, queryAnswerSpacing),
		closed:        make(chan struct{}),
		notifyCh:      make(chan struct{}, 1),
		kickCh:        make(chan struct{}, 1),
		verifySem:     make(chan struct{}, 2),
		manual:        map[string]bool{},
		knocks:        map[*pendingKnock]bool{},
		knockGate:     knockGate{seen: map[string]time.Time{}},
		rendezvousSem: make(chan struct{}, maxRendezvous),
		directFailed:  map[string]time.Time{},
	}
	s.self.Nickname = cleanName(s.self.Nickname)
	s.self.DeviceType = cleanDeviceType(s.self.DeviceType)
	s.setPeersLocked(cfg.Peers)
	if err := s.rotateTagLocked(); err != nil {
		return nil, err
	}

	listenAddr := cfg.ListenAddr
	if listenAddr == "" {
		listenAddr = ":0"
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	s.ln = ln
	s.port = ln.Addr().(*net.TCPAddr).Port

	port := cfg.DiscoveryPort
	if port == 0 {
		port = MulticastPort
	}
	// Without multicast the service still works for addresses the user
	// enters, so a discovery failure is reported rather than fatal.
	disc, err := openDiscovery(port, logger)
	if err != nil {
		logger.Printf("%v", err)
		s.discErr = err
	} else {
		s.disc = disc
	}
	s.fastUntil = time.Now().Add(fastPhase)

	s.wg.Add(4)
	if disc != nil {
		packets := make(chan packet, 64)
		s.wg.Add(2)
		go func() { defer s.wg.Done(); disc.readLoop(disc.raw, packets, s.closed) }()
		go func() { defer s.wg.Done(); s.packetLoop(packets) }()
	}
	go func() { defer s.wg.Done(); s.announceLoop() }()
	go func() { defer s.wg.Done(); s.acceptLoop() }()
	go func() { defer s.wg.Done(); s.notifyLoop() }()
	go func() { defer s.wg.Done(); s.manualLoop() }()
	return s, nil
}

// DiscoveryError reports why multicast discovery is unavailable, or nil.
func (s *Service) DiscoveryError() error { return s.discErr }

// Close stops discovery and listening and waits for service goroutines.
// Sessions already handed to the application stay open until it closes them.
func (s *Service) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		_ = s.ln.Close()
		if s.disc != nil {
			s.disc.close()
		}
	})
	s.wg.Wait()
	return nil
}

// AddAddress looks for a device at host:port over TCP, for networks where
// multicast does not reach it. The address stays in the device list while
// the device answers; Forget it with RemoveAddress.
func (s *Service) AddAddress(ctx context.Context, address string) (Device, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return Device{}, errors.New("nearby: enter the address as host:port")
	}
	id, err := s.probe(ctx, address)
	if err != nil {
		return Device{}, err
	}
	s.mu.Lock()
	s.manual[address] = true
	d, ok := s.devices[id]
	var dev Device
	if ok {
		dev = d.Device
		dev.Addresses = append([]string(nil), d.Addresses...)
	}
	s.mu.Unlock()
	if !ok {
		return Device{}, ErrUnknown
	}
	return dev, nil
}

// RemoveAddress stops probing an address added with AddAddress.
func (s *Service) RemoveAddress(address string) {
	s.mu.Lock()
	delete(s.manual, address)
	s.mu.Unlock()
}

// probe asks the device at address for its advertisement and records it as
// if it had arrived by multicast from that host.
func (s *Service) probe(ctx context.Context, address string) (string, error) {
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", address)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(sessionStepTimeout))
	if err := writeMsg(conn, &wireMsg{Op: opHello, V: ProtocolVersion}); err != nil {
		return "", err
	}
	m, err := readMsg(conn)
	if err != nil {
		return "", err
	}
	if err := expectOp(m, opHelloOK); err != nil {
		return "", err
	}
	a := &advert{M: advertMagic, V: ProtocolVersion, Tag: m.Tag, Name: m.Name, Type: m.Type, Port: m.Port, QR: m.OK}
	if len(a.Tag) != tagBytes || a.Port <= 0 || a.Port > 65535 {
		return "", errors.New("nearby: malformed device answer")
	}
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	s.mu.Lock()
	if s.isOwnTagLocked(a.Tag) {
		s.mu.Unlock()
		return "", errors.New("nearby: that address is this device")
	}
	id, verify, changed := s.observeLocked(a, host, nil, time.Now())
	s.mu.Unlock()
	if changed {
		s.notify()
	}
	if verify {
		s.startVerify(id)
	}
	return id, nil
}

// manualLoop keeps devices at user-entered addresses in the list.
func (s *Service) manualLoop() {
	ticker := time.NewTicker(manualProbeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-ticker.C:
		}
		now := time.Now()
		s.mu.Lock()
		if s.paused {
			s.mu.Unlock()
			continue
		}
		addrs := make([]string, 0, len(s.manual))
		for a := range s.manual {
			if !s.recentlySeenAtLocked(a, now) {
				addrs = append(addrs, a)
			}
		}
		s.mu.Unlock()
		for _, a := range addrs {
			ctx, cancel := s.context(sessionStepTimeout)
			_, _ = s.probe(ctx, a)
			cancel()
		}
	}
}

// recentlySeenAtLocked reports whether a device listed at addr was heard
// from within manualProbeSkip, for example by multicast.
func (s *Service) recentlySeenAtLocked(addr string, now time.Time) bool {
	for _, d := range s.devices {
		if now.Sub(d.LastSeen) < manualProbeSkip && containsAddr(d.Addresses, addr) {
			return true
		}
	}
	return false
}

// Port is the TCP port advertised for pairing and sessions.
func (s *Service) Port() int { return s.port }

// SetDiscovering turns discovery traffic on or off. While it is off the
// service sends no advertisements, answers no queries and probes no
// addresses, so it stays quiet on the network. It still listens, accepts
// connections and answers knocks, so transfers in progress and devices
// that try to reach it directly keep working. Turning it on announces at
// once.
func (s *Service) SetDiscovering(on bool) {
	s.mu.Lock()
	changed := s.paused == on
	s.paused = !on
	if changed && on {
		s.fastUntil = time.Now().Add(fastPhase)
	}
	s.mu.Unlock()
	if changed {
		s.kick()
	}
}

func (s *Service) SetVisible(visible bool) {
	s.mu.Lock()
	changed := s.visible != visible
	s.visible = visible
	if changed && visible {
		s.fastUntil = time.Now().Add(fastPhase)
	}
	s.mu.Unlock()
	if changed {
		s.kick()
	}
}

func (s *Service) SetNickname(name string) {
	s.mu.Lock()
	s.self.Nickname = cleanName(name)
	s.mu.Unlock()
	s.kick()
}

// SetPeers replaces the saved pairings, for example after the user forgets
// a device. Records created by successful pairings are added automatically.
func (s *Service) SetPeers(records []PeerRecord) {
	s.mu.Lock()
	s.setPeersLocked(records)
	s.reresolveLocked()
	s.mu.Unlock()
	s.notify()
}

// Refresh asks nearby devices to announce themselves now.
func (s *Service) Refresh() {
	s.mu.Lock()
	s.fastUntil = time.Now().Add(fastPhase)
	s.mu.Unlock()
	s.kick()
}

// Devices returns the current device list, paired devices first.
func (s *Service) Devices() []Device {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.devicesLocked()
}

func (s *Service) devicesLocked() []Device {
	out := make([]Device, 0, len(s.devices))
	for _, d := range s.devices {
		dev := d.Device
		dev.Addresses = append([]string(nil), d.Addresses...)
		out = append(out, dev)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Paired != out[j].Paired {
			return out[i].Paired
		}
		if out[i].Nickname != out[j].Nickname {
			return out[i].Nickname < out[j].Nickname
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (s *Service) setPeersLocked(records []PeerRecord) {
	s.peers = map[string]PeerRecord{}
	for _, r := range records {
		if r.valid() && r.InstallationID != s.self.InstallationID {
			s.peers[r.InstallationID] = r
		}
	}
}

func (s *Service) addPeer(r PeerRecord) {
	s.mu.Lock()
	s.peers[r.InstallationID] = r
	s.reresolveLocked()
	// Pairing just proved the key, so the device needs no separate check.
	s.markVerifiedLocked(r.InstallationID)
	s.mu.Unlock()
	s.notify()
}

// markVerifiedLocked records that the paired device peerID just proved it
// holds the pairing key, through pairing or an authenticated session.
func (s *Service) markVerifiedLocked(peerID string) bool {
	d, ok := s.devices[deviceID(nil, peerID)]
	if !ok {
		return false
	}
	d.lastCheck = time.Now()
	changed := !d.Verified
	d.Verified = true
	return changed
}

func (s *Service) markVerified(peerID string) {
	s.mu.Lock()
	changed := s.markVerifiedLocked(peerID)
	s.mu.Unlock()
	if changed {
		s.notify()
	}
}

func (s *Service) resolveLocked(tag []byte) (PeerRecord, bool) {
	for _, r := range s.peers {
		if tagMatches(r.IRK, tag) {
			return r, true
		}
	}
	return PeerRecord{}, false
}

func deviceID(tag []byte, peerID string) string {
	if peerID != "" {
		return "p-" + peerID
	}
	if len(tag) < 8 {
		return ""
	}
	return "t-" + hex.EncodeToString(tag[:8])
}

// reresolveLocked re-keys devices after the set of pairings changed.
func (s *Service) reresolveLocked() {
	old := s.devices
	s.devices = map[string]*deviceState{}
	for _, d := range old {
		rec, ok := s.resolveLocked(d.tag)
		d.PeerID, d.Paired = "", false
		if ok {
			d.PeerID, d.Paired = rec.InstallationID, true
		} else {
			d.Verified = false
		}
		// A new or removed pairing invalidates earlier verification.
		d.lastCheck = time.Time{}
		d.ID = deviceID(d.tag, d.PeerID)
		s.devices[d.ID] = d
	}
}

func (s *Service) rotateTagLocked() error {
	tag, err := makeTag(s.self.IRK)
	if err != nil {
		return err
	}
	s.prevTag, s.tag, s.tagAt = s.tag, tag, time.Now()
	return nil
}

func (s *Service) isOwnTagLocked(tag []byte) bool {
	return bytes.Equal(tag, s.tag) || (s.prevTag != nil && bytes.Equal(tag, s.prevTag))
}

func (s *Service) notify() {
	select {
	case s.notifyCh <- struct{}{}:
	default:
	}
}

func (s *Service) kick() {
	select {
	case s.kickCh <- struct{}{}:
	default:
	}
}

func (s *Service) notifyLoop() {
	for {
		select {
		case <-s.closed:
			return
		case <-s.notifyCh:
			if s.handler != nil {
				s.handler.DevicesChanged(s.Devices())
			}
		}
	}
}

func (s *Service) announceLoop() {
	lastIfaceRefresh := time.Now()
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-s.kickCh:
		case <-timer.C:
		}
		now := time.Now()
		if s.disc != nil && now.Sub(lastIfaceRefresh) >= interfaceRefresh {
			_ = s.disc.refreshInterfaces()
			lastIfaceRefresh = now
		}
		s.mu.Lock()
		if now.Sub(s.tagAt) >= tagRotation {
			_ = s.rotateTagLocked()
		}
		fast := now.Before(s.fastUntil)
		// Every packet asks for a reply. A device behind a firewall cannot
		// receive other devices' multicast, but it does receive unicast
		// replies to its own, so this keeps its device list current.
		var data []byte
		if s.paused {
			// Send nothing; expired devices are still pruned below.
		} else if s.visible {
			data, _ = json.Marshal(advert{M: advertMagic, V: ProtocolVersion, Tag: s.tag, Name: s.self.Nickname, Type: s.self.DeviceType, Port: s.port, Q: true, QR: s.quickReceive})
		} else {
			data, _ = json.Marshal(advert{M: advertMagic, V: ProtocolVersion, Q: true})
		}
		changed := s.pruneLocked(now)
		s.mu.Unlock()
		if data != nil && s.disc != nil {
			s.disc.multicast(data)
		}
		if changed {
			s.notify()
		}
		interval := announceSlow
		if fast {
			interval = announceFast
		}
		timer.Reset(interval)
	}
}

func (s *Service) pruneLocked(now time.Time) bool {
	changed := false
	for id, d := range s.devices {
		if now.Sub(d.LastSeen) > deviceExpiry {
			delete(s.devices, id)
			changed = true
		}
	}
	return changed
}

func (s *Service) packetLoop(packets <-chan packet) {
	for {
		select {
		case <-s.closed:
			return
		case p := <-packets:
			s.handlePacket(p)
		}
	}
}

func (s *Service) handlePacket(p packet) {
	var kind struct {
		K string `json:"k"`
	}
	if json.Unmarshal(p.data, &kind) == nil {
		switch kind.K {
		case knockKind:
			s.handleKnock(p.data, p.src)
			return
		case knockRefusedKind:
			s.handleKnockRefused(p.data, p.src)
			return
		}
	}
	a, ok := parseAdvert(p.data)
	if !ok {
		return
	}
	udp, ok := p.src.(*net.UDPAddr)
	if !ok || udp.IP == nil || udp.IP.IsUnspecified() {
		return
	}
	ip := udp.IP.String()

	s.mu.Lock()
	if len(a.Tag) > 0 && s.isOwnTagLocked(a.Tag) {
		s.mu.Unlock()
		return
	}
	var answer []byte
	if a.Q && s.visible && !s.paused && s.answerLimit.allow(p.src.String()) {
		// Replies do not ask for a reply, so two devices do not ping-pong.
		answer, _ = json.Marshal(advert{M: advertMagic, V: ProtocolVersion, Tag: s.tag, Name: s.self.Nickname, Type: s.self.DeviceType, Port: s.port, QR: s.quickReceive})
	}
	verify := false
	changed := false
	var id string
	var knocks [][]byte
	if len(a.Tag) > 0 {
		id, verify, changed = s.observeLocked(a, ip, p.src, time.Now())
		verify = verify && !s.paused
		knocks = s.pendingKnocksForLocked(id)
	}
	s.mu.Unlock()

	if answer != nil && s.disc != nil {
		s.disc.unicast(answer, p.src)
	}
	for _, k := range knocks {
		s.disc.unicast(k, p.src)
	}
	if changed {
		s.notify()
	}
	if verify {
		s.startVerify(id)
	}
}

// observeLocked records an advertisement and reports whether a paired
// device is due for background verification.
func (s *Service) observeLocked(a *advert, ip string, src net.Addr, now time.Time) (string, bool, bool) {
	rec, paired := s.resolveLocked(a.Tag)
	peerID := ""
	if paired {
		peerID = rec.InstallationID
	}
	id := deviceID(a.Tag, peerID)
	addr := net.JoinHostPort(ip, strconv.Itoa(a.Port))
	d, exists := s.devices[id]
	changed := false
	if !exists {
		if len(s.devices) >= maxDevices && !s.evictLocked() {
			return id, false, false
		}
		d = &deviceState{}
		d.ID, d.PeerID, d.Paired = id, peerID, paired
		s.devices[id] = d
		changed = true
	}
	name, typ := cleanName(a.Name), cleanDeviceType(a.Type)
	if name == "" && paired {
		name = rec.Nickname
	}
	if d.Nickname != name || d.DeviceType != typ || d.QuickReceive != a.QR {
		d.Nickname, d.DeviceType, d.QuickReceive = name, typ, a.QR
		changed = true
	}
	d.tag = a.Tag
	d.LastSeen = now
	if src != nil {
		d.src = src
	}
	if len(d.Addresses) == 0 || d.Addresses[0] != addr {
		addrs := []string{addr}
		for _, existing := range d.Addresses {
			if existing != addr && len(addrs) < maxAddresses {
				addrs = append(addrs, existing)
			}
		}
		d.Addresses = addrs
		changed = true
	}
	// A device that restarts, or rotates its tag, appears under a new tag.
	// Drop the older unpaired entry for the same device right away instead
	// of listing it twice until the old one expires.
	for otherID, other := range s.devices {
		if otherID == id || other.Paired {
			continue
		}
		if containsAddr(other.Addresses, addr) || (other.Nickname == name && sameHost(other.Addresses, ip)) {
			delete(s.devices, otherID)
			changed = true
		}
	}
	verify := false
	if paired && !d.verifying && (d.lastCheck.IsZero() || now.Sub(d.lastCheck) > reverifyAfter) {
		d.lastCheck = now
		d.verifying = true
		verify = true
	}
	return id, verify, changed
}

func containsAddr(addrs []string, addr string) bool {
	for _, a := range addrs {
		if a == addr {
			return true
		}
	}
	return false
}

func sameHost(addrs []string, ip string) bool {
	for _, a := range addrs {
		if host, _, err := net.SplitHostPort(a); err == nil && host == ip {
			return true
		}
	}
	return false
}

// evictLocked drops the least recently seen unverified device.
func (s *Service) evictLocked() bool {
	var victim *deviceState
	for _, d := range s.devices {
		if d.Verified {
			continue
		}
		if victim == nil || d.LastSeen.Before(victim.LastSeen) {
			victim = d
		}
	}
	if victim == nil {
		return false
	}
	delete(s.devices, victim.ID)
	return true
}

func (s *Service) startVerify(id string) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		select {
		case s.verifySem <- struct{}{}:
		case <-s.closed:
			return
		}
		defer func() { <-s.verifySem }()
		ok := s.verifyDevice(id)
		s.mu.Lock()
		d, exists := s.devices[id]
		changed := false
		if exists {
			d.verifying = false
			if d.Verified != ok {
				d.Verified = ok
				changed = true
			}
		}
		s.mu.Unlock()
		if changed {
			s.notify()
		}
	}()
}

// verifyDevice proves that a paired device holds the pairing key, using
// the same connection paths as a transfer.
func (s *Service) verifyDevice(id string) bool {
	d, self, err := s.device(id)
	if err != nil {
		return false
	}
	s.mu.Lock()
	rec, ok := s.peers[d.PeerID]
	s.mu.Unlock()
	if !ok {
		return false
	}
	ctx, cancel := s.context(rendezvousWindow + 2*sessionStepTimeout)
	defer cancel()
	conn, err := s.connect(ctx, d, knockSession, &rec)
	if err != nil {
		return false
	}
	defer conn.Close()
	tc, _, err := sessionInitiate(ctx, conn, self, s.port, rec)
	if err != nil {
		s.logf("could not verify %s: %v", rec.Nickname, err)
		return false
	}
	defer tc.Close()
	_ = tc.SetDeadline(time.Now().Add(sessionStepTimeout))
	if err := writeMsg(tc, &wireMsg{Op: opVerify}); err != nil {
		return false
	}
	m, err := readMsg(tc)
	return err == nil && m.Op == opVerified
}

func (s *Service) logf(format string, args ...any) {
	s.logger.Printf("nearby: "+format, args...)
}

// context returns a context cancelled by Close or after timeout.
func (s *Service) context(timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	go func() {
		select {
		case <-s.closed:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

func (s *Service) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		s.mu.Lock()
		allowed := s.activeConns < maxActiveConns && s.connLimit.allow(host)
		if allowed {
			s.activeConns++
		}
		s.mu.Unlock()
		if !allowed {
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.finishConn(conn, s.handleConn(conn, host))
		}()
	}
}

func (s *Service) finishConn(conn net.Conn, keep bool) {
	s.mu.Lock()
	s.activeConns--
	s.mu.Unlock()
	if !keep {
		_ = conn.Close()
	}
}

// serveConn handles a connection that a rendezvous produced as if it had
// been accepted on the listener.
func (s *Service) serveConn(conn net.Conn) {
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	s.mu.Lock()
	s.activeConns++
	s.mu.Unlock()
	s.finishConn(conn, s.handleConn(conn, host))
}

// handleConn serves one incoming connection. It returns true when the
// connection was handed to the application and must stay open.
func (s *Service) handleConn(conn net.Conn, host string) bool {
	_ = conn.SetDeadline(time.Now().Add(sessionStepTimeout))
	first, err := readMsg(conn)
	if err != nil {
		return false
	}
	if first.V != ProtocolVersion {
		_ = writeMsg(conn, &wireMsg{Op: opError, Message: "unsupported protocol version"})
		return false
	}
	switch first.Op {
	case opHello:
		s.mu.Lock()
		reply := &wireMsg{Op: opError, Message: "not visible"}
		if s.visible {
			reply = &wireMsg{Op: opHelloOK, Tag: s.tag, Name: s.self.Nickname, Type: s.self.DeviceType, Port: s.port, OK: s.quickReceive}
		}
		s.mu.Unlock()
		_ = writeMsg(conn, reply)
		return false
	case opPair:
		s.handlePair(conn, first, host)
		return false
	case opSession:
		return s.handleSession(conn, first)
	case opQuick:
		return s.handleQuick(conn, first, host)
	}
	return false
}

func (s *Service) handlePair(conn net.Conn, first *wireMsg, host string) {
	s.mu.Lock()
	targetOK := len(first.Target) == tagBytes && s.isOwnTagLocked(first.Target)
	allowed := targetOK && !s.pairingBusy && s.handler != nil && s.pairLimit.allow(host)
	if allowed {
		s.pairingBusy = true
	}
	self := s.self
	s.mu.Unlock()
	if !targetOK {
		_ = writeMsg(conn, &wireMsg{Op: opError, Message: "unknown pairing target"})
		return
	}
	if !allowed {
		_ = writeMsg(conn, &wireMsg{Op: opBusy})
		return
	}
	defer func() {
		s.mu.Lock()
		s.pairingBusy = false
		s.mu.Unlock()
	}()
	p, x, k, err := pairRespond(conn, first, self, first.Target)
	if err != nil {
		s.logger.Printf("nearby: pairing request from %s failed: %v", host, err)
		return
	}
	s.handler.IncomingPairing(p)
	rec, err := runConfirmation(conn, p, x, k, self, s.closed)
	if err == nil {
		s.addPeer(*rec)
		s.learnAddress(host, first.Port)
	}
	p.finish(rec, err)
}

const maxManualAddresses = 32

// learnAddress remembers where a device that just proved its pairing can be
// reached, so this side can send to it even when multicast does not carry
// its advertisements. Only authenticated peers reach this point.
func (s *Service) learnAddress(host string, port int) {
	if host == "" || port <= 0 || port > 65535 {
		return
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	s.mu.Lock()
	_, known := s.manual[addr]
	if !known && len(s.manual) < maxManualAddresses {
		s.manual[addr] = true
	}
	s.mu.Unlock()
	if known {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ctx, cancel := s.context(sessionStepTimeout)
		defer cancel()
		_, _ = s.probe(ctx, addr)
	}()
}

func (s *Service) handleSession(conn net.Conn, first *wireMsg) bool {
	s.mu.Lock()
	rec, ok := PeerRecord{}, false
	if len(first.Tag) == tagBytes {
		rec, ok = s.resolveLocked(first.Tag)
	}
	self := s.self
	s.mu.Unlock()
	if !ok {
		_ = writeMsg(conn, &wireMsg{Op: opUnknown})
		return false
	}
	ctx, cancel := s.context(2 * sessionStepTimeout)
	defer cancel()
	tc, keys, err := sessionRespond(ctx, conn, first, self, rec)
	if err != nil {
		s.logger.Printf("nearby: session from %s failed: %v", rec.Nickname, err)
		return false
	}
	if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
		s.learnAddress(host, first.Port)
	}
	s.markVerified(rec.InstallationID)
	_ = tc.SetDeadline(time.Now().Add(sessionStepTimeout))
	m, err := readMsg(tc)
	if err != nil {
		return false
	}
	switch m.Op {
	case opVerify:
		_ = writeMsg(tc, &wireMsg{Op: opVerified, Name: self.Nickname, Type: self.DeviceType})
		_ = tc.Close()
		return false
	case opOffer:
		return s.serveOffer(tc, rec, m, keys, true)
	}
	_ = tc.Close()
	return false
}

// serveOffer hands an offer to the application, one at a time. verified is
// false for quick sends from unpaired devices.
func (s *Service) serveOffer(tc *tls.Conn, rec PeerRecord, m *wireMsg, keys *sessionKeys, verified bool) bool {
	s.mu.Lock()
	busy := s.incomingBusy || s.handler == nil
	if !busy {
		s.incomingBusy = true
	}
	s.mu.Unlock()
	if busy {
		_ = writeMsg(tc, &wireMsg{Op: opBusy})
		_ = tc.Close()
		return false
	}
	release := func() {
		s.mu.Lock()
		s.incomingBusy = false
		s.mu.Unlock()
	}
	_ = tc.SetDeadline(time.Time{})
	t, err := newIncomingTransfer(tc, rec, m, keys.transfer, release)
	if err != nil {
		release()
		_ = writeMsg(tc, &wireMsg{Op: opError, Message: err.Error()})
		_ = tc.Close()
		return false
	}
	t.Verified = verified
	s.handler.IncomingTransfer(t)
	return true
}

func (s *Service) device(id string) (*deviceState, Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.closed:
		return nil, Identity{}, ErrClosed
	default:
	}
	d, ok := s.devices[id]
	if !ok {
		return nil, Identity{}, ErrUnknown
	}
	copyState := *d
	copyState.Addresses = append([]string(nil), d.Addresses...)
	copyState.tag = append([]byte(nil), d.tag...)
	return &copyState, s.self, nil
}

// dialDevice connects directly to the first reachable advertised address.
func dialDevice(ctx context.Context, d *deviceState) (net.Conn, error) {
	addrs := append([]string(nil), d.Addresses...)
	var lastErr error = ErrUnknown
	for _, addr := range addrs {
		conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// Pair starts numeric-comparison pairing with a device from the list. The
// returned Pairing already has its Code; show it and call Confirm.
func (s *Service) Pair(deviceID string) (*Pairing, error) {
	d, self, err := s.device(deviceID)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	ownTag := append([]byte(nil), s.tag...)
	s.mu.Unlock()
	ctx, cancel := s.context(rendezvousWindow + 5*time.Second)
	conn, err := s.connect(ctx, d, knockPair, nil)
	cancel()
	if err != nil {
		return nil, err
	}
	p, x, k, err := pairInitiate(conn, self, s.port, ownTag, d.tag)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer conn.Close()
		rec, err := runConfirmation(conn, p, x, k, self, s.closed)
		if err == nil {
			s.addPeer(*rec)
		}
		p.finish(rec, err)
	}()
	return p, nil
}

// OpenTransfer opens an authenticated session to a paired device.
func (s *Service) OpenTransfer(ctx context.Context, deviceID string) (*OutgoingTransfer, error) {
	d, self, err := s.device(deviceID)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	rec, ok := s.peers[d.PeerID]
	s.mu.Unlock()
	if !d.Paired || !ok {
		return nil, ErrNotPaired
	}
	conn, err := s.connect(ctx, d, knockSession, &rec)
	if err != nil {
		return nil, err
	}
	tc, keys, err := sessionInitiate(ctx, conn, self, s.port, rec)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	s.markVerified(rec.InstallationID)
	localIP, _, _ := net.SplitHostPort(conn.LocalAddr().String())
	return &OutgoingTransfer{Peer: rec, Passphrase: keys.transfer, LocalIP: localIP, conn: tc}, nil
}
