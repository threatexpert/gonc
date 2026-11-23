package nearby

import (
	"context"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"net"
	"time"
)

// Quick sessions send files to a device without pairing first.
//
// The two devices agree on a one-time key with an unauthenticated X25519
// exchange and use it exactly like a paired session's key: it secures the
// control connection with TLS and derives the transfer passphrase. This
// keeps the files from anyone who only listens on the network, but nothing
// proves who is on the other end, so a device in the middle could read or
// replace the files. The recipient is told the sender is unverified, still
// decides about every offer, and can turn quick receiving off.

const (
	quickLabel      = "gonc-quick-v1"
	quicksPerMinute = 10
)

func quickContext(first *wireMsg, pubR, nonceR []byte) []byte {
	return encode([]byte(quickLabel), u32(ProtocolVersion), first.Tag, first.Target, first.Pub, pubR, first.Nonce, nonceR)
}

func deriveQuickKeys(shared, context []byte) (*sessionKeys, error) {
	prk, err := hkdf.Extract(sha256.New, shared, sha256Sum(context))
	if err != nil {
		return nil, err
	}
	control, err := hkdfExpand(prk, encode([]byte(quickLabel), []byte("control"), context), keyBytes)
	if err != nil {
		return nil, err
	}
	transfer, err := hkdfExpand(prk, encode([]byte(quickLabel), []byte("transfer"), context), keyBytes)
	if err != nil {
		return nil, err
	}
	return &sessionKeys{
		control:  encodeKey(controlKeyPrefix, control),
		transfer: encodeKey(transferKeyPrefix, transfer),
	}, nil
}

// quickInitiate opens a quick session to the device advertising target.
func quickInitiate(ctx context.Context, conn net.Conn, self Identity, listenPort int, ownTag, target []byte) (*tls.Conn, *sessionKeys, error) {
	priv, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := randomBytes(nonceBytes)
	if err != nil {
		return nil, nil, err
	}
	first := &wireMsg{Op: opQuick, V: ProtocolVersion, Tag: ownTag, Target: target, Pub: priv.PublicKey().Bytes(), Nonce: nonce,
		Name: self.Nickname, Type: self.DeviceType, Port: listenPort}
	_ = conn.SetDeadline(time.Now().Add(sessionStepTimeout))
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if err := writeMsg(conn, first); err != nil {
		return nil, nil, err
	}
	m, err := readMsg(conn)
	if err != nil {
		return nil, nil, err
	}
	if m.Op == opQuickOff {
		return nil, nil, ErrQuickRefused
	}
	if err := expectOp(m, opQuickOK); err != nil {
		return nil, nil, err
	}
	if len(m.Nonce) != nonceBytes {
		return nil, nil, errors.New("nearby: malformed quick send response")
	}
	peer, err := ecdh.X25519().NewPublicKey(m.Pub)
	if err != nil {
		return nil, nil, errors.New("nearby: malformed quick send response")
	}
	shared, err := priv.ECDH(peer) // fails for an all-zero result
	if err != nil {
		return nil, nil, err
	}
	keys, err := deriveQuickKeys(shared, quickContext(first, m.Pub, m.Nonce))
	if err != nil {
		return nil, nil, err
	}
	tc, err := secureControl(ctx, conn, keys.control, true)
	if err != nil {
		return nil, nil, err
	}
	return tc, keys, nil
}

// quickRespond answers a quick session request.
func quickRespond(ctx context.Context, conn net.Conn, first *wireMsg) (*tls.Conn, *sessionKeys, error) {
	if len(first.Nonce) != nonceBytes || len(first.Tag) != tagBytes {
		return nil, nil, errors.New("nearby: malformed quick send request")
	}
	peer, err := ecdh.X25519().NewPublicKey(first.Pub)
	if err != nil {
		return nil, nil, errors.New("nearby: malformed quick send request")
	}
	priv, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	shared, err := priv.ECDH(peer)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := randomBytes(nonceBytes)
	if err != nil {
		return nil, nil, err
	}
	pub := priv.PublicKey().Bytes()
	keys, err := deriveQuickKeys(shared, quickContext(first, pub, nonce))
	if err != nil {
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(sessionStepTimeout))
	if err := writeMsg(conn, &wireMsg{Op: opQuickOK, Pub: pub, Nonce: nonce}); err != nil {
		return nil, nil, err
	}
	tc, err := secureControl(ctx, conn, keys.control, false)
	if err != nil {
		return nil, nil, err
	}
	return tc, keys, nil
}

// SetQuickReceive sets whether unpaired devices may offer files. Each offer
// still needs the user's answer.
func (s *Service) SetQuickReceive(on bool) {
	s.mu.Lock()
	changed := s.quickReceive != on
	s.quickReceive = on
	s.mu.Unlock()
	if changed {
		s.kick()
	}
}

// handleQuick serves a quick session request. It returns true when the
// connection was handed to the application.
func (s *Service) handleQuick(conn net.Conn, first *wireMsg, host string) bool {
	s.mu.Lock()
	targetOK := len(first.Target) == tagBytes && s.isOwnTagLocked(first.Target)
	on := s.quickReceive && s.handler != nil
	allowed := targetOK && on && s.quickLimit.allow(host)
	s.mu.Unlock()
	switch {
	case !targetOK:
		_ = writeMsg(conn, &wireMsg{Op: opError, Message: "unknown target"})
		return false
	case !on:
		_ = writeMsg(conn, &wireMsg{Op: opQuickOff})
		return false
	case !allowed:
		_ = writeMsg(conn, &wireMsg{Op: opBusy})
		return false
	}
	ctx, cancel := s.context(2 * sessionStepTimeout)
	defer cancel()
	tc, keys, err := quickRespond(ctx, conn, first)
	if err != nil {
		s.logf("quick send from %s failed: %v", host, err)
		return false
	}
	_ = tc.SetDeadline(time.Now().Add(sessionStepTimeout))
	m, err := readMsg(tc)
	if err != nil || m.Op != opOffer {
		_ = tc.Close()
		return false
	}
	sender := PeerRecord{Nickname: cleanName(first.Name), DeviceType: cleanDeviceType(first.Type)}
	if sender.Nickname == "" {
		sender.Nickname = host
	}
	return s.serveOffer(tc, sender, m, keys, false)
}

// OpenQuickTransfer opens a session to a device without pairing. The
// recipient sees the sender as unverified. Use OpenTransfer for paired
// devices.
func (s *Service) OpenQuickTransfer(ctx context.Context, deviceID string) (*OutgoingTransfer, error) {
	d, self, err := s.device(deviceID)
	if err != nil {
		return nil, err
	}
	if len(d.tag) != tagBytes {
		return nil, ErrUnknown
	}
	conn, err := s.connect(ctx, d, knockQuick, nil)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	ownTag := append([]byte(nil), s.tag...)
	s.mu.Unlock()
	tc, keys, err := quickInitiate(ctx, conn, self, s.port, ownTag, d.tag)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	localIP, _, _ := net.SplitHostPort(conn.LocalAddr().String())
	peer := PeerRecord{Nickname: d.Nickname, DeviceType: d.DeviceType}
	return &OutgoingTransfer{Peer: peer, Passphrase: keys.transfer, LocalIP: localIP, conn: tc}, nil
}
