package nearby

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/threatexpert/gonc/v2/secure"
)

const (
	sessionStepTimeout = 10 * time.Second
	transferKeyPrefix  = "nb1-"
	controlKeyPrefix   = "nbc-"
)

// sessionKeys are derived from the pairing key and both fresh nonces, so
// every session has its own control key and transfer passphrase.
type sessionKeys struct {
	control  string
	transfer string
}

func deriveSessionKeys(rec PeerRecord, initiatorID, responderID string, nonceA, nonceB []byte) (*sessionKeys, error) {
	pairID, err := hex.DecodeString(rec.PairID)
	if err != nil {
		return nil, err
	}
	ctx := encode([]byte(sessionLabel), u32(ProtocolVersion), pairID, []byte(initiatorID), []byte(responderID), nonceA, nonceB)
	prk, err := hkdf.Extract(sha256.New, rec.PairKey, pairID)
	if err != nil {
		return nil, err
	}
	control, err := hkdfExpand(prk, encode([]byte(sessionLabel), []byte("control"), ctx), keyBytes)
	if err != nil {
		return nil, err
	}
	transfer, err := hkdfExpand(prk, encode([]byte(sessionLabel), []byte("transfer"), ctx), keyBytes)
	if err != nil {
		return nil, err
	}
	return &sessionKeys{
		control:  encodeKey(controlKeyPrefix, control),
		transfer: encodeKey(transferKeyPrefix, transfer),
	}, nil
}

// secureControl runs TLS 1.3 with mutual authentication over conn. Both
// certificates derive from the per-session control key, as gonc -psk does,
// so the handshake succeeds only between the two holders of the pairing key.
func secureControl(ctx context.Context, conn net.Conn, key string, client bool) (*tls.Conn, error) {
	cert, err := secure.GenerateECDSACertificate("gonc-nearby", key)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion:            tls.VersionTLS13,
		MaxVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{*cert},
		InsecureSkipVerify:    true, // identity is checked by VerifyPeerCertificate
		VerifyPeerCertificate: secure.VerifyPeerCertificateByPSK(key),
		ServerName:            "gonc-nearby",
	}
	var tc *tls.Conn
	if client {
		tc = tls.Client(conn, cfg)
	} else {
		cfg.ClientAuth = tls.RequireAnyClientCert
		tc = tls.Server(conn, cfg)
	}
	hsCtx, cancel := context.WithTimeout(ctx, sessionStepTimeout)
	defer cancel()
	if err := tc.HandshakeContext(hsCtx); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerification, err)
	}
	_ = conn.SetDeadline(time.Time{})
	return tc, nil
}

// sessionInitiate authenticates an outgoing session to a paired device.
func sessionInitiate(ctx context.Context, conn net.Conn, self Identity, listenPort int, rec PeerRecord) (*tls.Conn, *sessionKeys, error) {
	tag, err := makeTag(self.IRK)
	if err != nil {
		return nil, nil, err
	}
	nonceA, err := randomBytes(nonceBytes)
	if err != nil {
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(sessionStepTimeout))
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if err := writeMsg(conn, &wireMsg{Op: opSession, V: ProtocolVersion, Tag: tag, Nonce: nonceA, Port: listenPort}); err != nil {
		return nil, nil, err
	}
	m, err := readMsg(conn)
	if err != nil {
		return nil, nil, err
	}
	if err := expectOp(m, opSessionOK); err != nil {
		return nil, nil, err
	}
	if len(m.Nonce) != nonceBytes {
		return nil, nil, errors.New("nearby: malformed session response")
	}
	keys, err := deriveSessionKeys(rec, self.InstallationID, rec.InstallationID, nonceA, m.Nonce)
	if err != nil {
		return nil, nil, err
	}
	tc, err := secureControl(ctx, conn, keys.control, true)
	if err != nil {
		return nil, nil, err
	}
	return tc, keys, nil
}

// sessionRespond answers an incoming session request from the paired
// device rec, which the service resolved from the request's tag.
func sessionRespond(ctx context.Context, conn net.Conn, first *wireMsg, self Identity, rec PeerRecord) (*tls.Conn, *sessionKeys, error) {
	if len(first.Nonce) != nonceBytes {
		return nil, nil, errors.New("nearby: malformed session request")
	}
	nonceB, err := randomBytes(nonceBytes)
	if err != nil {
		return nil, nil, err
	}
	keys, err := deriveSessionKeys(rec, rec.InstallationID, self.InstallationID, first.Nonce, nonceB)
	if err != nil {
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(sessionStepTimeout))
	if err := writeMsg(conn, &wireMsg{Op: opSessionOK, Nonce: nonceB}); err != nil {
		return nil, nil, err
	}
	tc, err := secureControl(ctx, conn, keys.control, false)
	if err != nil {
		return nil, nil, err
	}
	return tc, keys, nil
}

// OutgoingTransfer is an authenticated session to a paired device. Start a
// direct share with Passphrase on LocalIP, then call Offer with its port.
type OutgoingTransfer struct {
	Peer       PeerRecord
	Passphrase string
	// LocalIP is this device's address on the interface that reaches the
	// peer. Bind the share listener to it rather than to all interfaces.
	LocalIP string

	conn      *tls.Conn
	closeOnce sync.Once
	release   func()
}

// OfferItem is one top-level file or folder in an offer.
type OfferItem struct {
	Name string `json:"n"`
	Dir  bool   `json:"d,omitempty"`
	Size int64  `json:"s,omitempty"`
}

// MaxOfferItems is how many top-level items an offer lists by name; Files
// and Bytes still count everything.
const MaxOfferItems = 40

const maxOfferItemName = 120

// OfferInfo describes a transfer for the recipient.
type OfferInfo struct {
	// Port is the direct share's port on LocalIP.
	Port int
	// Name is shown to the recipient as the sender.
	Name string
	// LAN is true when the files are also shared through a LAN-only gonc
	// session keyed with Passphrase, for when the direct path is blocked.
	LAN bool
	// Items, Files and Bytes summarize what is offered. The recipient shows
	// them while it connects to the share.
	Items []OfferItem
	Files int64
	Bytes int64
}

// Offer tells the recipient what is offered and where to fetch it.
func (o *OutgoingTransfer) Offer(info OfferInfo) error {
	if info.Port <= 0 || info.Port > 65535 {
		return errors.New("nearby: invalid share port")
	}
	m := &wireMsg{Op: opOffer, Port: info.Port, Name: cleanName(info.Name), LAN: info.LAN, Files: max(info.Files, 0), Bytes: max(info.Bytes, 0)}
	m.Items = cleanOfferItems(info.Items)
	_ = o.conn.SetWriteDeadline(time.Now().Add(sessionStepTimeout))
	return writeMsg(o.conn, m)
}

func cleanOfferItems(items []OfferItem) []OfferItem {
	var out []OfferItem
	for _, it := range items {
		if len(out) >= MaxOfferItems {
			break
		}
		name := cleanText(it.Name, maxOfferItemName)
		if name == "" {
			continue
		}
		out = append(out, OfferItem{Name: name, Dir: it.Dir, Size: max(it.Size, 0)})
	}
	return out
}

// WaitResponse blocks until the recipient accepts or declines.
func (o *OutgoingTransfer) WaitResponse(ctx context.Context) (bool, error) {
	m, err := o.read(ctx)
	if err != nil {
		return false, err
	}
	switch m.Op {
	case opAccepted:
		return true, nil
	case opDeclined:
		return false, nil
	}
	return false, expectOp(m, opAccepted)
}

// WaitFinished blocks until the recipient reports the outcome.
func (o *OutgoingTransfer) WaitFinished(ctx context.Context) (bool, string, error) {
	m, err := o.read(ctx)
	if err != nil {
		return false, "", err
	}
	if err := expectOp(m, opFinished); err != nil {
		return false, "", err
	}
	return m.OK, cleanText(m.Message, 200), nil
}

func (o *OutgoingTransfer) read(ctx context.Context) (*wireMsg, error) {
	stop := context.AfterFunc(ctx, func() { _ = o.conn.SetReadDeadline(time.Now()) })
	defer stop()
	_ = o.conn.SetReadDeadline(time.Time{})
	m, err := readMsg(o.conn)
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return m, err
}

// Cancel tells the recipient the sender stopped, then closes the session.
func (o *OutgoingTransfer) Cancel() {
	_ = o.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_ = writeMsg(o.conn, &wireMsg{Op: opCancel})
	o.Close()
}

func (o *OutgoingTransfer) Close() {
	o.closeOnce.Do(func() {
		_ = o.conn.Close()
		if o.release != nil {
			o.release()
		}
	})
}

// IncomingTransfer is an offer from a paired device. Start a direct receive
// to SenderAddress with Passphrase to read the file list, then Accept or
// Decline. After an accepted transfer ends, call Finish.
type IncomingTransfer struct {
	ID            string
	PeerID        string
	PeerName      string
	PeerType      string
	SenderAddress string
	Passphrase    string
	// LANFallback is true when the sender also shares through a LAN-only
	// gonc session with Passphrase.
	LANFallback bool
	// Verified is true for offers from a paired device. Offers from an
	// unpaired device (a quick send) have no PeerID, and nothing proves the
	// sender's name; tell the user so.
	Verified bool
	// Items, Files and Bytes are the sender's summary of the offer. They
	// are empty when the sender did not include one.
	Items []OfferItem
	Files int64
	Bytes int64

	mu        sync.Mutex
	conn      *tls.Conn
	cancelled chan struct{}
	closeOnce sync.Once
	release   func()
}

func newIncomingTransfer(conn *tls.Conn, rec PeerRecord, offer *wireMsg, passphrase string, release func()) (*IncomingTransfer, error) {
	if offer.Port <= 0 || offer.Port > 65535 {
		return nil, errors.New("nearby: invalid share port")
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil, err
	}
	id, err := randomBytes(8)
	if err != nil {
		return nil, err
	}
	name := cleanName(offer.Name)
	if name == "" {
		name = rec.Nickname
	}
	t := &IncomingTransfer{
		ID:            hex.EncodeToString(id),
		PeerID:        rec.InstallationID,
		PeerName:      name,
		PeerType:      rec.DeviceType,
		SenderAddress: net.JoinHostPort(host, strconv.Itoa(offer.Port)),
		Passphrase:    passphrase,
		LANFallback:   offer.LAN,
		Items:         cleanOfferItems(offer.Items),
		Files:         max(offer.Files, 0),
		Bytes:         max(offer.Bytes, 0),
		conn:          conn,
		cancelled:     make(chan struct{}),
		release:       release,
	}
	go t.watch()
	return t, nil
}

// watch closes Cancelled when the sender cancels or the session drops.
func (t *IncomingTransfer) watch() {
	defer close(t.cancelled)
	for {
		m, err := readMsg(t.conn)
		if err != nil || m.Op == opCancel {
			return
		}
	}
}

// Cancelled is closed when the sender stops or the connection is lost.
func (t *IncomingTransfer) Cancelled() <-chan struct{} { return t.cancelled }

func (t *IncomingTransfer) send(m *wireMsg) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	_ = t.conn.SetWriteDeadline(time.Now().Add(sessionStepTimeout))
	return writeMsg(t.conn, m)
}

func (t *IncomingTransfer) Accept() error { return t.send(&wireMsg{Op: opAccepted}) }

func (t *IncomingTransfer) Decline() error {
	err := t.send(&wireMsg{Op: opDeclined})
	t.Close()
	return err
}

// Finish reports the outcome to the sender and closes the session.
func (t *IncomingTransfer) Finish(ok bool, message string) error {
	err := t.send(&wireMsg{Op: opFinished, OK: ok, Message: cleanText(message, 200)})
	t.Close()
	return err
}

func (t *IncomingTransfer) Close() {
	t.closeOnce.Do(func() {
		_ = t.conn.Close()
		if t.release != nil {
			t.release()
		}
	})
}
