package nearby

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	pairStepTimeout    = 10 * time.Second
	pairConfirmTimeout = 2 * time.Minute
	roleA              = "A" // initiator
	roleB              = "B" // responder
)

// Pairing is one numeric-comparison pairing attempt. Show Code to the user,
// then call Confirm with their decision. Done is closed when the attempt
// ends; Result then returns the new record or the reason it failed.
type Pairing struct {
	ID          string
	Incoming    bool
	PeerName    string
	PeerType    string
	PeerAddress string
	Code        string

	decideOnce sync.Once
	decision   chan bool
	done       chan struct{}
	record     *PeerRecord
	err        error
}

func newPairing(req []byte, incoming bool) *Pairing {
	return &Pairing{
		ID:       hex.EncodeToString(req),
		Incoming: incoming,
		decision: make(chan bool, 1),
		done:     make(chan struct{}),
	}
}

// Confirm records the local user's decision: true when the numbers on both
// screens match. Only the first call counts.
func (p *Pairing) Confirm(accept bool) {
	p.decideOnce.Do(func() { p.decision <- accept })
}

// Cancel abandons the attempt.
func (p *Pairing) Cancel() { p.Confirm(false) }

func (p *Pairing) Done() <-chan struct{} { return p.done }

// Result returns the saved-pairing record on success. It is valid after Done.
func (p *Pairing) Result() (*PeerRecord, error) {
	select {
	case <-p.done:
		return p.record, p.err
	default:
		return nil, errors.New("nearby: pairing still in progress")
	}
}

func (p *Pairing) finish(record *PeerRecord, err error) {
	p.record, p.err = record, err
	close(p.done)
}

// pairExchange holds one side's view of the commit-and-reveal exchange.
type pairExchange struct {
	role    string
	context []byte

	priv   *ecdh.PrivateKey
	pub    []byte
	nonce  []byte
	commit []byte

	peerPub    []byte
	peerNonce  []byte
	peerCommit []byte

	nameA, typeA, nameB, typeB string
}

type pairKeys struct {
	transcript []byte
	code       string
	pairKey    []byte
	confirmA   []byte
	confirmB   []byte
	identityA  []byte
	identityB  []byte
	pairID     []byte
}

func pairContext(req, tagA, tagB []byte) []byte {
	return encode([]byte(pairLabel), []byte("context"), u32(ProtocolVersion), req, tagA, tagB)
}

func commitment(context []byte, role string, pub, nonce []byte) []byte {
	return sha256Sum(encode([]byte(pairLabel), []byte("commit"), context, []byte(role), pub, nonce))
}

func newPairExchange(role string, context []byte) (*pairExchange, error) {
	priv, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	nonce, err := randomBytes(nonceBytes)
	if err != nil {
		return nil, err
	}
	x := &pairExchange{role: role, context: context, priv: priv, pub: priv.PublicKey().Bytes(), nonce: nonce}
	x.commit = commitment(context, role, x.pub, x.nonce)
	return x, nil
}

func (x *pairExchange) peerRole() string {
	if x.role == roleA {
		return roleB
	}
	return roleA
}

// acceptReveal checks the peer's revealed values against its earlier
// commitment. The commitment was received before this side revealed, so the
// peer could not choose its values after seeing ours.
func (x *pairExchange) acceptReveal(pub, nonce []byte) error {
	if len(pub) != 32 || len(nonce) != nonceBytes || len(x.peerCommit) != sha256.Size {
		return errors.New("nearby: malformed reveal")
	}
	if !hmac.Equal(commitment(x.context, x.peerRole(), pub, nonce), x.peerCommit) {
		return errors.New("nearby: commitment mismatch")
	}
	x.peerPub, x.peerNonce = pub, nonce
	return nil
}

func (x *pairExchange) keys() (*pairKeys, error) {
	peer, err := ecdh.X25519().NewPublicKey(x.peerPub)
	if err != nil {
		return nil, err
	}
	z, err := x.priv.ECDH(peer)
	if err != nil {
		return nil, errAllZero
	}
	if bytes.Equal(z, make([]byte, len(z))) {
		return nil, errAllZero
	}
	cA, cB, pA, nA, pB, nB := x.commit, x.peerCommit, x.pub, x.nonce, x.peerPub, x.peerNonce
	if x.role == roleB {
		cA, cB, pA, nA, pB, nB = x.peerCommit, x.commit, x.peerPub, x.peerNonce, x.pub, x.nonce
	}
	t := sha256Sum(encode(x.context,
		[]byte(x.nameA), []byte(x.typeA), []byte(x.nameB), []byte(x.typeB),
		cA, cB, pA, nA, pB, nB))
	prk, err := hkdf.Extract(sha256.New, z, make([]byte, 32))
	if err != nil {
		return nil, err
	}
	derive := func(label string, n int) ([]byte, error) {
		return hkdfExpand(prk, encode([]byte(pairLabel), []byte(label), t), n)
	}
	k := &pairKeys{transcript: t}
	sas, err := derive("sas", 8)
	if err != nil {
		return nil, err
	}
	k.code = fmt.Sprintf("%06d", binary.BigEndian.Uint64(sas)%1000000)
	for _, item := range []struct {
		label string
		dst   *[]byte
	}{
		{"pair-key", &k.pairKey},
		{"confirm-A", &k.confirmA},
		{"confirm-B", &k.confirmB},
		{"identity-A", &k.identityA},
		{"identity-B", &k.identityB},
	} {
		if *item.dst, err = derive(item.label, keyBytes); err != nil {
			return nil, err
		}
	}
	k.pairID = sha256Sum(encode([]byte(pairLabel), []byte("pair-id"), t))
	return k, nil
}

func (k *pairKeys) confirmKey(role string) []byte {
	if role == roleA {
		return k.confirmA
	}
	return k.confirmB
}

func (k *pairKeys) identityKey(role string) []byte {
	if role == roleA {
		return k.identityA
	}
	return k.identityB
}

func (k *pairKeys) confirmMAC(role string) []byte {
	return hmacSHA256(k.confirmKey(role), encode([]byte("accept"), []byte(role), k.transcript))
}

type sealedIdentity struct {
	InstallationID string `json:"id"`
	IRK            []byte `json:"irk"`
	Nickname       string `json:"name"`
	DeviceType     string `json:"type"`
}

func sealIdentity(key, transcript []byte, id Identity) ([]byte, error) {
	plain, err := json.Marshal(sealedIdentity{id.InstallationID, id.IRK, id.Nickname, id.DeviceType})
	if err != nil {
		return nil, err
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce, err := randomBytes(aead.NonceSize())
	if err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, transcript), nil
}

func openIdentity(key, transcript, sealed []byte) (*sealedIdentity, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < aead.NonceSize() {
		return nil, errors.New("nearby: malformed identity")
	}
	plain, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], transcript)
	if err != nil {
		return nil, errors.New("nearby: identity failed authentication")
	}
	var id sealedIdentity
	if err := json.Unmarshal(plain, &id); err != nil {
		return nil, err
	}
	if !validInstallationID(id.InstallationID) || len(id.IRK) != irkBytes {
		return nil, errors.New("nearby: invalid peer identity")
	}
	return &id, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

type msgResult struct {
	msg *wireMsg
	err error
}

// runConfirmation waits for both users to confirm the matching numbers, then
// exchanges identities encrypted under keys only the two exchange
// participants hold. Nothing identifying is released before both confirm.
func runConfirmation(conn net.Conn, p *Pairing, x *pairExchange, k *pairKeys, self Identity, closed <-chan struct{}) (*PeerRecord, error) {
	_ = conn.SetDeadline(time.Time{})
	msgs := make(chan msgResult, 4)
	go func() {
		for {
			m, err := readMsg(conn)
			msgs <- msgResult{m, err}
			if err != nil {
				return
			}
		}
	}()
	timer := time.NewTimer(pairConfirmTimeout)
	defer timer.Stop()

	localOK, peerOK, sent := false, false, false
	var peerSealed []byte
	write := func(m *wireMsg) error {
		_ = conn.SetWriteDeadline(time.Now().Add(pairStepTimeout))
		return writeMsg(conn, m)
	}
	for {
		if localOK && peerOK && !sent {
			sealed, err := sealIdentity(k.identityKey(x.role), k.transcript, self)
			if err != nil {
				return nil, err
			}
			if err := write(&wireMsg{Op: opIdentity, Sealed: sealed}); err != nil {
				return nil, err
			}
			sent = true
		}
		if sent && peerSealed != nil {
			id, err := openIdentity(k.identityKey(x.peerRole()), k.transcript, peerSealed)
			if err != nil {
				return nil, err
			}
			if id.InstallationID == self.InstallationID {
				return nil, errors.New("nearby: peer reused this device's identity")
			}
			return &PeerRecord{
				InstallationID: id.InstallationID,
				IRK:            id.IRK,
				PairKey:        k.pairKey,
				PairID:         hex.EncodeToString(k.pairID),
				Nickname:       cleanName(id.Nickname),
				DeviceType:     cleanDeviceType(id.DeviceType),
				PairedAt:       time.Now().UTC(),
			}, nil
		}
		select {
		case accept := <-p.decision:
			if !accept {
				_ = write(&wireMsg{Op: opReject})
				return nil, ErrRejected
			}
			if err := write(&wireMsg{Op: opConfirm, MAC: k.confirmMAC(x.role)}); err != nil {
				return nil, err
			}
			localOK = true
		case r := <-msgs:
			if r.err != nil {
				return nil, fmt.Errorf("nearby: pairing connection lost: %w", r.err)
			}
			switch r.msg.Op {
			case opConfirm:
				if peerOK || !hmac.Equal(r.msg.MAC, k.confirmMAC(x.peerRole())) {
					return nil, errors.New("nearby: invalid confirmation")
				}
				peerOK = true
			case opIdentity:
				if !localOK || !peerOK || peerSealed != nil {
					return nil, errors.New("nearby: identity sent out of order")
				}
				peerSealed = r.msg.Sealed
			default:
				return nil, expectOp(r.msg, opConfirm)
			}
		case <-timer.C:
			return nil, ErrTimeout
		case <-closed:
			return nil, ErrClosed
		}
	}
}

// pairInitiate runs the initiator (A) side up to the displayed code.
// listenPort is this device's pairing port, sent so the responder can reach
// it later even where multicast does not carry its advertisements.
func pairInitiate(conn net.Conn, self Identity, listenPort int, tagA, tagB []byte) (*Pairing, *pairExchange, *pairKeys, error) {
	req, err := randomBytes(16)
	if err != nil {
		return nil, nil, nil, err
	}
	x, err := newPairExchange(roleA, pairContext(req, tagA, tagB))
	if err != nil {
		return nil, nil, nil, err
	}
	x.nameA, x.typeA = cleanName(self.Nickname), cleanDeviceType(self.DeviceType)
	step := func() { _ = conn.SetDeadline(time.Now().Add(pairStepTimeout)) }

	step()
	if err := writeMsg(conn, &wireMsg{Op: opPair, V: ProtocolVersion, Req: req, Tag: tagA, Target: tagB, Commit: x.commit, Name: x.nameA, Type: x.typeA, Port: listenPort}); err != nil {
		return nil, nil, nil, err
	}
	m, err := readMsg(conn)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := expectOp(m, opPairCommit); err != nil {
		return nil, nil, nil, err
	}
	if len(m.Commit) != sha256.Size {
		return nil, nil, nil, errors.New("nearby: malformed commitment")
	}
	x.peerCommit = m.Commit
	x.nameB, x.typeB = cleanName(m.Name), cleanDeviceType(m.Type)

	step()
	if err := writeMsg(conn, &wireMsg{Op: opReveal, Pub: x.pub, Nonce: x.nonce}); err != nil {
		return nil, nil, nil, err
	}
	if m, err = readMsg(conn); err != nil {
		return nil, nil, nil, err
	}
	if err := expectOp(m, opReveal); err != nil {
		return nil, nil, nil, err
	}
	if err := x.acceptReveal(m.Pub, m.Nonce); err != nil {
		return nil, nil, nil, err
	}
	k, err := x.keys()
	if err != nil {
		return nil, nil, nil, err
	}
	p := newPairing(req, false)
	p.PeerName, p.PeerType, p.Code = x.nameB, x.typeB, k.code
	p.PeerAddress = conn.RemoteAddr().String()
	return p, x, k, nil
}

// pairRespond runs the responder (B) side after the first message arrived
// and the service decided to accept a pairing prompt.
func pairRespond(conn net.Conn, first *wireMsg, self Identity, ownTag []byte) (*Pairing, *pairExchange, *pairKeys, error) {
	if len(first.Req) != 16 || len(first.Tag) != tagBytes || len(first.Commit) != sha256.Size {
		return nil, nil, nil, errors.New("nearby: malformed pairing request")
	}
	x, err := newPairExchange(roleB, pairContext(first.Req, first.Tag, ownTag))
	if err != nil {
		return nil, nil, nil, err
	}
	x.peerCommit = first.Commit
	x.nameA, x.typeA = cleanName(first.Name), cleanDeviceType(first.Type)
	x.nameB, x.typeB = cleanName(self.Nickname), cleanDeviceType(self.DeviceType)
	step := func() { _ = conn.SetDeadline(time.Now().Add(pairStepTimeout)) }

	step()
	if err := writeMsg(conn, &wireMsg{Op: opPairCommit, Commit: x.commit, Name: x.nameB, Type: x.typeB}); err != nil {
		return nil, nil, nil, err
	}
	m, err := readMsg(conn)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := expectOp(m, opReveal); err != nil {
		return nil, nil, nil, err
	}
	// Verify A's commitment before revealing anything of ours.
	if err := x.acceptReveal(m.Pub, m.Nonce); err != nil {
		return nil, nil, nil, err
	}
	step()
	if err := writeMsg(conn, &wireMsg{Op: opReveal, Pub: x.pub, Nonce: x.nonce}); err != nil {
		return nil, nil, nil, err
	}
	k, err := x.keys()
	if err != nil {
		return nil, nil, nil, err
	}
	p := newPairing(first.Req, true)
	p.PeerName, p.PeerType, p.Code = x.nameA, x.typeA, k.code
	p.PeerAddress = conn.RemoteAddr().String()
	return p, x, k, nil
}
