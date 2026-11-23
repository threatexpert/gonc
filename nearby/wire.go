package nearby

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
)

const (
	maxWireMessage = 16 << 10
	maxNameRunes   = 64
)

// wireMsg is the single message shape used on pairing and session
// connections. Unused fields are omitted. []byte fields travel as base64.
type wireMsg struct {
	Op      string `json:"op"`
	V       int    `json:"v,omitempty"`
	Req     []byte `json:"req,omitempty"`
	Tag     []byte `json:"tag,omitempty"`
	Target  []byte `json:"target,omitempty"`
	Commit  []byte `json:"commit,omitempty"`
	Pub     []byte `json:"pub,omitempty"`
	Nonce   []byte `json:"nonce,omitempty"`
	MAC     []byte `json:"mac,omitempty"`
	Sealed  []byte `json:"sealed,omitempty"`
	Name    string `json:"name,omitempty"`
	Type    string `json:"type,omitempty"`
	ID      string `json:"id,omitempty"`
	Port    int    `json:"port,omitempty"`
	OK      bool   `json:"ok,omitempty"`
	LAN     bool   `json:"lan,omitempty"`
	Message string `json:"msg,omitempty"`

	// Offers carry a summary of what is being sent, so the recipient can
	// ask the user before connecting to the share.
	Items []OfferItem `json:"items,omitempty"`
	Files int64       `json:"files,omitempty"`
	Bytes int64       `json:"bytes,omitempty"`
}

const (
	opPair       = "pair"
	opPairCommit = "pair-commit"
	opReveal     = "reveal"
	opConfirm    = "confirm"
	opReject     = "reject"
	opIdentity   = "identity"
	opBusy       = "busy"
	opError      = "error"

	opSession   = "session"
	opSessionOK = "session-ok"
	opUnknown   = "unknown"
	opVerify    = "verify"
	opVerified  = "verified"
	opOffer     = "offer"
	opAccepted  = "accepted"
	opDeclined  = "declined"
	opFinished  = "finished"
	opCancel    = "cancel"

	// hello asks a device at a known address for its advertisement, for
	// networks where multicast does not reach it.
	opHello   = "hello"
	opHelloOK = "hello-ok"

	// quick opens an unauthenticated session to send without pairing.
	opQuick    = "quick"
	opQuickOK  = "quick-ok"
	opQuickOff = "quick-off"
)

func writeMsg(w io.Writer, m *wireMsg) error {
	body, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(body) > maxWireMessage {
		return errors.New("nearby: message too large")
	}
	frame := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(body)), uint32(len(body)))
	frame = append(frame, body...)
	_, err = w.Write(frame)
	return err
}

func readMsg(r io.Reader) (*wireMsg, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > maxWireMessage {
		return nil, fmt.Errorf("nearby: invalid message length %d", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	var m wireMsg
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("nearby: malformed message: %w", err)
	}
	if m.Op == "" {
		return nil, errors.New("nearby: message without op")
	}
	return &m, nil
}

func expectOp(m *wireMsg, op string) error {
	if m.Op == op {
		return nil
	}
	switch m.Op {
	case opBusy:
		return ErrBusy
	case opUnknown:
		return ErrNotPaired
	case opReject:
		return ErrRejected
	case opError:
		return fmt.Errorf("nearby: peer error: %s", cleanName(m.Message))
	}
	return fmt.Errorf("nearby: unexpected message %q, want %q", cleanName(m.Op), op)
}

// cleanName strips control characters and bounds the length of a nickname
// or other short text that a peer supplies for display.
func cleanName(s string) string { return cleanText(s, maxNameRunes) }

func cleanText(s string, limit int) string {
	var b strings.Builder
	count := 0
	for _, r := range s {
		if count >= limit {
			break
		}
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			continue
		}
		b.WriteRune(r)
		count++
	}
	return strings.TrimSpace(b.String())
}

func cleanDeviceType(s string) string {
	switch s {
	case "desktop", "laptop", "phone", "tablet", "server":
		return s
	}
	return "desktop"
}
