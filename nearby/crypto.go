package nearby

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	pairLabel    = "gonc-pair-v1"
	sessionLabel = "gonc-session-v1"
	advertLabel  = "gonc-nearby-v1"

	installationIDBytes = 16
	irkBytes            = 16
	tagRandomBytes      = 16
	tagMACBytes         = 16
	tagBytes            = tagRandomBytes + tagMACBytes
	nonceBytes          = 32
	keyBytes            = 32
)

// encode is the canonical, unambiguous encoding used for every hashed or
// authenticated value: each field is a 4-byte big-endian length followed by
// its bytes. Field order is fixed by each caller.
func encode(fields ...[]byte) []byte {
	size := 0
	for _, f := range fields {
		size += 4 + len(f)
	}
	out := make([]byte, 0, size)
	for _, f := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, f...)
	}
	return out
}

func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func hmacSHA256(key []byte, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func sha256Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// NewInstallationID returns a random installation ID as 32 lowercase hex
// characters. The application generates it once and stores it.
func NewInstallationID() (string, error) {
	b, err := randomBytes(installationIDBytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// NewIRK returns a random identity resolving key. The application generates
// it once, stores it as a secret, and shares it only with paired devices.
func NewIRK() ([]byte, error) {
	return randomBytes(irkBytes)
}

func validInstallationID(id string) bool {
	if len(id) != installationIDBytes*2 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil && strings.ToLower(id) == id
}

// makeTag builds a resolvable tag r || trunc16(HMAC(IRK, encode(label, r))).
// Anyone holding the IRK can recognize it; to others it is a random value.
func makeTag(irk []byte) ([]byte, error) {
	r, err := randomBytes(tagRandomBytes)
	if err != nil {
		return nil, err
	}
	return append(r, tagMAC(irk, r)...), nil
}

func tagMAC(irk, r []byte) []byte {
	return hmacSHA256(irk, encode([]byte(advertLabel), []byte("adv-tag"), r))[:tagMACBytes]
}

func tagMatches(irk, tag []byte) bool {
	if len(irk) != irkBytes || len(tag) != tagBytes {
		return false
	}
	return hmac.Equal(tag[tagRandomBytes:], tagMAC(irk, tag[:tagRandomBytes]))
}

var lowerBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// encodeKey renders 32 derived bytes as a printable key with a fixed prefix.
// The prefix guarantees both letters and digits, which the desktop
// application's passphrase strength check requires.
func encodeKey(prefix string, b []byte) string {
	return prefix + strings.ToLower(lowerBase32.EncodeToString(b))
}

func hkdfExpand(prk []byte, info []byte, n int) ([]byte, error) {
	return hkdf.Expand(sha256.New, prk, string(info), n)
}

var errAllZero = errors.New("nearby: invalid key agreement result")
