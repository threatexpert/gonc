// Package mobilegonc exposes a gomobile-friendly API for Android and iOS shells.
package mobilegonc

import (
	"encoding/hex"
	"errors"
	"strings"

	"github.com/threatexpert/gonc/v2/goncembed"
	"github.com/zeebo/blake3"
)

// Callback is implemented by the Android layer. Keep this interface small and
// primitive because gomobile bind does not support arbitrary Go types.
type Callback interface {
	Event(level string, message string)
	P2PReport(topic string, side string, status string, network string, mode string, peer string, timestamp int64, pid int)
	Traffic(side string, inBytes int64, outBytes int64, inBps float64, outBps float64, elapsed int64, connCount int, final bool)
	Ready(endpoint string)
	Stopped(exitCode int)
	Error(message string)
}

// Session represents one running gonc task.
type Session struct {
	inner *goncembed.Session
}

// Stop requests cancellation.
func (s *Session) Stop() {
	if s != nil && s.inner != nil {
		s.inner.Stop()
	}
}

// StartP2PShareSource starts the P2P sender side using an Android-provided FileSource.
// File contents are streamed from Android on demand; they are not copied into a
// temporary cache before sharing.
func StartP2PShareSource(source AndroidFileSource, password string, useUDP bool, cb Callback) (*Session, error) {
	if source == nil {
		return nil, errors.New("file source is required")
	}
	if strings.TrimSpace(password) == "" {
		return nil, errors.New("password is required")
	}
	session, err := goncembed.StartP2PShareSource(newMobileFileSource(source), password, useUDP, cb)
	if err != nil {
		return nil, err
	}
	return &Session{inner: session}, nil
}

// StartP2PReceive starts the P2P receiver side and exposes the peer's HTTP share
// on a local endpoint.
func StartP2PReceive(password string, useUDP bool, cb Callback) (*Session, error) {
	session, err := goncembed.StartP2PReceive(password, useUDP, cb)
	if err != nil {
		return nil, err
	}
	return &Session{inner: session}, nil
}

// Blake3Hex returns the BLAKE3-256 digest for a byte slice as lowercase hex.
func Blake3Hex(data []byte) string {
	sum := blake3.Sum256(data)
	return hex.EncodeToString(sum[:])
}
