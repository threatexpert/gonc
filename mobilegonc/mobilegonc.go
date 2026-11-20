// Package mobilegonc exposes a gomobile-friendly API for Android and iOS shells.
package mobilegonc

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

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

// AwaitDone waits for the session to finish. A timeout does not cancel the session.
// Call off the UI thread and outside callbacks. Nonpositive timeouts only poll.
func (s *Session) AwaitDone(timeoutMillis int) bool {
	if s == nil || s.inner == nil {
		return true
	}
	if timeoutMillis <= 0 {
		select {
		case <-s.inner.Done():
			return true
		default:
			return false
		}
	}
	timer := time.NewTimer(time.Duration(timeoutMillis) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-s.inner.Done():
		return true
	case <-timer.C:
		return false
	}
}

// StartP2PShareSource starts the P2P sender side using an Android-provided FileSource.
// File contents are streamed from Android on demand; they are not copied into a
// temporary cache before sharing.
func StartP2PShareSource(source AndroidFileSource, password string, useUDP bool, cb Callback) (*Session, error) {
	return StartP2PShareSourceWithLAN(source, password, useUDP, false, cb)
}

// StartP2PShareSourceWithLAN optionally runs normal P2P and passive LAN
// discovery concurrently while serving the same file source.
func StartP2PShareSourceWithLAN(source AndroidFileSource, password string, useUDP bool, p2pWithLAN bool, cb Callback) (*Session, error) {
	if source == nil {
		return nil, errors.New("file source is required")
	}
	if strings.TrimSpace(password) == "" {
		return nil, errors.New("password is required")
	}
	session, err := goncembed.StartP2PShareSourceWithOptions(
		newMobileFileSource(source),
		password,
		goncembed.P2POptions{UseUDP: useUDP, P2PWithLANMode: p2pWithLAN},
		cb,
	)
	if err != nil {
		return nil, err
	}
	return &Session{inner: session}, nil
}

// StartP2PReceive starts the P2P receiver side and exposes the peer's HTTP share
// on a local endpoint.
func StartP2PReceive(password string, useUDP bool, cb Callback) (*Session, error) {
	return StartP2PReceiveWithLAN(password, useUDP, false, cb)
}

// StartP2PReceiveWithLAN optionally races normal P2P with active LAN discovery
// and exposes only the winning connection to the local HTTP client.
func StartP2PReceiveWithLAN(password string, useUDP bool, p2pWithLAN bool, cb Callback) (*Session, error) {
	return StartP2PReceiveWithHelloTimeout(password, useUDP, p2pWithLAN, 0, cb)
}

// StartP2PReceiveWithHelloTimeout accepts a peer wait deadline in seconds.
// Zero keeps the legacy 30-second default; negative or overflowing values are rejected.
func StartP2PReceiveWithHelloTimeout(password string, useUDP bool, p2pWithLAN bool, helloTimeoutSeconds int64, cb Callback) (*Session, error) {
	if helloTimeoutSeconds < 0 || helloTimeoutSeconds > int64((1<<63-1)/time.Second) {
		return nil, fmt.Errorf("invalid Hello timeout seconds")
	}
	session, err := goncembed.StartP2PReceiveWithOptions(
		password,
		goncembed.P2POptions{UseUDP: useUDP, P2PWithLANMode: p2pWithLAN, HelloTimeout: time.Duration(helloTimeoutSeconds) * time.Second},
		cb,
	)
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
