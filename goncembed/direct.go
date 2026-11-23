package goncembed

import (
	"errors"
	"net"
	"os"
	"strings"

	"github.com/threatexpert/gonc/v2/apps"
	"github.com/threatexpert/gonc/v2/httpfileshare"
)

// Direct sessions connect two peers whose address is already known, for
// example a device found on the local network. They skip MQTT signaling, STUN
// and multicast discovery entirely and run the same HTTP file share over a
// TCP connection protected by TLS 1.3 with mutual authentication. Both
// certificates are derived from key, exactly as -psk does on the command line.

func validateDirectKey(key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return errors.New("direct session key is required")
	}
	// The CLI treats "." as "generate a key" and "@path" as "read the key
	// from a file"; neither is meaningful for a derived session key.
	if key == "." || strings.HasPrefix(key, "@") {
		return errors.New("direct session key has an invalid format")
	}
	return nil
}

func validateDirectAddress(address string) (string, string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", "", err
	}
	if host == "" || port == "" || port == "0" {
		return "", "", errors.New("direct session address needs an explicit host and port")
	}
	return host, port, nil
}

func directSecurityArgs(key string) []string {
	return []string{"-tls", "-tls13", "-psk", key}
}

// sideDirectSend marks direct share sessions, whose Ready callback reports
// the bound listen address.
const sideDirectSend = "direct-send"

const listeningMarker = "Listening tcp on "

// findListeningEndpoint extracts host:port from the listener's startup log.
func findListeningEndpoint(message string) string {
	i := strings.Index(message, listeningMarker)
	if i < 0 {
		return ""
	}
	rest := message[i+len(listeningMarker):]
	if end := strings.IndexAny(rest, " \t\r\n"); end >= 0 {
		rest = rest[:end]
	}
	if _, _, err := net.SplitHostPort(rest); err != nil {
		return ""
	}
	return rest
}

// StartDirectShareSource serves source on listenAddr (host:port). The peer
// must connect with StartDirectReceive and the same key. Callback.Ready
// reports the address once the listener accepts connections; tell the peer
// to connect only after that. The listener keeps accepting so the receiver
// can reconnect; call Stop when the transfer ends.
func StartDirectShareSource(source httpfileshare.FileSource, listenAddr, key string, cb Callback) (*Session, error) {
	if source == nil {
		return nil, errors.New("file source is required")
	}
	if err := validateDirectKey(key); err != nil {
		return nil, err
	}
	if _, _, err := validateDirectAddress(listenAddr); err != nil {
		return nil, err
	}
	args := directSecurityArgs(key)
	args = append(args, "-k", "-l", "-local", listenAddr, "-httpserver", os.DevNull)
	return startSession(args, cb, sideDirectSend, source, apps.RunOptions{}, false)
}

// StartDirectReceive connects to a StartDirectShareSource listener at
// remoteAddr and exposes the share on a loopback HTTP endpoint reported
// through Callback.Ready, like StartP2PReceive.
func StartDirectReceive(remoteAddr, key string, cb Callback) (*Session, error) {
	if err := validateDirectKey(key); err != nil {
		return nil, err
	}
	host, port, err := validateDirectAddress(remoteAddr)
	if err != nil {
		return nil, err
	}
	// Choose the loopback HTTP port explicitly. With the default, gonc reuses
	// the port of the previous session in this process, which may still be
	// shutting down, and the new session would wait for a retry.
	local, err := freeLoopbackPort()
	if err != nil {
		return nil, err
	}
	args := directSecurityArgs(key)
	args = append(args, "-httplocal-port", local, host, port)
	return startSession(args, cb, "receive", nil, apps.RunOptions{}, false)
}

func freeLoopbackPort() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr, nil
}
