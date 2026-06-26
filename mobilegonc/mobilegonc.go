// Package mobilegonc exposes a gomobile-friendly API for Android and iOS shells.
//
// The first version deliberately wraps the existing gonc command-line engine.
// That keeps behavior aligned with the desktop/CLI build while the lower-level
// P2P and file-share packages are made friendlier to mobile file streams.
package mobilegonc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/threatexpert/gonc/v2/apps"
)

// Callback is implemented by the Android layer. Keep this interface small and
// primitive because gomobile bind does not support arbitrary Go types.
type Callback interface {
	Event(level string, message string)
	P2PReport(topic string, side string, status string, network string, mode string, peer string, timestamp int64, pid int)
	Ready(endpoint string)
	Stopped(exitCode int)
	Error(message string)
}

// Session represents one running gonc task.
type Session struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// Stop requests cancellation. Some legacy CLI paths still need follow-up work
// to observe context promptly, but P2P discovery paths already use context.
func (s *Session) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
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
	args := []string{"-p2p", password}
	if useUDP {
		args = append(args, "-u")
	}
	args = append(args, "-httpserver", ".")
	return startP2PWithFileSource(args, cb, "send", source), nil
}

// StartP2PReceive starts the P2P receiver side and exposes the peer's HTTP share on a
// local endpoint. The Android layer can later download through that endpoint or
// call a dedicated download API.
func StartP2PReceive(password string, useUDP bool, cb Callback) (*Session, error) {
	if strings.TrimSpace(password) == "" {
		return nil, errors.New("password is required")
	}
	args := []string{"-p2p", password}
	if useUDP {
		args = append(args, "-u")
	}
	args = append(args, "-httplocal")
	return start(args, cb, "receive"), nil
}

func start(args []string, cb Callback, side string) *Session {
	return startP2PWithFileSource(args, cb, side, nil)
}

func startP2PWithFileSource(args []string, cb Callback, side string, source AndroidFileSource) *Session {
	ctx, cancel := context.WithCancel(context.Background())
	session := &Session{
		cancel: cancel,
		done:   make(chan struct{}),
	}
	reportServer, reportURL := startP2PReportServer(ctx, cb, side)
	if reportURL != "" {
		args = append([]string{}, args...)
		args = append(args, "-p2p-report-url", reportURL)
	}
	writer := &callbackWriter{cb: cb, side: side}
	go func() {
		defer close(session.done)
		if reportServer != nil {
			defer reportServer.Close()
		}
		exitCode := 0
		if source != nil {
			exitCode = apps.RunNetcatP2PWithHTTPFileSource(ctx, nil, writer, args, newMobileFileSource(source))
		} else {
			exitCode = apps.RunNetcat(ctx, nil, writer, args)
		}
		if cb != nil {
			cb.Stopped(exitCode)
		}
	}()
	return session
}

type p2pStatusReport struct {
	Topic     string `json:"topic"`
	Status    string `json:"status"`
	Network   string `json:"network"`
	Mode      string `json:"mode"`
	Side      string `json:"side"`
	Peer      string `json:"peer"`
	Timestamp int64  `json:"timestamp"`
	PID       int    `json:"pid"`
}

func startP2PReportServer(ctx context.Context, cb Callback, side string) (*http.Server, string) {
	if cb == nil {
		return nil, ""
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cb.Event("warn", "P2P report server unavailable: "+err.Error())
		return nil, ""
	}

	mux := http.NewServeMux()
	server := &http.Server{Handler: mux}
	mux.HandleFunc("/p2p-report", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var report p2pStatusReport
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if report.Side == "" {
			report.Side = side
		}
		cb.P2PReport(report.Topic, report.Side, report.Status, report.Network, report.Mode, report.Peer, report.Timestamp, report.PID)
		w.WriteHeader(http.StatusNoContent)
	})

	go func() {
		<-ctx.Done()
		_ = server.Close()
	}()
	go func() {
		_ = server.Serve(ln)
	}()
	return server, "http://" + ln.Addr().String() + "/p2p-report"
}

type callbackWriter struct {
	cb                    Callback
	side                  string
	mu                    sync.Mutex
	pendingSOCKS5Endpoint string
	readySent             bool
}

func (w *callbackWriter) Write(p []byte) (int, error) {
	if w.cb == nil {
		return len(p), nil
	}
	message := strings.TrimSpace(string(p))
	if message != "" {
		w.cb.Event("info", message)
		switch w.side {
		case "receive":
			if endpoint := findLocalHTTPEndpoint(message); endpoint != "" {
				w.cb.Ready(endpoint)
			}
		case "tunnel":
			if endpoint := w.findTunnelReadyEndpoint(message); endpoint != "" {
				w.cb.Ready(endpoint)
			}
		}
	}
	return len(p), nil
}

func (w *callbackWriter) findTunnelReadyEndpoint(message string) string {
	if endpoint := findLocalSOCKS5Endpoint(message); endpoint != "" {
		w.mu.Lock()
		w.pendingSOCKS5Endpoint = endpoint
		w.mu.Unlock()
	}
	if !strings.Contains(message, "[link] Local service started.") {
		return ""
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.readySent || w.pendingSOCKS5Endpoint == "" {
		return ""
	}
	w.readySent = true
	return w.pendingSOCKS5Endpoint
}

func findLocalHTTPEndpoint(message string) string {
	const openPrefix = "You can open "
	const urlPrefix = "http://127.0.0.1:"
	marker := openPrefix + urlPrefix

	markerStart := strings.Index(message, marker)
	if markerStart < 0 {
		return ""
	}
	start := markerStart + len(openPrefix)
	end := start
	for end < len(message) {
		c := message[end]
		if c <= ' ' || c == '"' || c == '\'' || c == '<' || c == '>' {
			break
		}
		end++
	}
	return message[start:end]
}

func findLocalSOCKS5Endpoint(message string) string {
	const marker = "[link-x] Listening on "
	markerStart := strings.Index(message, marker)
	if markerStart < 0 {
		return ""
	}
	start := markerStart + len(marker)
	end := start
	for end < len(message) {
		c := message[end]
		if c <= ' ' || c == '(' {
			break
		}
		end++
	}
	if end <= start {
		return ""
	}
	host, port, err := net.SplitHostPort(message[start:end])
	if err != nil || port == "" {
		return ""
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return "socks5://" + net.JoinHostPort(host, port)
}
