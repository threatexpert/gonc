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
	P2PReport(topic string, status string, network string, mode string, peer string, timestamp int64, pid int)
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

// StartShare starts the sender side using path-based sharing.
//
// paths is a newline-separated list of filesystem paths. Android should pass
// app-cache paths for the first integration, then this can evolve to stream
// ContentResolver inputs directly.
func StartShare(paths string, password string, useUDP bool, cb Callback) (*Session, error) {
	items := splitLines(paths)
	if strings.TrimSpace(password) == "" {
		return nil, errors.New("password is required")
	}
	if len(items) == 0 {
		return nil, errors.New("at least one path is required")
	}
	args := []string{"-p2p", password}
	if useUDP {
		args = append(args, "-u")
	}
	args = append(args, "-httpserver")
	args = append(args, items...)
	return start(args, cb, "send"), nil
}

// StartReceive starts the receiver side and exposes the peer's HTTP share on a
// local endpoint. The Android layer can later download through that endpoint or
// call a dedicated download API.
func StartReceive(password string, useUDP bool, cb Callback) (*Session, error) {
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

func start(args []string, cb Callback, mode string) *Session {
	ctx, cancel := context.WithCancel(context.Background())
	session := &Session{
		cancel: cancel,
		done:   make(chan struct{}),
	}
	reportServer, reportURL := startP2PReportServer(ctx, cb, mode)
	if reportURL != "" {
		args = append([]string{}, args...)
		args = append(args, "-p2p-report-url", reportURL)
	}
	writer := callbackWriter{cb: cb}
	go func() {
		defer close(session.done)
		if reportServer != nil {
			defer reportServer.Close()
		}
		exitCode := apps.RunNetcat(ctx, nil, writer, args)
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
	Peer      string `json:"peer"`
	Timestamp int64  `json:"timestamp"`
	PID       int    `json:"pid"`
}

func startP2PReportServer(ctx context.Context, cb Callback, mode string) (*http.Server, string) {
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
		if report.Mode == "" {
			report.Mode = mode
		}
		cb.P2PReport(report.Topic, report.Status, report.Network, report.Mode, report.Peer, report.Timestamp, report.PID)
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

func splitLines(value string) []string {
	lines := strings.Split(value, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

type callbackWriter struct {
	cb Callback
}

func (w callbackWriter) Write(p []byte) (int, error) {
	if w.cb == nil {
		return len(p), nil
	}
	message := strings.TrimSpace(string(p))
	if message != "" {
		w.cb.Event("info", message)
		if endpoint := findLocalHTTPEndpoint(message); endpoint != "" {
			w.cb.Ready(endpoint)
		}
	}
	return len(p), nil
}

func findLocalHTTPEndpoint(message string) string {
	start := strings.Index(message, "http://127.0.0.1:")
	if start < 0 {
		return ""
	}
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
