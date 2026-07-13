// Package goncembed exposes an in-process API for embedding gonc sessions in
// GUI or mobile shells.
package goncembed

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/threatexpert/gonc/v2/apps"
	"github.com/threatexpert/gonc/v2/httpfileshare"
)

// Callback receives primitive session events so UI layers can bridge them to
// their own event systems.
type Callback interface {
	Event(level string, message string)
	P2PReport(topic string, side string, status string, network string, mode string, peer string, timestamp int64, pid int)
	Ready(endpoint string)
	Stopped(exitCode int)
	Error(message string)
}

type TrafficCallback interface {
	Traffic(side string, inBytes int64, outBytes int64, inBps float64, outBps float64, elapsed int64, connCount int, final bool)
}

type P2POptions struct {
	UseUDP         bool
	P2PWithLANMode bool
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

// Done returns a channel closed after the embedded gonc task exits.
func (s *Session) Done() <-chan struct{} {
	if s == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return s.done
}

// StartP2PShareSource starts the P2P sender side using a caller-provided file
// source. The source is consulted on each HTTP request, so callers can implement
// a mutable source for live share-list updates.
func StartP2PShareSource(source httpfileshare.FileSource, password string, useUDP bool, cb Callback) (*Session, error) {
	return StartP2PShareSourceWithOptions(source, password, P2POptions{UseUDP: useUDP}, cb)
}

func StartP2PShareSourceWithOptions(source httpfileshare.FileSource, password string, options P2POptions, cb Callback) (*Session, error) {
	if source == nil {
		return nil, errors.New("file source is required")
	}
	if strings.TrimSpace(password) == "" {
		return nil, errors.New("password is required")
	}
	args := []string{"-p2p", password}
	if options.UseUDP {
		args = append(args, "-u")
	}
	args = append(args, "-httpserver", os.DevNull) // a Placeholder
	return startP2PWithFileSourceAndOptions(args, cb, "send", source, apps.RunOptions{
		P2PWithLANMode: options.P2PWithLANMode,
	})
}

// StartP2PSharePaths starts the P2P sender side from fixed local filesystem
// paths. Use StartP2PShareSource when the root list must be updated live.
func StartP2PSharePaths(paths []string, password string, useUDP bool, cb Callback) (*Session, error) {
	return StartP2PSharePathsWithOptions(paths, password, P2POptions{UseUDP: useUDP}, cb)
}

func StartP2PSharePathsWithOptions(paths []string, password string, options P2POptions, cb Callback) (*Session, error) {
	if len(paths) == 0 {
		return nil, errors.New("select at least one file or folder to send")
	}
	if strings.TrimSpace(password) == "" {
		return nil, errors.New("password is required")
	}
	args := []string{"-p2p", password}
	if options.UseUDP {
		args = append(args, "-u")
	}
	args = append(args, "-httpserver")
	args = append(args, paths...)
	return startP2PWithFileSourceAndOptions(args, cb, "send", nil, apps.RunOptions{
		P2PWithLANMode: options.P2PWithLANMode,
	})
}

// StartP2PReceive starts the P2P receiver side and exposes the peer's HTTP
// share on a local endpoint.
func StartP2PReceive(password string, useUDP bool, cb Callback) (*Session, error) {
	return StartP2PReceiveWithOptions(password, P2POptions{UseUDP: useUDP}, cb)
}

// StartP2PReceiveWithOptions optionally races normal P2P with active LAN
// discovery and exposes only the winning connection to the local HTTP client.
func StartP2PReceiveWithOptions(password string, options P2POptions, cb Callback) (*Session, error) {
	if strings.TrimSpace(password) == "" {
		return nil, errors.New("password is required")
	}
	args := []string{"-p2p", password}
	if options.UseUDP {
		args = append(args, "-u")
	}
	args = append(args, "-httplocal")
	return startP2PWithFileSourceAndOptions(args, cb, "receive", nil, apps.RunOptions{
		P2PWithLANMode: options.P2PWithLANMode,
	})
}

func start(args []string, cb Callback, side string) (*Session, error) {
	return startP2PWithFileSource(args, cb, side, nil)
}

func startP2PWithFileSource(args []string, cb Callback, side string, source httpfileshare.FileSource) (*Session, error) {
	return startP2PWithFileSourceAndOptions(args, cb, side, source, apps.RunOptions{})
}

func startP2PWithFileSourceAndOptions(args []string, cb Callback, side string, source httpfileshare.FileSource, runOptions apps.RunOptions) (*Session, error) {
	ctx, cancel := context.WithCancel(context.Background())
	reportServer, reportURL := startP2PReportServer(cb, side)
	if reportURL != "" {
		args = append([]string{}, args...)
		args = append(args, "-p2p-report-url", reportURL)
	}
	writer := &callbackWriter{cb: cb, side: side}
	progressSink := progressSinkFor(cb, side)
	runOptions.HTTPFileSource = source
	runOptions.ProgressSink = progressSink
	config, err := apps.PrepareNetcatConfigWithOptions(ctx, writer, args, runOptions)
	if err != nil {
		cancel()
		if reportServer != nil {
			_ = reportServer.Close()
		}
		if cb != nil {
			cb.Error(err.Error())
		}
		return nil, err
	}
	session := &Session{
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go func() {
		defer close(session.done)
		if reportServer != nil {
			defer reportServer.Close()
		}
		exitCode := apps.RunPreparedNetcat(nil, config)
		if cb != nil {
			cb.Stopped(exitCode)
		}
	}()
	return session, nil
}

func progressSinkFor(cb Callback, side string) func(apps.ProgressSnapshot) {
	trafficCB, ok := cb.(TrafficCallback)
	if !ok {
		return nil
	}
	return func(snapshot apps.ProgressSnapshot) {
		trafficCB.Traffic(side, snapshot.InBytes, snapshot.OutBytes, snapshot.InBps, snapshot.OutBps, int64(snapshot.Elapsed), snapshot.ConnCount, snapshot.Final)
	}
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

func startP2PReportServer(cb Callback, side string) (*http.Server, string) {
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
		_ = server.Serve(ln)
	}()
	return server, "http://" + ln.Addr().String() + "/p2p-report"
}

type callbackWriter struct {
	cb                    Callback
	side                  string
	mu                    sync.Mutex
	pendingSOCKS5Endpoint string
	readyArmed            bool
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
		w.readyArmed = true
		w.mu.Unlock()
	}
	if !strings.Contains(message, "[link] Local service started.") {
		return ""
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.readyArmed || w.pendingSOCKS5Endpoint == "" {
		return ""
	}
	w.readyArmed = false
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
