package goncembed

import (
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/threatexpert/gonc/v2/httpfileshare"
)

type directTestCallback struct {
	mu     sync.Mutex
	ready  chan string
	events []string
}

func newDirectTestCallback() *directTestCallback {
	return &directTestCallback{ready: make(chan string, 4)}
}

func (c *directTestCallback) Event(level string, message string) {
	c.mu.Lock()
	c.events = append(c.events, message)
	c.mu.Unlock()
}
func (c *directTestCallback) P2PReport(string, string, string, string, string, string, int64, int) {}
func (c *directTestCallback) Ready(endpoint string)                                                { c.ready <- endpoint }
func (c *directTestCallback) Stopped(int)                                                          {}
func (c *directTestCallback) Error(message string)                                                 { c.Event("error", message) }

func (c *directTestCallback) log() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.events, "\n")
}

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func stopAndWait(t *testing.T, session *Session) {
	t.Helper()
	session.Stop()
	select {
	case <-session.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("session did not stop within 10 seconds")
	}
}

func startDirectShareForTest(t *testing.T, key string) (string, *Session) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello nearby"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := httpfileshare.NewOSFileSource([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	addr := freeLoopbackAddr(t)
	cb := newDirectTestCallback()
	share, err := StartDirectShareSource(source, addr, key, cb)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopAndWait(t, share) })
	select {
	case ready := <-cb.ready:
		if ready != addr {
			t.Fatalf("share reported ready at %s, want %s", ready, addr)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("share never reported that it is listening:\n%s", cb.log())
	}
	return addr, share
}

func TestDirectShareAndReceive(t *testing.T) {
	const key = "nb1-directtestkey0123456789"
	addr, _ := startDirectShareForTest(t, key)

	cb := newDirectTestCallback()
	receive, err := StartDirectReceive(addr, key, cb)
	if err != nil {
		t.Fatal(err)
	}
	defer stopAndWait(t, receive)

	var endpoint string
	select {
	case endpoint = <-cb.ready:
	case <-time.After(15 * time.Second):
		t.Fatalf("receiver never became ready:\n%s", cb.log())
	}
	dirName := ""
	resp, err := http.Get(endpoint + "/")
	if err != nil {
		t.Fatal(err)
	}
	listing, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(listing), "hello.txt") {
		// A single shared directory is exposed under its own name.
		for _, line := range strings.Split(string(listing), "\"") {
			if strings.HasSuffix(line, "/") && line != "/" && !strings.Contains(line, "<") {
				dirName = strings.TrimSuffix(strings.TrimPrefix(line, "/"), "/")
				break
			}
		}
	}
	path := "/hello.txt"
	if dirName != "" {
		path = "/" + dirName + "/hello.txt"
	}
	resp, err = http.Get(endpoint + path)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello nearby" {
		t.Fatalf("GET %s = %q (status %d)", path, body, resp.StatusCode)
	}
}

func TestDirectReceiveRejectsWrongKey(t *testing.T) {
	addr, _ := startDirectShareForTest(t, "nb1-rightkey0123456789abc")

	cb := newDirectTestCallback()
	receive, err := StartDirectReceive(addr, "nb1-wrongkey0123456789abc", cb)
	if err != nil {
		t.Fatal(err)
	}
	defer stopAndWait(t, receive)

	select {
	case endpoint := <-cb.ready:
		t.Fatalf("receiver became ready with the wrong key at %s", endpoint)
	case <-time.After(4 * time.Second):
	}
	if !strings.Contains(cb.log(), "PSK identity mismatch") {
		t.Fatalf("expected a PSK mismatch, log:\n%s", cb.log())
	}
}

func TestFindListeningEndpoint(t *testing.T) {
	cases := map[string]string{
		"20261122 [gonc] Listening tcp on 127.0.0.1:47123": "127.0.0.1:47123",
		"[gonc] Listening tcp on [::1]:80 extra":           "[::1]:80",
		"[gonc] Listening tcp on nonsense":                 "",
		"[gonc] Connected from: 127.0.0.1:5000":            "",
	}
	for in, want := range cases {
		if got := findListeningEndpoint(in); got != want {
			t.Errorf("findListeningEndpoint(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDirectSessionValidation(t *testing.T) {
	source, err := httpfileshare.NewOSFileSource([]string{t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		addr string
		key  string
	}{
		{"empty key", "127.0.0.1:1234", " "},
		{"generate marker", "127.0.0.1:1234", "."},
		{"file marker", "127.0.0.1:1234", "@key.txt"},
		{"missing port", "127.0.0.1", "nb1-key0123456789"},
		{"zero port", "127.0.0.1:0", "nb1-key0123456789"},
		{"missing host", ":1234", "nb1-key0123456789"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if s, err := StartDirectShareSource(source, tc.addr, tc.key, nil); err == nil {
				stopAndWait(t, s)
				t.Fatal("StartDirectShareSource accepted invalid input")
			}
			if s, err := StartDirectReceive(tc.addr, tc.key, nil); err == nil {
				stopAndWait(t, s)
				t.Fatal("StartDirectReceive accepted invalid input")
			}
		})
	}
}

// Back-to-back receives in one process must not wait for the previous
// session's loopback port to be released.
func TestDirectReceiveTwiceIsImmediate(t *testing.T) {
	const key = "nb1-backtobackkey0123456789"
	addr, _ := startDirectShareForTest(t, key)
	for i := 0; i < 2; i++ {
		cb := newDirectTestCallback()
		start := time.Now()
		receive, err := StartDirectReceive(addr, key, cb)
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-cb.ready:
		case <-time.After(15 * time.Second):
			t.Fatalf("receive %d never became ready:\n%s", i, cb.log())
		}
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Fatalf("receive %d took %v to become ready", i, elapsed)
		}
		receive.Stop() // deliberately not waiting for it to finish
	}
}
