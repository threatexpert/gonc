package httpfileshare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type interruptedWalkSource struct {
	FileSource
	failNext atomic.Bool
}

// Fail the write of the second block, after the header and first block have
// reached the client. Preserve Flusher so this exercises actual HTTP framing.
type interruptedManifestWriter struct {
	http.ResponseWriter
	writes int
}

func (w *interruptedManifestWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == 3 {
		return 0, io.ErrClosedPipe
	}
	return w.ResponseWriter.Write(p)
}

func (w *interruptedManifestWriter) Flush() {
	w.ResponseWriter.(http.Flusher).Flush()
}

type unreadableManifestSource struct {
	FileSource
	failRead atomic.Bool
}

func (s *unreadableManifestSource) Open(name string) (fs.File, error) {
	f, err := s.FileSource.Open(name)
	if err != nil || !s.failRead.Load() {
		return f, err
	}
	return unreadableManifestFile{File: f}, nil
}

type unreadableManifestFile struct{ fs.File }

func (unreadableManifestFile) Read([]byte) (int, error) { return 0, fs.ErrPermission }

func TestManifestStreamingAndFailureRecovery(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		name   string
		size   int64
		blocks int
	}{
		{"empty", 0, 0},
		{"small", 7, 1},
		{"multiple", defaultManifestBlockSize + 1, 2},
	}
	for _, tc := range cases {
		f, err := os.Create(filepath.Join(root, tc.name))
		if err != nil {
			t.Fatal(err)
		}
		err = f.Truncate(tc.size)
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			t.Fatalf("create fixture: %v, close: %v", err, closeErr)
		}
	}
	base, err := NewOSFileSource([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	source := &unreadableManifestSource{FileSource: base}
	server, err := NewServer(ServerConfig{FileSource: source})
	if err != nil {
		t.Fatal(err)
	}
	var failWrite atomic.Bool
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failWrite.Swap(false) {
			w = &interruptedManifestWriter{ResponseWriter: w}
		}
		server.serveFilesFromSource(w, r)
	}))
	defer httpServer.Close()
	client, err := newTestClient(httpServer.URL, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	fetch := func(name string) (*blake3Manifest, error) {
		return client.fetchBlake3Manifest(ctx, httpServer.Client(), httpServer.URL+"/"+name, 0)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manifest, err := fetch(tc.name)
			if err != nil {
				t.Fatal(err)
			}
			if manifest.Size != tc.size || len(manifest.Blocks) != tc.blocks {
				t.Fatalf("unexpected manifest: %+v", manifest)
			}
		})
	}

	source.failRead.Store(true)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpServer.URL+"/multiple?manifest=blake3", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := httpServer.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("hash read failure: got HTTP %d, want 500", resp.StatusCode)
	}
	source.failRead.Store(false)

	failWrite.Store(true)
	if _, err := fetch("multiple"); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("interrupted manifest should fail with unexpected EOF: %v", err)
	}
	manifest, err := fetch("multiple")
	if err != nil || manifest == nil || len(manifest.Blocks) != 2 {
		t.Fatalf("same server failed after interrupted manifest: manifest=%+v, error=%v", manifest, err)
	}
}

func (s *interruptedWalkSource) Walk(name string, fn func(string, fs.FileInfo, error) error) error {
	fail := s.failNext.Swap(false)
	return s.FileSource.Walk(name, func(name string, info fs.FileInfo, err error) error {
		if err := fn(name, info, err); err != nil {
			return err
		}
		if info != nil && info.Mode().IsRegular() {
			if err := fn("/unreadable", nil, fs.ErrPermission); err != nil {
				return err
			}
		}
		if fail && info != nil && info.Mode().IsRegular() {
			// Fail only after a complete file entry has been encoded and flushed.
			return io.ErrUnexpectedEOF
		}
		return nil
	})
}

func TestInterruptedListFailsClientAndServerKeepsServing(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.txt", "b.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name+" contents"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	base, err := NewOSFileSource([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	source := &interruptedWalkSource{FileSource: base}
	server, err := NewServer(ServerConfig{FileSource: source})
	if err != nil {
		t.Fatal(err)
	}
	// Use an actual HTTP server: ResponseRecorder does not recover handler panics
	// or model the incomplete chunked response seen by a network client.
	httpServer := httptest.NewServer(http.HandlerFunc(server.serveFilesFromSource))
	defer httpServer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	source.failNext.Store(true)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpServer.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := httpServer.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected a response already started with 200, got %d", resp.StatusCode)
	}
	decoder := json.NewDecoder(resp.Body)
	sawFile := false
	for {
		var file FileInfo
		err = decoder.Decode(&file)
		if err != nil {
			break
		}
		if file.Path == "/a.txt" {
			sawFile = true
		}
		if file.Path == "/b.txt" {
			t.Fatal("fault was not injected before the second file")
		}
	}
	if !sawFile || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("partial response: saw first file=%v, error=%v; want unexpected EOF", sawFile, err)
	}

	// Exercise the real receiving client as well, not only HTTP decoding.
	dest := t.TempDir()
	client, err := newTestClient(httpServer.URL, dest)
	if err != nil {
		t.Fatal(err)
	}
	source.failNext.Store(true)
	if err := client.Start(ctx); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("receiving client accepted a partial list or returned the wrong error: %v", err)
	}
	entries, err := os.ReadDir(dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("client started downloading from a partial list: %v", entries)
	}

	// Keep the same server running; a subsequent complete listing and both
	// content downloads must succeed after the two aborted responses.
	client, err = newTestClient(httpServer.URL, dest)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(ctx); err != nil {
		t.Fatalf("subsequent transfer failed: %v", err)
	}
	for _, name := range []string{"a.txt", "b.txt"} {
		body, err := os.ReadFile(filepath.Join(dest, name))
		if err != nil || string(body) != name+" contents" {
			t.Fatalf("subsequent download %s: content=%q, error=%v", name, body, err)
		}
	}
}

func TestReceiveSkipsBadEntriesAndConflictingSubtrees(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintln(w, "{bad json}")
		for _, name := range []string{"/duplicate", "/duplicate", "/duplicate/nested", "/file", "/file/nested", "/ok", "/a:b", `/a\b`} {
			json.NewEncoder(w).Encode(FileInfo{Path: name})
		}
	}))
	defer srv.Close()
	client, err := newTestClient(srv.URL, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	client.config.LogLevel = LogLevelError
	client.errorLogger.SetOutput(&logs)
	files, err := client.fetchFileList(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/ok"}
	if runtime.GOOS != "windows" {
		want = append(want, "/a:b", `/a\b`)
	}
	if len(files) != len(want) {
		t.Fatalf("planned entries: %v", files)
	}
	for i, name := range want {
		if files[i].Path != name {
			t.Fatalf("planned entries: %v", files)
		}
	}
	for _, reason := range []string{"invalid file list record", "duplicate list path", "non-directory parent"} {
		if !strings.Contains(logs.String(), reason) {
			t.Fatalf("missing %q in logs: %s", reason, logs.String())
		}
	}
	client.config.ServerURL = srv.URL + "/missing"
	if _, err := client.fetchFileList(context.Background()); err == nil {
		t.Fatal("missing requested root accepted")
	}
}
