package apps

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type brokenShellUpload struct{}

func (brokenShellUpload) Read([]byte) (int, error) { return 0, errors.New("connection interrupted") }

func TestShellFileUploadFailureIsAtomic(t *testing.T) {
	for _, kind := range []string{"interrupted", "checksum", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "existing.txt")
			if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			var body io.Reader = strings.NewReader("replacement")
			if kind == "interrupted" {
				body = io.MultiReader(body, brokenShellUpload{})
			}
			r := httptest.NewRequest(http.MethodPut, testFileURL("http://shell/v1/", path)+"&overwrite=1", body)
			if kind == "checksum" {
				r.Header.Set("X-Content-SHA256", strings.Repeat("0", 64))
			}
			if kind == "canceled" {
				ctx, cancel := context.WithCancel(r.Context())
				cancel()
				r = r.WithContext(ctx)
			}
			w := httptest.NewRecorder()
			shellFileHandler(nil).ServeHTTP(w, r)
			if kind != "canceled" && w.Code < 400 {
				t.Fatalf("failure returned success: %d", w.Code)
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != "original" {
				t.Fatalf("destination corrupted: %q %v", data, err)
			}
			files, err := os.ReadDir(dir)
			if err != nil || len(files) != 1 {
				t.Fatalf("temporary files leaked: %v %v", files, err)
			}
		})
	}
}

func TestShellFileHTTPValidationAndRange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.txt")
	os.WriteFile(path, []byte("0123456789"), 0600)
	h := shellFileHandler(nil)
	for _, tc := range []struct {
		method, path, suffix string
		status               int
	}{
		{http.MethodGet, "relative.txt", "", 400},
		{http.MethodGet, filepath.Join(dir, "missing"), "", 404},
		{http.MethodGet, dir, "", 400},
		{http.MethodPut, path, "&overwrite=maybe", 400},
		{http.MethodPut, dir, "&overwrite=1", 400},
		{http.MethodDelete, path, "", 405},
	} {
		r := httptest.NewRequest(tc.method, testFileURL("http://shell/v1/", tc.path)+tc.suffix, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Errorf("%s %s: %d %s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
	r := httptest.NewRequest(http.MethodGet, testFileURL("http://shell/v1/", path), nil)
	r.Header.Set("Range", "bytes=2-5")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 206 || w.Body.String() != "2345" {
		t.Fatalf("range: %d %s", w.Code, w.Body.String())
	}
}

func TestShellFileRecordsMetadataOnly(t *testing.T) {
	var log bytes.Buffer
	recorder := testShellRecorder(&log, 128)
	go recorder.run()
	path := filepath.Join(t.TempDir(), "upload.txt")
	r := httptest.NewRequest(http.MethodPut, testFileURL("http://shell/v1/", path), strings.NewReader("file-content-not-for-shell-log"))
	w := httptest.NewRecorder()
	shellFileHandler(recorder).ServeHTTP(w, r)
	recorder.close("done")
	// A canceled HTTP handler can finish after the shell recording closes.
	recorder.add("FILE", []byte("late handler completion"))
	if w.Code != 201 || !strings.Contains(log.String(), "FILE") || strings.Contains(log.String(), "file-content-not-for-shell-log") {
		t.Fatalf("unexpected file log: status=%d log=%s", w.Code, log.String())
	}
}
