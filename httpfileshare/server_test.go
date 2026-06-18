package httpfileshare

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type testFileInfo struct {
	name string
	size int64
}

func (i testFileInfo) Name() string       { return i.name }
func (i testFileInfo) Size() int64        { return i.size }
func (i testFileInfo) Mode() fs.FileMode  { return 0644 }
func (i testFileInfo) ModTime() time.Time { return time.Unix(1700000000, 0) }
func (i testFileInfo) IsDir() bool        { return false }
func (i testFileInfo) Sys() any           { return nil }

type testSeekableFile struct {
	*strings.Reader
	info fs.FileInfo
}

func (f *testSeekableFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *testSeekableFile) Close() error               { return nil }

type testStreamingFile struct {
	reader io.Reader
	info   fs.FileInfo
}

func (f *testStreamingFile) Read(p []byte) (int, error) { return f.reader.Read(p) }
func (f *testStreamingFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *testStreamingFile) Close() error               { return nil }

type testBrokenSeekFile struct {
	reader io.Reader
	info   fs.FileInfo
}

func (f *testBrokenSeekFile) Read(p []byte) (int, error) { return f.reader.Read(p) }
func (f *testBrokenSeekFile) Seek(int64, int) (int64, error) {
	return 0, errors.New("seek unavailable")
}
func (f *testBrokenSeekFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *testBrokenSeekFile) Close() error               { return nil }

func TestHandleFileDownloadReadSeekerSupportsRange(t *testing.T) {
	body := "0123456789"
	stat := testFileInfo{name: "data.bin", size: int64(len(body))}
	file := &testSeekableFile{Reader: strings.NewReader(body), info: stat}
	req := httptest.NewRequest(http.MethodGet, "/data.bin", nil)
	req.Header.Set("Range", "bytes=3-")
	rr := httptest.NewRecorder()

	server := &Server{config: ServerConfig{WebMode: true}, logger: log.New(io.Discard, "", 0)}
	server.handleFileDownload(rr, req, file, stat)

	resp := rr.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusPartialContent)
	}
	got := rr.Body.String()
	if got != "3456789" {
		t.Fatalf("body = %q, want %q", got, "3456789")
	}
	if got := resp.Header.Get("Content-Range"); got != "bytes 3-9/10" {
		t.Fatalf("Content-Range = %q, want %q", got, "bytes 3-9/10")
	}
}

func TestHandleFileDownloadNonSeekableIgnoresRange(t *testing.T) {
	body := []byte("0123456789")
	stat := testFileInfo{name: "stream.bin", size: int64(len(body))}
	file := &testStreamingFile{reader: bytes.NewReader(body), info: stat}
	req := httptest.NewRequest(http.MethodGet, "/stream.bin", nil)
	req.Header.Set("Range", "bytes=3-")
	rr := httptest.NewRecorder()

	server := &Server{config: ServerConfig{WebMode: true}, logger: log.New(io.Discard, "", 0)}
	server.handleFileDownload(rr, req, file, stat)

	resp := rr.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := rr.Body.String(); got != string(body) {
		t.Fatalf("body = %q, want %q", got, string(body))
	}
	if got := resp.Header.Get("Accept-Ranges"); got != "none" {
		t.Fatalf("Accept-Ranges = %q, want %q", got, "none")
	}
	if got := resp.Header.Get("Content-Length"); got != "10" {
		t.Fatalf("Content-Length = %q, want %q", got, "10")
	}
}

func TestHandleFileDownloadBrokenReadSeekerFallsBackToStreaming(t *testing.T) {
	body := []byte("abcdef")
	stat := testFileInfo{name: "broken.bin", size: int64(len(body))}
	file := &testBrokenSeekFile{reader: bytes.NewReader(body), info: stat}
	req := httptest.NewRequest(http.MethodGet, "/broken.bin", nil)
	rr := httptest.NewRecorder()

	server := &Server{config: ServerConfig{WebMode: true}, logger: log.New(io.Discard, "", 0)}
	server.handleFileDownload(rr, req, file, stat)

	resp := rr.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := rr.Body.String(); got != string(body) {
		t.Fatalf("body = %q, want %q", got, string(body))
	}
}
