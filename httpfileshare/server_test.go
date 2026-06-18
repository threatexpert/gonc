package httpfileshare

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
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

type testFileSource struct {
	files map[string]string
}

func (s *testFileSource) Description() string { return "test file source" }

func (s *testFileSource) Stat(name string) (fs.FileInfo, error) {
	name = path.Clean(name)
	if name == "/" {
		return sourceDirInfo{name: "/", modTime: time.Unix(1700000000, 0)}, nil
	}
	body, ok := s.files[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return testFileInfo{name: path.Base(name), size: int64(len(body))}, nil
}

func (s *testFileSource) Open(name string) (fs.File, error) {
	name = path.Clean(name)
	body, ok := s.files[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return &testSeekableFile{Reader: strings.NewReader(body), info: testFileInfo{name: path.Base(name), size: int64(len(body))}}, nil
}

func (s *testFileSource) ReadDir(name string) ([]fs.FileInfo, error) {
	name = path.Clean(name)
	if name != "/" {
		return nil, fs.ErrNotExist
	}
	var entries []fs.FileInfo
	for filePath, body := range s.files {
		entries = append(entries, testFileInfo{name: strings.TrimPrefix(filePath, "/"), size: int64(len(body))})
	}
	return entries, nil
}

func (s *testFileSource) Walk(name string, fn func(sourcePath string, info fs.FileInfo, err error) error) error {
	name = path.Clean(name)
	if name == "/" {
		if err := fn("/", sourceDirInfo{name: "/", modTime: time.Unix(1700000000, 0)}, nil); err != nil {
			return err
		}
		for filePath, body := range s.files {
			if err := fn(filePath, testFileInfo{name: path.Base(filePath), size: int64(len(body))}, nil); err != nil {
				return err
			}
		}
		return nil
	}
	info, err := s.Stat(name)
	if err != nil {
		return err
	}
	return fn(name, info, nil)
}

func TestServerUsesConfiguredFileSource(t *testing.T) {
	source := &testFileSource{files: map[string]string{"/hello.txt": "hello from source"}}
	server, err := NewServer(ServerConfig{FileSource: source, LoggerOutput: io.Discard})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/hello.txt", nil)
	rr := httptest.NewRecorder()
	server.serveFilesFromSource(rr, req)

	resp := rr.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := rr.Body.String(); got != "hello from source" {
		t.Fatalf("body = %q, want %q", got, "hello from source")
	}
}

func TestConfiguredFileSourceRecursiveList(t *testing.T) {
	source := &testFileSource{files: map[string]string{"/hello.txt": "hello"}}
	server, err := NewServer(ServerConfig{FileSource: source, LoggerOutput: io.Discard})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	server.serveFilesFromSource(rr, req)

	resp := rr.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := rr.Body.String(); !strings.Contains(got, `"path":"/hello.txt"`) {
		t.Fatalf("recursive list = %q, want /hello.txt entry", got)
	}
}

func TestSingleFileRootServesVirtualDirectory(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(filePath, []byte("hello from disk"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	server, err := NewServer(ServerConfig{RootPaths: []string{filePath}, LoggerOutput: io.Discard})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	rootReq := httptest.NewRequest(http.MethodGet, "/", nil)
	rootRR := httptest.NewRecorder()
	server.serveFilesFromSource(rootRR, rootReq)
	rootResp := rootRR.Result()
	defer rootResp.Body.Close()
	if rootResp.StatusCode != http.StatusOK {
		t.Fatalf("root status = %d, want %d", rootResp.StatusCode, http.StatusOK)
	}
	rootBody := rootRR.Body.String()
	if strings.Contains(rootBody, "hello from disk") {
		t.Fatalf("root response downloaded file body, want directory listing")
	}
	if !strings.Contains(rootBody, "hello.txt") {
		t.Fatalf("root response = %q, want directory listing with hello.txt", rootBody)
	}

	fileReq := httptest.NewRequest(http.MethodGet, "/hello.txt", nil)
	fileRR := httptest.NewRecorder()
	server.serveFilesFromSource(fileRR, fileReq)
	fileResp := fileRR.Result()
	defer fileResp.Body.Close()
	if fileResp.StatusCode != http.StatusOK {
		t.Fatalf("file status = %d, want %d", fileResp.StatusCode, http.StatusOK)
	}
	if got := fileRR.Body.String(); got != "hello from disk" {
		t.Fatalf("file body = %q, want %q", got, "hello from disk")
	}
}

func TestSingleFileRootRecursiveListUsesFileNamePath(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(filePath, []byte("hello from disk"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	server, err := NewServer(ServerConfig{RootPaths: []string{filePath}, LoggerOutput: io.Discard})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	server.serveFilesFromSource(rr, req)

	resp := rr.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body := rr.Body.String()
	if strings.Contains(body, `"path":"/","`) && strings.Count(body, `"path":"/"`) > 1 {
		t.Fatalf("recursive list = %q, root path repeated unexpectedly", body)
	}
	if !strings.Contains(body, `"path":"/hello.txt"`) {
		t.Fatalf("recursive list = %q, want /hello.txt entry", body)
	}
}
