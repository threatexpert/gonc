package httpfileshare

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDownloadFileOldServerManifestUnsupportedRedownloadsFullFile(t *testing.T) {
	const remoteBody = "0123456789"
	const localPartial = "0123"
	remoteModTime := time.Unix(1700001000, 0)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("manifest") == blake3ManifestAlgo {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Range") != "" {
			t.Fatalf("unexpected Range request after manifest fallback")
		}
		_, _ = io.WriteString(w, remoteBody)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "data.bin")
	if err := os.WriteFile(localPath, []byte(localPartial), 0644); err != nil {
		t.Fatal(err)
	}

	client, err := newTestClient(server.URL, tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	client.progressTracker.AddTotalBytes(int64(len(remoteBody)))

	err = client.downloadFile(context.Background(), server.Client(), FileInfo{
		Name:    "data.bin",
		Path:    "/data.bin",
		Size:    int64(len(remoteBody)),
		ModTime: remoteModTime,
	})
	if err != nil {
		t.Fatal(err)
	}

	gotProgress := client.progressTracker.bytesDownloaded.Load()
	if gotProgress != int64(len(remoteBody)) {
		t.Fatalf("bytesDownloaded = %d, want %d", gotProgress, len(remoteBody))
	}
	gotBody, err := os.ReadFile(localPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotBody) != remoteBody {
		t.Fatalf("local body = %q, want %q", gotBody, remoteBody)
	}
}

func TestDownloadFileInitialFullDownloadDoesNotLogPerFileInfo(t *testing.T) {
	const remoteBody = "0123456789"
	remoteModTime := time.Unix(1700001500, 0)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, remoteBody)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	var logs bytes.Buffer
	client, err := NewClient(ClientConfig{
		ServerURL:              server.URL,
		LocalDir:               tmpDir,
		Concurrency:            1,
		Resume:                 true,
		NoCompress:             true,
		LogLevel:               LogLevelRepair,
		LoggerOutput:           &logs,
		ProgressOutput:         io.Discard,
		ProgressUpdateInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	client.progressTracker.AddTotalBytes(int64(len(remoteBody)))

	err = client.downloadFile(context.Background(), server.Client(), FileInfo{
		Name:    "data.bin",
		Path:    "/data.bin",
		Size:    int64(len(remoteBody)),
		ModTime: remoteModTime,
	})
	if err != nil {
		t.Fatal(err)
	}

	gotLogs := logs.String()
	if bytes.Contains([]byte(gotLogs), []byte("Downloaded")) || bytes.Contains([]byte(gotLogs), []byte("Full download completed")) {
		t.Fatalf("logs = %q, want no per-file full download info", gotLogs)
	}
}

func TestDownloadFileBlake3RepairAppendsMissingTail(t *testing.T) {
	remoteModTime := time.Unix(1700002000, 123)
	remoteBody := testBytes(20 * 1024 * 1024)
	localBody := remoteBody[:16*1024*1024]

	server, fileInfo, rangeRequests := newTestHTTPFileServer(t, remoteBody, remoteModTime)
	defer server.Close()

	localDir := t.TempDir()
	localPath := filepath.Join(localDir, "data.bin")
	if err := os.WriteFile(localPath, localBody, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(localPath, time.Now(), remoteModTime.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	client, err := newTestClient(server.URL, localDir)
	if err != nil {
		t.Fatal(err)
	}
	client.progressTracker.AddTotalBytes(fileInfo.Size)

	if err := client.downloadFile(context.Background(), server.Client(), fileInfo); err != nil {
		t.Fatal(err)
	}

	assertFileBody(t, localPath, remoteBody)
	if got := client.progressTracker.bytesDownloaded.Load(); got != fileInfo.Size {
		t.Fatalf("bytesDownloaded = %d, want %d", got, fileInfo.Size)
	}
	if got := rangeRequests.Load(); got == 0 {
		t.Fatal("expected at least one range request for repair")
	}
}

func TestDownloadFileBlake3RepairTailResumeBypassesLargeTransferThreshold(t *testing.T) {
	remoteModTime := time.Unix(1700002500, 0)
	remoteBody := testBytes(20 * 1024 * 1024)
	localBody := remoteBody[:10*1024*1024]

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "data.bin")
	if err := os.WriteFile(filePath, remoteBody, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filePath, time.Now(), remoteModTime); err != nil {
		t.Fatal(err)
	}
	fileServer, err := NewServer(ServerConfig{RootPaths: []string{tmpDir}, LoggerOutput: io.Discard})
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var rangeHeaders []string
	var manifestLimitSizes []string
	var fullDownloads int
	var client *Client
	progressAtFirstRange := int64(-1)
	speedBytesAtFirstRange := int64(-1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if r.URL.Query().Get("manifest") == blake3ManifestAlgo {
			manifestLimitSizes = append(manifestLimitSizes, r.URL.Query().Get("limit_size"))
		} else if rangeHeader := r.Header.Get("Range"); rangeHeader != "" {
			if len(rangeHeaders) == 0 && client != nil {
				progressAtFirstRange = client.progressTracker.bytesDownloaded.Load()
				speedBytesAtFirstRange = client.progressTracker.bytesDownloadedLastInterval.Load()
			}
			rangeHeaders = append(rangeHeaders, rangeHeader)
		} else {
			fullDownloads++
		}
		mu.Unlock()
		fileServer.serveFilesFromSource(w, r)
	}))
	defer server.Close()

	localDir := t.TempDir()
	localPath := filepath.Join(localDir, "data.bin")
	if err := os.WriteFile(localPath, localBody, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(localPath, time.Now(), remoteModTime.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	client, err = newTestClient(server.URL, localDir)
	if err != nil {
		t.Fatal(err)
	}
	fileInfo := FileInfo{Name: "data.bin", Path: "/data.bin", Size: int64(len(remoteBody)), ModTime: remoteModTime}
	client.progressTracker.AddTotalBytes(fileInfo.Size)

	if err := client.downloadFile(context.Background(), server.Client(), fileInfo); err != nil {
		t.Fatal(err)
	}

	assertFileBody(t, localPath, remoteBody)
	mu.Lock()
	defer mu.Unlock()
	if len(manifestLimitSizes) == 0 || manifestLimitSizes[0] != fmt.Sprintf("%d", len(localBody)) {
		t.Fatalf("manifest limit sizes = %v, want first %d", manifestLimitSizes, len(localBody))
	}
	if len(rangeHeaders) != 1 {
		t.Fatalf("range headers = %v, want one tail-resume range", rangeHeaders)
	}
	wantRange := fmt.Sprintf("bytes=%d-%d", 8*1024*1024, len(remoteBody)-1)
	if rangeHeaders[0] != wantRange {
		t.Fatalf("range = %q, want %q", rangeHeaders[0], wantRange)
	}
	if progressAtFirstRange != 8*1024*1024 {
		t.Fatalf("progressAtFirstRange = %d, want retained block size %d", progressAtFirstRange, 8*1024*1024)
	}
	if speedBytesAtFirstRange != 0 {
		t.Fatalf("speedBytesAtFirstRange = %d, want 0", speedBytesAtFirstRange)
	}
	if fullDownloads != 0 {
		t.Fatalf("fullDownloads = %d, want 0", fullDownloads)
	}
}

func TestDownloadFileBlake3RepairTruncatesRemoteShorterFile(t *testing.T) {
	remoteModTime := time.Unix(1700003000, 0)
	localBody := testBytes(20 * 1024 * 1024)
	remoteBody := localBody[:16*1024*1024]

	server, fileInfo, rangeRequests := newTestHTTPFileServer(t, remoteBody, remoteModTime)
	defer server.Close()

	localDir := t.TempDir()
	localPath := filepath.Join(localDir, "data.bin")
	if err := os.WriteFile(localPath, localBody, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(localPath, time.Now(), remoteModTime.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	client, err := newTestClient(server.URL, localDir)
	if err != nil {
		t.Fatal(err)
	}
	client.progressTracker.AddTotalBytes(fileInfo.Size)

	if err := client.downloadFile(context.Background(), server.Client(), fileInfo); err != nil {
		t.Fatal(err)
	}

	assertFileBody(t, localPath, remoteBody)
	if got := client.progressTracker.bytesDownloaded.Load(); got != fileInfo.Size {
		t.Fatalf("bytesDownloaded = %d, want %d", got, fileInfo.Size)
	}
	if got := rangeRequests.Load(); got != 0 {
		t.Fatalf("rangeRequests = %d, want 0", got)
	}
}

func TestDownloadFileBlake3RepairOverwritesDirtyBlock(t *testing.T) {
	remoteModTime := time.Unix(1700004000, 0)
	remoteBody := testBytes(24 * 1024 * 1024)
	localBody := bytes.Clone(remoteBody)
	for i := 8 * 1024 * 1024; i < 16*1024*1024; i++ {
		localBody[i] ^= 0xff
	}

	server, fileInfo, rangeRequests := newTestHTTPFileServer(t, remoteBody, remoteModTime)
	defer server.Close()

	localDir := t.TempDir()
	localPath := filepath.Join(localDir, "data.bin")
	if err := os.WriteFile(localPath, localBody, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(localPath, time.Now(), remoteModTime.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	client, err := newTestClient(server.URL, localDir)
	if err != nil {
		t.Fatal(err)
	}
	client.progressTracker.AddTotalBytes(fileInfo.Size)

	if err := client.downloadFile(context.Background(), server.Client(), fileInfo); err != nil {
		t.Fatal(err)
	}

	assertFileBody(t, localPath, remoteBody)
	if got := client.progressTracker.bytesDownloaded.Load(); got != fileInfo.Size {
		t.Fatalf("bytesDownloaded = %d, want %d", got, fileInfo.Size)
	}
	if got := rangeRequests.Load(); got != 1 {
		t.Fatalf("rangeRequests = %d, want 1", got)
	}
}

func TestDownloadFileBlake3RepairSupportsCompressedManifestAndRange(t *testing.T) {
	remoteModTime := time.Unix(1700004500, 0)
	remoteBody := testBytes(20 * 1024 * 1024)
	localBody := remoteBody[:16*1024*1024]

	server, fileInfo, rangeRequests := newTestHTTPFileServerWithZstd(t, remoteBody, remoteModTime)
	defer server.Close()

	localDir := t.TempDir()
	localPath := filepath.Join(localDir, "data.bin")
	if err := os.WriteFile(localPath, localBody, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(localPath, time.Now(), remoteModTime.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	client, err := NewClient(ClientConfig{
		ServerURL:              server.URL,
		LocalDir:               localDir,
		Concurrency:            1,
		Resume:                 true,
		ProgressOutput:         io.Discard,
		ProgressUpdateInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	client.progressTracker.AddTotalBytes(fileInfo.Size)

	if err := client.downloadFile(context.Background(), server.Client(), fileInfo); err != nil {
		t.Fatal(err)
	}

	assertFileBody(t, localPath, remoteBody)
	if got := rangeRequests.Load(); got == 0 {
		t.Fatal("expected at least one compressed range request for repair")
	}
}

func TestDownloadRangeSupportsGzipEncodedBody(t *testing.T) {
	const rangeBody = "repair-data"
	var sawCompressedRange atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "bytes=4-14" {
			t.Fatalf("Range = %q, want %q", r.Header.Get("Range"), "bytes=4-14")
		}
		if r.Header.Get("Accept-Encoding") != "" {
			sawCompressedRange.Store(true)
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusPartialContent)
		gw := gzip.NewWriter(w)
		_, _ = io.WriteString(gw, rangeBody)
		_ = gw.Close()
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "data.bin")
	if err := os.WriteFile(localPath, []byte("00000000000000000000"), 0644); err != nil {
		t.Fatal(err)
	}
	outFile, err := os.OpenFile(localPath, os.O_RDWR, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer outFile.Close()

	client, err := newTestClient(server.URL, tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	client.config.NoCompress = false
	if err := client.downloadRange(context.Background(), server.Client(), server.URL+"/data.bin", outFile, repairRange{Offset: 4, Size: int64(len(rangeBody))}); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(localPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "0000"+rangeBody+"00000" {
		t.Fatalf("local body = %q", got)
	}
	if !sawCompressedRange.Load() {
		t.Fatal("expected compressed range request")
	}
}

func TestDownloadFileBlake3RepairLogsPlanAndCompletion(t *testing.T) {
	remoteModTime := time.Unix(1700006000, 0)
	remoteBody := testBytes(20 * 1024 * 1024)
	localBody := remoteBody[:16*1024*1024]

	server, fileInfo, _ := newTestHTTPFileServer(t, remoteBody, remoteModTime)
	defer server.Close()

	localDir := t.TempDir()
	localPath := filepath.Join(localDir, "data.bin")
	if err := os.WriteFile(localPath, localBody, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(localPath, time.Now(), remoteModTime.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	client, err := NewClient(ClientConfig{
		ServerURL:              server.URL,
		LocalDir:               localDir,
		Concurrency:            1,
		Resume:                 true,
		NoCompress:             true,
		LogLevel:               LogLevelRepair,
		LoggerOutput:           &logs,
		ProgressOutput:         io.Discard,
		ProgressUpdateInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	client.progressTracker.AddTotalBytes(fileInfo.Size)

	if err := client.downloadFile(context.Background(), server.Client(), fileInfo); err != nil {
		t.Fatal(err)
	}

	gotLogs := logs.String()
	if !bytes.Contains([]byte(gotLogs), []byte("Repair plan")) {
		t.Fatalf("logs = %q, want repair plan", gotLogs)
	}
	if !bytes.Contains([]byte(gotLogs), []byte("Repair completed")) {
		t.Fatalf("logs = %q, want repair completion", gotLogs)
	}
}

func TestLogLevelRepairDoesNotLogGeneralInfo(t *testing.T) {
	var logs bytes.Buffer
	client, err := NewClient(ClientConfig{
		ServerURL:              "http://127.0.0.1/",
		LocalDir:               t.TempDir(),
		Concurrency:            1,
		LogLevel:               LogLevelRepair,
		LoggerOutput:           &logs,
		ProgressOutput:         io.Discard,
		ProgressUpdateInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	client.logInfo("general info")
	client.logRepair("repair info")

	gotLogs := logs.String()
	if bytes.Contains([]byte(gotLogs), []byte("general info")) {
		t.Fatalf("logs = %q, want no general info at repair level", gotLogs)
	}
	if !bytes.Contains([]byte(gotLogs), []byte("repair info")) {
		t.Fatalf("logs = %q, want repair info", gotLogs)
	}
}

func newTestClient(serverURL, localDir string) (*Client, error) {
	return NewClient(ClientConfig{
		ServerURL:              serverURL,
		LocalDir:               localDir,
		Concurrency:            1,
		Resume:                 true,
		NoCompress:             true,
		ProgressOutput:         io.Discard,
		ProgressUpdateInterval: time.Hour,
	})
}

func newTestHTTPFileServer(t *testing.T, body []byte, modTime time.Time) (*httptest.Server, FileInfo, *atomic.Int64) {
	t.Helper()

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "data.bin")
	if err := os.WriteFile(filePath, body, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filePath, time.Now(), modTime); err != nil {
		t.Fatal(err)
	}

	fileServer, err := NewServer(ServerConfig{RootPaths: []string{tmpDir}, LoggerOutput: io.Discard})
	if err != nil {
		t.Fatal(err)
	}

	var rangeRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "" {
			rangeRequests.Add(1)
		}
		fileServer.serveFilesFromSource(w, r)
	}))

	return server, FileInfo{
		Name:    "data.bin",
		Path:    "/data.bin",
		Size:    int64(len(body)),
		ModTime: modTime,
	}, &rangeRequests
}

func newTestHTTPFileServerWithZstd(t *testing.T, body []byte, modTime time.Time) (*httptest.Server, FileInfo, *atomic.Int64) {
	t.Helper()

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "data.bin")
	if err := os.WriteFile(filePath, body, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filePath, time.Now(), modTime); err != nil {
		t.Fatal(err)
	}

	fileServer, err := NewServer(ServerConfig{RootPaths: []string{tmpDir}, LoggerOutput: io.Discard, EnableZstd: true})
	if err != nil {
		t.Fatal(err)
	}
	handler := fileServer.zstdMiddleware(http.HandlerFunc(fileServer.serveFilesFromSource))

	var rangeRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "" {
			rangeRequests.Add(1)
		}
		handler.ServeHTTP(w, r)
	}))

	return server, FileInfo{
		Name:    "data.bin",
		Path:    "/data.bin",
		Size:    int64(len(body)),
		ModTime: modTime,
	}, &rangeRequests
}

func testBytes(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i*131 + i/7)
	}
	return data
}

func assertFileBody(t *testing.T, path string, want []byte) {
	t.Helper()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("local body mismatch: got %d bytes, want %d bytes", len(got), len(want))
	}
}
