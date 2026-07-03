package httpfileshare

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
