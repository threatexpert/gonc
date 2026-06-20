package httpfileshare

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDownloadFileRangeFallbackDoesNotDoubleCountResumeBytes(t *testing.T) {
	const remoteBody = "0123456789"
	const localPartial = "0123"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") == "" {
			t.Fatalf("expected Range request")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, remoteBody)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "data.bin")
	if err := os.WriteFile(localPath, []byte(localPartial), 0644); err != nil {
		t.Fatal(err)
	}

	client, err := NewClient(ClientConfig{
		ServerURL:              server.URL,
		LocalDir:               tmpDir,
		Concurrency:            1,
		Resume:                 true,
		NoCompress:             true,
		ProgressOutput:         io.Discard,
		ProgressUpdateInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	client.progressTracker.AddTotalBytes(int64(len(remoteBody)))

	err = client.downloadFile(context.Background(), server.Client(), FileInfo{
		Name: "data.bin",
		Path: "/data.bin",
		Size: int64(len(remoteBody)),
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

func TestDownloadFileRangeFallbackTruncatesExistingFile(t *testing.T) {
	const serverBody = "01234"
	const localPartial = "01234567"
	const remoteSize = 10

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") == "" {
			t.Fatalf("expected Range request")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, serverBody)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "data.bin")
	if err := os.WriteFile(localPath, []byte(localPartial), 0644); err != nil {
		t.Fatal(err)
	}

	client, err := NewClient(ClientConfig{
		ServerURL:              server.URL,
		LocalDir:               tmpDir,
		Concurrency:            1,
		Resume:                 true,
		NoCompress:             true,
		ProgressOutput:         io.Discard,
		ProgressUpdateInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	client.progressTracker.AddTotalBytes(remoteSize)

	err = client.downloadFile(context.Background(), server.Client(), FileInfo{
		Name: "data.bin",
		Path: "/data.bin",
		Size: remoteSize,
	})
	if err == nil {
		t.Fatal("expected incomplete download error")
	}

	gotBody, readErr := os.ReadFile(localPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(gotBody) != serverBody {
		t.Fatalf("local body = %q, want %q", gotBody, serverBody)
	}
}
