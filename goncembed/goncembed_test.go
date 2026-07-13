package goncembed

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestFindLocalSOCKS5Endpoint(t *testing.T) {
	tests := []struct {
		name    string
		message string
		want    string
	}{
		{
			name:    "unspecified IPv4 maps to loopback",
			message: "20260626 [:mux] [link-x] Listening on 0.0.0.0:8888 (TProxy=true)",
			want:    "socks5://127.0.0.1:8888",
		},
		{
			name:    "specific IPv4 is preserved",
			message: "20260626 [:mux] [link-x] Listening on 192.168.1.10:8888 (TProxy=true)",
			want:    "socks5://192.168.1.10:8888",
		},
		{
			name:    "unspecified IPv6 maps to loopback",
			message: "20260626 [:mux] [link-x] Listening on [::]:8888 (TProxy=false)",
			want:    "socks5://[::1]:8888",
		},
		{
			name:    "unrelated log",
			message: "20260626 [:mux] [link] Local service started.",
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := findLocalSOCKS5Endpoint(tt.message); got != tt.want {
				t.Fatalf("findLocalSOCKS5Endpoint() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTunnelReadyWaitsForLocalServiceStarted(t *testing.T) {
	cb := &recordingCallback{}
	writer := &callbackWriter{cb: cb, side: "tunnel"}

	if _, err := writer.Write([]byte("[link-x] Listening on 0.0.0.0:8888 (TProxy=true)")); err != nil {
		t.Fatal(err)
	}
	if cb.ready != "" {
		t.Fatalf("Ready called before local service started: %q", cb.ready)
	}

	if _, err := writer.Write([]byte("[link] Local service started.")); err != nil {
		t.Fatal(err)
	}
	if cb.ready != "socks5://127.0.0.1:8888" {
		t.Fatalf("Ready endpoint = %q, want socks5://127.0.0.1:8888", cb.ready)
	}
}

func TestTunnelReadyCanFireAfterReconnect(t *testing.T) {
	cb := &recordingCallback{}
	writer := &callbackWriter{cb: cb, side: "tunnel"}

	if _, err := writer.Write([]byte("[link-x] Listening on 127.0.0.1:8888 (TProxy=false)")); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("[link] Local service started.")); err != nil {
		t.Fatal(err)
	}
	if cb.readyCount != 1 || cb.ready != "socks5://127.0.0.1:8888" {
		t.Fatalf("first Ready count=%d endpoint=%q", cb.readyCount, cb.ready)
	}

	if _, err := writer.Write([]byte("[link] Local service started.")); err != nil {
		t.Fatal(err)
	}
	if cb.readyCount != 1 {
		t.Fatalf("duplicate Local service started fired Ready count=%d, want 1", cb.readyCount)
	}

	if _, err := writer.Write([]byte("[link-x] Listening on 127.0.0.1:9999 (TProxy=false)")); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("[link] Local service started.")); err != nil {
		t.Fatal(err)
	}
	if cb.readyCount != 2 || cb.ready != "socks5://127.0.0.1:9999" {
		t.Fatalf("second Ready count=%d endpoint=%q", cb.readyCount, cb.ready)
	}
}

func TestStartP2PTunnelReturnsPrepareError(t *testing.T) {
	cb := &recordingCallback{}
	missing := filepath.Join(t.TempDir(), "missing")

	session, err := StartP2PTunnel("A9f#K2m!Q7x@L4v$R8p%T6z", false, "1080", "-stunsrv @"+missing, cb)
	if err == nil {
		t.Fatal("StartP2PTunnel returned nil error")
	}
	if session != nil {
		t.Fatal("StartP2PTunnel returned a session after prepare failure")
	}
	if !strings.Contains(err.Error(), "stun server file") {
		t.Fatalf("error = %q, want stun server file", err.Error())
	}
	if cb.errorMessage == "" {
		t.Fatal("callback Error was not called")
	}
}

type recordingCallback struct {
	ready        string
	readyCount   int
	errorMessage string
}

func (c *recordingCallback) Event(level string, message string) {
}

func (c *recordingCallback) P2PReport(topic string, side string, status string, network string, mode string, peer string, timestamp int64, pid int) {
}

func (c *recordingCallback) Ready(endpoint string) {
	c.ready = endpoint
	c.readyCount++
}

func (c *recordingCallback) Stopped(exitCode int) {
}

func (c *recordingCallback) Error(message string) {
	c.errorMessage = message
}
