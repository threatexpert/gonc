package goncembed

import "testing"

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

type recordingCallback struct {
	ready string
}

func (c *recordingCallback) Event(level string, message string) {
}

func (c *recordingCallback) P2PReport(topic string, side string, status string, network string, mode string, peer string, timestamp int64, pid int) {
}

func (c *recordingCallback) Ready(endpoint string) {
	c.ready = endpoint
}

func (c *recordingCallback) Stopped(exitCode int) {
}

func (c *recordingCallback) Error(message string) {
}
