package apps

import (
	"context"
	"io"
	"log"
	"testing"
)

func TestShouldRetryPersistentDial(t *testing.T) {
	tests := []struct {
		name   string
		config *AppNetcatConfig
		want   bool
	}{
		{
			name: "link",
			config: &AppNetcatConfig{
				keepOpen:       true,
				app_mux_Config: &AppMuxConfig{AppMode: "link"},
			},
			want: true,
		},
		{
			name: "link without keep open",
			config: &AppNetcatConfig{
				app_mux_Config: &AppMuxConfig{AppMode: "link"},
			},
		},
		{
			name: "mux local mapping",
			config: &AppNetcatConfig{
				keepOpen:     true,
				muxLocalPort: "1080",
			},
			want: true,
		},
		{
			name: "one shot download",
			config: &AppNetcatConfig{
				keepOpen:       true,
				app_mux_Config: &AppMuxConfig{AppMode: "httpclient"},
			},
		},
		{
			name: "plain netcat",
			config: &AppNetcatConfig{
				keepOpen: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldRetryPersistentDial(tt.config); got != tt.want {
				t.Fatalf("shouldRetryPersistentDial() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRemoteLinkConfigurationEnablesPersistentDialRetry(t *testing.T) {
	config, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{
		"-remote", "127.0.0.1:4443",
		"-link", "none;x://127.0.0.1:3180",
	})
	if err != nil {
		t.Fatalf("AppNetcatConfigByArgs: %v", err)
	}
	if !config.keepOpen {
		t.Fatal("-link did not enable keep-open")
	}
	if !shouldRetryPersistentDial(config) {
		t.Fatal("-remote + -link did not enable persistent dial retry")
	}
}

func TestPlainRemoteKeepOpenRetainsSingleDialBehavior(t *testing.T) {
	config, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{
		"-remote", "127.0.0.1:4443",
		"-k",
	})
	if err != nil {
		t.Fatalf("AppNetcatConfigByArgs: %v", err)
	}
	if shouldRetryPersistentDial(config) {
		t.Fatal("plain -remote unexpectedly enabled persistent dial retry")
	}
}

func TestPersistentDialLoopRetriesUntilCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	result := runPersistentDialLoop(ctx, 0, log.New(io.Discard, "", 0), func() int {
		attempts++
		if attempts == 3 {
			cancel()
		}
		return 1
	})
	if result != 0 {
		t.Fatalf("runPersistentDialLoop result = %d, want 0", result)
	}
	if attempts != 3 {
		t.Fatalf("dial attempts = %d, want 3", attempts)
	}
}
