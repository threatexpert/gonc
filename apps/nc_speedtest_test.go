package apps

import (
	"context"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/threatexpert/gonc/v2/misc"
	"github.com/threatexpert/gonc/v2/secure"
)

func TestParseBinarySize(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{input: "100", want: 100},
		{input: "100K", want: 100 * 1024},
		{input: "100kb", want: 100 * 1024},
		{input: "100M", want: 100 * 1024 * 1024},
		{input: "100MiB", want: 100 * 1024 * 1024},
		{input: "2G", want: 2 * 1024 * 1024 * 1024},
		{input: "1TiB", want: 1024 * 1024 * 1024 * 1024},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseBinarySize(tt.input)
			if err != nil {
				t.Fatalf("parseBinarySize(%q) error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("parseBinarySize(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseBinarySizeRejectsInvalidValues(t *testing.T) {
	for _, input := range []string{"", "-1", "1.5G", "12XB", "9223372036854775808", "9000000000000TiB"} {
		t.Run(input, func(t *testing.T) {
			if _, err := parseBinarySize(input); err == nil {
				t.Fatalf("parseBinarySize(%q) returned nil error", input)
			}
		})
	}
}

func TestSpeedTestAppliesDefaults(t *testing.T) {
	config, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{
		"-speedtest", "30s", "127.0.0.1", "8888",
	})
	if err != nil {
		t.Fatalf("AppNetcatConfigByArgs() error: %v", err)
	}

	if config.speedTestDuration != 30*time.Second {
		t.Fatalf("speedTestDuration = %s, want 30s", config.speedTestDuration)
	}
	if !config.progressEnabled {
		t.Fatal("progressEnabled = false, want true")
	}
	if config.sendfile != "/dev/urandom" {
		t.Fatalf("sendfile = %q, want /dev/urandom", config.sendfile)
	}
	if config.writefile != "/dev/null" {
		t.Fatalf("writefile = %q, want /dev/null", config.writefile)
	}
}

func TestSpeedTestPreservesExplicitFilesAndParsesSendSize(t *testing.T) {
	config, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{
		"-speedtest", "30s",
		"-send", "input.bin",
		"-write", "output.bin",
		"-sendsize", "100M",
		"127.0.0.1", "8888",
	})
	if err != nil {
		t.Fatalf("AppNetcatConfigByArgs() error: %v", err)
	}

	if config.sendfile != "input.bin" {
		t.Fatalf("sendfile = %q, want input.bin", config.sendfile)
	}
	if config.writefile != "output.bin" {
		t.Fatalf("writefile = %q, want output.bin", config.writefile)
	}
	if config.sendsize != 100*1024*1024 {
		t.Fatalf("sendsize = %d, want %d", config.sendsize, int64(100*1024*1024))
	}
}

func TestSpeedTestZeroDoesNotEnableDefaults(t *testing.T) {
	config, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{
		"-speedtest", "0", "127.0.0.1", "8888",
	})
	if err != nil {
		t.Fatalf("AppNetcatConfigByArgs() error: %v", err)
	}

	if config.progressEnabled || config.sendfile != "" || config.writefile != "" {
		t.Fatalf("disabled speedtest changed config: progress=%v send=%q write=%q",
			config.progressEnabled, config.sendfile, config.writefile)
	}
}

func TestSpeedTestRejectsNegativeDuration(t *testing.T) {
	_, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{
		"-speedtest", "-1s", "127.0.0.1", "8888",
	})
	if err == nil {
		t.Fatal("AppNetcatConfigByArgs() returned nil error")
	}
	if !strings.Contains(err.Error(), "speedtest") {
		t.Fatalf("error = %q, want speedtest validation error", err)
	}
}

func TestSpeedTestAcceptsGoDurationUnits(t *testing.T) {
	for _, value := range []string{"500ms", "10s", "5m", "1h", "1h30m"} {
		t.Run(value, func(t *testing.T) {
			config, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{
				"-speedtest", value, "127.0.0.1", "8888",
			})
			if err != nil {
				t.Fatalf("AppNetcatConfigByArgs() error: %v", err)
			}
			want, err := time.ParseDuration(value)
			if err != nil {
				t.Fatalf("time.ParseDuration(%q) error: %v", value, err)
			}
			if config.speedTestDuration != want {
				t.Fatalf("speedTestDuration = %s, want %s", config.speedTestDuration, want)
			}
		})
	}
}

func TestSpeedTestRejectsNonDurationValues(t *testing.T) {
	for _, value := range []string{"10", "1d"} {
		t.Run(value, func(t *testing.T) {
			_, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{
				"-speedtest", value, "127.0.0.1", "8888",
			})
			if err == nil {
				t.Fatalf("AppNetcatConfigByArgs() accepted invalid duration %q", value)
			}
		})
	}
}

func TestSpeedTestDisablesGracefulNegotiatedClose(t *testing.T) {
	config, err := preinitNegotiationConfig(&AppNetcatConfig{
		speedTestDuration: time.Second,
	})
	if err != nil {
		t.Fatalf("preinitNegotiationConfig() error: %v", err)
	}
	if !config.DisableGracefulClose {
		t.Fatal("DisableGracefulClose = false, want true for speed test")
	}

	config, err = preinitNegotiationConfig(&AppNetcatConfig{})
	if err != nil {
		t.Fatalf("preinitNegotiationConfig() normal mode error: %v", err)
	}
	if config.DisableGracefulClose {
		t.Fatal("DisableGracefulClose = true, want false outside speed test")
	}
}

func TestSpeedTestDurationClosesActiveTransfer(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	console, consolePeer := net.Pipe()
	defer console.Close()
	defer consolePeer.Close()

	config := &AppNetcatConfig{
		LogWriter:         io.Discard,
		Logger:            log.New(io.Discard, "", 0),
		ctx:               context.Background(),
		sendfile:          "/dev/zero",
		writefile:         "/dev/null",
		speedTestDuration: time.Second,
		progressEnabled:   true,
	}
	nconn := &secure.NegotiatedConn{
		TopLayer:   local,
		ConnLayers: []net.Conn{local},
		Config:     secure.NewNegotiationConfig(),
	}
	statsIn := misc.NewProgressStats()
	statsOut := misc.NewProgressStats()

	started := time.Now()
	done := make(chan int, 1)
	go func() {
		done <- handleNegotiatedConnection(console, config, nconn, statsIn, statsOut)
	}()

	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("handleNegotiatedConnection() = %d, want 0", code)
		}
		elapsed := time.Since(started)
		if elapsed < 900*time.Millisecond || elapsed > 3*time.Second {
			t.Fatalf("speed test elapsed %s, want approximately 2s including existing 1s sleep", elapsed)
		}
	case <-time.After(3 * time.Second):
		nconn.Close()
		<-done
		t.Fatal("speed test did not stop after its configured duration")
	}
}
