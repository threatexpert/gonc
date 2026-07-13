package apps

import (
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppNetcatConfigByArgsReturnsErrorsInsteadOfExiting(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	strongKey := "A9f#K2m!Q7x@L4v$R8p%T6z"
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "PSK file",
			args:    []string{"-psk", "@" + missing, "127.0.0.1", "1"},
			wantErr: "PSK file",
		},
		{
			name:    "STUN file",
			args:    []string{"-stunsrv", "@" + missing, "-p2p", strongKey},
			wantErr: "stun server file",
		},
		{
			name:    "app mode conflicts with exec",
			args:    []string{"-p2p", strongKey, "-httpserver", ".", "-e", ":sh"},
			wantErr: "cannot be used with -e",
		},
		{
			name:    "TLS cert file",
			args:    []string{"-tls", "-ssl-cert", missing, "-ssl-key", missing, "-l", "127.0.0.1", "0"},
			wantErr: "certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := AppNetcatConfigByArgs(io.Discard, "gonc", tt.args)
			if err == nil {
				t.Fatal("AppNetcatConfigByArgs returned nil error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}
