package easyp2p

import (
	"testing"
	"time"
)

func TestTCPActiveDialDelay(t *testing.T) {
	tests := []struct {
		name         string
		isClient     bool
		inSameLAN    bool
		lanProbeOnly bool
		want         time.Duration
	}{
		{
			name:     "client on non-LAN route starts immediately",
			isClient: true,
			want:     0,
		},
		{
			name:      "server on same-LAN route starts immediately",
			inSameLAN: true,
			want:      0,
		},
		{
			name:         "LAN-probe-only server starts immediately",
			lanProbeOnly: true,
			want:         0,
		},
		{
			name: "server on non-LAN route keeps stagger",
			want: 2 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tcpActiveDialDelay(tt.isClient, tt.inSameLAN, tt.lanProbeOnly)
			if got != tt.want {
				t.Fatalf("tcpActiveDialDelay() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestTCPTraversalTimeout(t *testing.T) {
	tests := []struct {
		name         string
		round        int
		inSameLAN    bool
		lanProbeOnly bool
		want         time.Duration
	}{
		{
			name:      "unsynchronized same-LAN traversal uses eight seconds",
			inSameLAN: true,
			want:      8 * time.Second,
		},
		{
			name:         "LAN-probe-only keeps five seconds",
			inSameLAN:    true,
			lanProbeOnly: true,
			want:         5 * time.Second,
		},
		{
			name:      "synchronized same-LAN traversal keeps default",
			round:     1,
			inSameLAN: true,
			want:      25 * time.Second,
		},
		{
			name: "round zero non-LAN traversal keeps default",
			want: 25 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tcpTraversalTimeout(tt.round, tt.inSameLAN, tt.lanProbeOnly)
			if got != tt.want {
				t.Fatalf("tcpTraversalTimeout() = %s, want %s", got, tt.want)
			}
		})
	}
}
