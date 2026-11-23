package apps

import (
	"context"
	"io"
	"os"
	"testing"
)

func TestLANOnlyNeverUsesMQTT(t *testing.T) {
	cases := map[string][]string{
		"share":   {"-p2p", "nb1-lanonlytestkey0123456789", "-httpserver", os.DevNull},
		"receive": {"-p2p", "nb1-lanonlytestkey0123456789", "-httplocal"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, err := PrepareNetcatConfigWithOptions(context.Background(), io.Discard, args, RunOptions{LANOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			if !cfg.useLAN || cfg.useLANPassive || cfg.p2pWithLanMode {
				t.Fatalf("LAN flags: useLAN=%v passive=%v withLan=%v", cfg.useLAN, cfg.useLANPassive, cfg.p2pWithLanMode)
			}
			if cfg.useMQTTWait || cfg.useMQTTHello {
				t.Fatalf("MQTT still enabled: wait=%v hello=%v", cfg.useMQTTWait, cfg.useMQTTHello)
			}
			if cfg.network != "tcp4" {
				t.Fatalf("network = %q, want tcp4", cfg.network)
			}
		})
	}
}

func TestLANOnlyRejectsCombinations(t *testing.T) {
	if _, err := PrepareNetcatConfigWithOptions(context.Background(), io.Discard,
		[]string{"-p2p", "nb1-lanonlytestkey0123456789", "-httplocal"},
		RunOptions{LANOnly: true, P2PWithLANMode: true}); err == nil {
		t.Fatal("LANOnly with P2PWithLANMode was accepted")
	}
	if _, err := PrepareNetcatConfigWithOptions(context.Background(), io.Discard,
		[]string{"-l", "12345"}, RunOptions{LANOnly: true}); err == nil {
		t.Fatal("LANOnly without -p2p was accepted")
	}
}
