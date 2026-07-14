package easyp2p

import (
	"bytes"
	"testing"
)

func TestEasyP2PMPOptionsNormalized(t *testing.T) {
	relay := &RelayPacketConn{}
	signal := &MQTTSignalSession{}
	hookCalled := false
	options := EasyP2PMPOptions{
		Bind:             "127.0.0.1:0",
		MultipathEnabled: true,
		RelayConn:        relay,
		Signal:           signal,
		OnAddressExchangeDone: func() {
			hookCalled = true
		},
	}

	normalized := options.normalized()
	if normalized.LogWriter == nil {
		t.Fatal("nil LogWriter was not normalized")
	}
	if _, err := normalized.LogWriter.Write([]byte("discarded")); err != nil {
		t.Fatalf("normalized LogWriter.Write: %v", err)
	}
	if options.LogWriter != nil {
		t.Fatal("normalization mutated the input value")
	}
	if normalized.Bind != options.Bind || !normalized.MultipathEnabled {
		t.Fatalf("network options changed: %+v", normalized)
	}
	if normalized.RelayConn != relay || normalized.Signal != signal {
		t.Fatal("injected dependencies changed during normalization")
	}
	if normalized.OnAddressExchangeDone == nil {
		t.Fatal("callback was lost during normalization")
	}
	normalized.OnAddressExchangeDone()
	if !hookCalled {
		t.Fatal("normalized callback is not the supplied callback")
	}

	var logs bytes.Buffer
	options.LogWriter = &logs
	normalized = options.normalized()
	if normalized.LogWriter != &logs {
		t.Fatal("normalization replaced a supplied LogWriter")
	}
}
