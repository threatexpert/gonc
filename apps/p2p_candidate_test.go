package apps

import (
	"context"
	"errors"
	"testing"
)

func TestPendingP2PCandidateCancelCurrent(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	candidate := &pendingP2PCandidate{}
	token := candidate.arm(cancel)

	if token == 0 {
		t.Fatal("arm returned an empty token")
	}
	if !candidate.cancelCurrent(errP2PCandidateSuperseded) {
		t.Fatal("armed candidate was not canceled")
	}
	if !errors.Is(context.Cause(ctx), errP2PCandidateSuperseded) {
		t.Fatalf("context cause = %v, want superseded", context.Cause(ctx))
	}
	if candidate.cancelCurrent(errP2PCandidateSuperseded) {
		t.Fatal("candidate was canceled more than once")
	}
}

func TestPendingP2PCandidateDisarmPreventsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	candidate := &pendingP2PCandidate{}
	token := candidate.arm(cancel)

	if !candidate.disarm(token) {
		t.Fatal("armed candidate was not disarmed")
	}
	if candidate.cancelCurrent(errP2PCandidateSuperseded) {
		t.Fatal("disarmed candidate was canceled")
	}
	if context.Cause(ctx) != nil {
		t.Fatalf("disarmed context was canceled: %v", context.Cause(ctx))
	}
}

func TestPendingP2PCandidateIgnoresStaleDisarm(t *testing.T) {
	firstCtx, firstCancel := context.WithCancelCause(context.Background())
	secondCtx, secondCancel := context.WithCancelCause(context.Background())
	candidate := &pendingP2PCandidate{}
	firstToken := candidate.arm(firstCancel)
	secondToken := candidate.arm(secondCancel)

	if !errors.Is(context.Cause(firstCtx), errP2PCandidateSuperseded) {
		t.Fatalf("replaced context cause = %v, want superseded", context.Cause(firstCtx))
	}
	if candidate.disarm(firstToken) {
		t.Fatal("stale token disarmed the current candidate")
	}
	if !candidate.cancelCurrent(errP2PCandidateSuperseded) {
		t.Fatal("current candidate was not canceled")
	}
	if !errors.Is(context.Cause(secondCtx), errP2PCandidateSuperseded) {
		t.Fatalf("current context cause = %v, want superseded", context.Cause(secondCtx))
	}
	if candidate.disarm(secondToken) {
		t.Fatal("canceled token remained armed")
	}
}

func TestP2PCandidateHasGuaranteedHandshakeBoundary(t *testing.T) {
	tests := []struct {
		name        string
		config      AppNetcatConfig
		cipherSuite string
		want        bool
	}{
		{name: "TLS auto transport", cipherSuite: "tls", want: true},
		{name: "DTLS forced UDP", config: AppNetcatConfig{udpProtocol: true}, cipherSuite: "tls", want: true},
		{name: "default TLS suite", want: true},
		{name: "shadow stream auto transport", cipherSuite: "ss", want: false},
		{name: "shadow stream KCP", config: AppNetcatConfig{udpProtocol: true}, cipherSuite: "ss", want: true},
		{name: "plain TCP", cipherSuite: "plain", want: false},
		{name: "plain UDP", config: AppNetcatConfig{udpProtocol: true}, cipherSuite: "plain", want: false},
		{
			name:        "plain explicit KCP",
			config:      AppNetcatConfig{udpProtocol: true, kcpEnabled: true},
			cipherSuite: "plain",
			want:        true,
		},
		{name: "unknown suite", cipherSuite: "unknown", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p2pCandidateHasGuaranteedHandshakeBoundary(&tt.config, tt.cipherSuite); got != tt.want {
				t.Fatalf("p2pCandidateHasGuaranteedHandshakeBoundary() = %v, want %v", got, tt.want)
			}
		})
	}
}
