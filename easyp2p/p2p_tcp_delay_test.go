package easyp2p

import (
	"context"
	"errors"
	"io"
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

func TestTCPUnsynchronizedSameLANRetryInterval(t *testing.T) {
	if tcpUnsynchronizedSameLANRetryInterval != 250*time.Millisecond {
		t.Fatalf("retry interval = %s, want 250ms", tcpUnsynchronizedSameLANRetryInterval)
	}
}

func TestLANProbeErrorGracePeriod(t *testing.T) {
	if lanProbeErrorGracePeriod != time.Second {
		t.Fatalf("LAN probe error grace = %s, want 1s", lanProbeErrorGracePeriod)
	}
}

func TestReportTraversalErrorWaitsForGrace(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wantErr := errors.New("candidate failed")
	errCh := make(chan error, 1)
	started := time.Now()
	go reportTraversalError(ctx, errCh, wantErr, 100*time.Millisecond)

	select {
	case err := <-errCh:
		t.Fatalf("error reported before grace elapsed: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, wantErr) {
			t.Fatalf("reported error = %v, want %v", err, wantErr)
		}
		if elapsed := time.Since(started); elapsed < 80*time.Millisecond {
			t.Fatalf("error reported after %s, want at least 80ms", elapsed)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("error was not reported after grace elapsed")
	}
}

func TestReportTraversalErrorCancellationSuppressesPendingError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		reportTraversalError(ctx, errCh, errors.New("candidate failed"), 200*time.Millisecond)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("error reporter did not stop after cancellation")
	}
	select {
	case err := <-errCh:
		t.Fatalf("canceled error reporter delivered %v", err)
	default:
	}
}

func TestReportTraversalErrorHonorsShorterAttemptDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()

	errCh := make(chan error, 1)
	done := make(chan struct{})
	started := time.Now()
	go func() {
		defer close(done)
		reportTraversalError(ctx, errCh, errors.New("candidate failed"), 200*time.Millisecond)
	}()

	select {
	case <-done:
		if elapsed := time.Since(started); elapsed >= 150*time.Millisecond {
			t.Fatalf("error reporter exceeded attempt deadline: %s", elapsed)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("error reporter ignored attempt deadline")
	}
	select {
	case err := <-errCh:
		t.Fatalf("deadline-canceled error reporter delivered %v", err)
	default:
	}
}

func TestTCPPunchAckSelectorCommitsOnlyAfterConfirmationSucceeds(t *testing.T) {
	var selector tcpPunchAckSelector
	wantErr := errors.New("confirmation failed")

	selected, err := selector.trySelect(func() error {
		return wantErr
	})
	if selected {
		t.Fatal("failed confirmation selected the candidate")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("failed confirmation error = %v, want %v", err, wantErr)
	}

	selected, err = selector.trySelect(func() error {
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !selected {
		t.Fatal("next candidate was not selected after the first confirmation failed")
	}

	confirmationCalled := false
	selected, err = selector.trySelect(func() error {
		confirmationCalled = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if selected {
		t.Fatal("selector selected more than one candidate")
	}
	if confirmationCalled {
		t.Fatal("selector confirmed a candidate after selection was committed")
	}
}

func TestTCPPunchAckWriteErrorTreatsCompleteWriteAsCommitted(t *testing.T) {
	wantErr := errors.New("write reported an error")

	if err := tcpPunchAckWriteError(16, 16, wantErr); err != nil {
		t.Fatalf("complete write error = %v, want nil", err)
	}
	if err := tcpPunchAckWriteError(8, 16, wantErr); !errors.Is(err, wantErr) {
		t.Fatalf("partial write error = %v, want %v", err, wantErr)
	}
	if err := tcpPunchAckWriteError(8, 16, nil); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write error = %v, want %v", err, io.ErrShortWrite)
	}
}

func TestTCPValidateThenHandshakeRejectsBeforeHandshake(t *testing.T) {
	wantErr := errors.New("unexpected peer")
	handshakeCalled := false

	err := tcpValidateThenHandshake(
		func() error {
			return wantErr
		},
		func() error {
			handshakeCalled = true
			return nil
		},
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("validation error = %v, want %v", err, wantErr)
	}
	if handshakeCalled {
		t.Fatal("handshake ran before peer validation succeeded")
	}
}
