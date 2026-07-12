package netx

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestWaitContext(t *testing.T) {
	started := time.Now()
	if err := WaitContext(context.Background(), 25*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < 20*time.Millisecond {
		t.Fatalf("wait returned too early after %s", elapsed)
	}
}

func TestWaitContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	started := time.Now()
	err := WaitContext(ctx, time.Minute)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("canceled wait returned too slowly after %s", elapsed)
	}
}

func TestReadFullWithContextContinuesAfterPollTimeout(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()

	go func() {
		defer peer.Close()
		_, _ = peer.Write([]byte("HE"))
		time.Sleep(75 * time.Millisecond)
		_, _ = peer.Write([]byte("LLO"))
	}()

	buf := make([]byte, len("HELLO"))
	n, err := ReadFullWithContext(context.Background(), local, buf, time.Second, 25*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(buf) || string(buf) != "HELLO" {
		t.Fatalf("read (%d) %q, want (%d) HELLO", n, buf, len(buf))
	}
}

func TestWriteFullWithContextContinuesAfterPollTimeout(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()

	readDone := make(chan []byte, 1)
	go func() {
		defer peer.Close()
		buf := make([]byte, len("HELLO"))
		if _, err := io.ReadFull(peer, buf[:2]); err != nil {
			readDone <- nil
			return
		}
		time.Sleep(75 * time.Millisecond)
		if _, err := io.ReadFull(peer, buf[2:]); err != nil {
			readDone <- nil
			return
		}
		readDone <- buf
	}()

	want := []byte("HELLO")
	n, err := WriteFullWithContext(context.Background(), local, want, time.Second, 25*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(want) {
		t.Fatalf("wrote %d bytes, want %d", n, len(want))
	}
	select {
	case got := <-readDone:
		if string(got) != string(want) {
			t.Fatalf("peer read %q, want %q", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("peer did not receive the complete write")
	}
}
