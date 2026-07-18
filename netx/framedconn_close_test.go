package netx

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type blockingFrameTransport struct {
	writeStarted chan struct{}
	closed       chan struct{}
	startOnce    sync.Once
	closeOnce    sync.Once
}

func newBlockingFrameTransport() *blockingFrameTransport {
	return &blockingFrameTransport{
		writeStarted: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (c *blockingFrameTransport) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.ErrClosedPipe
}

func (c *blockingFrameTransport) Write([]byte) (int, error) {
	c.startOnce.Do(func() { close(c.writeStarted) })
	<-c.closed
	return 0, io.ErrClosedPipe
}

func (c *blockingFrameTransport) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func TestFramedConnCloseSkipsGracefulWaitWhenDisabled(t *testing.T) {
	transport := newBlockingFrameTransport()
	conn := NewFramedConnWithOptions(transport, transport, FramedConnOptions{
		DisableGracefulClose: true,
	})

	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("payload"))
		writeDone <- err
	}()

	select {
	case <-transport.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("write did not reach the blocking transport")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- conn.Close() }()

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close() error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Close() waited for writeMu despite DisableGracefulClose")
	}

	select {
	case err := <-writeDone:
		if !isClosedFrameWriteError(err) {
			t.Fatalf("blocked Write() error = %v, want closed connection error", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked Write() did not exit after Close()")
	}
}

func isClosedFrameWriteError(err error) bool {
	return err != nil && (err == io.ErrClosedPipe || err == net.ErrClosed)
}
