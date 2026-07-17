package easyp2p

import (
	"context"
	"errors"
	"testing"
	"time"
)

type mqttTestToken struct {
	done chan struct{}
	err  error
}

func (t *mqttTestToken) Wait() bool {
	<-t.done
	return true
}

func (t *mqttTestToken) WaitTimeout(timeout time.Duration) bool {
	select {
	case <-t.done:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (t *mqttTestToken) Done() <-chan struct{} { return t.done }
func (t *mqttTestToken) Error() error          { return t.err }

func TestMQTTSignalSessionReplaysMessageReceivedBeforeWaiter(t *testing.T) {
	const topic = "nat-exchange/test"

	session := &MQTTSignalSession{
		waiters: make(map[string]map[*mqttSignalWaiter]struct{}),
	}
	session.dispatchMessage(topic, 2, "remote-payload")

	waiter := &mqttSignalWaiter{
		selfPayload: "local-payload",
		handler: func(data string) (bool, error) {
			return data == "remote-payload", nil
		},
		recvCh: make(chan mqttSignalRecvPayload, 1),
		errCh:  make(chan error, 1),
	}
	remove := session.addWaiter(topic, waiter)
	defer remove()

	select {
	case got := <-waiter.recvCh:
		if got.data != "remote-payload" || got.index != 2 {
			t.Fatalf("cached MQTT payload = %+v, want data remote-payload from broker 2", got)
		}
	case err := <-waiter.errCh:
		t.Fatalf("cached MQTT payload returned handler error: %v", err)
	case <-time.After(time.Second):
		t.Fatal("cached MQTT payload was not replayed to waiter")
	}
}

func TestMQTTSignalSessionKeepsOnlyLatestMessageBeforeWaiter(t *testing.T) {
	const topic = "nat-exchange/test"

	session := &MQTTSignalSession{
		waiters: make(map[string]map[*mqttSignalWaiter]struct{}),
	}
	session.dispatchMessage(topic, 1, "older-payload")
	session.dispatchMessage(topic, 3, "latest-payload")

	waiter := &mqttSignalWaiter{
		recvCh: make(chan mqttSignalRecvPayload, 1),
		errCh:  make(chan error, 1),
	}
	remove := session.addWaiter(topic, waiter)
	defer remove()

	select {
	case got := <-waiter.recvCh:
		if got.data != "latest-payload" || got.index != 3 {
			t.Fatalf("cached MQTT payload = %+v, want latest-payload from broker 3", got)
		}
	case err := <-waiter.errCh:
		t.Fatalf("cached MQTT payload returned handler error: %v", err)
	case <-time.After(time.Second):
		t.Fatal("latest cached MQTT payload was not replayed to waiter")
	}
}

func TestMQTTSignalSessionCloseHasNoFixedDelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	session := &MQTTSignalSession{
		ctx:    ctx,
		cancel: cancel,
	}

	startedAt := time.Now()
	session.Close()
	if elapsed := time.Since(startedAt); elapsed >= 100*time.Millisecond {
		t.Fatalf("MQTTSignalSession.Close took %s, want less than 100ms", elapsed)
	}
}

func TestWaitMQTTTokenContextReturnsCancellationCause(t *testing.T) {
	cancelCause := errors.New("LAN path won")
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(cancelCause)
	token := &mqttTestToken{done: make(chan struct{})}

	if err := waitMQTTTokenContext(ctx, token); !errors.Is(err, cancelCause) {
		t.Fatalf("waitMQTTTokenContext error = %v, want %v", err, cancelCause)
	}
}

func TestWaitMQTTTokenContextReturnsTokenError(t *testing.T) {
	tokenErr := errors.New("broker rejected request")
	token := &mqttTestToken{done: make(chan struct{}), err: tokenErr}
	close(token.done)

	if err := waitMQTTTokenContext(context.Background(), token); !errors.Is(err, tokenErr) {
		t.Fatalf("waitMQTTTokenContext error = %v, want %v", err, tokenErr)
	}
}
