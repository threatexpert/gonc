package easyp2p

import (
	"testing"
	"time"
)

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
