package easyp2p

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLanDeriveKey(t *testing.T) {
	k1 := lanDeriveKey("abc")
	k2 := lanDeriveKey("abc")
	k3 := lanDeriveKey("xyz")
	if string(k1) != string(k2) { t.Fatal("same") }
	if string(k1) == string(k3) { t.Fatal("diff") }
	if len(k1) != 32 { t.Fatal("32") }
}

func TestLanSessionID(t *testing.T) {
	a := lanDeriveSessionID("abc")
	b := lanDeriveSessionID("abc")
	c := lanDeriveSessionID("xyz")
	if a != b || a == c || a == "" { t.Fatal("sid") }
}

func TestLanHMAC(t *testing.T) {
	key := lanDeriveKey("test")
	m1 := lanHMAC(key, "B", "d1")
	m2 := lanHMAC(key, "B", "d1")
	m3 := lanHMAC(key, "B", "d2")
	if m1 != m2 || m1 == m3 { t.Fatal("hmac") }
	msg := &lanMsg{Magic: LANBeaconMagic, Type: "B", Payload: "d1", HMAC: m1}
	if !lanVerify(key, msg) { t.Fatal("verify ok") }
	msg.HMAC = "bad"
	if lanVerify(key, msg) { t.Fatal("verify bad") }
}

func TestLanEncodeDecode(t *testing.T) {
	key := lanDeriveKey("test")
	b := lanBeacon{SessionID: "sid", NonceA: "na", Transport: "udp"}
	data := lanEncode(key, lanMsgBeacon, b)
	m, err := lanDecode(key, data)
	if err != nil { t.Fatal(err) }
	if m.Type != lanMsgBeacon { t.Fatal("type") }
	var d lanBeacon
	if err := lanUnmarshal(m, &d); err != nil { t.Fatal(err) }
	if d.SessionID != "sid" || d.NonceA != "na" || d.Transport != "udp" { t.Fatal("fields") }
}

func TestLanDecodeWrongKey(t *testing.T) {
	data := lanEncode(lanDeriveKey("a"), lanMsgBeacon, lanBeacon{})
	if _, err := lanDecode(lanDeriveKey("b"), data); err == nil { t.Fatal("wrong key") }
}

func TestLanDecodeTampered(t *testing.T) {
	key := lanDeriveKey("test")
	data := lanEncode(key, lanMsgBeacon, lanBeacon{})
	var m lanMsg
	json.Unmarshal(data, &m)
	m.Payload += "X"
	tampered, _ := json.Marshal(m)
	if _, err := lanDecode(key, tampered); err == nil { t.Fatal("tampered") }
}

func TestNegotiateTransport(t *testing.T) {
	cases := [][3]string{
		{"udp", "udp", "udp"}, {"udp", "tcp", "udp"}, {"udp", "", "udp"},
		{"tcp", "udp", "udp"}, {"tcp", "tcp", "tcp"}, {"tcp", "", "tcp"},
		{"", "udp", "udp"}, {"", "tcp", "tcp"}, {"", "", "tcp"},
	}
	for _, c := range cases {
		if negotiateTransport(c[0], c[1]) != c[2] {
			t.Errorf("negotiate(%q,%q) want %q", c[0], c[1], c[2])
		}
	}
}

func TestSelfFilter(t *testing.T) {
	f := newSelfFilter()
	if f.IsSelf("a") { t.Fatal("not yet") }
	f.Add("a")
	if !f.IsSelf("a") { t.Fatal("should") }
	if f.IsSelf("b") { t.Fatal("b") }
}

func TestLanPunchPortSelectorIsLazyAndShared(t *testing.T) {
	var calls atomic.Int32
	var output bytes.Buffer
	selector := newLanPunchPortSelector(func() (int, error) {
		calls.Add(1)
		return 42042, nil
	}, log.New(&output, "[LAN] ", 0))

	if got := calls.Load(); got != 0 {
		t.Fatalf("allocator called during construction: %d", got)
	}

	const workers = 32
	ports := make(chan int, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			port, err := selector.Get()
			ports <- port
			errs <- err
		}()
	}
	wg.Wait()
	close(ports)
	close(errs)

	if got := calls.Load(); got != 1 {
		t.Fatalf("allocator calls = %d, want 1", got)
	}
	for port := range ports {
		if port != 42042 {
			t.Fatalf("port = %d, want 42042", port)
		}
	}
	for err := range errs {
		if err != nil {
			t.Fatalf("Get returned error: %v", err)
		}
	}
	if got := strings.Count(output.String(), "Selected punchPort=42042 after authenticated peer discovery"); got != 1 {
		t.Fatalf("selection log count = %d, output = %q", got, output.String())
	}
}

func TestLanPunchPortSelectorSharesAllocationError(t *testing.T) {
	sentinel := errors.New("no test port")
	var calls atomic.Int32
	allocateStarted := make(chan struct{})
	releaseAllocation := make(chan struct{})
	selector := newLanPunchPortSelector(func() (int, error) {
		calls.Add(1)
		close(allocateStarted)
		<-releaseAllocation
		return 0, sentinel
	}, log.New(&bytes.Buffer{}, "", 0))

	const callers = 16
	type outcome struct {
		port int
		err  error
	}
	outcomes := make(chan outcome, callers)
	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			ready.Done()
			<-start
			port, err := selector.Get()
			outcomes <- outcome{port: port, err: err}
		}()
	}
	ready.Wait()
	close(start)
	<-allocateStarted
	close(releaseAllocation)

	for i := 0; i < callers; i++ {
		outcome := <-outcomes
		port, err := outcome.port, outcome.err
		if port != 0 {
			t.Fatalf("port = %d, want 0", port)
		}
		if !errors.Is(err, sentinel) {
			t.Fatalf("error = %v, want wrapped sentinel", err)
		}
		if !strings.Contains(err.Error(), "allocate LAN punch port") {
			t.Fatalf("error = %v, want allocation context", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("allocator calls = %d, want 1", got)
	}
}

type recordingLANMessage struct {
	msg *lanMsg
	err error
}

type invalidLANAddr string

func (a invalidLANAddr) Network() string { return "invalid" }
func (a invalidLANAddr) String() string  { return string(a) }

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(data)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

type recordingLANMessenger struct {
	key      []byte
	messages chan recordingLANMessage
	mu       sync.Mutex
	events   []string
}

func newRecordingLANMessenger(key []byte) *recordingLANMessenger {
	return &recordingLANMessenger{
		key:      key,
		messages: make(chan recordingLANMessage, 128),
	}
}

func (m *recordingLANMessenger) broadcast(data []byte) {
	m.record(data)
}

func (m *recordingLANMessenger) broadcastAndSendTo(data []byte, _ net.Addr) {
	m.record(data)
}

func (m *recordingLANMessenger) record(data []byte) {
	data = append([]byte(nil), data...)
	msg, err := lanDecode(m.key, data)
	if err == nil {
		m.recordEvent(msg.Type)
	}
	m.messages <- recordingLANMessage{msg: msg, err: err}
}

func (m *recordingLANMessenger) recordEvent(event string) {
	m.mu.Lock()
	m.events = append(m.events, event)
	m.mu.Unlock()
}

func (m *recordingLANMessenger) eventIndex(event string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, got := range m.events {
		if got == event {
			return i
		}
	}
	return -1
}

func (m *recordingLANMessenger) hasEvent(event string) bool {
	return m.eventIndex(event) >= 0
}

func lanTestPacket(t *testing.T, key []byte, msgType string, payload interface{}, src net.Addr) lanRecvPacket {
	t.Helper()
	msg, err := lanDecode(key, lanEncode(key, msgType, payload))
	if err != nil {
		t.Fatalf("decode test %s packet: %v", msgType, err)
	}
	return lanRecvPacket{msg: msg, src: src}
}

func sendLANPacket(t *testing.T, packets chan<- lanRecvPacket, packet lanRecvPacket) {
	t.Helper()
	select {
	case packets <- packet:
	case <-time.After(time.Second):
		t.Fatal("timed out delivering LAN test packet")
	}
}

func waitForLANMessages(t *testing.T, messenger *recordingLANMessenger, messageTypes ...string) map[string]*lanMsg {
	t.Helper()
	wanted := make(map[string]struct{}, len(messageTypes))
	for _, messageType := range messageTypes {
		wanted[messageType] = struct{}{}
	}
	got := make(map[string]*lanMsg, len(wanted))
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for len(got) < len(wanted) {
		select {
		case recorded := <-messenger.messages:
			if recorded.err != nil {
				t.Fatalf("decode recorded LAN message: %v", recorded.err)
			}
			if _, ok := wanted[recorded.msg.Type]; ok {
				if _, exists := got[recorded.msg.Type]; !exists {
					got[recorded.msg.Type] = recorded.msg
				}
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for LAN message types %v", messageTypes)
		}
	}
	return got
}

type lanWorkerOutcome struct {
	result *LANDiscoverResult
	err    error
}

func waitForLANWorker(t *testing.T, outcomes <-chan lanWorkerOutcome) lanWorkerOutcome {
	t.Helper()
	select {
	case outcome := <-outcomes:
		return outcome
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for LAN worker")
		return lanWorkerOutcome{}
	}
}

func testLANRoute(messenger *recordingLANMessenger) func(string) (string, error) {
	return func(string) (string, error) {
		messenger.recordEvent("route")
		return "127.0.0.1", nil
	}
}

func TestLanInitiatorRejectsWrongNonceResponseWithoutAllocating(t *testing.T) {
	key := lanDeriveKey("initiator-wrong-nonce")
	sid := lanDeriveSessionID("initiator-wrong-nonce")
	messenger := newRecordingLANMessenger(key)
	disp := newLanDispatcher()
	disp.responseCh = make(chan lanRecvPacket)
	selectorCalls := atomic.Int32{}
	selector := newLanPunchPortSelector(func() (int, error) {
		selectorCalls.Add(1)
		return 42101, nil
	}, nil)
	routeCalls := atomic.Int32{}
	route := func(string) (string, error) {
		routeCalls.Add(1)
		return "127.0.0.1", nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	outcomes := make(chan lanWorkerOutcome, 1)
	go func() {
		result, err := lanInitiator(ctx, messenger, disp, key, sid, "", route, selector, newSelfFilter(), log.New(&bytes.Buffer{}, "", 0), false, "Initiator")
		outcomes <- lanWorkerOutcome{result: result, err: err}
	}()

	beaconMessage := waitForLANMessages(t, messenger, lanMsgBeacon)[lanMsgBeacon]
	var beacon lanBeacon
	if err := lanUnmarshal(beaconMessage, &beacon); err != nil {
		t.Fatal(err)
	}
	sendLANPacket(t, disp.responseCh, lanTestPacket(t, key, lanMsgResponse, lanResponse{
		NonceA: beacon.NonceA + "-wrong",
		NonceB: "peer-nonce",
		IP:     "127.0.0.2",
		Port:   51001,
	}, &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 19730}))
	cancel()

	outcome := waitForLANWorker(t, outcomes)
	if !errors.Is(outcome.err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", outcome.err)
	}
	if got := routeCalls.Load(); got != 0 {
		t.Fatalf("route calls after wrong nonce = %d, want 0", got)
	}
	if got := selectorCalls.Load(); got != 0 {
		t.Fatalf("allocator calls after wrong nonce = %d, want 0", got)
	}
	if messenger.hasEvent(lanMsgConfirm) {
		t.Fatal("initiator sent Confirm for wrong-nonce Response")
	}
}

func TestLanInitiatorAllocatesBeforeConfirmAndReturnsSelectedPort(t *testing.T) {
	key := lanDeriveKey("initiator-valid-response")
	sid := lanDeriveSessionID("initiator-valid-response")
	messenger := newRecordingLANMessenger(key)
	disp := newLanDispatcher()
	selectorCalls := atomic.Int32{}
	selector := newLanPunchPortSelector(func() (int, error) {
		selectorCalls.Add(1)
		messenger.recordEvent("allocate")
		return 42102, nil
	}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	outcomes := make(chan lanWorkerOutcome, 1)
	go func() {
		result, err := lanInitiator(ctx, messenger, disp, key, sid, "", testLANRoute(messenger), selector, newSelfFilter(), log.New(&bytes.Buffer{}, "", 0), false, "Initiator")
		outcomes <- lanWorkerOutcome{result: result, err: err}
	}()

	beaconMessage := waitForLANMessages(t, messenger, lanMsgBeacon)[lanMsgBeacon]
	var beacon lanBeacon
	if err := lanUnmarshal(beaconMessage, &beacon); err != nil {
		t.Fatal(err)
	}
	disp.responseCh <- lanTestPacket(t, key, lanMsgResponse, lanResponse{
		NonceA:    beacon.NonceA,
		NonceB:    "peer-response-nonce",
		Transport: "udp",
		IP:        "127.0.0.2",
		Port:      51002,
	}, &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 19730})

	confirmMessage := waitForLANMessages(t, messenger, lanMsgConfirm)[lanMsgConfirm]
	var confirm lanConfirm
	if err := lanUnmarshal(confirmMessage, &confirm); err != nil {
		t.Fatal(err)
	}
	if confirm.Port != 42102 {
		t.Fatalf("Confirm port = %d, want 42102", confirm.Port)
	}
	if routeIndex, allocateIndex, confirmIndex := messenger.eventIndex("route"), messenger.eventIndex("allocate"), messenger.eventIndex(lanMsgConfirm); !(routeIndex >= 0 && routeIndex < allocateIndex && allocateIndex < confirmIndex) {
		t.Fatalf("event order route=%d allocate=%d Confirm=%d", routeIndex, allocateIndex, confirmIndex)
	}
	disp.ackCh <- lanTestPacket(t, key, lanMsgAck, lanAck{NonceA: beacon.NonceA}, &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 19730})

	outcome := waitForLANWorker(t, outcomes)
	if outcome.err != nil {
		t.Fatalf("initiator error: %v", outcome.err)
	}
	if got := selectorCalls.Load(); got != 1 {
		t.Fatalf("allocator calls = %d, want 1", got)
	}
	if outcome.result.LocalPort != 42102 {
		t.Fatalf("result LocalPort = %d, want 42102", outcome.result.LocalPort)
	}
}

func TestLanResponderRejectsInvalidBeaconsWithoutAllocating(t *testing.T) {
	const sessionKey = "responder-invalid-beacon"
	key := lanDeriveKey(sessionKey)
	sid := lanDeriveSessionID(sessionKey)
	for _, test := range []struct {
		name           string
		beacon         lanBeacon
		selfNonce      string
		src            net.Addr
		routeIP        string
		routeErr       error
		wantRouteCalls int32
	}{
		{name: "wrong session", beacon: lanBeacon{SessionID: sid + "-wrong", NonceA: "peer-wrong-session"}},
		{name: "self", beacon: lanBeacon{SessionID: sid, NonceA: "self-nonce"}, selfNonce: "self-nonce"},
		{name: "unusable source", beacon: lanBeacon{SessionID: sid, NonceA: "peer-bad-source"}, src: invalidLANAddr("not-an-address")},
		{name: "route error", beacon: lanBeacon{SessionID: sid, NonceA: "peer-route-error"}, routeErr: errors.New("no route"), wantRouteCalls: 1},
		{name: "route selects peer", beacon: lanBeacon{SessionID: sid, NonceA: "peer-same-route"}, routeIP: "127.0.0.2", wantRouteCalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			messenger := newRecordingLANMessenger(key)
			disp := newLanDispatcher()
			disp.beaconCh = make(chan lanRecvPacket)
			selectorCalls := atomic.Int32{}
			selector := newLanPunchPortSelector(func() (int, error) {
				selectorCalls.Add(1)
				return 42201, nil
			}, nil)
			routeCalls := atomic.Int32{}
			route := func(string) (string, error) {
				routeCalls.Add(1)
				if test.routeErr != nil {
					return "", test.routeErr
				}
				if test.routeIP != "" {
					return test.routeIP, nil
				}
				return "127.0.0.1", nil
			}
			selfFilter := newSelfFilter()
			if test.selfNonce != "" {
				selfFilter.Add(test.selfNonce)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			outcomes := make(chan lanWorkerOutcome, 1)
			go func() {
				result, err := lanResponder(ctx, messenger, disp, key, sid, "", route, selector, selfFilter, log.New(&bytes.Buffer{}, "", 0))
				outcomes <- lanWorkerOutcome{result: result, err: err}
			}()

			src := test.src
			if src == nil {
				src = &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 19730}
			}
			sendLANPacket(t, disp.beaconCh, lanTestPacket(t, key, lanMsgBeacon, test.beacon, src))
			cancel()
			outcome := waitForLANWorker(t, outcomes)
			if !errors.Is(outcome.err, context.Canceled) {
				t.Fatalf("error = %v, want context cancellation", outcome.err)
			}
			if got := routeCalls.Load(); got != test.wantRouteCalls {
				t.Fatalf("route calls for rejected Beacon = %d, want %d", got, test.wantRouteCalls)
			}
			if got := selectorCalls.Load(); got != 0 {
				t.Fatalf("allocator calls for rejected Beacon = %d, want 0", got)
			}
			if messenger.hasEvent(lanMsgResponse) {
				t.Fatal("responder sent Response for rejected Beacon")
			}
		})
	}
}

func TestLanResponderAllocatesBeforeResponseAndReturnsSelectedPort(t *testing.T) {
	const sessionKey = "responder-valid-beacon"
	key := lanDeriveKey(sessionKey)
	sid := lanDeriveSessionID(sessionKey)
	messenger := newRecordingLANMessenger(key)
	disp := newLanDispatcher()
	selectorCalls := atomic.Int32{}
	selector := newLanPunchPortSelector(func() (int, error) {
		selectorCalls.Add(1)
		messenger.recordEvent("allocate")
		return 42202, nil
	}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	outcomes := make(chan lanWorkerOutcome, 1)
	go func() {
		result, err := lanResponder(ctx, messenger, disp, key, sid, "", testLANRoute(messenger), selector, newSelfFilter(), log.New(&bytes.Buffer{}, "", 0))
		outcomes <- lanWorkerOutcome{result: result, err: err}
	}()

	disp.beaconCh <- lanTestPacket(t, key, lanMsgBeacon, lanBeacon{
		SessionID: sid,
		NonceA:    "peer-valid-beacon",
		Transport: "udp",
	}, &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 19730})
	responseMessage := waitForLANMessages(t, messenger, lanMsgResponse)[lanMsgResponse]
	var response lanResponse
	if err := lanUnmarshal(responseMessage, &response); err != nil {
		t.Fatal(err)
	}
	if response.Port != 42202 {
		t.Fatalf("Response port = %d, want 42202", response.Port)
	}
	if routeIndex, allocateIndex, responseIndex := messenger.eventIndex("route"), messenger.eventIndex("allocate"), messenger.eventIndex(lanMsgResponse); !(routeIndex >= 0 && routeIndex < allocateIndex && allocateIndex < responseIndex) {
		t.Fatalf("event order route=%d allocate=%d Response=%d", routeIndex, allocateIndex, responseIndex)
	}
	disp.confirmCh <- lanTestPacket(t, key, lanMsgConfirm, lanConfirm{
		NonceB:    response.NonceB,
		Transport: "udp",
		IP:        "127.0.0.3",
		Port:      52002,
	}, &net.UDPAddr{IP: net.ParseIP("127.0.0.3"), Port: 19730})

	outcome := waitForLANWorker(t, outcomes)
	if outcome.err != nil {
		t.Fatalf("responder error: %v", outcome.err)
	}
	if got := selectorCalls.Load(); got != 1 {
		t.Fatalf("allocator calls = %d, want 1", got)
	}
	if outcome.result.LocalPort != 42202 {
		t.Fatalf("result LocalPort = %d, want 42202", outcome.result.LocalPort)
	}
}

func TestLanInitiatorAndResponderShareSelectedPort(t *testing.T) {
	const sessionKey = "shared-worker-selector"
	key := lanDeriveKey(sessionKey)
	sid := lanDeriveSessionID(sessionKey)
	messenger := newRecordingLANMessenger(key)
	disp := newLanDispatcher()
	selectorCalls := atomic.Int32{}
	selector := newLanPunchPortSelector(func() (int, error) {
		selectorCalls.Add(1)
		return 42301, nil
	}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	outcomes := make(chan lanWorkerOutcome, 2)
	selfFilter := newSelfFilter()
	go func() {
		result, err := lanInitiator(ctx, messenger, disp, key, sid, "", testLANRoute(messenger), selector, selfFilter, log.New(&bytes.Buffer{}, "", 0), false, "Initiator")
		outcomes <- lanWorkerOutcome{result: result, err: err}
	}()
	go func() {
		result, err := lanResponder(ctx, messenger, disp, key, sid, "", testLANRoute(messenger), selector, selfFilter, log.New(&bytes.Buffer{}, "", 0))
		outcomes <- lanWorkerOutcome{result: result, err: err}
	}()

	beaconMessage := waitForLANMessages(t, messenger, lanMsgBeacon)[lanMsgBeacon]
	var beacon lanBeacon
	if err := lanUnmarshal(beaconMessage, &beacon); err != nil {
		t.Fatal(err)
	}
	disp.responseCh <- lanTestPacket(t, key, lanMsgResponse, lanResponse{
		NonceA: beacon.NonceA,
		NonceB: "shared-response-nonce",
		IP:     "127.0.0.2",
		Port:   53001,
	}, &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 19730})
	disp.beaconCh <- lanTestPacket(t, key, lanMsgBeacon, lanBeacon{
		SessionID: sid,
		NonceA:    "shared-peer-beacon",
	}, &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 19730})

	messages := waitForLANMessages(t, messenger, lanMsgConfirm, lanMsgResponse)
	var confirm lanConfirm
	if err := lanUnmarshal(messages[lanMsgConfirm], &confirm); err != nil {
		t.Fatal(err)
	}
	var response lanResponse
	if err := lanUnmarshal(messages[lanMsgResponse], &response); err != nil {
		t.Fatal(err)
	}
	if confirm.Port != 42301 || response.Port != 42301 {
		t.Fatalf("shared ports: Confirm=%d Response=%d, want 42301", confirm.Port, response.Port)
	}
	if got := selectorCalls.Load(); got != 1 {
		t.Fatalf("allocator calls = %d, want 1", got)
	}

	cancel()
	for i := 0; i < 2; i++ {
		outcome := waitForLANWorker(t, outcomes)
		if !errors.Is(outcome.err, context.Canceled) {
			t.Fatalf("worker error = %v, want context cancellation", outcome.err)
		}
	}
}

func TestLANDiscoverWorkersReturnAllocationErrorPromptly(t *testing.T) {
	const sessionKey = "prompt-allocation-error"
	key := lanDeriveKey(sessionKey)
	sid := lanDeriveSessionID(sessionKey)
	messenger := newRecordingLANMessenger(key)
	disp := newLanDispatcher()
	sentinel := fmt.Errorf("allocator unavailable: %w", context.Canceled)
	selector := newLanPunchPortSelector(func() (int, error) {
		return 0, sentinel
	}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	siblingStarted := make(chan struct{})
	siblingCanceled := make(chan struct{})
	outcomes := make(chan lanWorkerOutcome, 1)
	go func() {
		result, err := runLANDiscoverWorkers(ctx, cancel,
			func() (*LANDiscoverResult, error) {
				return lanInitiator(ctx, messenger, disp, key, sid, "", testLANRoute(messenger), selector, newSelfFilter(), log.New(&bytes.Buffer{}, "", 0), false, "Initiator")
			},
			func() (*LANDiscoverResult, error) {
				close(siblingStarted)
				<-ctx.Done()
				close(siblingCanceled)
				return nil, ctx.Err()
			},
		)
		outcomes <- lanWorkerOutcome{result: result, err: err}
	}()
	select {
	case <-siblingStarted:
	case <-time.After(time.Second):
		t.Fatal("idle sibling did not start")
	}

	beaconMessage := waitForLANMessages(t, messenger, lanMsgBeacon)[lanMsgBeacon]
	var beacon lanBeacon
	if err := lanUnmarshal(beaconMessage, &beacon); err != nil {
		t.Fatal(err)
	}
	disp.responseCh <- lanTestPacket(t, key, lanMsgResponse, lanResponse{
		NonceA: beacon.NonceA,
		NonceB: "allocation-error-response",
		IP:     "127.0.0.2",
		Port:   54001,
	}, &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 19730})

	select {
	case outcome := <-outcomes:
		if !errors.Is(outcome.err, sentinel) {
			t.Fatalf("error = %v, want wrapped allocator error", outcome.err)
		}
		if !strings.Contains(outcome.err.Error(), "allocate LAN punch port") {
			t.Fatalf("error = %v, want allocation context", outcome.err)
		}
	case <-time.After(time.Second):
		t.Fatal("LAN discovery waited for the idle sibling after allocation failed")
	}
	select {
	case <-siblingCanceled:
	case <-time.After(time.Second):
		t.Fatal("LAN discovery did not cancel the idle sibling")
	}
}

func TestLANDiscoverDefersPunchPortSelectionUntilPeer(t *testing.T) {
	for _, passive := range []bool{false, true} {
		passive := passive
		t.Run(fmt.Sprintf("passive=%t", passive), func(t *testing.T) {
			var calls atomic.Int32
			var output lockedBuffer
			ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
			defer cancel()

			_, err := lanDiscoverWithPortAllocator(
				ctx,
				fmt.Sprintf("deferred-port-%t-%d", passive, time.Now().UnixNano()),
				"",
				time.Second,
				passive,
				&output,
				func() (int, error) {
					calls.Add(1)
					return 42042, nil
				},
			)
			if err == nil {
				t.Fatal("discovery without a peer unexpectedly succeeded")
			}
			if !errors.Is(err, context.DeadlineExceeded) && err.Error() != "LAN discovery timeout" {
				t.Fatalf("discovery error = %v, want timeout", err)
			}
			if got := calls.Load(); got != 0 {
				t.Fatalf("allocator called without an authenticated peer: %d", got)
			}
			modeLog := "Mode: active beacon"
			if passive {
				modeLog = "Mode: passive startup burst"
			}
			if !strings.Contains(output.String(), "Multicast "+LANMulticastIP) || !strings.Contains(output.String(), modeLog) {
				t.Fatalf("discovery did not reach multicast readiness before timing out: %q", output.String())
			}
			if strings.Contains(output.String(), "punchPort=") {
				t.Fatalf("initial logs claim a selected punch port: %q", output.String())
			}
		})
	}
}

func TestBestLocalIP(t *testing.T) {
	ip, err := bestLocalIPForRemote("192.168.1.1")
	if err != nil { t.Skipf("no route: %v", err) }
	if ip == "" { t.Fatal("empty") }
	t.Logf("best for 192.168.1.1: %s", ip)
}

func TestAddrToIP(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	if addrToIP(addr) != "192.168.1.100" { t.Fatal("udp addr") }
}

func TestMulticastSendRecv(t *testing.T) {
	mc, err := newLanMcast()
	if err != nil { t.Skipf("multicast: %v", err) }
	defer mc.Close()
	t.Logf("joined %d ifaces", len(mc.ifaces))
	testMsg := []byte("hello-mcast")
	mc.broadcast(testMsg)
	buf := make([]byte, 1024)
	mc.rawConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, _, err := mc.conn.ReadFrom(buf)
	if err != nil { t.Fatalf("recv: %v", err) }
	if string(buf[:n]) != string(testMsg) { t.Fatalf("got %q", buf[:n]) }
	t.Log("OK")
}

func TestDispatcher(t *testing.T) {
	mc, err := newLanMcast()
	if err != nil { t.Skipf("multicast: %v", err) }
	defer mc.Close()
	key := lanDeriveKey("disp-test")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	disp := newLanDispatcher()
	go disp.run(ctx, mc, key)
	// 发一个 beacon
	mc.broadcast(lanEncode(key, lanMsgBeacon, lanBeacon{SessionID: "test", NonceA: "n1"}))
	// 发一个 response
	mc.broadcast(lanEncode(key, lanMsgResponse, lanResponse{NonceA: "n1", NonceB: "n2"}))
	// 验证分发
	select {
	case pkt := <-disp.beaconCh:
		if pkt.msg.Type != lanMsgBeacon { t.Fatal("type") }
	case <-time.After(2 * time.Second):
		t.Fatal("beacon timeout")
	}
	select {
	case pkt := <-disp.responseCh:
		if pkt.msg.Type != lanMsgResponse { t.Fatal("type") }
	case <-time.After(2 * time.Second):
		t.Fatal("response timeout")
	}
}

func TestLANTransportFromConfig(t *testing.T) {
	if LANTransportFromConfig(true) != "udp" { t.Fatal("udp") }
	if LANTransportFromConfig(false) != "" { t.Fatal("empty") }
}

// ── 集成测试 ──

func TestLANDiscoverLoopback(t *testing.T) {
	if os.Getenv("TEST_LAN_DISCOVER") == "" { t.Skip("set TEST_LAN_DISCOVER=1") }
	ctx := context.Background()
	key := "test-lan-12345"
	type rp struct { r *LANDiscoverResult; err error }
	ch := make(chan rp, 2)
	go func() { r, e := LANDiscover(ctx, key, "", 15*time.Second, os.Stderr); ch <- rp{r, e} }()
	time.Sleep(300 * time.Millisecond)
	go func() { r, e := LANDiscover(ctx, key, "", 15*time.Second, os.Stderr); ch <- rp{r, e} }()
	r1 := <-ch; if r1.err != nil { t.Fatalf("n1: %v", r1.err) }; t.Logf("N1: %+v", r1.r)
	r2 := <-ch; if r2.err != nil { t.Fatalf("n2: %v", r2.err) }; t.Logf("N2: %+v", r2.r)
}

func TestLANDiscoverUDP(t *testing.T) {
	if os.Getenv("TEST_LAN_DISCOVER") == "" { t.Skip("set TEST_LAN_DISCOVER=1") }
	ctx := context.Background()
	key := "test-lan-udp"
	type rp struct { r *LANDiscoverResult; err error }
	ch := make(chan rp, 2)
	go func() { r, e := LANDiscover(ctx, key, "udp", 15*time.Second, os.Stderr); ch <- rp{r, e} }()
	time.Sleep(300 * time.Millisecond)
	go func() { r, e := LANDiscover(ctx, key, "", 15*time.Second, os.Stderr); ch <- rp{r, e} }()
	r1 := <-ch; if r1.err != nil { t.Fatalf("A: %v", r1.err) }
	r2 := <-ch; if r2.err != nil { t.Fatalf("B: %v", r2.err) }
	if r1.r.Transport != "udp" || r2.r.Transport != "udp" {
		t.Fatalf("both udp: %s %s", r1.r.Transport, r2.r.Transport)
	}
}

func TestMcastPortAvailable(t *testing.T) {
	addr := fmt.Sprintf("%s:%d", LANMulticastIP, LANMulticastPort)
	c, err := net.ListenPacket("udp4", addr)
	if err != nil { t.Skipf("port unavailable: %v", err) }
	c.Close()
}
