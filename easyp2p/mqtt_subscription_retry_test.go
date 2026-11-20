package easyp2p

import (
	"context"
	"errors"
	"io"
	"log"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type mqttRetrySubscribeStub struct {
	mqttSubscribeStub
	times []time.Time
	sub   func(string, int) mqtt.Token
}

func (c *mqttRetrySubscribeStub) Subscribe(topic string, _ byte, handler mqtt.MessageHandler) mqtt.Token {
	c.mu.Lock()
	c.calls++
	call := c.calls
	c.handler = handler
	c.times = append(c.times, time.Now())
	c.mu.Unlock()
	return c.sub(topic, call)
}

func (c *mqttRetrySubscribeStub) callTimes() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Time(nil), c.times...)
}

type mqttRetryTestLog struct {
	mu   sync.Mutex
	text strings.Builder
}

func (l *mqttRetryTestLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.text.Write(p)
}

func (l *mqttRetryTestLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.text.String()
}

func newMQTTRetryTestSession(ctx context.Context, client *mqttRetrySubscribeStub) (*MQTTSignalSession, *mqttRetryTestLog) {
	s, _ := newStalledSubscribeSession(ctx)
	s.clients[1].client = client
	output := &mqttRetryTestLog{}
	s.logger = log.New(output, "[MQTT] ", 0)
	return s, output
}

func TestMQTTSubscriptionRetriesInBackgroundAndLogsThirdFailureOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		client := &mqttRetrySubscribeStub{sub: func(_ string, call int) mqtt.Token {
			if call <= 4 {
				return mqttCompletedTestToken(io.EOF)
			}
			return mqttCompletedTestToken(nil)
		}}
		s, output := newMQTTRetryTestSession(ctx, client)
		caller, cancelCaller := context.WithCancel(ctx)
		if err := s.subscribe(caller, "topic", 1); err != nil {
			t.Fatal(err)
		}
		cancelCaller()
		synctest.Wait()
		wantFirst := "[MQTT] subscribed topic topic via healthy\n"
		if got := output.String(); got != wantFirst {
			t.Fatalf("initial log = %q", got)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if client.callCount() != 2 || output.String() != wantFirst {
			t.Fatal("second failure was logged or background retry did not happen")
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		for range 10 {
			if err := s.subscribe(ctx, "topic", 1); err != nil {
				t.Fatal(err)
			}
		}
		synctest.Wait()
		if client.callCount() != 3 || !strings.Contains(output.String(), "broker=stalled; consecutive_failures=3; reason=EOF") {
			t.Fatalf("calls=%d log=%q", client.callCount(), output.String())
		}
		time.Sleep(4 * time.Second)
		synctest.Wait()
		if client.callCount() != 4 || strings.Count(output.String(), "subscribe failed:") != 1 {
			t.Fatal("fourth failure repeated warning or backoff was bypassed")
		}
		time.Sleep(8 * time.Second)
		synctest.Wait()
		if s.subscribedCount("topic") != 2 || strings.Count(output.String(), "subscription recovered:") != 1 || strings.Count(output.String(), "subscribed topic") != 1 {
			t.Fatalf("recovery log=%q", output.String())
		}
		// A healthy resubscription should not repeat a resolved alert.
		s.brokerConnectionLost(client, 1, io.EOF)
		synctest.Wait()
		if strings.Count(output.String(), "subscription recovered:") != 1 {
			t.Fatal("healthy resubscription repeated recovery log")
		}
		time.Sleep(30 * time.Second)
		synctest.Wait()
		if client.callCount() != 6 {
			t.Fatalf("successful subscription kept retrying: %d", client.callCount())
		}
	})
}

func TestMQTTSubscriptionRetryBackoffCapsAndStopsOnClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		client := &mqttRetrySubscribeStub{sub: func(string, int) mqtt.Token { return mqttCompletedTestToken(io.EOF) }}
		s, output := newMQTTRetryTestSession(ctx, client)
		s.cancel = cancel
		started := time.Now()
		if err := s.subscribe(ctx, "topic", 1); err != nil {
			t.Fatal(err)
		}
		time.Sleep(36 * time.Second)
		synctest.Wait()
		want := []time.Duration{0, 1, 3, 7, 15, 25, 35}
		times := client.callTimes()
		if len(times) != len(want) {
			t.Fatalf("attempts=%d, want %d", len(times), len(want))
		}
		for i, at := range times {
			if at.Sub(started) != want[i]*time.Second {
				t.Fatalf("attempt %d at %s", i, at.Sub(started))
			}
		}
		if strings.Count(output.String(), "subscribe failed:") != 1 {
			t.Fatalf("warnings=%q", output.String())
		}
		s.Close()
		time.Sleep(30 * time.Second)
		synctest.Wait()
		if client.callCount() != len(want) {
			t.Fatal("retry survived session close")
		}
	})
}

func TestMQTTSubscriptionTimeoutIgnoresLateTokenAndRetries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		late := &mqttTestToken{done: make(chan struct{})}
		client := &mqttRetrySubscribeStub{sub: func(_ string, call int) mqtt.Token {
			if call == 1 {
				return late
			}
			return mqttCompletedTestToken(nil)
		}}
		s, output := newMQTTRetryTestSession(ctx, client)
		if err := s.subscribe(ctx, "topic", 1); err != nil {
			t.Fatal(err)
		}
		time.Sleep(mqttSubscribeTimeout + 100*time.Millisecond)
		synctest.Wait()
		close(late.done)
		synctest.Wait()
		if s.subscribedCount("topic") != 1 || client.callCount() != 1 {
			t.Fatal("late SUBACK changed readiness or retry started without backoff")
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if s.subscribedCount("topic") != 2 || client.callCount() != 2 || strings.Contains(output.String(), "failed:") {
			t.Fatalf("timeout recovery failed: calls=%d log=%q", client.callCount(), output.String())
		}
	})
}

func TestMQTTSubscriptionRetryWaitsForReconnect(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		client := &mqttRetrySubscribeStub{sub: func(_ string, call int) mqtt.Token {
			if call == 1 {
				return mqttCompletedTestToken(io.EOF)
			}
			return mqttCompletedTestToken(nil)
		}}
		s, output := newMQTTRetryTestSession(ctx, client)
		if err := s.subscribe(ctx, "topic", 1); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		client.mu.Lock()
		client.disconnected = true
		client.mu.Unlock()
		s.brokerConnectionLost(client, 1, io.EOF)
		time.Sleep(30 * time.Second)
		synctest.Wait()
		if client.callCount() != 1 {
			t.Fatal("SUBSCRIBE retried while disconnected")
		}
		client.mu.Lock()
		client.disconnected = false
		client.mu.Unlock()
		s.brokerConnected(client, 1)
		synctest.Wait()
		if client.callCount() != 2 || s.subscribedCount("topic") != 2 {
			t.Fatal("reconnect did not immediately restore failed subscription")
		}
		time.Sleep(30 * time.Second)
		synctest.Wait()
		if client.callCount() != 2 || strings.Count(output.String(), "\n") != 1 {
			t.Fatalf("old retry survived reconnect or extra logging: %q", output.String())
		}
	})
}

func TestMQTTSubscriptionRetriesRespectCallerAndPreparationDeadlines(t *testing.T) {
	for _, prepare := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client := &mqttRetrySubscribeStub{sub: func(string, int) mqtt.Token { return mqttCompletedTestToken(errors.New("subscription rejected")) }}
			s, output := newMQTTRetryTestSession(ctx, client)
			s.clients = s.clients[1:]
			started := time.Now()
			var err error
			want := 2500 * time.Millisecond
			if prepare {
				want = mqttPrepareTopicsTimeout
				err = s.prepareP2PTopics(ctx, "session")
			} else {
				_, _, _, err = s.exchange(ctx, EXMODE_waitOnly, "", "address", "session", want, nil, mqttNoPreferredBroker)
			}
			if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) != want || !strings.Contains(err.Error(), "subscription rejected") {
				t.Fatalf("elapsed=%s err=%v", time.Since(started), err)
			}
			if !prepare && strings.Contains(output.String(), "subscribe failed:") {
				t.Fatal("logged before three failures")
			}
			// Settle retries already runnable at the preparation deadline before
			// measuring cancellation. Otherwise one can finish between this
			// snapshot and cancel(), falsely appearing to run after cancellation.
			synctest.Wait()
			before := client.callCount()
			cancel()
			time.Sleep(30 * time.Second)
			synctest.Wait()
			if client.callCount() != before {
				t.Fatal("retry after cancellation")
			}
		})
	}
}

func TestMQTTConnectionFailuresCountOnceAndRecoverOnlyAfterSubscription(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		pending := &mqttTestToken{done: make(chan struct{})}
		client := &mqttRetrySubscribeStub{sub: func(string, int) mqtt.Token { return pending }}
		s, output := newMQTTRetryTestSession(ctx, client)
		s.clients = s.clients[:1]
		if err := s.subscribe(ctx, "topic", 1); err != nil {
			t.Fatal(err)
		}
		for i := 1; i <= 5; i++ {
			s.connectionNotification(1, mqtt.ConnectionNotificationBrokerFailed{Reason: io.EOF})
			s.connectionNotification(1, mqtt.ConnectionNotificationFailed{Reason: io.EOF})
			count := strings.Count(output.String(), "broker unavailable for subscription:")
			if (i < 3 && count != 0) || (i >= 3 && count != 1) {
				t.Fatalf("attempt=%d log=%q", i, output.String())
			}
		}
		s.brokerConnected(client, 1)
		synctest.Wait()
		if strings.Contains(output.String(), "recovered:") {
			t.Fatal("connection alone was reported as subscription recovery")
		}
		close(pending.done)
		synctest.Wait()
		if strings.Count(output.String(), "broker subscription recovered:") != 1 || strings.Count(output.String(), "subscribed topic") != 1 {
			t.Fatalf("recovery log=%q", output.String())
		}
		for range 3 {
			s.connectionNotification(1, mqtt.ConnectionNotificationFailed{Reason: io.EOF})
		}
		if strings.Count(output.String(), "broker unavailable for subscription:") != 2 {
			t.Fatal("recovered failure counter was not reset")
		}
		before := output.String()
		cancel()
		s.connectionNotification(0, mqtt.ConnectionNotificationFailed{Reason: context.Canceled})
		s.brokerConnectionLost(client, 1, io.EOF)
		if output.String() != before {
			t.Fatal("normal shutdown emitted failure log")
		}
	})
}

func TestMQTTSubscriptionRecoveryDoesNotClearAnotherTopicFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		started := time.Now()
		client := &mqttRetrySubscribeStub{sub: func(topic string, _ int) mqtt.Token {
			if topic == "a" && time.Since(started) >= 7*time.Second {
				return mqttCompletedTestToken(nil)
			}
			return mqttCompletedTestToken(io.EOF)
		}}
		s, output := newMQTTRetryTestSession(ctx, client)
		for _, topic := range []string{"a", "b"} {
			if err := s.subscribe(ctx, topic, 1); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(8 * time.Second)
		synctest.Wait()
		s.mu.Lock()
		a, b := s.failures[mqttSignalFailureKey{broker: 1, topic: "a"}], s.failures[mqttSignalFailureKey{broker: 1, topic: "b"}]
		valid := a == nil && b != nil && b.alerted && b.count == 4
		s.mu.Unlock()
		if !valid || strings.Count(output.String(), "subscribe failed:") != 2 || strings.Count(output.String(), "subscription recovered:") != 1 {
			t.Fatalf("topic failure states or logs mixed: %q", output.String())
		}
	})
}

func TestMQTTSubscriptionWaitSurvivesDisconnectAndIgnoresOldSUBACK(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		old := &mqttTestToken{done: make(chan struct{})}
		client := &mqttRetrySubscribeStub{sub: func(_ string, call int) mqtt.Token {
			if call == 1 {
				return old
			}
			return mqttCompletedTestToken(nil)
		}}
		s, output := newMQTTRetryTestSession(ctx, client)
		s.clients = s.clients[1:]
		result := make(chan error, 1)
		go func() { result <- s.subscribe(ctx, "topic", 1) }()
		synctest.Wait()
		client.mu.Lock()
		client.disconnected = true
		client.mu.Unlock()
		s.brokerConnectionLost(client, 1, io.EOF)
		close(old.done)
		synctest.Wait()
		select {
		case err := <-result:
			t.Fatalf("subscription stopped before caller deadline: %v", err)
		default:
		}
		if s.subscribedCount("topic") != 0 || output.String() != "" {
			t.Fatal("old SUBACK changed state or cancellation emitted a failure")
		}
		time.Sleep(time.Second)
		client.mu.Lock()
		client.disconnected = false
		client.mu.Unlock()
		s.brokerConnected(client, 1)
		if err := <-result; err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if client.callCount() != 2 || output.String() != "[MQTT] subscribed topic topic via stalled\n" {
			t.Fatalf("calls=%d log=%q", client.callCount(), output.String())
		}
	})
}

func TestMQTTMutualExchangeRecoversMissingCommonSubscription(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		commonA := &mqttRetrySubscribeStub{sub: func(_ string, call int) mqtt.Token {
			if call == 1 {
				return mqttCompletedTestToken(io.EOF)
			}
			return mqttCompletedTestToken(nil)
		}}
		commonB := &mqttRetrySubscribeStub{sub: func(string, int) mqtt.Token { return mqttCompletedTestToken(nil) }}
		a, _ := newMQTTRetryTestSession(ctx, commonA)
		b, _ := newMQTTRetryTestSession(ctx, commonB)
		route := func(peer *MQTTSignalSession) func(string, string) {
			return func(topic, payload string) {
				peer.mu.Lock()
				_, subscribed := peer.subscribed[topic][1]
				peer.mu.Unlock()
				if subscribed {
					peer.dispatchMessage(topic, 1, payload)
				}
			}
		}
		commonA.publish, commonB.publish = route(b), route(a)
		results := make(chan error, 2)
		for i, session := range []*MQTTSignalSession{a, b} {
			send, want := "A", "B"
			if i == 1 {
				send, want = want, send
			}
			go func() {
				got, _, _, err := session.exchange(ctx, EXMODE_mutual, send, "address", "session", 6*time.Second, nil, mqttNoPreferredBroker)
				if err == nil && got != want {
					err = errors.New("wrong peer payload")
				}
				results <- err
			}()
		}
		time.Sleep(3500 * time.Millisecond)
		synctest.Wait()
		for range 2 {
			select {
			case err := <-results:
				if err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatal("exchange did not recover after common broker subscription retry")
			}
		}
		if commonA.callCount() != 2 || commonB.callCount() != 1 {
			t.Fatalf("unexpected subscription calls: %d/%d", commonA.callCount(), commonB.callCount())
		}
	})
}

func TestMQTTP2PPreparationSharesBudgetAcrossTopics(t *testing.T) {
	for _, scenario := range []string{"slow-success", "shared-deadline", "parent-deadline"} {
		t.Run(scenario, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				address := topicFromSaltAndSessionUid("gonc-exchange-address", "session")
				client := &mqttRetrySubscribeStub{sub: func(topic string, _ int) mqtt.Token {
					token := &mqttTestToken{done: make(chan struct{})}
					if topic == address || scenario == "slow-success" {
						time.AfterFunc(8*time.Second, func() { close(token.done) })
					}
					return token
				}}
				s, _ := newMQTTRetryTestSession(ctx, client)
				s.clients = s.clients[1:]
				prepareCtx := ctx
				wantElapsed := 16 * time.Second
				if scenario == "shared-deadline" {
					wantElapsed = 25 * time.Second
				} else if scenario == "parent-deadline" {
					var stop context.CancelFunc
					prepareCtx, stop = context.WithTimeout(ctx, 12*time.Second)
					defer stop()
					wantElapsed = 12 * time.Second
				}
				started := time.Now()
				err := s.prepareP2PTopics(prepareCtx, "session")
				if elapsed := time.Since(started); elapsed != wantElapsed {
					t.Fatalf("elapsed=%s, want %s; err=%v", elapsed, wantElapsed, err)
				}
				if scenario == "slow-success" {
					if err != nil {
						t.Fatal(err)
					}
					// Ending the preparation context must not invalidate either
					// completed subscription or delay the later exchange.
					for _, salt := range []string{"gonc-exchange-address", "gonc-exchange-sync"} {
						if err := s.prepareTopic(ctx, salt, "session"); err != nil {
							t.Fatal(err)
						}
					}
					if client.callCount() != 2 {
						t.Fatal("slow successful subscription was retried or not reused")
					}
				} else if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "prepare MQTT sync topic") {
					t.Fatalf("wrong preparation error: %v", err)
				}
				if scenario == "shared-deadline" {
					times := client.callTimes()
					want := []time.Duration{0, 8 * time.Second, 19 * time.Second}
					if len(times) != len(want) {
						t.Fatalf("attempts=%d, want %d", len(times), len(want))
					}
					for i, at := range times {
						if at.Sub(started) != want[i] {
							t.Fatalf("attempt %d at %s, want %s", i, at.Sub(started), want[i])
						}
					}
				}
				if ctx.Err() != nil {
					t.Fatal("preparation canceled the shared session")
				}
			})
		})
	}
}
