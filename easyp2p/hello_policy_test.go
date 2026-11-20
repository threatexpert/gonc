package easyp2p

import (
	"context"
	"errors"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"testing"
	"testing/synctest"
	"time"
)

func TestLongHelloWaitRateAndTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &mqttLifecyclePublishStub{pub: func(string, string, int) mqtt.Token { return mqttCompletedTestToken(nil) }}
		s, cancel := newMQTTLifecycleTestSession(t, client)
		defer cancel()
		start := time.Now()
		_, _, _, err := s.exchange(context.Background(), EXMODE_mutual, "SYN", "hello", "session", 5*time.Minute, nil, mqttNoPreferredBroker, mqttExchangePolicy{hello: true, slowHello: true})
		if !errors.Is(err, ErrHelloWaitTimeout) {
			t.Fatalf("timeout classification: %v", err)
		}
		if time.Since(start) != 5*time.Minute {
			t.Fatalf("wait = %s", time.Since(start))
		}
		times := client.callTimes()
		if len(times) < 35 || len(times) > 40 {
			t.Fatalf("5-minute publish count = %d", len(times))
		}
		for i := 1; i < len(times); i++ {
			if times[i-1].Sub(start) >= 30*time.Second && times[i].Sub(times[i-1]) < 10*time.Second {
				t.Fatalf("high frequency late publish: %v", times)
			}
		}
		count := len(times)
		time.Sleep(20 * time.Second)
		synctest.Wait()
		if len(client.callTimes()) != count {
			t.Fatal("publisher survived timeout")
		}
	})
}

func TestHelloLatePeerAndCancellation(t *testing.T) {
	for _, cancelEarly := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			client := &mqttLifecyclePublishStub{pub: func(string, string, int) mqtt.Token { return mqttCompletedTestToken(nil) }}
			s, cancel := newMQTTLifecycleTestSession(t, client)
			defer cancel()
			go func() {
				time.Sleep(2 * time.Minute)
				if cancelEarly {
					stop()
				} else {
					s.dispatchMessage(topicFromSaltAndSessionUid("hello", "session"), 0, "ACK")
				}
			}()
			start := time.Now()
			got, _, _, err := s.exchange(ctx, EXMODE_mutual, "SYN", "hello", "session", 5*time.Minute, nil, mqttNoPreferredBroker, mqttExchangePolicy{hello: true, slowHello: true})
			if time.Since(start) != 2*time.Minute {
				t.Fatalf("late peer/cancel not immediate: %s", time.Since(start))
			}
			if cancelEarly {
				if !errors.Is(err, context.Canceled) || errors.Is(err, ErrHelloWaitTimeout) {
					t.Fatalf("cancel: %v", err)
				}
			} else if err != nil || got != "ACK" {
				t.Fatalf("late peer: %q %v", got, err)
			}
		})
	}
}

func TestHelloTimeoutRequiresUsableChannel(t *testing.T) {
	for _, kind := range []string{"publish-failed", "disconnected", "subscription-failed", "non-hello"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client := &mqttLifecyclePublishStub{pub: func(string, string, int) mqtt.Token {
					if kind == "publish-failed" {
						return mqttCompletedTestToken(errors.New("network error"))
					}
					return mqttCompletedTestToken(nil)
				}}
				s, cancel := newMQTTLifecycleTestSession(t, client)
				defer cancel()
				if kind == "subscription-failed" {
					client.token = &mqttTestToken{done: make(chan struct{})}
				}
				if kind == "disconnected" {
					go func() {
						time.Sleep(5 * time.Second)
						client.mqttSubscribeStub.mu.Lock()
						client.disconnected = true
						client.mqttSubscribeStub.mu.Unlock()
					}()
				}
				start := time.Now()
				_, _, _, err := s.exchange(context.Background(), EXMODE_mutual, "SYN", "hello", "session", time.Minute, nil, mqttNoPreferredBroker, mqttExchangePolicy{hello: kind != "non-hello", slowHello: kind != "non-hello"})
				if err == nil || errors.Is(err, ErrHelloWaitTimeout) {
					t.Fatalf("misclassified %s: %v", kind, err)
				}
				if kind == "subscription-failed" && time.Since(start) > 25*time.Second {
					t.Fatal("subscription used the long peer deadline")
				}
				if kind == "non-hello" && len(client.callTimes()) < 30 {
					t.Fatal("non-Hello exchange was slowed")
				}
			})
		})
	}
}
