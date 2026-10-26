package easyp2p

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

func TestMQTTIdleWaitSurvivesOvernightOutageWithoutRepeatedLogs(t *testing.T) {
	for _, initiallyOffline := range []bool{false, true} {
		name := "disconnect-after-subscription"
		if initiallyOffline {
			name = "offline-at-startup"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				client := &mqttRetrySubscribeStub{sub: func(string, int) mqtt.Token {
					return mqttCompletedTestToken(nil)
				}}
				s, output := newMQTTRetryTestSession(ctx, client)
				s.clients = s.clients[1:]
				if initiallyOffline {
					s.clients = nil
				}
				const salt, uid = "wait", "overnight"
				topic := topicFromSaltAndSessionUid(salt, uid)
				type result struct {
					data string
					err  error
				}
				done := make(chan result, 1)
				go func() {
					data, _, _, err := s.exchange(ctx, EXMODE_waitOnly, "", salt, uid, 0, nil, mqttNoPreferredBroker)
					done <- result{data, err}
				}()
				synctest.Wait()
				client.mu.Lock()
				client.disconnected = true
				client.mu.Unlock()
				s.brokerConnectionLost(client, 1, io.EOF)
				// Simulate reconnect failures throughout eight hours of idle waiting.
				for range 16 {
					for range 3 {
						s.connectionNotification(1, mqtt.ConnectionNotificationFailed{Reason: io.EOF})
					}
					time.Sleep(30 * time.Minute)
					synctest.Wait()
					select {
					case got := <-done:
						t.Fatalf("idle wait ended: %+v", got)
					default:
					}
					if count := strings.Count(output.String(), "broker unavailable for subscription:"); count != 1 {
						t.Fatalf("failure logs=%d, want one: %s", count, output.String())
					}
				}
				client.mu.Lock()
				client.disconnected = false
				client.mu.Unlock()
				s.brokerConnected(client, 1)
				synctest.Wait()
				if s.subscribedCount(topic) != 1 || strings.Count(output.String(), "broker subscription recovered:") != 1 {
					t.Fatalf("subscription did not recover once: %s", output.String())
				}
				before := output.String()
				time.Sleep(time.Hour)
				synctest.Wait()
				if output.String() != before {
					t.Fatal("healthy idle wait repeated recovery log")
				}
				s.dispatchMessage(topic, 1, "SYN@late-peer")
				synctest.Wait()
				select {
				case got := <-done:
					if got.err != nil || got.data != "SYN@late-peer" {
						t.Fatalf("late wakeup = %+v", got)
					}
				default:
					t.Fatal("late wakeup did not finish idle wait")
				}
			})
		})
	}
}

func TestMQTTUnlimitedWaitHonorsCancellationAndParentDeadline(t *testing.T) {
	for _, subscribed := range []bool{false, true} {
		for _, stop := range []string{"cancel", "deadline", "close"} {
			t.Run(stop+"/subscribed="+map[bool]string{false: "false", true: "true"}[subscribed], func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					s, _ := newStalledSubscribeSession(ctx)
					s.cancel = cancel
					s.clients = s.clients[:1]
					if !subscribed {
						s.clients = nil
					}
					parent, cancelParent := context.WithCancelCause(context.Background())
					defer cancelParent(nil)
					if stop == "deadline" {
						var cancelDeadline context.CancelFunc
						parent, cancelDeadline = context.WithTimeout(parent, time.Hour)
						defer cancelDeadline()
					}
					done := make(chan error, 1)
					go func() {
						_, _, _, err := s.exchange(parent, EXMODE_waitOnly, "", "wait", "cancel", 0, nil, mqttNoPreferredBroker)
						done <- err
					}()
					synctest.Wait()
					want := errors.New("listener stopped")
					switch stop {
					case "cancel":
						cancelParent(want)
					case "deadline":
						time.Sleep(time.Hour)
						want = context.DeadlineExceeded
					case "close":
						s.Close()
					}
					synctest.Wait()
					select {
					case err := <-done:
						if stop == "close" {
							if err == nil || !strings.Contains(err.Error(), "session closed") {
								t.Fatalf("close error = %v", err)
							}
						} else if !errors.Is(err, want) {
							t.Fatalf("error = %v, want %v", err, want)
						}
					default:
						t.Fatal("idle wait did not stop")
					}
				})
			})
		}
	}
}

func TestMQTTPassiveSessionStartsBeforeBrokerHandshake(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// The broker never sends CONNACK. A passive session must still start,
	// leaving connection/subscription retries to its background workers.
	s, _, _, err := startMQTTSignalSession(ctx, []string{"tcp://" + listener.Addr().String()}, "passive-start", "", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if ctx.Err() != nil || s.ctx.Err() != nil {
		t.Fatal("passive startup waited for a broker handshake")
	}
	cancel()
}
