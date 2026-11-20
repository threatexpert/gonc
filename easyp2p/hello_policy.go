package easyp2p

import (
	"errors"
	"time"
)

// ErrHelloWaitTimeout means Hello was published on a subscribed broker but no
// valid peer response arrived before the deadline. It does not prove the peer is offline.
var ErrHelloWaitTimeout = errors.New("hello response timeout")

type mqttExchangePolicy struct {
	hello     bool
	slowHello bool
}

func (p mqttExchangePolicy) retryInterval(elapsed time.Duration) time.Duration {
	if !p.slowHello {
		return mqttPublishTickerInterval
	}
	if elapsed < 30*time.Second {
		return 5 * time.Second
	}
	return 10 * time.Second
}

// Require publish confirmation and a still-subscribed connection on the same
// broker. Subscription, startup and transport failures must not become peer timeouts.
func (s *MQTTSignalSession) hasConfirmedHelloChannel(topic string, d *mqttPublishDiagnostics) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, client := range s.clients {
		if _, ok := s.subscribed[topic][client.index]; !ok || !client.client.IsConnectionOpen() {
			continue
		}
		if b := d.brokers[client.index]; b != nil {
			b.collect()
			if b.confirmed > 0 {
				return true
			}
		}
	}
	return false
}
