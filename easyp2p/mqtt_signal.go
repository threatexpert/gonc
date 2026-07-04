package easyp2p

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/threatexpert/gonc/v2/misc"
)

type mqttSignalRecvPayload struct {
	data  string
	index int
}

type mqttSignalWaiter struct {
	selfPayload string
	handler     func(string) (bool, error)
	recvCh      chan mqttSignalRecvPayload
	errCh       chan error
}

type mqttSignalClient struct {
	client mqtt.Client
	index  int
}

// MQTTSignalSession keeps broker connections alive across multiple signaling
// exchanges in the same P2P attempt.
type MQTTSignalSession struct {
	ctx    context.Context
	cancel context.CancelFunc

	brokers  []string
	clientID string
	localIP  string
	logger   *log.Logger

	mu            sync.Mutex
	clients       []mqttSignalClient
	allClients    []mqtt.Client
	subscriptions map[string]byte
	waiters       map[string]map[*mqttSignalWaiter]struct{}
	closed        bool
}

func NewMQTTSignalSession(ctx context.Context, clientID, localIP string, logWriter io.Writer) (*MQTTSignalSession, error) {
	return newMQTTSignalSession(ctx, MQTTBrokerServers, clientID, localIP, logWriter)
}

func newMQTTSignalSession(ctx context.Context, brokerServers []string, clientID, localIP string, logWriter io.Writer) (*MQTTSignalSession, error) {
	if len(brokerServers) == 0 {
		return nil, fmt.Errorf("no MQTT broker servers configured")
	}
	if clientID == "" {
		clientID = MQTT_GenerateClientID("SG", "mqtt-signal-session", 0)
	}

	if logWriter == nil {
		logWriter = io.Discard
	}

	sctx, cancel := context.WithCancel(ctx)
	s := &MQTTSignalSession{
		ctx:           sctx,
		cancel:        cancel,
		brokers:       append([]string(nil), brokerServers...),
		clientID:      clientID,
		localIP:       localIP,
		logger:        misc.NewLog(logWriter, "[MQTT] ", log.LstdFlags|log.Lmsgprefix),
		subscriptions: make(map[string]byte),
		waiters:       make(map[string]map[*mqttSignalWaiter]struct{}),
	}

	ready := make(chan struct{}, 1)
	fail := make(chan struct{}, len(brokerServers))

	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}
	if localIP != "" {
		if ip := net.ParseIP(localIP); ip != nil {
			dialer.LocalAddr = &net.TCPAddr{IP: ip}
		}
	}

	for i, server := range brokerServers {
		serverURL, q, _ := ParseMQTTServerV3(server)
		go s.connectBroker(serverURL, q, i, dialer, ready, fail)
	}

	successOrAllFail := make(chan struct{})
	go func() {
		failCount := 0
		for {
			select {
			case <-ready:
				successOrAllFail <- struct{}{}
				return
			case <-fail:
				failCount++
				if failCount == len(brokerServers) {
					successOrAllFail <- struct{}{}
					return
				}
			case <-sctx.Done():
				return
			}
		}
	}()

	select {
	case <-successOrAllFail:
	case <-sctx.Done():
	}

	if len(s.clientsSnapshot()) == 0 {
		s.Close()
		return nil, fmt.Errorf("failed to connect to any MQTT broker")
	}
	return s, nil
}

func (s *MQTTSignalSession) connectBroker(brokerAddr string, qvals url.Values, index int, dialer *net.Dialer, ready, fail chan<- struct{}) {
	select {
	case <-s.ctx.Done():
		return
	default:
	}

	opts := mqtt.NewClientOptions().
		AddBroker(brokerAddr).
		SetClientID(s.clientID).
		SetConnectTimeout(5 * time.Second).
		SetAutoReconnect(true).
		SetConnectRetry(true).
		SetConnectRetryInterval(3 * time.Second).
		SetDialer(dialer)

	var tlsConfig *tls.Config
	insecure := false
	if qvals.Get("insecure") == "1" || qvals.Get("insecure") == "true" {
		insecure = true
	}
	if qvals.Get("_scheme") == "tls" || qvals.Get("_scheme") == "ssl" {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: insecure,
		}
		if !insecure && net.ParseIP(qvals.Get("_host")) == nil {
			tlsConfig.ServerName = qvals.Get("_host")
		}
		if serverName := qvals.Get("servername"); serverName != "" {
			tlsConfig.ServerName = serverName
		}
	}
	if tlsConfig != nil {
		opts.SetTLSConfig(tlsConfig)
	}

	opts.OnConnect = func(c mqtt.Client) {
		if s.ctx.Err() != nil {
			return
		}
		s.resubscribeClient(c, index)
	}

	client := mqtt.NewClient(opts)
	s.mu.Lock()
	s.allClients = append(s.allClients, client)
	s.mu.Unlock()

	if token := client.Connect(); token.Wait() && token.Error() != nil {
		select {
		case fail <- struct{}{}:
		case <-s.ctx.Done():
		}
		return
	}

	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil {
		s.mu.Unlock()
		client.Disconnect(250)
		return
	}
	s.clients = append(s.clients, mqttSignalClient{client: client, index: index})
	s.mu.Unlock()

	s.logger.Printf("broker connected: %s (%d/%d)\n", brokerAddr, index+1, len(s.brokers))

	select {
	case ready <- struct{}{}:
	case <-s.ctx.Done():
	}
}

func (s *MQTTSignalSession) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.cancel()
	allClients := append([]mqtt.Client(nil), s.allClients...)
	s.mu.Unlock()

	for _, c := range allClients {
		c.Disconnect(250)
	}
	time.Sleep(500 * time.Millisecond)
}

func (s *MQTTSignalSession) clientsSnapshot() []mqttSignalClient {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]mqttSignalClient, len(s.clients))
	copy(out, s.clients)
	return out
}

func (s *MQTTSignalSession) resubscribeClient(c mqtt.Client, index int) {
	s.mu.Lock()
	topics := make(map[string]byte, len(s.subscriptions))
	for topic, qos := range s.subscriptions {
		topics[topic] = qos
	}
	s.mu.Unlock()

	for topic, qos := range topics {
		s.subscribeClient(c, index, topic, qos)
	}
}

func (s *MQTTSignalSession) subscribe(topic string, qos byte) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("MQTT signal session closed")
	}
	if _, ok := s.subscriptions[topic]; ok {
		s.mu.Unlock()
		return nil
	}
	s.subscriptions[topic] = qos
	clients := make([]mqttSignalClient, len(s.clients))
	copy(clients, s.clients)
	s.mu.Unlock()

	success := 0
	for _, client := range clients {
		if s.subscribeClient(client.client, client.index, topic, qos) {
			success++
		}
	}
	if success == 0 {
		s.mu.Lock()
		delete(s.subscriptions, topic)
		s.mu.Unlock()
		return fmt.Errorf("failed to subscribe MQTT topic")
	}
	return nil
}

func (s *MQTTSignalSession) subscribeClient(c mqtt.Client, index int, topic string, qos byte) bool {
	token := c.Subscribe(topic, qos, func(_ mqtt.Client, msg mqtt.Message) {
		s.dispatchMessage(msg.Topic(), index, string(msg.Payload()))
	})
	return token.Wait() && token.Error() == nil
}

func (s *MQTTSignalSession) addWaiter(topic string, waiter *mqttSignalWaiter) func() {
	s.mu.Lock()
	if s.waiters[topic] == nil {
		s.waiters[topic] = make(map[*mqttSignalWaiter]struct{})
	}
	s.waiters[topic][waiter] = struct{}{}
	s.mu.Unlock()

	return func() {
		s.mu.Lock()
		if waiters := s.waiters[topic]; waiters != nil {
			delete(waiters, waiter)
			if len(waiters) == 0 {
				delete(s.waiters, topic)
			}
		}
		s.mu.Unlock()
	}
}

func (s *MQTTSignalSession) dispatchMessage(topic string, index int, data string) {
	s.mu.Lock()
	waitersMap := s.waiters[topic]
	waiters := make([]*mqttSignalWaiter, 0, len(waitersMap))
	for waiter := range waitersMap {
		waiters = append(waiters, waiter)
	}
	s.mu.Unlock()

	for _, waiter := range waiters {
		if data == waiter.selfPayload {
			continue
		}
		if waiter.handler != nil {
			ok, err := waiter.handler(data)
			if err != nil {
				select {
				case waiter.errCh <- fmt.Errorf("handling message error from broker %d: %w", index, err):
				default:
				}
				continue
			}
			if !ok {
				continue
			}
		}
		select {
		case waiter.recvCh <- mqttSignalRecvPayload{data: data, index: index}:
		default:
		}
	}
}

func publishAtLeastN(clients []mqttSignalClient, topic string, qos byte, payload string, minSuccess int) int {
	if len(clients) == 0 {
		return 0
	}
	if minSuccess <= 0 || minSuccess > len(clients) {
		minSuccess = len(clients)
	}

	var wg sync.WaitGroup
	successCh := make(chan struct{}, len(clients))

	for _, c := range clients {
		wg.Add(1)
		go func(client mqtt.Client) {
			defer wg.Done()
			token := client.Publish(topic, qos, false, payload)
			if token.Wait() && token.Error() == nil {
				successCh <- struct{}{}
			}
		}(c.client)
	}

	go func() {
		wg.Wait()
		close(successCh)
	}()

	count := 0
	for range successCh {
		count++
		if count >= minSuccess {
			break
		}
	}
	return count
}

func (s *MQTTSignalSession) publish(topic string, qos byte, payload string, minSuccess int) int {
	return publishAtLeastN(s.clientsSnapshot(), topic, qos, payload, minSuccess)
}

func (s *MQTTSignalSession) exchange(ctx context.Context, exmode int, sendData, topicCID, topicSalt, sessionUid string, timeout time.Duration, messageHandler func(string) (bool, error)) (recvData string, recvIndex int, keepAlive bool, err error) {
	var qos byte = 1
	topic := topicFromSaltAndSessionUid(topicSalt, sessionUid)

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if exmode != exmodePublishOnly {
		if err := s.subscribe(topic, qos); err != nil {
			return "", -1, false, err
		}
	}
	stopPublish := make(chan struct{})
	var stopPublishOnce sync.Once
	stopPublisher := func() {
		stopPublishOnce.Do(func() {
			close(stopPublish)
		})
	}

	startBackgroundPublisher := func() {
		go func() {
			burstDelays := []time.Duration{
				200 * time.Millisecond,
				800 * time.Millisecond,
				2 * time.Second,
			}
			for _, delay := range burstDelays {
				timer := time.NewTimer(delay)
				select {
				case <-stopPublish:
					timer.Stop()
					return
				case <-s.ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
					s.publish(topic, qos, sendData, 1)
				}
			}

			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-stopPublish:
					return
				case <-s.ctx.Done():
					return
				case <-ticker.C:
					s.publish(topic, qos, sendData, 1)
				}
			}
		}()
	}

	stopPublisherAfter := func(delay time.Duration) {
		go func() {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-timer.C:
				stopPublisher()
			case <-s.ctx.Done():
				stopPublisher()
			}
		}()
	}

	var waiter *mqttSignalWaiter
	var removeWaiter func()
	if exmode != exmodePublishOnly {
		waiter = &mqttSignalWaiter{
			selfPayload: sendData,
			handler:     messageHandler,
			recvCh:      make(chan mqttSignalRecvPayload, 1),
			errCh:       make(chan error, 1),
		}
		removeWaiter = s.addWaiter(topic, waiter)
		defer removeWaiter()
	}

	switch exmode {
	case EXMODE_waitOnly, EXMODE_reply:
	case exmodePublishOnly:
		success := s.publish(topic, qos, sendData, 1)
		if success == 0 {
			return "", -1, false, fmt.Errorf("failed to publish MQTT reply")
		}
		startBackgroundPublisher()
		stopPublisherAfter(5 * time.Second)
		return "", 0, true, nil
	default:
		s.publish(topic, qos, sendData, 1)
		startBackgroundPublisher()
	}

	select {
	case r := <-waiter.recvCh:
		if exmode != EXMODE_waitOnly {
			s.publish(topic, qos, sendData, 1)
			stopPublisherAfter(5 * time.Second)
			keepAlive = true
		} else {
			stopPublisher()
		}
		return r.data, r.index, keepAlive, nil
	case err := <-waiter.errCh:
		stopPublisher()
		return "", -1, false, err
	case <-ctx.Done():
		stopPublisher()
		return "", -1, false, fmt.Errorf("timeout waiting for remote data exchange")
	case <-s.ctx.Done():
		stopPublisher()
		return "", -1, false, fmt.Errorf("MQTT signal session closed")
	}
}
