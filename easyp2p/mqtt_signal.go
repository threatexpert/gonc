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

func waitMQTTTokenContext(ctx context.Context, token mqtt.Token) error {
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	select {
	case <-token.Done():
		return token.Error()
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

const (
	mqttNoPreferredBroker     = -1
	mqttPublishSettleWindow   = 500 * time.Millisecond
	mqttPreferredBrokerWindow = 800 * time.Millisecond
	mqttPublishKeepAlive      = 5 * time.Second
	mqttPublishTickerInterval = 2 * time.Second
)

var mqttPublishBurstDelays = []time.Duration{
	200 * time.Millisecond,
	800 * time.Millisecond,
	2 * time.Second,
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
	subscribed    map[string]map[int]struct{}
	loggedSubs    map[string]struct{}
	waiters       map[string]map[*mqttSignalWaiter]struct{}
	pending       map[string]mqttSignalRecvPayload
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
		clientID = MQTT_GenerateClientID(TopicDesc_Signal, "mqtt-signal-session", 0)
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
		subscribed:    make(map[string]map[int]struct{}),
		loggedSubs:    make(map[string]struct{}),
		waiters:       make(map[string]map[*mqttSignalWaiter]struct{}),
		pending:       make(map[string]mqttSignalRecvPayload),
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

	if err := waitMQTTTokenContext(s.ctx, client.Connect()); err != nil {
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
	topics := make(map[string]byte, len(s.subscriptions))
	for topic, qos := range s.subscriptions {
		topics[topic] = qos
	}
	s.mu.Unlock()

	s.logger.Printf("broker connected: %s (%d/%d)\n", brokerAddr, index+1, len(s.brokers))
	for topic, qos := range topics {
		s.subscribeClient(s.ctx, client, index, topic, qos)
	}

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
	quiesce := uint(250)
	if s.ctx.Err() != nil {
		quiesce = 0
	}
	s.cancel()
	allClients := append([]mqtt.Client(nil), s.allClients...)
	s.mu.Unlock()

	for _, c := range allClients {
		c.Disconnect(quiesce)
	}
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
		s.subscribeClient(s.ctx, c, index, topic, qos)
	}
}

func (s *MQTTSignalSession) brokerName(index int) string {
	if index < 0 || index >= len(s.brokers) {
		return fmt.Sprintf("broker#%d", index)
	}
	broker, _, err := ParseMQTTServerV3(s.brokers[index])
	if err != nil {
		return s.brokers[index]
	}
	return broker
}

func (s *MQTTSignalSession) markSubscribed(topic string, index int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.subscribed[topic] == nil {
		s.subscribed[topic] = make(map[int]struct{})
	}
	s.subscribed[topic][index] = struct{}{}
}

func (s *MQTTSignalSession) subscribedCount(topic string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.subscribed[topic])
}

func (s *MQTTSignalSession) subscribe(ctx context.Context, topic string, qos byte) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("MQTT signal session closed")
	}
	s.subscriptions[topic] = qos
	clients := make([]mqttSignalClient, len(s.clients))
	copy(clients, s.clients)
	s.mu.Unlock()

	success := 0
	for _, client := range clients {
		if s.subscribeClient(ctx, client.client, client.index, topic, qos) {
			success++
		}
	}
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	if success == 0 {
		s.mu.Lock()
		delete(s.subscriptions, topic)
		delete(s.subscribed, topic)
		delete(s.loggedSubs, topic)
		s.mu.Unlock()
		return fmt.Errorf("failed to subscribe MQTT topic %s", topic)
	}
	s.mu.Lock()
	_, logged := s.loggedSubs[topic]
	if !logged {
		s.loggedSubs[topic] = struct{}{}
	}
	s.mu.Unlock()
	if !logged {
		s.logger.Printf("subscribed topic %s via %d/%d brokers\n", topic, success, len(s.brokers))
	}
	return nil
}

func (s *MQTTSignalSession) prepareTopic(ctx context.Context, topicSalt, sessionUid string) error {
	return s.subscribe(ctx, topicFromSaltAndSessionUid(topicSalt, sessionUid), 1)
}

func (s *MQTTSignalSession) subscribeClient(ctx context.Context, c mqtt.Client, index int, topic string, qos byte) bool {
	token := c.Subscribe(topic, qos, func(_ mqtt.Client, msg mqtt.Message) {
		s.dispatchMessage(msg.Topic(), index, string(msg.Payload()))
	})
	ok := waitMQTTTokenContext(ctx, token) == nil
	if ok {
		s.markSubscribed(topic, index)
	}
	return ok
}

func (s *MQTTSignalSession) addWaiter(topic string, waiter *mqttSignalWaiter) func() {
	s.mu.Lock()
	if s.waiters[topic] == nil {
		s.waiters[topic] = make(map[*mqttSignalWaiter]struct{})
	}
	s.waiters[topic][waiter] = struct{}{}
	pending, hasPending := s.pending[topic]
	delete(s.pending, topic)
	s.mu.Unlock()

	if hasPending {
		s.deliverMessage(waiter, topic, pending.index, pending.data)
	}

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
	if len(waiters) == 0 {
		if s.pending == nil {
			s.pending = make(map[string]mqttSignalRecvPayload)
		}
		s.pending[topic] = mqttSignalRecvPayload{data: data, index: index}
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	for _, waiter := range waiters {
		s.deliverMessage(waiter, topic, index, data)
	}
}

func (s *MQTTSignalSession) deliverMessage(waiter *mqttSignalWaiter, topic string, index int, data string) {
	if data == waiter.selfPayload {
		return
	}
	if waiter.handler != nil {
		ok, err := waiter.handler(data)
		if err != nil {
			select {
			case waiter.errCh <- fmt.Errorf("handling message error from broker %d on topic %s: %w", index, topic, err):
			default:
			}
			return
		}
		if !ok {
			return
		}
	}
	select {
	case waiter.recvCh <- mqttSignalRecvPayload{data: data, index: index}:
	default:
	}
}

func publishAtLeastN(ctx context.Context, clients []mqttSignalClient, topic string, qos byte, payload string, minSuccess int, settleWindow time.Duration) int {
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
			if waitMQTTTokenContext(ctx, token) == nil {
				select {
				case successCh <- struct{}{}:
				case <-ctx.Done():
				}
			}
		}(c.client)
	}

	go func() {
		wg.Wait()
		close(successCh)
	}()

	var timer <-chan time.Time
	var stopTimer func()
	if settleWindow > 0 {
		t := time.NewTimer(settleWindow)
		timer = t.C
		stopTimer = func() {
			if !t.Stop() {
				select {
				case <-t.C:
				default:
				}
			}
		}
	} else {
		stopTimer = func() {}
	}
	defer stopTimer()

	count := 0
	for {
		select {
		case _, ok := <-successCh:
			if !ok {
				return count
			}
			count++
			if settleWindow <= 0 && count >= minSuccess {
				return count
			}
		case <-timer:
			return count
		case <-ctx.Done():
			return count
		}
	}
}

func (s *MQTTSignalSession) publish(ctx context.Context, topic string, qos byte, payload string, minSuccess int, settleWindow time.Duration) int {
	return publishAtLeastN(ctx, s.clientsSnapshot(), topic, qos, payload, minSuccess, settleWindow)
}

func (s *MQTTSignalSession) publishPreferred(ctx context.Context, topic string, qos byte, payload string, preferredBrokerIndex int) int {
	if preferredBrokerIndex < 0 {
		return 0
	}
	clients := s.clientsSnapshot()
	preferredClients := make([]mqttSignalClient, 0, 1)
	for _, client := range clients {
		if client.index == preferredBrokerIndex {
			preferredClients = append(preferredClients, client)
		}
	}
	success := publishAtLeastN(ctx, preferredClients, topic, qos, payload, 1, mqttPreferredBrokerWindow)
	if success > 0 {
		s.logger.Printf("published topic %s via preferred broker %s\n", topic, s.brokerName(preferredBrokerIndex))
	} else {
		s.logger.Printf("preferred broker publish missed for topic %s via %s\n", topic, s.brokerName(preferredBrokerIndex))
	}
	return success
}

func (s *MQTTSignalSession) exchange(ctx context.Context, exmode int, sendData, topicSalt, sessionUid string, timeout time.Duration, messageHandler func(string) (bool, error), preferredBrokerIndex int) (recvData string, recvIndex int, keepAlive bool, err error) {
	var qos byte = 1
	topic := topicFromSaltAndSessionUid(topicSalt, sessionUid)
	parentCtx := ctx
	if cause := context.Cause(parentCtx); cause != nil {
		return "", -1, false, cause
	}

	exchangeCtx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	if exmode != exmodePublishOnly {
		if err := s.subscribe(exchangeCtx, topic, qos); err != nil {
			return "", -1, false, err
		}
	}
	if cause := context.Cause(parentCtx); cause != nil {
		return "", -1, false, cause
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
			for _, delay := range mqttPublishBurstDelays {
				timer := time.NewTimer(delay)
				select {
				case <-stopPublish:
					timer.Stop()
					return
				case <-s.ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
					s.publish(s.ctx, topic, qos, sendData, 1, 0)
				}
			}

			ticker := time.NewTicker(mqttPublishTickerInterval)
			defer ticker.Stop()
			for {
				select {
				case <-stopPublish:
					return
				case <-s.ctx.Done():
					return
				case <-ticker.C:
					s.publish(s.ctx, topic, qos, sendData, 1, 0)
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
	case EXMODE_waitOnly:
	case exmodePublishOnly:
		success := s.publishPreferred(exchangeCtx, topic, qos, sendData, preferredBrokerIndex)
		if success == 0 {
			success = s.publish(exchangeCtx, topic, qos, sendData, 1, mqttPublishSettleWindow)
		}
		if success == 0 {
			return "", -1, false, fmt.Errorf("failed to publish MQTT reply")
		}
		startBackgroundPublisher()
		stopPublisherAfter(mqttPublishKeepAlive)
		return "", preferredBrokerIndex, true, nil
	default:
		s.publish(exchangeCtx, topic, qos, sendData, 1, 0)
		startBackgroundPublisher()
	}

	select {
	case r := <-waiter.recvCh:
		if exmode != EXMODE_waitOnly {
			s.publish(s.ctx, topic, qos, sendData, 1, 0)
			stopPublisherAfter(mqttPublishKeepAlive)
			keepAlive = true
		} else {
			stopPublisher()
		}
		return r.data, r.index, keepAlive, nil
	case err := <-waiter.errCh:
		stopPublisher()
		return "", -1, false, err
	case <-exchangeCtx.Done():
		stopPublisher()
		if cause := context.Cause(parentCtx); cause != nil {
			return "", -1, false, cause
		}
		return "", -1, false, fmt.Errorf("timeout waiting for remote data exchange on topic %s (brokers=%d/%d subscribed=%d)", topic, len(s.clientsSnapshot()), len(s.brokers), s.subscribedCount(topic))
	case <-s.ctx.Done():
		stopPublisher()
		if cause := context.Cause(parentCtx); cause != nil {
			return "", -1, false, cause
		}
		return "", -1, false, fmt.Errorf("MQTT signal session closed")
	}
}
