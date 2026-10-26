package easyp2p

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strings"
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
	diagnostics mqttReceiveDiagnostics
	selfPayload string
	handler     func(string) (bool, error)
	recvCh      chan mqttSignalRecvPayload
	errCh       chan error
}

type mqttSignalClient struct {
	client mqtt.Client
	index  int
}

type mqttSubscriptionAttempt struct {
	cancel context.CancelFunc
	done   bool
}

type mqttSignalFailureKey struct {
	broker int
	topic  string // Empty for a connection attempt, which affects every topic.
}

type mqttSignalFailure struct {
	count   int
	alerted bool
	lastErr error
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
	mqttPublishKeepAlive      = 5 * time.Second
	mqttPublishTickerInterval = 2 * time.Second
	mqttConnectTimeout        = 15 * time.Second
	mqttInitialConnectTimeout = 15 * time.Second
	mqttWriteTimeout          = 5 * time.Second
	mqttSubscribeTimeout      = 10 * time.Second
	mqttPrepareTopicsTimeout  = 25 * time.Second
	mqttSubscribeRetryMax     = 10 * time.Second
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
	subscribing   map[string]map[int]*mqttSubscriptionAttempt
	subChanged    chan struct{}
	loggedSubs    map[string]struct{}
	failures      map[mqttSignalFailureKey]*mqttSignalFailure
	waiters       map[string]map[*mqttSignalWaiter]struct{}
	pending       map[string]mqttSignalRecvPayload
	closed        bool
}

func NewMQTTSignalSession(ctx context.Context, clientID, localIP string, logWriter io.Writer) (*MQTTSignalSession, error) {
	return newMQTTSignalSession(ctx, MQTTBrokerServers, clientID, localIP, logWriter)
}

func newMQTTSignalSession(ctx context.Context, brokerServers []string, clientID, localIP string, logWriter io.Writer) (*MQTTSignalSession, error) {
	s, ready, fail, err := startMQTTSignalSession(ctx, brokerServers, clientID, localIP, logWriter)
	if err != nil {
		return nil, err
	}
	if err := s.waitForFirstConnection(ready, fail); err != nil {
		return nil, err
	}
	return s, nil
}

// startMQTTSignalSession starts reconnecting without requiring an available
// broker at startup. Passive listeners can wait for subscriptions on this same
// session indefinitely, retaining failure/recovery log state during outages.
func startMQTTSignalSession(ctx context.Context, brokerServers []string, clientID, localIP string, logWriter io.Writer) (*MQTTSignalSession, <-chan struct{}, <-chan struct{}, error) {
	if cause := context.Cause(ctx); cause != nil {
		return nil, nil, nil, cause
	}
	if len(brokerServers) == 0 {
		return nil, nil, nil, fmt.Errorf("no MQTT broker servers configured")
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
		Timeout: mqttConnectTimeout,
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

	return s, ready, fail, nil
}

func (s *MQTTSignalSession) waitForFirstConnection(ready, fail <-chan struct{}) (err error) {
	// This deadline bounds only startup, not the lifetime of a usable session.
	ctx, cancel := context.WithTimeout(s.ctx, mqttInitialConnectTimeout)
	defer cancel()
	defer func() {
		if err != nil {
			s.cancel()
			s.Close()
		}
	}()
	started := time.Now()
	failCount := 0
	for {
		if cause := context.Cause(ctx); cause != nil {
			return s.initialConnectionError(started, cause)
		}
		select {
		case <-ready:
			if cause := context.Cause(ctx); cause != nil {
				return s.initialConnectionError(started, cause)
			}
			return nil
		case <-fail:
			failCount++
			if failCount == len(s.brokers) {
				return s.initialConnectionError(started, fmt.Errorf("all broker connection attempts ended"))
			}
		case <-ctx.Done():
		}
	}
}

func (s *MQTTSignalSession) initialConnectionError(started time.Time, cause error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	details := make([]string, 0, len(s.brokers))
	for index := range s.brokers {
		status := "connection not confirmed"
		if failure := s.failures[mqttSignalFailureKey{broker: index}]; failure != nil && failure.lastErr != nil {
			status = fmt.Sprintf("last connection error: %v", failure.lastErr)
		}
		details = append(details, fmt.Sprintf("%s: %s", s.brokerName(index), status))
	}
	return fmt.Errorf("MQTT initial connection failed after %s: %w (%s)", time.Since(started).Round(time.Millisecond), cause, strings.Join(details, "; "))
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
		SetConnectTimeout(mqttConnectTimeout).
		SetWriteTimeout(mqttWriteTimeout).
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
		s.brokerConnected(c, index)
		select {
		case ready <- struct{}{}:
		default:
		}
	}
	opts.OnConnectionLost = func(c mqtt.Client, err error) {
		s.brokerConnectionLost(c, index, err)
	}
	opts.OnConnectionNotification = func(_ mqtt.Client, notification mqtt.ConnectionNotification) {
		s.connectionNotification(index, notification)
	}

	client := mqtt.NewClient(opts)
	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil {
		s.mu.Unlock()
		return
	}
	s.allClients = append(s.allClients, client)
	// Register and start atomically with respect to Close, so it cannot miss
	// this client or disconnect it before Connect starts. Connect is async.
	token := client.Connect()
	s.mu.Unlock()

	if err := waitMQTTTokenContext(s.ctx, token); err != nil {
		select {
		case fail <- struct{}{}:
		case <-s.ctx.Done():
		}
		return
	}

	if s.ctx.Err() != nil {
		client.Disconnect(250)
	}
}

func (s *MQTTSignalSession) brokerConnected(c mqtt.Client, index int) {
	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil {
		s.mu.Unlock()
		return
	}
	s.invalidateSubscriptionsLocked(index)
	if failure := s.failures[mqttSignalFailureKey{broker: index}]; failure != nil {
		// Connection recovery resets the streak, but an alert is only resolved
		// when a subscription has actually become usable again.
		failure.count, failure.lastErr = 0, nil
	}
	found := false
	for _, client := range s.clients {
		found = found || client.index == index
	}
	if !found {
		s.clients = append(s.clients, mqttSignalClient{client: c, index: index})
	}
	for topic, qos := range s.subscriptions {
		s.ensureSubscriptionLocked(c, index, topic, qos)
	}
	s.mu.Unlock()
}

func (s *MQTTSignalSession) connectionNotification(index int, notification mqtt.ConnectionNotification) {
	// Paho emits BrokerFailed and Failed for one failed connection attempt.
	// Count only the latter, including failures during the MQTT handshake.
	failed, ok := notification.(mqtt.ConnectionNotificationFailed)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return
	}
	s.noteSubscriptionFailureLocked("", index, failed.Reason)
}

func (s *MQTTSignalSession) failureLocked(topic string, index int) *mqttSignalFailure {
	if s.failures == nil {
		s.failures = make(map[mqttSignalFailureKey]*mqttSignalFailure)
	}
	key := mqttSignalFailureKey{broker: index, topic: topic}
	if s.failures[key] == nil {
		s.failures[key] = &mqttSignalFailure{}
	}
	return s.failures[key]
}

func (s *MQTTSignalSession) noteSubscriptionFailureLocked(topic string, index int, err error) {
	failure := s.failureLocked(topic, index)
	failure.count++
	failure.lastErr = err
	if failure.count < 3 || failure.alerted {
		return
	}
	failure.alerted = true
	if topic == "" {
		s.logger.Printf("broker unavailable for subscription: %s; consecutive_failures=%d; reason=connect: %v\n", s.brokerName(index), failure.count, err)
	} else {
		s.logger.Printf("subscribe failed: topic=%s broker=%s; consecutive_failures=%d; reason=%v\n", topic, s.brokerName(index), failure.count, err)
	}
}

func (s *MQTTSignalSession) subscriptionRecoveredLocked(topic string, index int) {
	for _, scope := range []string{"", topic} {
		key := mqttSignalFailureKey{broker: index, topic: scope}
		if failure := s.failures[key]; failure != nil {
			if failure.alerted {
				if scope == "" {
					s.logger.Printf("broker subscription recovered: %s\n", s.brokerName(index))
				} else {
					s.logger.Printf("subscription recovered: topic=%s via %s\n", topic, s.brokerName(index))
				}
			}
			delete(s.failures, key)
		}
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

func (s *MQTTSignalSession) brokerConnectionLost(c mqtt.Client, index int, reason error) {
	s.mu.Lock()
	s.invalidateSubscriptionsLocked(index)
	if s.closed || s.ctx.Err() != nil {
		s.mu.Unlock()
		return
	}
	// Preserve the reason for a final diagnostic, without treating one loss
	// as multiple failed subscriptions or as a failed reconnect attempt.
	s.failureLocked("", index).lastErr = reason
	// Paho dispatches callbacks asynchronously. If reconnection already
	// finished, replace invalidated subscriptions before waking callers.
	for topic, qos := range s.subscriptions {
		s.ensureSubscriptionLocked(c, index, topic, qos)
	}
	s.mu.Unlock()
}

func (s *MQTTSignalSession) subscriptionStatusLocked(topic string) string {
	details := make([]string, 0, len(s.brokers))
	for index := range s.brokers {
		status := "not subscribed"
		if _, ok := s.subscribed[topic][index]; ok {
			status = "subscribed"
		} else if failure := s.failures[mqttSignalFailureKey{broker: index, topic: topic}]; failure != nil && failure.lastErr != nil {
			status = fmt.Sprintf("last subscribe error: %v", failure.lastErr)
		} else if failure := s.failures[mqttSignalFailureKey{broker: index}]; failure != nil && failure.lastErr != nil {
			status = fmt.Sprintf("last connection error: %v", failure.lastErr)
		}
		details = append(details, fmt.Sprintf("%s: %s", s.brokerName(index), status))
	}
	return strings.Join(details, "; ")
}

func (s *MQTTSignalSession) signalError(stage, topic string, cause error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fmt.Errorf("MQTT %s for topic %s: %w (%s)", stage, topic, cause, s.subscriptionStatusLocked(topic))
}

func (s *MQTTSignalSession) brokerName(index int) string {
	if index < 0 || index >= len(s.brokers) {
		return fmt.Sprintf("broker#%d", index)
	}
	address := s.brokers[index]
	if !strings.Contains(address, "://") {
		address = "//" + address
	}
	broker, err := url.Parse(address)
	if err == nil && broker.Hostname() != "" {
		return broker.Hostname()
	}
	// Never fall back to the raw URL, which can contain credentials.
	return fmt.Sprintf("broker#%d", index)
}

func (s *MQTTSignalSession) invalidateSubscriptionsLocked(index int) {
	for _, brokers := range s.subscribed {
		delete(brokers, index)
	}
	for _, attempts := range s.subscribing {
		if attempt := attempts[index]; attempt != nil {
			attempt.cancel()
			delete(attempts, index)
		}
	}
	s.notifySubscriptionsLocked()
}

// Wake every caller waiting for any broker, including brokers connected later.
func (s *MQTTSignalSession) notifySubscriptionsLocked() {
	if s.subChanged != nil {
		close(s.subChanged)
	}
	s.subChanged = make(chan struct{})
}

func (s *MQTTSignalSession) subscribedCount(topic string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.subscribed[topic])
}

func (s *MQTTSignalSession) subscribe(ctx context.Context, topic string, qos byte) error {
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("MQTT signal session closed")
	}
	s.subscriptions[topic] = qos
	for _, client := range s.clients {
		s.ensureSubscriptionLocked(client.client, client.index, topic, qos)
	}
	if s.subChanged == nil {
		s.subChanged = make(chan struct{})
	}
	for {
		if cause := context.Cause(ctx); cause != nil {
			s.mu.Unlock()
			return s.signalError("subscription", topic, cause)
		}
		if s.closed || s.ctx.Err() != nil {
			s.mu.Unlock()
			return fmt.Errorf("MQTT signal session closed")
		}
		success := len(s.subscribed[topic])
		if success > 0 {
			s.mu.Unlock()
			return nil
		}
		// With no connected brokers, wait for OnConnect to restore the topic.
		// The caller's deadline still bounds this wait.
		changed := s.subChanged
		s.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return s.signalError("subscription", topic, context.Cause(ctx))
		case <-s.ctx.Done():
			return fmt.Errorf("MQTT signal session closed")
		}
		s.mu.Lock()
	}
}

func (s *MQTTSignalSession) prepareTopic(ctx context.Context, topicSalt, sessionUid string) error {
	return s.subscribe(ctx, topicFromSaltAndSessionUid(topicSalt, sessionUid), 1)
}

func (s *MQTTSignalSession) prepareP2PTopics(ctx context.Context, sessionUid string) error {
	// Both topics share one preparation budget, separate from STUN and the
	// later exchanges. Session-owned subscription retries outlive this wait.
	ctx, cancel := context.WithTimeout(ctx, mqttPrepareTopicsTimeout)
	defer cancel()
	for _, phase := range []string{"address", "sync"} {
		if err := s.prepareTopic(ctx, "gonc-exchange-"+phase, sessionUid); err != nil {
			return fmt.Errorf("failed to prepare MQTT %s topic: %w", phase, err)
		}
	}
	return nil
}

func (s *MQTTSignalSession) prepareP2PTopicsInBackground(ctx context.Context, sessionUid string) func() {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Preparation is opportunistic. Each exchange waits for its own topic
		// with its own deadline and reports any subscription failure there.
		_ = s.prepareP2PTopics(ctx, sessionUid)
	}()
	return func() {
		cancel()
		<-done
	}
}

// Share both completed subscriptions and in-flight requests across exchanges.
// Workers belong to the session, so returning after the first success does not
// cancel subscriptions on other brokers.
func (s *MQTTSignalSession) ensureSubscriptionLocked(c mqtt.Client, index int, topic string, qos byte) {
	if !c.IsConnectionOpen() {
		delete(s.subscribed[topic], index)
		return
	}
	if _, ok := s.subscribed[topic][index]; ok {
		return
	}
	if s.subscribing == nil {
		s.subscribing = make(map[string]map[int]*mqttSubscriptionAttempt)
	}
	if s.subscribing[topic] == nil {
		s.subscribing[topic] = make(map[int]*mqttSubscriptionAttempt)
	}
	if attempt := s.subscribing[topic][index]; attempt != nil && !attempt.done {
		return
	}
	ctx, cancel := context.WithCancel(s.ctx)
	attempt := &mqttSubscriptionAttempt{cancel: cancel}
	s.subscribing[topic][index] = attempt
	go s.runSubscription(ctx, c, index, topic, qos, attempt)
}

func (s *MQTTSignalSession) runSubscription(ctx context.Context, c mqtt.Client, index int, topic string, qos byte, attempt *mqttSubscriptionAttempt) {
	defer attempt.cancel()
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.subscribing[topic][index] == attempt {
			attempt.done = true
			s.notifySubscriptionsLocked()
		}
	}()
	delay := time.Second
	for {
		s.mu.Lock()
		current := s.subscribing[topic][index] == attempt && !s.closed && ctx.Err() == nil
		s.mu.Unlock()
		if !current || !c.IsConnectionOpen() {
			return
		}
		requestCtx, cancel := context.WithTimeout(ctx, mqttSubscribeTimeout)
		token := c.Subscribe(topic, qos, func(_ mqtt.Client, msg mqtt.Message) {
			s.dispatchMessage(msg.Topic(), index, string(msg.Payload()))
		})
		err := waitMQTTTokenContext(requestCtx, token)
		cancel()
		if err == nil {
			if result, ok := token.(interface{ Result() map[string]byte }); ok && result.Result()[topic] == 0x80 {
				err = fmt.Errorf("broker rejected MQTT subscription to %s", topic)
			}
		}
		s.mu.Lock()
		// A reconnect replaces the worker; its old token cannot mark the new
		// connection ready, count a failure, or start another retry.
		if s.subscribing[topic][index] != attempt || s.closed || ctx.Err() != nil || !c.IsConnectionOpen() {
			s.mu.Unlock()
			return
		}
		if err == nil {
			if s.subscribed[topic] == nil {
				s.subscribed[topic] = make(map[int]struct{})
			}
			s.subscribed[topic][index] = struct{}{}
			if s.loggedSubs == nil {
				s.loggedSubs = make(map[string]struct{})
			}
			if _, logged := s.loggedSubs[topic]; !logged {
				s.loggedSubs[topic] = struct{}{}
				s.logger.Printf("subscribed topic %s via %s\n", topic, s.brokerName(index))
			}
			s.subscriptionRecoveredLocked(topic, index)
			s.mu.Unlock()
			return
		}
		s.noteSubscriptionFailureLocked(topic, index, err)
		s.mu.Unlock()
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		delay = min(delay*2, mqttSubscribeRetryMax)
	}
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
		waiter.diagnostics.mu.Lock()
		waiter.diagnostics.self++
		waiter.diagnostics.mu.Unlock()
		return
	}
	if waiter.handler != nil {
		ok, err := waiter.handler(data)
		if err != nil {
			waiter.diagnostics.mu.Lock()
			waiter.diagnostics.handlerErrors++
			waiter.diagnostics.mu.Unlock()
			select {
			case waiter.errCh <- fmt.Errorf("handling message error from broker %d on topic %s: %w", index, topic, err):
			default:
			}
			return
		}
		if !ok {
			waiter.diagnostics.mu.Lock()
			waiter.diagnostics.filtered++
			waiter.diagnostics.mu.Unlock()
			return
		}
	}
	waiter.diagnostics.mu.Lock()
	defer waiter.diagnostics.mu.Unlock()
	waiter.diagnostics.valid++
	select {
	case waiter.recvCh <- mqttSignalRecvPayload{data: data, index: index}:
		if waiter.diagnostics.enqueued == 0 {
			waiter.diagnostics.firstQueuedBroker = index
		}
		waiter.diagnostics.enqueued++
	default:
	}
}

func publishAtLeastN(ctx context.Context, clients []mqttSignalClient, topic string, qos byte, payload string, minSuccess int, diagnostics *mqttPublishDiagnostics) int {
	if ctx.Err() != nil || len(clients) == 0 {
		return 0
	}
	if minSuccess <= 0 || minSuccess > len(clients) {
		minSuccess = len(clients)
	}

	var wg sync.WaitGroup
	successCh := make(chan struct{}, len(clients))

	for _, c := range clients {
		wg.Add(1)
		go func(client mqttSignalClient) {
			defer wg.Done()
			if ctx.Err() != nil {
				return
			}
			token := diagnostics.publish(client, topic, qos, payload)
			if waitMQTTTokenContext(ctx, token) == nil {
				select {
				case successCh <- struct{}{}:
				case <-ctx.Done():
				}
			}
		}(c)
	}

	go func() {
		wg.Wait()
		close(successCh)
	}()

	count := 0
	for {
		select {
		case _, ok := <-successCh:
			if !ok {
				return count
			}
			count++
			if count >= minSuccess {
				return count
			}
		case <-ctx.Done():
			return count
		}
	}
}

func (s *MQTTSignalSession) publish(ctx context.Context, topic string, qos byte, payload string, minSuccess int, diagnostics *mqttPublishDiagnostics) int {
	return publishAtLeastN(ctx, s.clientsSnapshot(), topic, qos, payload, minSuccess, diagnostics)
}

// Keep one pending publish per broker until its result is known. A slow PUBACK
// remains eligible for success while other brokers and retries participate.
func (s *MQTTSignalSession) publishReply(ctx context.Context, topic string, qos byte, payload string, preferredBrokerIndex int) (int, error) {
	ctx, cancel := context.WithCancelCause(ctx)
	stop := context.AfterFunc(s.ctx, func() { cancel(context.Cause(s.ctx)) })
	defer stop()
	defer cancel(context.Canceled)
	started := time.Now()
	diagnostics := &mqttPublishDiagnostics{}
	type result struct {
		index int
		err   error
	}
	type state struct {
		pending bool
		err     error
		retryAt time.Time
	}
	states := make(map[int]*state)
	results := make(chan result)
	ticker := time.NewTicker(mqttPublishTickerInterval)
	defer ticker.Stop()
	for {
		if cause := context.Cause(ctx); cause != nil {
			details := make([]string, 0, len(s.brokers))
			for index := range s.brokers {
				status := "not connected"
				if st := states[index]; st != nil {
					if st.pending {
						status = "publish incomplete"
					} else if st.err != nil {
						status = st.err.Error()
					}
					if st.pending && st.err != nil {
						status += "; last error: " + st.err.Error()
					}
				}
				details = append(details, fmt.Sprintf("%s: %s", s.brokerName(index), status))
			}
			err := fmt.Errorf("MQTT reply publish unconfirmed after %s: %w (%s); %s", time.Since(started).Round(time.Millisecond), cause, strings.Join(details, "; "), diagnostics.summary(s))
			s.logger.Printf("topic %s: %v\n", topic, err)
			return -1, err
		}
		// Take the notification channel and client snapshot under the same lock
		// so a newly connected broker cannot be missed between the two reads.
		s.mu.Lock()
		if s.subChanged == nil {
			s.subChanged = make(chan struct{})
		}
		changed := s.subChanged
		clients := append([]mqttSignalClient(nil), s.clients...)
		s.mu.Unlock()
		for i, client := range clients {
			if client.index == preferredBrokerIndex {
				clients[0], clients[i] = clients[i], clients[0]
				break
			}
		}
		for _, client := range clients {
			st := states[client.index]
			if st == nil {
				st = &state{}
				states[client.index] = st
			}
			if st.pending || time.Now().Before(st.retryAt) {
				continue
			}
			if !client.client.IsConnectionOpen() {
				st.err = fmt.Errorf("not connected")
				continue
			}
			st.pending = true
			go func() {
				token := diagnostics.publish(client, topic, qos, payload)
				err := waitMQTTTokenContext(ctx, token)
				select {
				case results <- result{index: client.index, err: err}:
				case <-ctx.Done():
				}
			}()
		}
		select {
		case r := <-results:
			if r.err == nil {
				s.logger.Printf("ACK publish confirmed by broker %s; SYN received via %s; topic=%s\n", s.brokerName(r.index), s.brokerName(preferredBrokerIndex), topic)
				return r.index, nil
			}
			st := states[r.index]
			st.pending, st.err = false, r.err
			st.retryAt = time.Now().Add(mqttPublishTickerInterval)
		case <-changed:
		case <-ticker.C:
		case <-ctx.Done():
		}
	}
}

func (s *MQTTSignalSession) exchange(ctx context.Context, exmode int, sendData, topicSalt, sessionUid string, timeout time.Duration, messageHandler func(string) (bool, error), preferredBrokerIndex int) (recvData string, recvIndex int, keepAlive bool, err error) {
	var qos byte = 1
	topic := topicFromSaltAndSessionUid(topicSalt, sessionUid)
	parentCtx := ctx
	if cause := context.Cause(parentCtx); cause != nil {
		return "", -1, false, cause
	}

	// A zero timeout is unlimited only for passive waiting. Active exchanges
	// retain their existing deadlines, and parent cancellation always applies.
	exchangeCtx := parentCtx
	var cancel context.CancelFunc
	if exmode == EXMODE_waitOnly && timeout == 0 {
		exchangeCtx, cancel = context.WithCancel(parentCtx)
	} else {
		exchangeCtx, cancel = context.WithTimeout(parentCtx, timeout)
	}
	defer cancel()

	if exmode != exmodePublishOnly {
		if err := s.subscribe(exchangeCtx, topic, qos); err != nil {
			return "", -1, false, err
		}
	}
	if cause := context.Cause(parentCtx); cause != nil {
		return "", -1, false, cause
	}
	// Successful exchanges keep publishing briefly after exchangeCtx ends.
	// Cancel this separate scope on failure or when the keep-alive window ends.
	publishCtx, stopPublisher := context.WithCancel(s.ctx)
	diagnostics := &mqttPublishDiagnostics{}
	defer func() {
		if !keepAlive {
			stopPublisher()
		}
	}()

	startBackgroundPublisher := func() {
		go func() {
			for _, delay := range mqttPublishBurstDelays {
				timer := time.NewTimer(delay)
				select {
				case <-publishCtx.Done():
					timer.Stop()
					return
				case <-timer.C:
					s.publish(publishCtx, topic, qos, sendData, 1, diagnostics)
				}
			}

			ticker := time.NewTicker(mqttPublishTickerInterval)
			defer ticker.Stop()
			for {
				select {
				case <-publishCtx.Done():
					return
				case <-ticker.C:
					s.publish(publishCtx, topic, qos, sendData, 1, diagnostics)
				}
			}
		}()
	}

	stopPublisherAfter := func(delay time.Duration) {
		timer := time.NewTimer(delay)
		go func() {
			defer timer.Stop()
			select {
			case <-timer.C:
				stopPublisher()
			case <-publishCtx.Done():
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
	var initialPublishWait time.Duration
	defer func() {
		if err != nil && waiter != nil {
			err = fmt.Errorf("%w; initial_publish_wait=%s; %s; %s", err, initialPublishWait.Round(time.Millisecond), diagnostics.summary(s), waiter.receiveSummary(s))
		}
	}()

	switch exmode {
	case EXMODE_waitOnly:
	case exmodePublishOnly:
		index, err := s.publishReply(exchangeCtx, topic, qos, sendData, preferredBrokerIndex)
		if err != nil {
			return "", -1, false, err
		}
		startBackgroundPublisher()
		stopPublisherAfter(mqttPublishKeepAlive)
		return "", index, true, nil
	default:
		started := time.Now()
		s.publish(exchangeCtx, topic, qos, sendData, 1, diagnostics)
		initialPublishWait = time.Since(started)
		startBackgroundPublisher()
	}

	select {
	case r := <-waiter.recvCh:
		if exmode != EXMODE_waitOnly {
			stopPublisherAfter(mqttPublishKeepAlive)
			go s.publish(publishCtx, topic, qos, sendData, 1, diagnostics)
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
		return "", -1, false, s.signalError("exchange", topic, fmt.Errorf("timeout waiting for remote data exchange (brokers=%d/%d subscribed=%d)", len(s.clientsSnapshot()), len(s.brokers), s.subscribedCount(topic)))
	case <-s.ctx.Done():
		stopPublisher()
		if cause := context.Cause(parentCtx); cause != nil {
			return "", -1, false, cause
		}
		return "", -1, false, fmt.Errorf("MQTT signal session closed")
	}
}
