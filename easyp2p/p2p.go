package easyp2p

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/threatexpert/gonc/v2/misc"
	"github.com/threatexpert/gonc/v2/netx"
	"github.com/threatexpert/gonc/v2/secure"
)

const DefaultPunchingShortTTL = 5

var (
	TopicExchange              = "nat-exchange/"
	MQTTBrokerServers []string = []string{
		"tcp://broker.hivemq.com:1883",
		"tcp://broker.emqx.io:1883",
		"tcp://test.mosquitto.org:1883",
		"tcp://guest:guest@mqtt.gonc.cc:1883",
	}

	PunchingShortTTL        int = DefaultPunchingShortTTL
	PunchingRandomPortCount int = 600

	TopicDesc_WAIT            = "WT"
	TopicDesc_HELLO           = "HL"
	TopicDesc_ExchangeAddress = "EA"
	TopicDesc_RoundSync       = "RS"
)

type P2PAddressInfo struct {
	Network               string
	LocalLAN              string
	LocalNAT              string
	LocalNATType          string
	RemoteLAN             string
	RemoteNAT             string
	RemoteNATType         string
	SharedKey             [32]byte
	LocalPublicIPv4Count  int
	LocalPublicIPv6Count  int
	RemotePublicIPv4Count int
	RemotePublicIPv6Count int
	LocalBindIP           string
}

type securePayload struct {
	Nonce string `json:"nonce"`
	Data  string `json:"data"`
}

type UnRetryableError struct {
	Err error
}

func (e UnRetryableError) Error() string {
	return e.Err.Error()
}

func (e UnRetryableError) Unwrap() error {
	return e.Err
}

func WrapUnRetryable(err error) error {
	if err == nil {
		return nil
	}
	return UnRetryableError{Err: err}
}

func IsUnRetryable(err error) bool {
	var target UnRetryableError
	return err != nil && errors.As(err, &target)
}

func encryptAES(key, plaintext []byte) (*securePayload, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return &securePayload{
		Nonce: base64.StdEncoding.EncodeToString(nonce),
		Data:  base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

func decryptAES(key []byte, payload *securePayload) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce, err := base64.StdEncoding.DecodeString(payload.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(payload.Data)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, ciphertext, nil)
}

func CalculateMD5(input string) string {
	// 计算 MD5 哈希
	hash := md5.Sum([]byte(input))
	// 转换为十六进制字符串
	return hex.EncodeToString(hash[:])
}

func deriveKeyForTopic(salt, uid string) string {
	h := sha256.New()
	h.Write([]byte(salt))
	h.Write([]byte(CalculateMD5(uid)))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func deriveKeyForPayload(uid string, ascii bool) string {
	h := sha256.New()
	h.Write([]byte("gonc-p2p-payload"))
	h.Write([]byte(CalculateMD5(uid)))
	if ascii {
		return hex.EncodeToString(h.Sum(nil))[:8]
	} else {
		return string(h.Sum(nil)[:8])
	}
}

func deriveKey(salt, uid string) [32]byte {
	salt0 := "nc-p2p-tool"
	h := sha256.New()
	h.Write([]byte(salt0))
	h.Write([]byte(salt))
	h.Write([]byte(uid))
	return sha256.Sum256(h.Sum(nil))
}

func publishAtLeastN(clients []mqtt.Client, topic string, qos byte, payload string, minSuccess int) {
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
		}(c)
	}

	go func() {
		wg.Wait()
		close(successCh)
	}()

	// 等待至少 minSuccess 个成功或者所有尝试完成
	count := 0
	for range successCh {
		count++
		if count >= minSuccess {
			break
		}
	}
}

var (
	EXMODE_mutual   int = 0
	EXMODE_waitOnly int = 1
	EXMODE_reply    int = 2
)

func MQTT_SecureExchange[T any](ctx context.Context, exmode int, sendData any, topicCID, topicSalt, sessionUid, localIP string, timeout time.Duration, messageFilter func(T) (bool, error)) (recvData T, recvIndex int, err error) {
	var zero T
	myKey := deriveKey("mqtt-exchange-gonc-v2.2.0", sessionUid)
	infoBytes, _ := json.Marshal(sendData)
	encPayload, _ := encryptAES(myKey[:], infoBytes)
	encPayloadBytes, _ := json.Marshal(encPayload)

	decoder := func(data string) (T, error) {
		var zero T
		var remoteSecurePayload securePayload
		verIncomp := "possible version incompatibility with the peer"
		if err = json.Unmarshal([]byte(data), &remoteSecurePayload); err != nil {
			return zero, fmt.Errorf("failed to unmarshal remote secure payload: %w (%s)", err, verIncomp)
		}
		plain, err := decryptAES(myKey[:], &remoteSecurePayload)
		if err != nil {
			return zero, fmt.Errorf("failed to decrypt remote payload: %w (%s)", err, verIncomp)
		}
		var remotePayload T
		if err = json.Unmarshal(plain, &remotePayload); err != nil {
			return zero, fmt.Errorf("failed to unmarshal remote exchange payload: %w (%s)", err, verIncomp)
		}
		return remotePayload, nil
	}

	msgHandler := func(data string) (bool, error) {
		decodedData, err := decoder(data)
		if err != nil {
			return false, err
		}
		if messageFilter != nil {
			return messageFilter(decodedData)
		}
		return true, nil
	}

	remoteInfoRaw, srvIndex, err := MQTT_Exchange(ctx, exmode, string(encPayloadBytes), topicCID, topicSalt, sessionUid, localIP, timeout, msgHandler)
	if err != nil {
		return zero, srvIndex, err
	}
	remotePayload, err := decoder(remoteInfoRaw)
	return remotePayload, srvIndex, err
}

func topicFromSaltAndSessionUid(topicSalt, sessionUid string) string {
	return TopicExchange + deriveKeyForTopic(topicSalt, sessionUid)
}

// no longer than 23 characters
func MQTT_GenerateClientID(topicDesc, sessionUid string, seed int64) string {
	if seed == 0 {
		seed = secure.MakeSeed()
	}

	clientID_L8 := deriveKeyForTopic("mqtt-topic-gonc-cid", sessionUid)[:8]
	uidNano_L8 := secure.GenerateSeededRandomString(8, seed)

	return fmt.Sprintf("%s-%s-%s", topicDesc[:2], clientID_L8, uidNano_L8)
}

func MQTT_Exchange(ctx context.Context, exmode int, sendData, topicCID, topicSalt, sessionUid, localIP string, timeout time.Duration, messageHandler func(string) (bool, error)) (recvData string, recvIndex int, err error) {
	brokerServers := MQTTBrokerServers
	var qos byte = 1
	topic := topicFromSaltAndSessionUid(topicSalt, sessionUid)

	type recvPayload struct {
		data  string
		index int
	}

	var clients []mqtt.Client
	var clientsMu sync.Mutex
	recvRemoteData := make(chan recvPayload, 1)
	errChan := make(chan error, 1)

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer func() {
		clientsMu.Lock()
		for _, c := range clients {
			c.Disconnect(250)
		}
		clientsMu.Unlock()
		time.Sleep(500 * time.Millisecond)
	}()
	defer cancel() //放后面，因为要比上面的协程先执行，想实现cancel后不会有新的添加到clients

	ready := make(chan struct{}, 1)
	fail := make(chan struct{}, len(brokerServers))

	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}
	if localIP != "" {
		ip := net.ParseIP(localIP)
		if ip != nil {
			dialer.LocalAddr = &net.TCPAddr{IP: ip}
		}
	}

	// ---- 订阅函数：OnConnect / 首次连接 / 重连都会走这里 ----
	subscribeFn := func(c mqtt.Client, index int) {
		if token := c.Subscribe(topic, qos, func(_ mqtt.Client, msg mqtt.Message) {
			data := string(msg.Payload())
			if data == sendData {
				return
			}

			if messageHandler != nil {
				ok, err := messageHandler(data)
				if err != nil {
					select {
					case errChan <- fmt.Errorf(
						"handling message error from broker %d: %w",
						index, err,
					):
					default:
					}
					return
				}
				if !ok {
					return
				}
			}

			select {
			case recvRemoteData <- recvPayload{data, index}:
			default:
			}
		}); token.Wait() && token.Error() != nil {
			select {
			case fail <- struct{}{}:
			case <-ctx.Done():
			}
		}
	}

	for i, server := range brokerServers {
		serverURL, q, _ := ParseMQTTServerV3(server)
		go func(brokerAddr string, qvals url.Values, index int) {
			// ctx 已取消就不启动
			select {
			case <-ctx.Done():
				return
			default:
			}

			// ---- MQTT client options ----
			opts := mqtt.NewClientOptions().
				AddBroker(brokerAddr).
				SetClientID(topicCID).
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
				// 只有在不 insecure 的情况下才设置 ServerName
				if !insecure {
					// 如果是 IP，不要设置 ServerName
					if net.ParseIP(qvals.Get("_host")) == nil {
						tlsConfig.ServerName = qvals.Get("_host")
					}
				}
				serverName := qvals.Get("servername")
				if serverName != "" {
					tlsConfig.ServerName = serverName
				}
			}
			if tlsConfig != nil {
				opts.SetTLSConfig(tlsConfig)
			}

			// ---- OnConnect：每次连接成功都重新订阅 ----
			opts.OnConnect = func(c mqtt.Client) {
				if ctx.Err() != nil {
					return
				}
				subscribeFn(c, index)
			}

			// （可选但强烈建议）
			opts.OnConnectionLost = func(_ mqtt.Client, err error) {
				// 这里只记录，不做逻辑判断
				// 自动重连 + OnConnect 会负责恢复
			}

			client := mqtt.NewClient(opts)

			// ---- 首次 Connect ----
			if token := client.Connect(); token.Wait() && token.Error() != nil {
				select {
				case fail <- struct{}{}:
				case <-ctx.Done():
				}
				return
			}

			// ---- 注册 client ----
			clientsMu.Lock()
			if ctx.Err() != nil {
				clientsMu.Unlock()
				client.Disconnect(250)
				return
			}
			clients = append(clients, client)
			clientsMu.Unlock()

			// ---- 通知“至少有一个 broker 可用” ----
			select {
			case ready <- struct{}{}:
			case <-ctx.Done():
			}

		}(serverURL, q, i)
	}

	// 等待第一个成功连接或全部失败
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
			case <-ctx.Done():
				return
			}
		}
	}()

	select {
	case <-successOrAllFail:
	case <-ctx.Done():
	}

	if len(clients) == 0 {
		return "", -1, fmt.Errorf("failed to connect to any MQTT broker")
	}

	switch exmode {
	case EXMODE_waitOnly, EXMODE_reply:
		//不主动发布消息
	default:
		// 广播数据
		publishAtLeastN(clients, topic, qos, sendData, 2)
		// 定时重发 goroutine
		stopPublish := make(chan struct{})
		defer close(stopPublish)
		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-stopPublish:
					return
				case <-ctx.Done():
					return
				case <-ticker.C:
					publishAtLeastN(clients, topic, qos, sendData, 2)
				}
			}
		}()

	}

	select {
	case r := <-recvRemoteData:
		if exmode != EXMODE_waitOnly {
			publishAtLeastN(clients, topic, qos, sendData, 2)
		}
		return r.data, r.index, nil
	case err := <-errChan:
		return "", -1, err
	case <-ctx.Done():
		return "", -1, fmt.Errorf("timeout waiting for remote data exchange")
	}
}

type PunchingAddressInfo struct {
	Network string `json:"network"` // 网络名称, 例如 "tcp", "udp"
	NatType string `json:"nattype"` // NAT 类型
	Lan     string `json:"lan"`     // 局域网地址
	Nat     string `json:"nat"`     // 公网地址
}

type exchangeAddressPayload struct {
	// 地址信息列表
	Addresses []PunchingAddressInfo `json:"addrs"`
	// 公钥的 Base64 编码字符串
	PubKey string `json:"pk"`
}

type RelayPacketConn struct {
	net.PacketConn
	FallbackMode bool
}

func DetectNATAddressInfo(networks []string, bind string, relayConn *RelayPacketConn, logWriter io.Writer) ([]PunchingAddressInfo, []*STUNResult, error) {
	Addresses := []PunchingAddressInfo{}
	var allResults, directResults, relayResults []*STUNResult
	var err error

	fmt.Fprintf(logWriter, "    Getting local public IP info via %d STUN servers...", len(STUNServers))

	if relayConn == nil || !relayConn.FallbackMode {
		// 单轮 STUN 探测（无 relay 或直接使用 relay）
		if relayConn == nil {
			directResults, err = GetNetworksPublicIPs(networks, bind, 5*time.Second, nil)
		} else {
			relayResults, err = GetNetworksPublicIPs(networks, bind, 5*time.Second, relayConn)
		}
		allResults = append(directResults, relayResults...)
		if err != nil {
			fmt.Fprintf(logWriter, "Failed(%v)\n", err)
		} else {
			fmt.Fprintf(logWriter, "(%d answers)", succeededSTUNResults(allResults))
		}
	} else {
		// Fallback 模式，尝试两轮：先直连STUN获取地址信息，再走 relay获取地址信息
		// 第一轮（直连）
		directResults, _ = GetNetworksPublicIPs(networks, bind, 5*time.Second, nil)
		// 第二轮（使用中继）
		relayResults, err = GetNetworksPublicIPs(networks, bind, 5*time.Second, relayConn)
		// 合并
		allResults = append(directResults, relayResults...)
		if len(allResults) == 0 && err != nil {
			fmt.Fprintf(logWriter, "Failed(%v)\n", err)
		} else {
			fmt.Fprintf(logWriter, "(%d answers)", succeededSTUNResults(allResults))
			err = nil
		}
	}

	if len(allResults) > 0 {
		analyzed := analyzeSTUNResults(directResults)
		for _, item := range analyzed {
			Addresses = append(Addresses, PunchingAddressInfo{
				Network: item.Network,
				NatType: item.NATType,
				Lan:     item.LAN,
				Nat:     item.NAT,
			})
		}
		analyzed = analyzeSTUNResults(relayResults)
		for _, item := range analyzed {
			Addresses = append(Addresses, PunchingAddressInfo{
				Network: item.Network,
				NatType: "relay",
				Lan:     item.LAN,
				Nat:     item.NAT,
			})
		}

		if len(Addresses) == 0 {
			fmt.Fprintln(logWriter, "Failed")
		} else {
			fmt.Fprintf(logWriter, "OK\n")
			addressesPrint(logWriter, Addresses)
		}
	}

	return Addresses, allResults, err
}

func Do_autoP2PEx(networks []string, sessionUid string, timeout time.Duration, needSharedKey bool, relayConn *RelayPacketConn, logWriter io.Writer) ([]*P2PAddressInfo, error) {
	return Do_autoP2PEx2(context.Background(), networks, "", sessionUid, timeout, needSharedKey, relayConn, logWriter)
}

func Do_autoP2PEx2(ctx context.Context, networks []string, bind, sessionUid string, timeout time.Duration, needSharedKey bool, relayConn *RelayPacketConn, logWriter io.Writer) ([]*P2PAddressInfo, error) {

	myInfoForExchange := exchangeAddressPayload{
		Addresses: []PunchingAddressInfo{},
	}
	var err error
	localBindIP := ""
	if bind != "" {
		localBindIP, _, _ = net.SplitHostPort(bind)
	}

	myInfoForExchange.Addresses, _, _ = DetectNATAddressInfo(networks, bind, relayConn, logWriter)

	var priv *ecdsa.PrivateKey
	if needSharedKey && len(myInfoForExchange.Addresses) > 0 {
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
		}
		pubBytes := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
		myInfoForExchange.PubKey = base64.StdEncoding.EncodeToString(pubBytes)
	}

	fmt.Fprintf(logWriter, "    Exchanging address info with peer ...")
	topicCID := MQTT_GenerateClientID(TopicDesc_ExchangeAddress, sessionUid, 0)
	remotePayload, srvIndex, err := MQTT_SecureExchange[exchangeAddressPayload](
		ctx, EXMODE_mutual, myInfoForExchange, topicCID, "gonc-exchange-address", sessionUid, localBindIP, timeout, nil)
	if err != nil {
		fmt.Fprintf(logWriter, "Failed\n")
		return nil, err
	}

	brokerServer, _, _ := ParseMQTTServerV3(MQTTBrokerServers[srvIndex])
	fmt.Fprintf(logWriter, "OK (via %s)\n", brokerServer)

	addressesPrint(logWriter, remotePayload.Addresses)

	if len(myInfoForExchange.Addresses) == 0 || len(remotePayload.Addresses) == 0 {
		return nil, fmt.Errorf("no common usable network types with peer")
	}

	var sharedKey [32]byte
	if needSharedKey {
		if priv == nil || remotePayload.PubKey == "" {
			return nil, fmt.Errorf("missing public key from peer for key exchange")
		}
		remotePubBytes, err := base64.StdEncoding.DecodeString(remotePayload.PubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode peer's public key: %w", err)
		}
		x, y := elliptic.Unmarshal(elliptic.P256(), remotePubBytes)
		if x == nil {
			return nil, fmt.Errorf("invalid peer public key")
		}
		sharedX, _ := priv.PublicKey.Curve.ScalarMult(x, y, priv.D.Bytes())
		sharedKey = sha256.Sum256(sharedX.Bytes())
	}

	var finalResults []*P2PAddressInfo
	haveCommonNetwork := false
	LocalPublicIPv4Count := countUniquePublicIPs(myInfoForExchange.Addresses, "4")
	LocalPublicIPv6Count := countUniquePublicIPs(myInfoForExchange.Addresses, "6")
	RemotePublicIPv4Count := countUniquePublicIPs(remotePayload.Addresses, "4")
	RemotePublicIPv6Count := countUniquePublicIPs(remotePayload.Addresses, "6")

	for _, myNetInfo := range myInfoForExchange.Addresses {
		// 获取我们自己的地址组，支持多个地址
		net := myNetInfo.Network
		myNATType := myNetInfo.NatType
		myLAN := myNetInfo.Lan
		myNAT := myNetInfo.Nat

		// 检查对方是否也返回了相同网络类型的信息
		for _, remoteNetInfo := range remotePayload.Addresses {
			if remoteNetInfo.Network != net {
				continue
			}
			haveCommonNetwork = true
			rNATType := remoteNetInfo.NatType
			remoteLAN := remoteNetInfo.Lan
			remoteNAT := remoteNetInfo.Nat

			item := &P2PAddressInfo{
				Network:               net,
				LocalLAN:              myLAN,
				LocalNAT:              myNAT,
				LocalNATType:          myNATType,
				RemoteLAN:             remoteLAN,
				RemoteNAT:             remoteNAT,
				RemoteNATType:         rNATType,
				SharedKey:             sharedKey,
				LocalPublicIPv4Count:  LocalPublicIPv4Count,
				LocalPublicIPv6Count:  LocalPublicIPv6Count,
				RemotePublicIPv4Count: RemotePublicIPv4Count,
				RemotePublicIPv6Count: RemotePublicIPv6Count,
				LocalBindIP:           localBindIP,
			}

			//Priority == 0 means invalid type
			if getNATTypePriority(myNATType) == 0 || getNATTypePriority(rNATType) == 0 {
				continue
			}

			sameNAT, similarLAN := CompareP2PAddresses(item)

			if myNATType == "symm" && rNATType == "symm" {
				if !sameNAT || !similarLAN {
					continue
				}
				//对称型，但在相同内网，可以p2p
			}

			if strings.HasPrefix(net, "tcp") {
				if !sameNAT || !similarLAN {
					//TCP，如果不在相同内网，必须至少一端是easy的
					if myNATType != "easy" && rNATType != "easy" {
						continue
					}
				}
			}

			finalResults = append(finalResults, item)
		}
	}
	if len(finalResults) == 0 {
		if !haveCommonNetwork {
			return nil, fmt.Errorf("no common usable network types with peer")
		} else {
			return nil, fmt.Errorf("no usable NAT types with peer")
		}
	}

	return SortP2PAddressInfos(finalResults), nil
}

func Do_autoP2P(network string, sessionUid string, stunServers, brokerServers []string, timeout time.Duration, needSharedKey bool, logWriter io.Writer) (*P2PAddressInfo, error) {
	p2pInfos, err := Do_autoP2PEx([]string{network}, sessionUid, timeout, needSharedKey, nil, logWriter)
	if err != nil {
		return nil, err
	}

	return p2pInfos[0], nil
}

func addressesPrint(logWriter io.Writer, Addresses []PunchingAddressInfo) {
	for _, info := range Addresses {
		net := info.Network
		nattype := info.NatType
		lan := info.Lan
		nat := info.Nat
		if lan == nat {
			fmt.Fprintf(logWriter, "      %-5s: %s (%s)\n", net, nat, nattype)
		} else {
			fmt.Fprintf(logWriter, "      %-5s: LAN=%s | NAT=%s (%s)\n", net, lan, nat, nattype)
		}
	}
}

// 提取 IP（去掉端口）
func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// 不是 host:port 格式，尝试直接返回原始字符串
		if ip := net.ParseIP(addr); ip != nil {
			return addr
		}
		return ""
	}
	return host
}

func IsPeerSameLAN(conn net.Conn) bool {
	localIP, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return false
	}
	remoteIP, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return false
	}
	return IsSameLAN(localIP, remoteIP)
}

func IsSameLAN(ip1, ip2 string) bool {
	parsed1 := net.ParseIP(ip1)
	parsed2 := net.ParseIP(ip2)
	if parsed1 == nil || parsed2 == nil {
		return false
	}

	// 检查是否都是环回地址
	if parsed1.IsLoopback() && parsed2.IsLoopback() {
		return true
	}

	// IPv4 私有地址判断
	if parsed1.To4() != nil && parsed2.To4() != nil {
		if parsed1.IsPrivate() && parsed2.IsPrivate() {
			switch {
			case parsed1[12] == 10 && parsed2[12] == 10:
				return true // 10.0.0.0/8
			case parsed1[12] == 172 && parsed2[12] == 172 &&
				parsed1[13] >= 16 && parsed1[13] <= 31 &&
				parsed2[13] >= 16 && parsed2[13] <= 31:
				return parsed1[12] == parsed2[12] && parsed1[13] == parsed2[13]
			case parsed1[12] == 192 && parsed1[13] == 168 &&
				parsed2[12] == 192 && parsed2[13] == 168:
				return parsed1[12] == parsed2[12] && parsed1[13] == parsed2[13]
			}
		}
		parts1 := strings.Split(ip1, ".")
		parts2 := strings.Split(ip2, ".")
		if len(parts1) == 4 && len(parts2) == 4 {
			return parts1[0] == parts2[0] && parts1[1] == parts2[1] && parts1[2] == parts2[2]
		}
		return false
	}

	// IPv6 私有地址判断 (ULA, fc00::/7)
	if parsed1.IsPrivate() && parsed2.IsPrivate() {
		// 简单判断前 64 位是否相同（通常 IPv6 LAN 使用相同前缀）
		for i := 0; i < 8; i++ {
			if parsed1[i] != parsed2[i] {
				return false
			}
		}
		return true
	}
	return false
}

func CompareP2PAddresses(info *P2PAddressInfo) (sameNATIP bool, similarLAN bool) {
	natIP1 := extractIP(info.LocalNAT)
	natIP2 := extractIP(info.RemoteNAT)
	sameNATIP = (natIP1 != "" && natIP2 != "" && natIP1 == natIP2)

	lanIP1 := extractIP(info.LocalLAN)
	lanIP2 := extractIP(info.RemoteLAN)
	similarLAN = IsSameLAN(lanIP1, lanIP2)
	return
}

func IsIPv6(addr string) bool {
	ipStr, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(ipStr)
	return ip != nil && ip.To4() == nil
}

func SelectRole(p2pInfo *P2PAddressInfo) bool {
	role := os.Getenv("ROLE_DEBUG")
	if role == "C" || role == "S" {
		return role == "C"
	}

	//easy  -  easy		go Compare
	//easy  -  hard		S - C
	//easy  -  symm		S - C

	//hard  -  easy		C - S
	//hard  -  hard		go Compare
	//hard  -  symm		C - S

	//symm  -  easy		C - S
	//symm  -  hard		S - C

	//relay和哪个NAT类型都不需要讲究谁先主动打，反正relay有公网ip，且假设不应该有防火墙
	//其他包括relay的	go Compare

	//return true means C, false means S

	if p2pInfo.LocalNATType == "easy" && p2pInfo.RemoteNATType == "hard" {
		return false
	} else if p2pInfo.LocalNATType == "hard" && p2pInfo.RemoteNATType == "easy" {
		return true
	} else if p2pInfo.LocalNATType == "easy" && p2pInfo.RemoteNATType == "symm" {
		return false
	} else if p2pInfo.LocalNATType == "symm" && p2pInfo.RemoteNATType == "easy" {
		return true
	} else if p2pInfo.LocalNATType == "hard" && p2pInfo.RemoteNATType == "symm" {
		return true
	} else if p2pInfo.LocalNATType == "symm" && p2pInfo.RemoteNATType == "hard" {
		return false
	} else {
		return strings.Compare(CalculateMD5(p2pInfo.LocalLAN+p2pInfo.LocalNAT), CalculateMD5(p2pInfo.RemoteLAN+p2pInfo.RemoteNAT)) <= 0
	}
}

func p2pInfoPrint(logWriter io.Writer, p2pInfo *P2PAddressInfo) {
	fmt.Fprintf(logWriter, "  - %-14s: %s\n", "Network", p2pInfo.Network)
	if p2pInfo.LocalLAN == p2pInfo.LocalNAT {
		fmt.Fprintf(logWriter, "  - %-14s: %s (NAT-%s)\n", "Local Address", p2pInfo.LocalLAN, p2pInfo.LocalNATType)
	} else {
		fmt.Fprintf(logWriter, "  - %-14s: %s (LAN) / %s (NAT-%s)\n", "Local Address", p2pInfo.LocalLAN, p2pInfo.LocalNAT, p2pInfo.LocalNATType)
	}
	if p2pInfo.RemoteLAN == p2pInfo.RemoteNAT {
		fmt.Fprintf(logWriter, "  - %-14s: %s (NAT-%s)\n", "Remote Address", p2pInfo.RemoteLAN, p2pInfo.RemoteNATType)
	} else {
		fmt.Fprintf(logWriter, "  - %-14s: %s (LAN) / %s (NAT-%s)\n", "Remote Address", p2pInfo.RemoteLAN, p2pInfo.RemoteNAT, p2pInfo.RemoteNATType)
	}
}

func countUniquePublicIPs(infos []PunchingAddressInfo, ver string) int {
	uniqueIPs := make(map[string]struct{})

	for _, info := range infos {
		if !strings.HasSuffix(info.Network, ver) {
			continue
		}
		host, _, err := net.SplitHostPort(info.Nat)
		if err != nil {
			host = info.Nat
		}
		uniqueIPs[host] = struct{}{}
	}

	return len(uniqueIPs)
}

type P2PConnInfo struct {
	Conns        []net.Conn
	SharedKey    [32]byte
	IsClient     bool
	RelayUsed    bool
	NetworksUsed []string
	PeerAddress  string
}

func Easy_P2P(network, sessionUid string, relayConn *RelayPacketConn, logWriter io.Writer) (*P2PConnInfo, error) {
	connInfo, err := Easy_P2P_MP(context.Background(), network, "", sessionUid, false, relayConn, logWriter)
	if err != nil {
		return nil, err
	}
	return connInfo, nil
}

func Easy_P2P_MP(ctx context.Context, network, bind, sessionUid string, multipathEnabled bool, relayConn *RelayPacketConn, logWriter io.Writer) (*P2PConnInfo, error) {
	// --- 1. Determine the ordered list of network protocols to attempt ---
	var networksToTryStun []string
	switch network {
	case "any":
		networksToTryStun = []string{"tcp6", "tcp4", "udp4"}
	case "any6":
		networksToTryStun = []string{"tcp6"}
	case "any4":
		networksToTryStun = []string{"tcp4", "udp4"}
	case "tcp":
		networksToTryStun = []string{"tcp6", "tcp4"}
	case "udp":
		networksToTryStun = []string{"udp6", "udp4"}
	case "tcp6", "tcp4", "udp6", "udp4":
		networksToTryStun = []string{network}
	default:
		return nil, fmt.Errorf("unsupported network type: '%s'", network)
	}

	fmt.Fprintf(logWriter, "=== Checking NAT reachability ===\n")

	// --- 2. Get address information for all required networks in one go ---
	p2pInfos, err := Do_autoP2PEx2(ctx, networksToTryStun, bind, sessionUid, 25*time.Second, true, relayConn, logWriter)
	if err != nil {
		// If we can't even get the address info, we can't proceed.
		return nil, fmt.Errorf("failed to exchange address info: %w", err)
	}
	// Do_autoP2PEx返回的p2pInfos是优先考虑建立TCP来排序的。
	var p2pInfo *P2PAddressInfo
	var round int
	var CorS []bool = []bool{false, true, false}
	var role int = 0 // 0: unknown, 1: client, 2: server
	var mconn []net.Conn
	var sharedKey [32]byte
	var isRelayUsed bool
	var networksUsed []string

	for round, p2pInfo = range p2pInfos {
		if strings.HasPrefix(p2pInfo.Network, "tcp") {
			conn, isRoleClient, _, err2 := Auto_P2P_TCP_NAT_Traversal(ctx, p2pInfo.Network, sessionUid, p2pInfo, false, round+1, logWriter)
			if err2 == nil {
				mconn = append(mconn, conn)
				if role == 0 {
					if isRoleClient {
						role = 1
					} else {
						role = 2
					}
					sharedKey = p2pInfo.SharedKey
				}
				networksUsed = append(networksUsed, p2pInfo.Network)
				if !multipathEnabled {
					break
				}
				continue
			}
			err = err2
		} else {
			conn, isRoleClient, _, relayUsed, err2 := Auto_P2P_UDP_NAT_Traversal(ctx, p2pInfo.Network, sessionUid, p2pInfo, false, round+1, relayConn, logWriter)
			if err2 == nil {
				mconn = append(mconn, conn)
				if role == 0 {
					if isRoleClient {
						role = 1
					} else {
						role = 2
					}
					sharedKey = p2pInfo.SharedKey
				}
				if !isRelayUsed {
					isRelayUsed = relayUsed
				}
				networksUsed = append(networksUsed, p2pInfo.Network)
				if !multipathEnabled {
					break
				}
				continue
			}
			err = err2
		}
		fmt.Fprintf(logWriter, "ERROR: %v\n", err)
		if IsUnRetryable(err) {
			break
		}
		time.Sleep(1 * time.Second)
	}

	if len(mconn) > 0 {
		connInfo := &P2PConnInfo{
			Conns:        mconn,
			SharedKey:    sharedKey,
			IsClient:     CorS[role],
			RelayUsed:    isRelayUsed,
			NetworksUsed: networksUsed,
			PeerAddress:  mconn[0].RemoteAddr().String(),
		}
		return connInfo, nil
	}

	return nil, fmt.Errorf("direct P2P connection failed")
}

func generateRandomPorts(count int) []int {
	const (
		minPort = 1024
		maxPort = 65535
	)
	var seed int64
	err := binary.Read(rand.Reader, binary.BigEndian, &seed)
	if err != nil {
		// 回退到时间种子
		seed = time.Now().UnixNano()
	}
	r := mathrand.New(mathrand.NewSource(seed))
	ports := make([]int, count)
	used := make(map[int]struct{}, count) // 哈希去重

	for i := 0; i < count; {
		port := minPort + r.Intn(maxPort-minPort)
		if _, exists := used[port]; !exists {
			used[port] = struct{}{}
			ports[i] = port
			i++
		}
	}

	return ports
}

func Auto_P2P_UDP_NAT_Traversal(ctx context.Context, network, sessionUid string, p2pInfo *P2PAddressInfo, needSharedKey bool, round int, relayConn *RelayPacketConn, logWriter io.Writer) (net.Conn, bool, []byte, bool, error) {
	var isClient bool
	var sharedKey []byte
	var count = 10
	var err error
	const (
		RPP_TIMEOUT = 7
	)
	punchPayload := []byte(deriveKeyForPayload(sessionUid, true))

	fmt.Fprintf(logWriter, "=== Trying P2P Connection ===\n")

	isClient = SelectRole(p2pInfo)

	if needSharedKey {
		sharedKey = p2pInfo.SharedKey[:]
	}

	// 选择最佳目标地址（内网优先）
	sameNAT, similarLAN := CompareP2PAddresses(p2pInfo)
	remoteAddr := p2pInfo.RemoteNAT // 默认公网
	routeReason := "different network"
	inSameLAN := false
	if sameNAT && similarLAN {
		remoteAddr = p2pInfo.RemoteLAN // 同内网
		routeReason = "same LAN"
		inSameLAN = true
	}
	ttl := 64
	randomSrcPort := false
	randomDstPort := false
	if !inSameLAN {
		if p2pInfo.LocalNATType == "easy" && p2pInfo.RemoteNATType != "easy" {
			randomDstPort = true
		} else if p2pInfo.LocalNATType != "easy" && p2pInfo.RemoteNATType == "easy" {
			randomSrcPort = true
		} else if p2pInfo.LocalNATType == "easy" && p2pInfo.RemoteNATType == "easy" {
			//
		} else {
			if isClient {
				randomDstPort = true
			} else {
				randomSrcPort = true
			}
		}
	}
	if isClient {
		//只有先发包的，适合用小ttl值。
		ttl = PunchingShortTTL
		//多出口IP的环境，可能网络稍微复杂，nat的位置可能在更远的跳数
		if ttl == DefaultPunchingShortTTL && strings.HasSuffix(p2pInfo.Network, "4") && p2pInfo.LocalPublicIPv4Count > 1 {
			ttl = 10
		}
	}
	if !inSameLAN && (p2pInfo.LocalNATType != "easy" || p2pInfo.RemoteNATType != "easy") {
		count = 4 + RPP_TIMEOUT*2
	} else {
		count = 8
	}

	localAddr, err := net.ResolveUDPAddr(network, p2pInfo.LocalLAN)
	if err != nil {
		return nil, false, nil, false, fmt.Errorf("failed to resolve local address: %v", err)
	}
	remoteUDPAddr, err := net.ResolveUDPAddr(network, remoteAddr)
	if err != nil {
		return nil, false, nil, false, fmt.Errorf("failed to resolve remote address: %v", err)
	}

	type AddrPair struct {
		Local  *net.UDPAddr
		Remote *net.UDPAddr
	}
	gotHoleCh := make(chan AddrPair, 1)
	recvChan := make(chan bool)
	errChan := make(chan error)

	var uconn net.PacketConn
	var isSharedUDPConn, isRelayUsed bool
	if relayConn != nil && p2pInfo.LocalNATType == "relay" {
		//本端用了relay的conn对象
		uconn = relayConn
		isSharedUDPConn = true
	} else {
		uconn, err = net.ListenUDP(network, localAddr)
		if err != nil {
			return nil, false, nil, false, fmt.Errorf("error binding UDP address: %v", err)
		}
	}

	if p2pInfo.LocalNATType == "relay" || p2pInfo.RemoteNATType == "relay" {
		//任意一端有relay，ttl还原正常值，也不采用生日悖论打洞
		isRelayUsed = true
		ttl = 64
		randomSrcPort = false
		randomDstPort = false
	}

	buconn := netx.NewBoundUDPConn(uconn, "", isSharedUDPConn)
	buconn.SetSupportRebuild(true)
	var pickOnce sync.Once
	var forceRebind bool

	netx.SetUDPTTL(uconn, ttl)

	//端口监听准备好了，开始P2P

	if round > 0 {
		err = Mqtt_P2P_Round_Sync(ctx, sessionUid, p2pInfo, isClient, round, 25*time.Second, logWriter)
		if err != nil {
			return nil, false, nil, isRelayUsed, WrapUnRetryable(fmt.Errorf("failed to sync P2P round: %w", err))
		}
	}

	// 打印详细连接信息
	p2pInfoPrint(logWriter, p2pInfo)
	fmt.Fprintf(logWriter, "  - %-14s: %s (reason: %s)\n", "Best Route", remoteAddr, routeReason)
	if isClient {
		fmt.Fprintf(logWriter, "  - %-14s: sending PING every 1s (start immediately)\n", "Client Mode")
	} else {
		fmt.Fprintf(logWriter, "  - %-14s: sending PING every 1s (start after 2s)\n", "Server Mode")
	}
	fmt.Fprintf(logWriter, "  - %-14s: %ds\n", "Timeout", count)

	ctxStopPunching, stopPunching := context.WithCancel(ctx)
	ctxRound, cancel := context.WithTimeout(ctx, time.Duration(count)*time.Second)
	defer cancel()
	defer stopPunching()

	// 读协程：收包，类似TCP三次握手等待TCP SYN+ACK
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := buconn.Read(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				select {
				case errChan <- err:
				default:
				}
				return
			}

			if bytes.Equal(buf[:n], punchPayload) {
				stopPunching()
				pickOnce.Do(func() {
					buconn.SetRemoteAddr(buconn.GetLastPacketRemoteAddr())
					netx.SetUDPTTL(uconn, 64)
					buconn.Write(punchPayload) //类似TCP三次握手收到SYN+ACK后，发送个ACK
					time.Sleep(250 * time.Millisecond)
					buconn.Write(punchPayload)
					recvChan <- true
				})
				return
			}
		}
	}()

	// 写协程：按角色发包，类似TCP三次握手发送 SYN
	go func() {

		// 定义公共的PING发送函数
		sendPing := func(i int) bool {
			if os.Getenv("BIPA_DEBUG") == "1" {
				//only test birthday paradox
				return true
			}
			if _, err := uconn.WriteTo(punchPayload, remoteUDPAddr); err != nil {
				if errors.Is(err, os.ErrPermission) {
					if _, ok := uconn.(*net.UDPConn); ok {
						//ErrPermission可能是对方先发过来打洞包被macos防火墙拦住了，现在防火墙限制这个udp socket主动向对端这个地址发包了。
						var uconnR net.PacketConn
						fmt.Fprintf(logWriter, "UDP sendto permission denied; try rebinding...\n")
						uconnR, err = buconn.Rebuild() //尝试关闭socket，重新创建，并立刻主动发包打通防火墙
						if err != nil {
							//无法重建socket，标志forceRebind，后续用dial+reuseport，本地地址用全零的方式重建
							stopPunching()
							pickOnce.Do(func() {
								forceRebind = true
								buconn.SetRemoteAddr(remoteUDPAddr.String())
								recvChan <- true
							})
							return true
						} else {
							uconn = uconnR
							_, err = uconn.WriteTo(punchPayload, remoteUDPAddr)
							if err == nil {
								//重建socket且发送成功了
								goto SentPingOK
							}
						}
					}
				}
				select {
				case errChan <- err:
				default:
				}
				return false
			}
		SentPingOK:
			fmt.Fprintf(logWriter, "  ↑ Sent PING(TTL=%d) (%d)\n", ttl, i+1)
			return true
		}

		sendRDPPing := func() bool {
			remoteNatIP, _, _ := net.SplitHostPort(remoteAddr)
			select {
			case <-ctxStopPunching.Done():
				return false
			case <-ctxRound.Done():
				return false
			default:
				if randomDstPort {
					randDstPorts := generateRandomPorts(PunchingRandomPortCount)
					netx.SetUDPTTL(uconn, ttl)
					fmt.Fprintf(logWriter, "  ↑ Sending random dst ports hole-punching packets. TTL=%d; total=%d; ...", ttl, PunchingRandomPortCount)
					for i := 0; i < PunchingRandomPortCount; i++ {
						addrStr := net.JoinHostPort(remoteNatIP, strconv.Itoa(randDstPorts[i]))
						peerAddr, _ := net.ResolveUDPAddr(network, addrStr)
						uconn.WriteTo(punchPayload, peerAddr)
					}
					fmt.Fprintf(logWriter, "completed.\n")
				}
			}
			return true
		}
		sendRSPPing := func(timeout time.Duration) bool {
			gotCh := make(chan bool)
			// 使用带缓冲的通道（容量1，只需要第一个成功的结果）
			ctxRSP, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			var wg sync.WaitGroup

			fmt.Fprintf(logWriter, "  ↑ Sending Random Src Ports hole-punching packets. TTL=%d; ", ttl)

			randSrcPorts := generateRandomPorts(PunchingRandomPortCount + 50)

			// Pre-allocate a slice to store successful UDP connections
			conns := make([]*net.UDPConn, 0, PunchingRandomPortCount)

			// Try binding ports until we get enough successful connections
			for _, port := range randSrcPorts {
				sa := &net.UDPAddr{
					IP:   localAddr.IP,
					Port: port,
					Zone: localAddr.Zone,
				}
				conn, err := net.ListenUDP(network, sa)
				if err != nil {
					continue // Skip if port is occupied
				}
				netx.SetUDPTTL(conn, ttl)
				conns = append(conns, conn)
				// Stop once we have enough successful binds
				if len(conns) >= PunchingRandomPortCount {
					break
				}
			}
			fmt.Fprintf(logWriter, "total=%d !\n", len(conns))

			// Now perform hole punching with the successfully bound ports
			for _, conn := range conns {
				// Send punch packet
				if _, err := conn.WriteToUDP(punchPayload, remoteUDPAddr); err != nil {
					conn.Close()
					continue
				}
			}

			for _, conn := range conns {
				wg.Add(1)
				go func(c *net.UDPConn) {
					defer wg.Done()
					defer c.Close()

					// 读取响应
					buf := make([]byte, 32)
					deadline := time.Now().Add(5 * time.Second)
					_ = c.SetDeadline(deadline)

					for {
						n, raddr, err := c.ReadFromUDP(buf)
						if err != nil {
							return // 超时或读取错误
						}

						// 检查是否为有效打洞包
						if !bytes.Equal(buf[:n], punchPayload) {
							continue
						}

						// 避免回复多个成功打出的洞
						// 只有第一个成功的协程会执行后续操作
						pickOnce.Do(func() {
							// 标记成功并发送确认包
							netx.SetUDPTTL(c, 64)
							_, _ = c.WriteToUDP(punchPayload, raddr)
							time.Sleep(250 * time.Millisecond)
							_, _ = c.WriteToUDP(punchPayload, raddr)

							// 获取本地地址并传递结果
							laddr := c.LocalAddr().(*net.UDPAddr)
							c.Close() // 通知gotHoleCh前确保socket关闭，这样那边确保可以绑定在此地址上
							select {
							case gotHoleCh <- AddrPair{laddr, raddr}:
							default:
							}
							gotCh <- true
						})
						break
					}
				}(conn)
			}

			// 等待第一个成功结果或超时
			result := false
			select {
			case <-gotCh:
				stopPunching()
				result = true
			case <-ctxRSP.Done():
			case <-ctxRound.Done():
			case <-time.After(timeout + 500*time.Millisecond): // 兜底超时
			}
			for _, conn := range conns {
				conn.Close()
			}
			return result
		}

		if isClient {
			// 客户端：立即发 ping
		} else {
			// 服务端：2秒后发 ping
			time.Sleep(2 * time.Second)
		}
		for i := 0; i < count; i++ {
			if i > 0 {
				time.Sleep(1 * time.Second)
			}
			select {
			case <-ctxStopPunching.Done():
				return
			case <-ctxRound.Done():
				return
			default:
				if i < 3 {
					//前面几次用普通方式打洞
					sendPing(i)
				} else {
					if isClient {
						ttl += 1
					}
					if randomSrcPort {
						sendRSPPing(RPP_TIMEOUT * time.Second)
					} else if randomDstPort {
						sendRDPPing()
						//大批量发的话，多等等，等回复，如果有回复立刻终止，否则持续大量，即使这批打洞成功，却被下批打爆NAT的映射表
						time.Sleep(RPP_TIMEOUT / 2 * time.Second)
					} else {
						sendPing(i)
					}
				}

			}
		}
	}()

	// 等待结果
	var errFin error
	var uconnBrandnew net.Conn
	select {
	case addrPair := <-gotHoleCh:
		if isRelayUsed {
			fmt.Fprintf(logWriter, "UDP relay connection established (RSP)!\n")
		} else {
			fmt.Fprintf(logWriter, "P2P(UDP) connection established (RSP)!\n")
		}
		buconn.Close()
		if isSharedUDPConn {
			uconnBrandnew, err = newConnFromPacketConn(uconn, addrPair.Remote.String())
		} else {
			uconnBrandnew, err = CreateUDPConnFromAddr(addrPair.Local, addrPair.Remote, false)
		}
		if err != nil {
			errFin = fmt.Errorf("error binding UDP address: %v", err)
		} else {
			//这个新的socket立刻主动发包打通本机防火墙
			uconnBrandnew.Write(punchPayload)
		}
	case <-recvChan:
		if isRelayUsed {
			fmt.Fprintf(logWriter, "UDP relay connection established!\n")
		} else {
			fmt.Fprintf(logWriter, "P2P(UDP) connection established!\n")
		}
		laddr := uconn.LocalAddr()
		raddr := buconn.RemoteAddr()
		buconn.Close()
		if isSharedUDPConn {
			uconnBrandnew, err = newConnFromPacketConn(uconn, raddr.String())
		} else {
			uconnBrandnew, err = CreateUDPConnFromAddr(laddr, raddr, forceRebind)
		}
		if err != nil {
			errFin = fmt.Errorf("error binding UDP address: %v", err)
		} else {
			//这个新的socket立刻主动发包打通本机防火墙
			uconnBrandnew.Write(punchPayload)
		}
	case errFin = <-errChan:
		buconn.Close()
	case <-ctxRound.Done():
		errFin = fmt.Errorf("timeout (%ds)", count)
		buconn.Close()
	}
	cancel()
	stopPunching()
	if errFin != nil {
		return nil, false, nil, isRelayUsed, fmt.Errorf("P2P UDP hole punching failed: %v", errFin)
	}
	return uconnBrandnew, isClient, sharedKey, isRelayUsed, nil
}

func newConnFromPacketConn(uconn net.PacketConn, raddr string) (*netx.ConnFromPacketConn, error) {
	//uconn如果已经是ConnFromPacketConn，修改配置后复用，不再嵌套
	if rpconn, ok := uconn.(*RelayPacketConn); ok {
		if conn, ok := rpconn.PacketConn.(*netx.ConnFromPacketConn); ok {
			err := conn.Config(false, raddr)
			if err != nil {
				return nil, err
			}
			return conn, nil
		}
	}

	return netx.NewConnFromPacketConn(uconn, false, raddr)
}

func CreateUDPConnFromAddr(laddr, raddr net.Addr, forcelyBind bool) (net.Conn, error) {
	// 类型断言：必须是 *net.UDPAddr
	la, ok1 := laddr.(*net.UDPAddr)
	ra, ok2 := raddr.(*net.UDPAddr)
	if !ok1 || !ok2 {
		return nil, fmt.Errorf("both laddr and raddr must be *net.UDPAddr, got %T and %T", laddr, raddr)
	}

	if forcelyBind {
		//不能用laddr带IP的去Dial，因为可能地址被占用了，这里不指定IP
		localAddr, _ := net.ResolveUDPAddr("udp", net.JoinHostPort("", fmt.Sprintf("%d", la.Port)))
		d := &net.Dialer{
			LocalAddr: localAddr,
			Control:   netx.ControlUDP,
		}
		return d.Dial("udp", ra.String())
	}

	// 使用 net.DialUDP 绑定本地地址并连接远程地址
	conn, err := net.DialUDP("udp", la, ra)
	if err != nil {
		return nil, fmt.Errorf("DialUDP failed: %w", err)
	}
	return conn, nil
}

func Mqtt_P2P_Round_Sync(ctx context.Context, sessionUid string, p2pInfo *P2PAddressInfo, isClient bool, round int, timeout time.Duration, logWriter io.Writer) error {
	var msgSend string
	var msgNeed string
	if isClient {
		msgSend = fmt.Sprintf("C%d", round)
		msgNeed = fmt.Sprintf("S%d", round)
	} else {
		msgSend = fmt.Sprintf("S%d", round)
		msgNeed = fmt.Sprintf("C%d", round)
	}

	fmt.Fprintf(logWriter, "    Exchanging sync message for P2P round %d ... ", round)
	topicCID := MQTT_GenerateClientID(TopicDesc_RoundSync, sessionUid, 0)
	msgRecv, _, err := MQTT_SecureExchange[string](
		ctx, EXMODE_mutual, msgSend, topicCID, "gonc-exchange-sync", sessionUid, p2pInfo.LocalBindIP, timeout, nil)
	if err != nil {
		return fmt.Errorf("failed to exchange sync message: %v", err)
	}

	if string(msgRecv) != msgNeed {
		return fmt.Errorf("expected message '%s', but got '%s'", msgNeed, msgRecv)
	}
	fmt.Fprintf(logWriter, "OK\n")
	return nil
}

func Auto_P2P_TCP_NAT_Traversal(ctx context.Context, network, sessionUid string, p2pInfo *P2PAddressInfo, needSharedKey bool, round int, logWriter io.Writer) (net.Conn, bool, []byte, error) {
	var isClient bool
	var sharedKey []byte
	var err error
	const (
		MaxWorkers = 800 // 控制并发量，避免过多文件描述符
	)

	fmt.Fprintf(logWriter, "=== Trying P2P Connection ===\n")

	isClient = SelectRole(p2pInfo)
	if needSharedKey {
		sharedKey = p2pInfo.SharedKey[:]
	}

	// Choose best target address (prioritize LAN)
	sameNAT, similarLAN := CompareP2PAddresses(p2pInfo)
	remoteAddr := p2pInfo.RemoteNAT
	routeReason := "different network"
	inSameLAN := false
	if sameNAT && similarLAN {
		remoteAddr = p2pInfo.RemoteLAN // same LAN
		routeReason = "same LAN"
		inSameLAN = true
	}

	randomSrcPort := false
	randomDstPort := false
	if !inSameLAN {
		if p2pInfo.LocalNATType == "easy" && p2pInfo.RemoteNATType != "easy" {
			randomDstPort = true
		} else if p2pInfo.LocalNATType != "easy" && p2pInfo.RemoteNATType == "easy" {
			randomSrcPort = true
		} else if p2pInfo.LocalNATType == "easy" && p2pInfo.RemoteNATType == "easy" {
			//
		} else {
			if isClient {
				randomDstPort = true
			} else {
				randomSrcPort = true
			}
		}
	}

	// Resolve addresses
	localAddr, err := net.ResolveTCPAddr(network, p2pInfo.LocalLAN)
	if err != nil {
		return nil, false, nil, fmt.Errorf("failed to resolve local address: %v", err)
	}
	origLocalPort := localAddr.Port
	localNatAddr, err := net.ResolveTCPAddr(network, p2pInfo.LocalNAT)
	if err != nil {
		return nil, false, nil, fmt.Errorf("failed to resolve local address: %v", err)
	}

	remoteLANAddr, err := net.ResolveTCPAddr(network, p2pInfo.RemoteLAN)
	if err != nil {
		return nil, false, nil, fmt.Errorf("failed to resolve remote address: %v", err)
	}
	remoteIP, remotePortStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return nil, false, nil, fmt.Errorf("invalid remote address: %v", err)
	}

	remotePortInt, err := strconv.Atoi(remotePortStr)
	if err != nil {
		return nil, false, nil, fmt.Errorf("invalid remote port: %v", err)
	}

	//这是对方通过STUN服务器获取的NAT端口，记下来后面避开使用，可能会因为STUN服务器断开连接（FIN、RST）导致用该洞的其他P2P连接中断（RST）。
	origRemotePortInt := remotePortInt

	if !inSameLAN {
		if p2pInfo.LocalNATType != "easy" && p2pInfo.RemoteNATType != "easy" {
			return nil, false, nil, fmt.Errorf("NAT type need at least one easy NAT for TCP hole punching")
		}
		//换本地端口，因为之前这个端口连接过stun服务器，可能不久后会被STUN服务器关闭（FIN或RST）都可能影响在这个洞建立的其他会话。
		//p2p两端彼此约定增加100
		localAddr.Port = incPort(localAddr.Port, 100)
		p2pInfo.LocalLAN = localAddr.String()

		localNatAddr.Port = incPort(localNatAddr.Port, 100)
		p2pInfo.LocalNAT = localNatAddr.String()

		remoteLANAddr.Port = incPort(remoteLANAddr.Port, 100)
		p2pInfo.RemoteLAN = remoteLANAddr.String()
		remotePortInt = incPort(remotePortInt, 100)
		remoteAddr = net.JoinHostPort(remoteIP, strconv.Itoa(remotePortInt))
		p2pInfo.RemoteNAT = remoteAddr
	}

	timeoutMax := 25
	timeoutPerconn := 6
	// Setup context and channels
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type ConnWithTag struct {
		Conn net.Conn
		Tag  string
	}
	connChan := make(chan ConnWithTag, 1)
	errChan := make(chan error, 1)
	punchAckPayload := []byte(deriveKeyForPayload(sessionUid, false))
	var punchAckOnce sync.Once
	var commitOnce sync.Once

	// Start listener
	lc := net.ListenConfig{Control: netx.ControlTCP}
	listener, err := lc.Listen(ctx, network, localAddr.String())
	if err != nil {
		return nil, false, nil, fmt.Errorf("failed to listen: %v", err)
	}
	defer listener.Close()
	//端口监听准备好了，开始P2P

	if round > 0 {
		err = Mqtt_P2P_Round_Sync(ctx, sessionUid, p2pInfo, isClient, round, 25*time.Second, logWriter)
		if err != nil {
			return nil, false, nil, WrapUnRetryable(fmt.Errorf("failed to sync P2P round: %w", err))
		}
	}

	// Print connection info
	p2pInfoPrint(logWriter, p2pInfo)
	fmt.Fprintf(logWriter, "  - %-14s: %s (reason: %s)\n", "Best Route", remoteAddr, routeReason)
	if isClient {
		fmt.Fprintf(logWriter, "  - %-14s: connect start immediately\n", "Active Mode")
	} else {
		fmt.Fprintf(logWriter, "  - %-14s: connect start after 2s\n", "Passive Mode")
	}

	tryCommit := func(conn net.Conn, tag string) bool {
		committed := false
		commitOnce.Do(func() {
			connChan <- ConnWithTag{Conn: conn, Tag: tag}
			cancel()
			committed = true
		})

		<-ctx.Done()

		if !committed {
			conn.Close()
		}
		return committed
	}

	//打洞有时候有多个连接都打洞成功了，通过doHandshake实现双向确认，共同选择同一条连接，其他关闭
	doHandshake := func(conn net.Conn, isClient bool, tag string) error {
		var success bool
		buf := make([]byte, len(punchAckPayload))
		if isClient {
			//所有C主动发送Ack
			_, writeErr := conn.Write(punchAckPayload)
			if writeErr != nil {
				return fmt.Errorf("connection(%s) failed to write: %v", tag, writeErr)
			}

			//然后进入等待S回复ACK。
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, readErr := conn.Read(buf)

			if readErr != nil {
				return fmt.Errorf("connection(%s) failed to read: %v", tag, readErr)
			}
			if !bytes.Equal(buf[:n], punchAckPayload) {
				return fmt.Errorf("connection(%s) got invalid punchAckPayload", tag)
			}
			conn.SetReadDeadline(time.Time{})

			//正常来说，只有一个S会回复，这里用punchAckOnce只允许一个C成功。
			punchAckOnce.Do(func() {
				success = true
			})
			if !success {
				return fmt.Errorf("connection(%s) not selected", tag)
			}
		} else {
			// S端尝试接收C, 然后从收到ACK的连接里只挑选一个回复ACK。确保只有一个C收到ACK，其他C都会关闭连接。
			errS := fmt.Errorf("connection(%s) not selected", tag)

			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, readErr := conn.Read(buf)
			if readErr != nil {
				return errS
			}
			if !bytes.Equal(buf[:n], punchAckPayload) {
				return fmt.Errorf("connection(%s) got invalid punchAckPayload", tag)
			}
			conn.SetReadDeadline(time.Time{})

			punchAckOnce.Do(func() {
				_, writeErr := conn.Write(punchAckPayload)
				if writeErr != nil {
					errS = fmt.Errorf("connection(%s) failed to write: %v", tag, writeErr)
					return
				}
				success = true
			})
			if !success {
				return errS
			}
		}

		return nil
	}

	// Start accepting connections in goroutine
	doAccept := func() {
		deadline := time.Now().Add(time.Duration(timeoutMax) * time.Second)
		listener.(*net.TCPListener).SetDeadline(deadline)
		conn, err := listener.Accept()
		if err != nil {
			errChan <- err
			return
		}

		err = doHandshake(conn, isClient, "accept")
		if err != nil {
			conn.Close()
			errChan <- err
			return
		}

		// Verify the connection is from expected peer
		clientIP, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err == nil && (clientIP == remoteIP || (sameNAT && similarLAN && IsSameLAN(clientIP, remoteIP))) {
			tryCommit(conn, "accept")
		} else {
			conn.Close()
			if err == nil {
				err = fmt.Errorf("unexpected peer connection from %s", clientIP)
			}
			errChan <- err
		}
	}

	// Start concurrent dialing
	doPunching := func() {
		defer cancel()

		// Setup worker pool for concurrent dialing
		var wg sync.WaitGroup
		workerChan := make(chan struct{}, MaxWorkers) // Semaphore for limiting concurrency

		// Function to try a single connection
		tryConnect := func(targetAddr string, localAddr *net.TCPAddr, reuseaddr bool, timeout_sec int, isClient bool, tag string) bool {
			defer wg.Done()
			<-workerChan // Release worker slot when done

			select {
			case <-ctx.Done():
				return false
			default:
				dialer := &net.Dialer{
					Timeout: time.Duration(timeout_sec) * time.Second,
				}
				if localAddr != nil {
					dialer.LocalAddr = localAddr
					if reuseaddr {
						dialer.Control = netx.ControlTCP
					}
				}

				conn, err := dialer.DialContext(ctx, network, targetAddr)
				if err != nil {
					return false
				}
				err = doHandshake(conn, isClient, tag)
				if err != nil {
					conn.Close()
					return false
				}

				if tryCommit(conn, tag) {
					return true
				}
			}
			return false
		}

		//相同子网的，以及easy对easy的，就尝试一下直接连接
		triedDirectDial := false
		if inSameLAN || (p2pInfo.LocalNATType == "easy" && p2pInfo.RemoteNATType == "easy") {
			select {
			case <-ctx.Done():
				return
			default:
			}
			workerChan <- struct{}{}
			wg.Add(1)
			fmt.Fprintf(logWriter, "  ↑ Trying direct dial to peer...")
			if tryConnect(remoteAddr, localAddr, true, timeoutPerconn, isClient, "dial") {
				fmt.Fprintf(logWriter, "completed.\n")
				return
			}
			fmt.Fprintf(logWriter, "failed.\n")
			triedDirectDial = true
			if !inSameLAN {
				if isClient {
					//easy - easy 失败，可能对方的洞口没开是不可以先碰的
					time.Sleep(3 * time.Second)
					randomDstPort = true
				} else {
					randomSrcPort = true
				}
			}
		}

		for i := 0; i < 3 && (randomDstPort || randomSrcPort); i++ {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Try random destination ports if needed
			if randomDstPort {
				randDstPorts := generateRandomPorts(PunchingRandomPortCount)
				fmt.Fprintf(logWriter, "  ↑ Trying %d Random Destination Ports concurrently...\n", len(randDstPorts))
				for _, port := range randDstPorts {
					if port == origRemotePortInt {
						//避开原来与STUN通讯的端口
						continue
					}
					select {
					case <-ctx.Done():
						return
					case workerChan <- struct{}{}: // Acquire worker slot
						wg.Add(1)
						targetAddr := net.JoinHostPort(remoteIP, strconv.Itoa(port))
						go tryConnect(targetAddr, localAddr, true, timeoutPerconn, isClient, "RDP")
					}
				}
			}

			// Try random source ports if needed
			if randomSrcPort {
				randSrcPorts := generateRandomPorts(PunchingRandomPortCount)
				fmt.Fprintf(logWriter, "  ↑ Trying %d Random Source Ports concurrently...\n", PunchingRandomPortCount)
				for _, port := range randSrcPorts {
					if port == origLocalPort {
						//避开原来与STUN通讯的端口
						continue
					}
					newLocalAddr := &net.TCPAddr{
						IP:   append([]byte(nil), localAddr.IP...),
						Port: port,
						Zone: localAddr.Zone,
					}

					select {
					case <-ctx.Done():
						return
					case workerChan <- struct{}{}: // Acquire worker slot
						if !triedDirectDial {
							//第一个连接EASY目标可以稍等一下，万一对方没NAT没防火墙，是可以直接成功了，就不用并发打洞
							triedDirectDial = true
							wg.Add(1)
							done := make(chan struct{})
							go func() {
								defer close(done)
								tryConnect(remoteAddr, newLocalAddr, false, timeoutPerconn, isClient, "dial")
							}()
							select {
							case <-done:
								// tryConnect 提前完成了，不等待了
							case <-time.After(1500 * time.Millisecond):
								// 超时了，还没结束，那我们继续
							}
						} else {
							wg.Add(1)
							go tryConnect(remoteAddr, newLocalAddr, false, timeoutPerconn, isClient, "RSP")
						}
					}
				}
			}

			// Wait for all workers to complete
			wg.Wait()
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		errChan <- fmt.Errorf("all connection attempts failed")
	}

	go doAccept()
	// Delay for passive side
	if !isClient {
		time.Sleep(2 * time.Second)
	}
	go doPunching()

	// Wait for results
	select {
	case connInfo := <-connChan:
		cancel()
		conn := connInfo.Conn    // 获取实际的连接对象
		connType := connInfo.Tag // 获取连接类型描述
		fmt.Fprintf(logWriter, "P2P(TCP) connection established (%s)!\n", connType)
		return conn, isClient, sharedKey, nil
	case errCh := <-errChan:
		return nil, false, nil, fmt.Errorf("P2P TCP hole punching failed: %s", errCh.Error())
	case <-time.After(time.Duration(timeoutMax) * time.Second):
		return nil, false, nil, fmt.Errorf("P2P TCP hole punching failed: Timeout")
	}
}

func MqttWait(ctx context.Context, sessionUid, localIP string, timeout time.Duration, logWriter io.Writer) (string, error) {
	uid := deriveKeyForTopic("mqtt-topic-gonc-wait", sessionUid)
	topicSalt := "nat-exchange-wait/" + uid
	topic := topicFromSaltAndSessionUid(topicSalt, sessionUid)
	topicCID := MQTT_GenerateClientID(TopicDesc_WAIT, sessionUid, 0)
	logger := misc.NewLog(logWriter, "[MQTT] ", log.LstdFlags|log.Lmsgprefix)
	logger.Printf("Waiting for event on topic: %s across %d servers\n", topic, len(MQTTBrokerServers))

	expectMsgPrefix := "SYN@"
	filterSYN := func(data string) (bool, error) {
		if !strings.HasPrefix(data, expectMsgPrefix) {
			return false, nil
		}
		return true, nil
	}

	recvData, srvIndex, err := MQTT_SecureExchange(ctx, EXMODE_waitOnly, "", topicCID, topicSalt, sessionUid, localIP, timeout, filterSYN)
	if err != nil {
		return "", err
	}
	brokerServer, _, _ := ParseMQTTServerV3(MQTTBrokerServers[srvIndex])
	logger.Printf("Received event: %s, (via %s)\n", string(recvData), brokerServer)
	if !strings.HasPrefix(recvData, "SYN@") {
		return "", fmt.Errorf("not the expected message")
	}
	tid := strings.TrimPrefix(recvData, "SYN@")
	msgACK := "ACK@" + tid

	logger.Printf("Waiting for message(%s) on topic: %s across %d servers\n", recvData, topic, len(MQTTBrokerServers))
	expectMsgPrefix = recvData
	recvData2, _, err := MQTT_SecureExchange(ctx, EXMODE_reply, msgACK, topicCID, topicSalt, sessionUid, localIP, 15*time.Second, filterSYN)
	if err != nil {
		return "", err
	}
	if recvData != recvData2 {
		return "", fmt.Errorf("not the expected message")
	}

	return tid, err
}

type HelloPayload struct {
	Control []string
	App     string
	Param   string
}

func (h HelloPayload) String() string {
	a := h.AppString()
	if len(h.Control) == 0 && len(a) == 0 {
		return ""
	}
	c := ""
	if len(h.Control) != 0 {
		c = ";" + strings.Join(h.Control, ";")
	}
	if len(a) == 0 {
		return c
	} else {
		return c + "|" + a
	}
}

func (h HelloPayload) CtrlString() string {
	if len(h.Control) == 0 {
		return ""
	} else {
		return strings.Join(h.Control, ";")
	}
}

func (h HelloPayload) AppString() string {
	if h.App == "" {
		return ""
	}
	return h.App + "::" + h.Param
}

func (h *HelloPayload) SetControlValue(key, val string) {
	h.Control = append(h.Control, key+"="+val)
}

func (h HelloPayload) GetControlValue(key string) (string, bool) {
	key = strings.ToLower(key)

	for _, c := range h.Control {
		kv := strings.SplitN(c, "=", 2)
		if len(kv) != 2 {
			continue
		}
		if strings.ToLower(kv[0]) == key {
			return kv[1], true
		}
	}
	return "", false
}

func HelloPayloadFromString(topicSalt string) HelloPayload {
	var hp HelloPayload

	if topicSalt == "" {
		return hp
	}

	// 拆 Control | App
	parts := strings.SplitN(topicSalt, "|", 2)
	if len(parts) != 2 && len(parts) != 1 {
		return hp
	}

	controlPart := parts[0]
	appPart := ""
	if len(parts) == 2 {
		appPart = parts[1]
	}

	// 解析 Control：以 ; 开头，按 ; 分割
	ctrls := strings.Split(controlPart, ";")
	for i, c := range ctrls {
		// skip first item which is the real topicSalt
		if i >= 1 && c != "" {
			hp.Control = append(hp.Control, c)
		}
	}

	// 解析 App::Param
	if appPart != "" {
		ap := strings.SplitN(appPart, "::", 2)
		hp.App = ap[0]
		if len(ap) == 2 {
			hp.Param = ap[1]
		}
	}

	return hp
}

func ParseMQTTHelloPayload(topicSalt string) (control, app, prefix string) {
	parts := strings.SplitN(topicSalt, "|", 2)
	if len(parts) != 2 {
		return
	}

	control = parts[0]
	app = parts[1]

	if p := strings.SplitN(app, "::", 2); len(p) == 2 {
		prefix = p[0]
	}
	return
}

func MQTTHello(ctx context.Context, sessionUid, localIP string, helloPayload HelloPayload, timeout time.Duration, logWriter io.Writer) (string, error) {
	uid := deriveKeyForTopic("mqtt-topic-gonc-wait", sessionUid)
	topicSalt := "nat-exchange-wait/" + uid
	topic := topicFromSaltAndSessionUid(topicSalt, sessionUid)
	topicCID := MQTT_GenerateClientID(TopicDesc_HELLO, sessionUid, 0)
	logger := misc.NewLog(logWriter, "[MQTT] ", log.LstdFlags|log.Lmsgprefix)
	logger.Printf("Pushing Hello to topic %s across %d servers\n", topic, len(MQTTBrokerServers))

	tid, err := secure.GenerateSecureRandomString(10)
	if err != nil {
		return "", fmt.Errorf("generate salt failed: %v", err)
	}
	tid += helloPayload.String()
	msgSYN := "SYN@" + tid
	msgACK := "ACK@" + tid

	filterACK := func(data string) (bool, error) {
		if !strings.HasPrefix(data, "ACK@") {
			return false, nil
		}
		return true, nil
	}

	recvData, srvIndex, err := MQTT_SecureExchange(ctx, EXMODE_mutual, msgSYN, topicCID, topicSalt, sessionUid, localIP, timeout, filterACK)
	if err != nil {
		return "", err
	}
	if recvData != msgACK {
		return "", fmt.Errorf("not the expected message")
	}

	brokerServer, _, _ := ParseMQTTServerV3(MQTTBrokerServers[srvIndex])
	logger.Printf("Hello operation completed (via %s). tid: %s\n", brokerServer, tid)
	return tid, nil
}

// getNetworkPriority assigns a numerical priority to network types. Higher value means higher priority.
func getNetworkPriority(network string) int {
	switch network {
	case "tcp6":
		return 4
	case "tcp4":
		return 3
	case "udp6":
		return 2
	case "udp4":
		return 1
	default:
		return 0 // Unknown network types have lowest priority
	}
}

// getNATTypePriority assigns a numerical priority to NAT types. Higher value means higher priority.
func getNATTypePriority(natType string) int {
	switch natType {
	case "easy":
		return 4
	case "hard":
		return 3
	case "symm":
		return 2
	case "relay":
		return 1
	default:
		return 0 // Unknown NAT types have lowest priority
	}
}

// SortP2PAddressInfos takes a slice of *P2PAddressInfo pointers, sorts it based on the specified
// priority, and returns the sorted slice. The original slice is not modified.
func SortP2PAddressInfos(addrs []*P2PAddressInfo) []*P2PAddressInfo {
	// 创建一个副本进行排序，以避免修改原始切片（如果它被其他地方引用）。
	// 如果你希望原地修改原始切片，可以跳过这一步，直接对 'addrs' 进行排序。
	sortedAddrs := make([]*P2PAddressInfo, len(addrs))
	copy(sortedAddrs, addrs)

	// 使用 sort.Slice 对指针切片进行排序
	sort.Slice(sortedAddrs, func(i, j int) bool {
		a := sortedAddrs[i] // 'a' 是 *P2PAddressInfo
		b := sortedAddrs[j] // 'b' 是 *P2PAddressInfo

		// 优雅地处理潜在的 nil 指针：nil 指针优先级最低
		if a == nil {
			return false // b (非nil) 在 a (nil) 之前
		}
		if b == nil {
			return true // a (非nil) 在 b (nil) 之前
		}

		// 1. 主要排序：按网络类型优先级
		netPriorityA := getNetworkPriority(a.Network)
		netPriorityB := getNetworkPriority(b.Network)

		if netPriorityA != netPriorityB {
			return netPriorityA > netPriorityB // 优先级高的在前
		}

		// 2. 次要排序：按 NAT 类型（如果网络类型相同）
		// 结合本地和远程 NAT 类型的优先级分数
		localNATPriorityA := getNATTypePriority(a.LocalNATType)
		remoteNATPriorityA := getNATTypePriority(a.RemoteNATType)
		combinedNATPriorityA := localNATPriorityA + remoteNATPriorityA

		localNATPriorityB := getNATTypePriority(b.LocalNATType)
		remoteNATPriorityB := getNATTypePriority(b.RemoteNATType)
		combinedNATPriorityB := localNATPriorityB + remoteNATPriorityB

		if combinedNATPriorityA != combinedNATPriorityB {
			return combinedNATPriorityA > combinedNATPriorityB // 组合分数高的在前
		}

		// 如果所有优先级都相同，则保持稳定排序（sort.Slice 会自动处理）
		return false
	})

	return sortedAddrs
}

func incPort(port, add int) int {
	if port+add > 65535 {
		return 1024 + (port+add)%65535
	}
	return port + add
}

func ParseMQTTServerV3(input string) (string, url.Values, error) {
	safeParams := make(url.Values)
	u, err := url.Parse(input)
	if err != nil {
		return input, safeParams, err
	}

	q := u.Query()
	q.Set("_host", u.Hostname())
	q.Set("_port", u.Port())
	q.Set("_scheme", u.Scheme)
	// 构造 paho 能理解的 broker
	u.RawQuery = ""
	return u.String(), q, nil
}
