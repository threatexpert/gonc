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
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

var (
	TopicExchange              = "nat-exchange/"
	TopicExchangeWait          = "nat-exchange-wait/"
	MQTTBrokerServers []string = []string{
		"tcp://broker.hivemq.com:1883",
		"tcp://broker.emqx.io:1883",
		"tcp://test.mosquitto.org:1883",
	}

	DebugServerRole         string
	PunchingShortTTL        int = 5
	PunchingRandomPortCount int = 600
	UDPIdleTimeoutSecond    int = 41
)

type P2PAddressInfo struct {
	Network       string
	LocalLAN      string
	LocalNAT      string
	LocalNATType  string
	RemoteLAN     string
	RemoteNAT     string
	RemoteNATType string
	SharedKey     [32]byte
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

func MQTT_Exchange_Symmetric(sendData, topicSalt, sessionUid string, timeout time.Duration) (recvData string, recvIndex int, err error) {
	brokerServers := MQTTBrokerServers
	var qos byte = 1
	topic := TopicExchange + deriveKeyForTopic(topicSalt, sessionUid)

	myClientIDPrefix := deriveKeyForTopic("mqtt-topic-gonc-cid", sessionUid)
	uidNano := fmt.Sprint(time.Now().UnixNano())

	type recvPayload struct {
		data  string
		index int
	}

	var clients []mqtt.Client
	var clientsMu sync.Mutex
	recvRemoteData := make(chan recvPayload, 1)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
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

	for i, server := range brokerServers {
		go func(brokerAddr string, index int) {
			select {
			case <-ctx.Done():
				return
			default:
			}

			opts := mqtt.NewClientOptions().
				AddBroker(brokerAddr).
				SetClientID(fmt.Sprintf("%s-%d-%s", myClientIDPrefix, index, uidNano)).
				SetConnectTimeout(5 * time.Second)

			client := mqtt.NewClient(opts)
			if token := client.Connect(); token.Wait() && token.Error() != nil {
				select {
				case fail <- struct{}{}:
				case <-ctx.Done():
				}
				return
			}

			if token := client.Subscribe(topic, qos, func(_ mqtt.Client, msg mqtt.Message) {
				data := string(msg.Payload())
				if data != sendData {
					recvRemoteData <- recvPayload{data, index}
				}
			}); token.Wait() && token.Error() != nil {
				select {
				case fail <- struct{}{}:
				case <-ctx.Done():
				}
				return
			}

			clientsMu.Lock()
			if ctx.Err() != nil {
				clientsMu.Unlock()
				client.Disconnect(250)
				return
			}
			clients = append(clients, client)
			clientsMu.Unlock()

			select {
			case ready <- struct{}{}:
			case <-ctx.Done():
			}
		}(server, i)
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

	select {
	case r := <-recvRemoteData:
		publishAtLeastN(clients, topic, qos, sendData, 2)
		return r.data, r.index, nil
	case <-ctx.Done():
		return "", -1, fmt.Errorf("timeout waiting for remote data exchange")
	}
}

// exchangePayload 是用于在 Broker 上交换的统一数据结构
// 它包含了所有网络类型的地址信息和一个公钥
type exchangePayload struct {
	// network -> {nattype, lan, nat}
	Addresses map[string]map[string]string `json:"addrs"`
	// 公钥的 Base64 编码字符串
	PubKey string `json:"pk"`
}

func Do_autoP2PEx(networks []string, sessionUid string, timeout time.Duration, needSharedKey bool, logWriter io.Writer) ([]*P2PAddressInfo, error) {

	myInfoForExchange := exchangePayload{
		Addresses: make(map[string]map[string]string),
	}

	fmt.Fprintf(logWriter, "    Getting local public IP info via %d STUN servers...", len(STUNServers))

	allResults, err := GetNetworksPublicIPs(networks, "", 5*time.Second)
	if err != nil {
		fmt.Fprintln(logWriter, "Failed")
	} else {
		analyzed := analyzeSTUNResults(allResults)
		nets := []string{}
		for _, item := range analyzed {
			myInfoForExchange.Addresses[item.Network] = map[string]string{
				"nattype": item.NATType,
				"lan":     item.LAN,
				"nat":     item.NAT,
			}
			nets = append(nets, item.Network)
		}
		if len(nets) == 0 {
			fmt.Fprintln(logWriter, "Failed")
		} else {
			fmt.Fprintf(logWriter, "OK\n")
			addressesPrint(logWriter, myInfoForExchange.Addresses)
		}
	}

	var priv *ecdsa.PrivateKey
	if needSharedKey && len(myInfoForExchange.Addresses) > 0 {
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
		}
		pubBytes := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
		myInfoForExchange.PubKey = base64.StdEncoding.EncodeToString(pubBytes)
	}

	myKey := deriveKey("p2p-exchange-v1.9.2", sessionUid)
	infoBytes, _ := json.Marshal(myInfoForExchange)
	encPayload, _ := encryptAES(myKey[:], infoBytes)
	encPayloadBytes, _ := json.Marshal(encPayload)

	fmt.Fprintf(logWriter, "    Exchanging address info with peer ...")

	remoteInfoRaw, srvIndex, err := MQTT_Exchange_Symmetric(string(encPayloadBytes), "gonc-exchange-address", sessionUid, timeout)
	if err != nil {
		fmt.Fprintf(logWriter, "Failed: %v\n", err)
		return nil, err
	}

	fmt.Fprintf(logWriter, "OK (via %s)\n", MQTTBrokerServers[srvIndex])

	var remoteSecurePayload securePayload
	verIncomp := "possible version incompatibility with the peer"
	if err = json.Unmarshal([]byte(remoteInfoRaw), &remoteSecurePayload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal remote secure payload: %w (%s)", err, verIncomp)
	}
	plain, err := decryptAES(myKey[:], &remoteSecurePayload)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt remote payload: %w (%s)", err, verIncomp)
	}
	var remotePayload exchangePayload
	if err = json.Unmarshal(plain, &remotePayload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal remote exchange payload: %w (%s)", err, verIncomp)
	}

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

	for net, myNetInfo := range myInfoForExchange.Addresses {
		// 获取我们自己的地址组，支持多个地址
		myNATType := myNetInfo["nattype"]
		myLAN := myNetInfo["lan"]
		myNAT := myNetInfo["nat"]

		// 检查对方是否也返回了相同网络类型的信息
		for rnet, remoteNetInfo := range remotePayload.Addresses {
			if rnet != net {
				continue
			}
			haveCommonNetwork = true
			rNATType := remoteNetInfo["nattype"]
			remoteLAN := remoteNetInfo["lan"]
			remoteNAT := remoteNetInfo["nat"]

			if myNATType == "symm" && rNATType == "symm" {
				continue
			}

			//Priority == 0 means invalid type
			if getNATTypePriority(myNATType) == 0 || getNATTypePriority(rNATType) == 0 {
				continue
			}

			item := &P2PAddressInfo{
				Network:       net,
				LocalLAN:      myLAN,
				LocalNAT:      myNAT,
				LocalNATType:  myNATType,
				RemoteLAN:     remoteLAN,
				RemoteNAT:     remoteNAT,
				RemoteNATType: rNATType,
				SharedKey:     sharedKey,
			}

			if strings.HasPrefix(net, "tcp") {
				sameNAT, similarLAN := CompareP2PAddresses(item)
				if !sameNAT || !similarLAN {
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
	p2pInfos, err := Do_autoP2PEx([]string{network}, sessionUid, timeout, needSharedKey, logWriter)
	if err != nil {
		return nil, err
	}

	return p2pInfos[0], nil
}

func addressesPrint(logWriter io.Writer, Addresses map[string]map[string]string) {
	for net, info := range Addresses {
		nattype := info["nattype"]
		lan := info["lan"]
		nat := info["nat"]
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
	// if DebugServerRole != "" {
	// 	return DebugServerRole == "C"
	// }

	//easy  -  easy		go Compare
	//easy  -  hard		S - C
	//easy  -  symm		S - C

	//hard  -  easy		C - S
	//hard  -  hard		go Compare
	//hard  -  symm		C - S

	//symm  -  easy		C - S
	//symm  -  hard		S - C

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

func Easy_P2P(network, sessionUid string, logWriter io.Writer) (net.Conn, bool, []byte, error) {
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
		return nil, false, nil, fmt.Errorf("unsupported network type: '%s'", network)
	}

	fmt.Fprintf(logWriter, "=== Checking NAT reachability ===\n")

	// --- 2. Get address information for all required networks in one go ---
	p2pInfos, err := Do_autoP2PEx(networksToTryStun, sessionUid, 25*time.Second, true, logWriter)
	if err != nil {
		// If we can't even get the address info, we can't proceed.
		return nil, false, nil, fmt.Errorf("failed to exchange address info: %w", err)
	}
	// Do_autoP2PEx返回的p2pInfos是优先考虑建立TCP来排序的。
	var p2pInfo *P2PAddressInfo
	var round int
	for round, p2pInfo = range p2pInfos {
		if strings.HasPrefix(p2pInfo.Network, "tcp") {
			conn, isRoleClient, _, err2 := Auto_P2P_TCP_NAT_Traversal(p2pInfo.Network, sessionUid, p2pInfo, false, round+1, logWriter)
			if err2 == nil {
				return conn, isRoleClient, p2pInfo.SharedKey[:], nil
			}
			err = err2
		} else {
			conn, isRoleClient, _, err2 := Auto_P2P_UDP_NAT_Traversal(p2pInfo.Network, sessionUid, p2pInfo, false, round+1, logWriter)
			if err2 == nil {
				return conn, isRoleClient, p2pInfo.SharedKey[:], nil
			}
			err = err2
		}
		fmt.Fprintf(logWriter, "ERROR: %v\n", err)
		if IsUnRetryable(err) {
			break
		}
		time.Sleep(1 * time.Second)
	}

	return nil, false, nil, fmt.Errorf("direct P2P connection failed")
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

func Auto_P2P_UDP_NAT_Traversal(network, sessionUid string, p2pInfo *P2PAddressInfo, needSharedKey bool, round int, logWriter io.Writer) (net.Conn, bool, []byte, error) {
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
	}
	if !inSameLAN && (p2pInfo.LocalNATType != "easy" || p2pInfo.RemoteNATType != "easy") {
		count = 4 + RPP_TIMEOUT*2
	} else {
		count = 8
	}

	localAddr, err := net.ResolveUDPAddr(network, p2pInfo.LocalLAN)
	if err != nil {
		return nil, false, nil, fmt.Errorf("failed to resolve local address: %v", err)
	}
	remoteUDPAddr, err := net.ResolveUDPAddr(network, remoteAddr)
	if err != nil {
		return nil, false, nil, fmt.Errorf("failed to resolve remote address: %v", err)
	}

	type AddrPair struct {
		Local  *net.UDPAddr
		Remote *net.UDPAddr
	}
	gotHoleCh := make(chan AddrPair, 1)
	recvChan := make(chan bool)
	errChan := make(chan error)

	uconn, err := net.ListenUDP(network, localAddr)
	if err != nil {
		return nil, false, nil, fmt.Errorf("error binding UDP address: %v", err)
	}
	buconn := NewBoundUDPConn(uconn, "", false)

	SetUDPTTL(uconn, ttl)

	//端口监听准备好了，开始P2P

	if round > 0 {
		err = Mqtt_P2P_Round_Sync(sessionUid, isClient, round, 25*time.Second, logWriter)
		if err != nil {
			return nil, false, nil, WrapUnRetryable(fmt.Errorf("failed to sync P2P round: %w", err))
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

	ctxStopPunching, stopPunching := context.WithCancel(context.Background())
	ctxRound, cancel := context.WithTimeout(context.Background(), time.Duration(count)*time.Second)
	defer cancel()
	defer stopPunching()

	// 读协程：收包，类似TCP三次握手等待TCP SYN+ACK
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := buconn.Read(buf)
			if err != nil {
				errChan <- err
				return
			}

			if bytes.Equal(buf[:n], punchPayload) {
				stopPunching()
				buconn.SetRemoteAddr(buconn.GetLastPacketRemoteAddr())
				SetUDPTTL(uconn, 64)
				buconn.Write(punchPayload) //类似TCP三次握手收到SYN+ACK后，发送个ACK
				time.Sleep(250 * time.Millisecond)
				buconn.Write(punchPayload)
				recvChan <- true
				return
			}
		}
	}()

	// 写协程：按角色发包，类似TCP三次握手发送 SYN
	go func() {

		// 定义公共的PING发送函数
		sendPing := func(i int) bool {
			if _, err := uconn.WriteToUDP(punchPayload, remoteUDPAddr); err != nil {
				errChan <- err
				return false
			}
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
					fmt.Fprintf(logWriter, "  ↑ Sending random dst ports hole-punching packets. TTL=%d; total=%d; ...", ttl, PunchingRandomPortCount)
					for i := 0; i < PunchingRandomPortCount; i++ {
						addrStr := net.JoinHostPort(remoteNatIP, strconv.Itoa(randDstPorts[i]))
						peerAddr, _ := net.ResolveUDPAddr(network, addrStr)
						uconn.WriteToUDP(punchPayload, peerAddr)
					}
					fmt.Fprintf(logWriter, "completed.\n")
				}
			}
			return true
		}
		sendRSPPing := func(timeout time.Duration) bool {
			gotCh := make(chan bool)
			// 使用带缓冲的通道（容量1，只需要第一个成功的结果）
			ctxRSP, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			var wg sync.WaitGroup
			var once sync.Once

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
				SetUDPTTL(conn, ttl)
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
						once.Do(func() {
							// 标记成功并发送确认包
							SetUDPTTL(c, 64)
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
	select {
	case addrPair := <-gotHoleCh:
		buconn.Close()
		uconn, err = net.ListenUDP(network, addrPair.Local)
		if err != nil {
			errFin = fmt.Errorf("error binding UDP address: %v", err)
		} else {
			buconn = NewBoundUDPConn(uconn, addrPair.Remote.String(), false)
			buconn.SetIdleTimeout(time.Duration(UDPIdleTimeoutSecond) * time.Second)
			fmt.Fprintf(logWriter, "P2P(UDP) connection established (RSP)!\n")
			SetUDPTTL(uconn, 64)
		}
	case <-recvChan:
		fmt.Fprintf(logWriter, "P2P(UDP) connection established!\n")
		buconn.SetIdleTimeout(time.Duration(UDPIdleTimeoutSecond) * time.Second)
		SetUDPTTL(uconn, 64)
	case errFin = <-errChan:
		buconn.Close()
	case <-ctxRound.Done():
		errFin = fmt.Errorf("timeout (%ds)", count)
		buconn.Close()
	}
	cancel()
	stopPunching()
	if errFin != nil {
		return nil, false, nil, fmt.Errorf("P2P UDP hole punching failed: %v", errFin)
	}
	return buconn, isClient, sharedKey, nil
}

func Mqtt_P2P_Round_Sync(sessionUid string, isClient bool, round int, timeout time.Duration, logWriter io.Writer) error {
	var msgSend string
	var msgNeed string
	if isClient {
		msgSend = fmt.Sprintf("C%d", round)
		msgNeed = fmt.Sprintf("S%d", round)
	} else {
		msgSend = fmt.Sprintf("S%d", round)
		msgNeed = fmt.Sprintf("C%d", round)
	}

	myKey := deriveKey("gonc-round-sync", sessionUid)
	encPayload, _ := encryptAES(myKey[:], []byte(msgSend))
	encPayloadBytes, _ := json.Marshal(encPayload)
	payloadSend := string(encPayloadBytes)

	fmt.Fprintf(logWriter, "    Exchanging sync message for P2P round %d ... ", round)
	payloadRecv, _, err := MQTT_Exchange_Symmetric(payloadSend, "gonc-exchange-sync", sessionUid, timeout)
	if err != nil {
		return fmt.Errorf("failed to exchange sync message: %v", err)
	}

	var remotePayload securePayload
	err = json.Unmarshal([]byte(payloadRecv), &remotePayload)
	if err != nil {
		return fmt.Errorf("failed to unmarshal sync message: %v", err)
	}

	msgRecv, err := decryptAES(myKey[:], &remotePayload)
	if err != nil {
		return fmt.Errorf("failed to decrypt sync message: %v", err)
	}

	if string(msgRecv) != msgNeed {
		return fmt.Errorf("expected message '%s', but got '%s'", msgNeed, msgRecv)
	}
	fmt.Fprintf(logWriter, "OK\n")
	return nil
}

func Auto_P2P_TCP_NAT_Traversal(network, sessionUid string, p2pInfo *P2PAddressInfo, needSharedKey bool, round int, logWriter io.Writer) (net.Conn, bool, []byte, error) {
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type ConnWithTag struct {
		Conn net.Conn
		Tag  string
	}
	connChan := make(chan ConnWithTag, 1)
	errChan := make(chan error, 1)
	punchAckPayload := []byte(deriveKeyForPayload(sessionUid, false))
	var punchAckOnce sync.Once

	// Start listener
	lc := net.ListenConfig{Control: ControlTCP}
	listener, err := lc.Listen(ctx, network, localAddr.String())
	if err != nil {
		return nil, false, nil, fmt.Errorf("failed to listen: %v", err)
	}
	defer listener.Close()
	//端口监听准备好了，开始P2P

	if round > 0 {
		err = Mqtt_P2P_Round_Sync(sessionUid, isClient, round, 25*time.Second, logWriter)
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

	//打洞有时候有多个连接都打洞成功了，通过doHandshake实现双向确认，共同选择同一条连接，其他关闭
	doHandshake := func(conn net.Conn, isClient bool, tag string) error {
		var success bool
		if isClient {
			//所有C主动发送Ack
			_, writeErr := conn.Write(punchAckPayload)
			if writeErr != nil {
				return fmt.Errorf("connection(%s) failed to write: %v", tag, writeErr)
			}

			//然后进入等待S回复ACK。
			buf := make([]byte, len(punchAckPayload))
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
			// S端只挑选一个C尝试接收ACK并回复ACK。确保只有一个C收到ACK，其他C都会关闭连接。
			errS := fmt.Errorf("connection(%s) not selected", tag)
			punchAckOnce.Do(func() {
				buf := make([]byte, len(punchAckPayload))
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, readErr := conn.Read(buf)
				if readErr != nil {
					errS = fmt.Errorf("connection(%s) failed to read: %v", tag, readErr)
					return
				}
				if !bytes.Equal(buf[:n], punchAckPayload) {
					errS = fmt.Errorf("connection(%s) got invalid punchAckPayload", tag)
					return
				}
				conn.SetReadDeadline(time.Time{})

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
	go func() {
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
			select {
			case connChan <- ConnWithTag{Conn: conn, Tag: "accept"}:
			default:
				conn.Close()
			}
		} else {
			conn.Close()
			if err == nil {
				err = fmt.Errorf("unexpected peer connection from %s", clientIP)
			}
			errChan <- err
		}
	}()

	// Delay for passive side
	if !isClient {
		time.Sleep(2 * time.Second)
	}
	// Start concurrent dialing
	go func() {
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
						dialer.Control = ControlTCP
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

				select {
				case connChan <- ConnWithTag{Conn: conn, Tag: tag}:
					cancel() // Cancel other attempts
					return true
				default:
					conn.Close()
				}
			}
			return false
		}

		//相同子网的，以及easy对easy的，就尝试一下直接连接
		if inSameLAN || (p2pInfo.LocalNATType == "easy" && p2pInfo.RemoteNATType == "easy") {
			// First try direct connection
			workerChan <- struct{}{}
			wg.Add(1)
			if tryConnect(remoteAddr, localAddr, true, timeoutPerconn, isClient, "dial") {
				return
			}
		}

		for i := 0; i < 3 && !(p2pInfo.LocalNATType == "easy" && p2pInfo.RemoteNATType == "easy"); i++ {
			select {
			case <-ctx.Done():
				return
			case connInfo := <-connChan:
				// 有连接成功，直接转发回主流程
				connChan <- connInfo
				return
			default:
			}

			// Try random destination ports if needed
			if randomDstPort {
				randDstPorts := generateRandomPorts(PunchingRandomPortCount)
				fmt.Fprintf(logWriter, "  ↑ Trying %d Random Destination Ports concurrently...\n", len(randDstPorts))
				for _, port := range randDstPorts {
					if port == origRemotePortInt {
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
						wg.Add(1)
						go tryConnect(remoteAddr, newLocalAddr, false, timeoutPerconn, isClient, "RSP")
					}
				}
			}

			// Wait for all workers to complete
			wg.Wait()
		}

		errChan <- fmt.Errorf("all connection attempts failed")
	}()

	// Wait for results
	select {
	case connInfo := <-connChan:
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

func logwts(logWriter io.Writer, msg string, args ...interface{}) {
	timestamp := time.Now().Format("20060102-150405")
	fmt.Fprintf(logWriter, "%s ", timestamp)
	fmt.Fprintf(logWriter, msg, args...)
}

func MqttWait(sessionUid string, timeout time.Duration, logWriter io.Writer) (string, error) {
	uid := deriveKeyForTopic("mqtt-topic-gonc-wait", sessionUid)
	topic := TopicExchangeWait + uid
	logwts(logWriter, "Waiting for event on topic: %s across %d servers\n", topic, len(MQTTBrokerServers))

	msgReceived := make(chan string, 1)
	var clients []mqtt.Client
	var clientsMutex sync.Mutex

	baseClientID := deriveKeyForTopic("mqtt-topic-gonc-waiter", sessionUid)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for i, server := range MQTTBrokerServers {
		go func(brokerAddr string, clientIndex int) {
			opts := mqtt.NewClientOptions().
				AddBroker(brokerAddr).
				SetClientID(fmt.Sprintf("%s-%d", baseClientID, clientIndex)).
				SetAutoReconnect(true).
				SetConnectRetry(true).
				SetConnectRetryInterval(3 * time.Second).
				SetOnConnectHandler(func(c mqtt.Client) {
					if token := c.Subscribe(topic, 1, func(client mqtt.Client, msg mqtt.Message) {
						select {
						case msgReceived <- string(msg.Payload()):
							cancel() // 通知其他协程停止工作
						default:
							// 已经接收到一条消息，忽略重复
						}
					}); token.Wait() && token.Error() != nil {
						logwts(logWriter, "Failed to subscribe to topic %s on %s: %v\n", topic, brokerAddr, token.Error())
					} else {
						logwts(logWriter, "Subscribed to topic %s on %s\n", topic, brokerAddr)
					}
				}).
				SetConnectionLostHandler(func(c mqtt.Client, err error) {
					logwts(logWriter, "MQTT connection lost from %s: %v\n", brokerAddr, err)
				})

			client := mqtt.NewClient(opts)

			// 连接 MQTT
			if token := client.Connect(); token.Wait() && token.Error() == nil {
				clientsMutex.Lock()
				clients = append(clients, client)
				clientsMutex.Unlock()

				// 监听 context.Done() 退出信号，防止 goroutine 悬挂
				go func() {
					<-ctx.Done()
					if client.IsConnected() {
						client.Disconnect(250)
					}
				}()
			} else {
				logwts(logWriter, "MQTT connect to %s failed: %v\n", brokerAddr, token.Error())
			}
		}(server, i)
	}

	// 等待消息或超时（context 有超时时间）
	var (
		payloadRaw string
		plain      []byte
		err        error
	)

	select {
	case payloadRaw = <-msgReceived:
		var remotePayload securePayload
		err = json.Unmarshal([]byte(payloadRaw), &remotePayload)
		if err != nil {
			break
		}
		myKey := deriveKey("hello", sessionUid)
		plain, err = decryptAES(myKey[:], &remotePayload)
		if err != nil {
			break
		}
		logwts(logWriter, "Received event: %s\n", string(plain))
	case <-ctx.Done():
		return "", fmt.Errorf("timeout waiting for MQTT event")
	}

	// 断开所有连接
	clientsMutex.Lock()
	for _, client := range clients {
		client.Disconnect(250)
	}
	clientsMutex.Unlock()
	time.Sleep(500 * time.Millisecond)

	return string(plain), err
}

func MqttPush(msg, sessionUid string, logWriter io.Writer) error {
	uid := deriveKeyForTopic("mqtt-topic-gonc-wait", sessionUid)
	topic := TopicExchangeWait + uid

	fmt.Fprintf(logWriter, "MQTT: Pushing to topic %s across %d servers: %s\n", topic, len(MQTTBrokerServers), msg)

	myKey := deriveKey("hello", sessionUid)
	encPayload, _ := encryptAES(myKey[:], []byte(msg))
	encPayloadBytes, _ := json.Marshal(encPayload)
	payload := string(encPayloadBytes)

	var successCount int32
	var wg sync.WaitGroup

	errChan := make(chan struct{}, len(MQTTBrokerServers)) // 用于通知“失败发生”
	successNotify := make(chan struct{}, 1)                // 用于通知“至少两个成功”
	var once sync.Once

	for _, server := range MQTTBrokerServers {
		wg.Add(1)
		go func(brokerAddr string) {
			defer wg.Done()

			opts := mqtt.NewClientOptions().
				AddBroker(brokerAddr).
				SetClientID(deriveKeyForTopic("mqtt-topic-gonc-push", sessionUid+brokerAddr)).
				SetConnectTimeout(5 * time.Second)

			client := mqtt.NewClient(opts)
			token := client.Connect()
			if token.Wait() && token.Error() != nil {
				errChan <- struct{}{}
				return
			}
			defer client.Disconnect(250)

			pub := client.Publish(topic, 1, false, payload)
			if pub.Wait() && pub.Error() != nil {
				errChan <- struct{}{}
				return
			}

			count := atomic.AddInt32(&successCount, 1)
			if count >= 2 {
				// 尝试通知主线程已有足够成功
				once.Do(func() { successNotify <- struct{}{} })
			}
		}(server)
	}

	// 等待两种情况之一：
	// 1. 成功数达到 2（通过 successNotify）
	// 2. 所有 goroutine 执行完（通过 wg.Wait）
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-successNotify:
		// 足够成功，立即返回成功
	case <-done:
		// 所有完成后再检查是否成功
	}

	successes := int(atomic.LoadInt32(&successCount))
	if successes == 0 {
		return fmt.Errorf("failed to publish to any MQTT server")
	}
	fmt.Fprintf(logWriter, "MQTT: Push operation completed. Successes: %d\n", successes)
	return nil
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
		return 3
	case "hard":
		return 2
	case "symm":
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
