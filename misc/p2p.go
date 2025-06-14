package misc

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
	"encoding/hex"
	"encoding/json"
	"fmt"
	mathrand "math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/pion/stun"
)

var (
	TopicExchange      = "nat-exchange/"
	TopicExchangeWait  = "nat-exchange-wait/"
	lastStunClient     *stun.Client
	lastStunClientConn net.Conn
	lastStunClientLock sync.Mutex

	DebugServerRole         string
	PunchingShortTTL        int = 5
	PunchingRandomPortCount int = 600
)

// GetPublicIP 获取公网IP，返回第一个成功响应的STUN服务器的结果
func GetPublicIP(network, bind string, stunServers []string, timeout time.Duration) (index int, localAddr, natAddr string, err error) {
	// 1. result 结构体包含连接和客户端
	type result struct {
		index  int
		local  string
		nat    string
		err    error
		client *stun.Client
		conn   net.Conn
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	results := make(chan result, len(stunServers))
	var wg sync.WaitGroup

	netLower := strings.ToLower(network)
	netProto := "udp"
	if strings.HasPrefix(netLower, "tcp") {
		netProto = "tcp"
	}
	isIPv6 := strings.HasSuffix(netLower, "6")

	resolveAddr := func(proto string) (string, net.Addr, error) {
		var network string
		if proto == "tcp" {
			network = "tcp4"
			if isIPv6 {
				network = "tcp6"
			}
			addr, err := net.ResolveTCPAddr(network, bind)
			return network, addr, err
		}
		network = "udp4"
		if isIPv6 {
			network = "udp6"
		}
		addr, err := net.ResolveUDPAddr(network, bind)
		return network, addr, err
	}

	for i, rawAddr := range stunServers {
		scheme := ""
		addr := rawAddr

		if strings.HasPrefix(rawAddr, "udp://") {
			scheme = "udp"
			addr = strings.TrimPrefix(rawAddr, "udp://")
		} else if strings.HasPrefix(rawAddr, "tcp://") {
			scheme = "tcp"
			addr = strings.TrimPrefix(rawAddr, "tcp://")
		}

		//选择匹配network的stun服务器
		if scheme != "" && scheme != netProto {
			continue
		}

		wg.Add(1)
		go func(index int, stunAddr string) {
			defer wg.Done()

			// 检查 context 是否已经被取消，避免不必要的拨号
			if ctx.Err() != nil {
				//fmt.Fprintf(os.Stderr, "Err: %s ...\n", stunAddr)
				return
			}

			useNetwork, laddr, err := resolveAddr(netProto)
			if err != nil {
				//fmt.Fprintf(os.Stderr, "stun resolve local addr: %s://%s err: %v\n", useNetwork, stunAddr, err)
				results <- result{err: fmt.Errorf("resolve local addr: %v", err)}
				return
			}

			// 为拨号器创建一个带 context 的超时
			dialer := &net.Dialer{LocalAddr: laddr}
			if strings.HasPrefix(useNetwork, "tcp") {
				dialer.Control = ControlTCP
			} else {
				dialer.Control = ControlUDP
			}

			//fmt.Fprintf(os.Stderr, "stun dial: %s://%s ...\n", useNetwork, stunAddr)
			conn, err := dialer.DialContext(ctx, useNetwork, stunAddr)
			if err != nil {
				//fmt.Fprintf(os.Stderr, "STUN dial failed: %s://%s err: %v\n", useNetwork, stunAddr, err)
				// 如果 context 被取消，错误会是 "context canceled"
				results <- result{err: fmt.Errorf("STUN dial failed: %v", err)}
				return
			}
			//fmt.Fprintf(os.Stderr, "stun dial: %s://%s OK\n", useNetwork, stunAddr)

			//这个conn不能defer Close，后面它可能是要保活的tcp。
			//为了打洞的TCP在程序结束后该端口不出现TIME_WAIT，方便再次复用端口。使用策略：
			// 1）并发多个stun查询的tcp，除了第一个成功的要保留，其他程序主动要关闭的可以SetLinger(0)就不会出现TIME_WAIT。
			// 2）第一个成功stun查询的TCP不主动关闭（主动正常关闭一定会有TIME_WAIT），要用Read等待的方式保活，可以做可以在程序退出时触发系统RST，RST就不会出现TIME_WAIT.
			//    但如果对方主动挥手，可能打开的洞还在通讯，这边被动正常关闭不会TIME_WAIT，不能SetLinger(0)避免RST导致打开的tcp的洞失效。
			// 3) 程序再次重新打洞时，上次第一个成功stun查询的TCP要SetLinger(0)主动关闭

			client, err := stun.NewClient(conn)
			if err != nil {
				//fmt.Fprintf(os.Stderr, "STUN NewClient failed: %s://%s err: %v\n", useNetwork, stunAddr, err)
				conn.Close()
				results <- result{err: fmt.Errorf("STUN NewClient failed: %v", err)}
				return
			}

			var xorAddr stun.XORMappedAddress
			var callErr error

			req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

			//fmt.Fprintf(os.Stderr, "stun do request: %s://%s\n", useNetwork, stunAddr)

			// client.Do 不直接支持 context，但拨号阶段已经支持了。
			// STUN 请求通常很快，超时主要由外层 context 控制。
			err = client.Do(req, func(e stun.Event) {
				if e.Error != nil {
					callErr = e.Error
				} else if err := xorAddr.GetFrom(e.Message); err != nil {
					callErr = err
				}
			})

			if err != nil {
				//fmt.Fprintf(os.Stderr, "STUN Do failed: %s://%s err: %v\n", useNetwork, stunAddr, err)
				client.Close() //前面不能用defer Close，要自己Close
				results <- result{err: fmt.Errorf("STUN Do failed: %v", err)}
				return
			}
			if callErr != nil {
				//fmt.Fprintf(os.Stderr, "STUN response error: %s://%s err: %v\n", useNetwork, stunAddr, callErr)
				client.Close()
				results <- result{err: fmt.Errorf("STUN response error: %v", callErr)}
				return
			}

			//fmt.Fprintf(os.Stderr, "stun result: %s://%s(%s) %s\n", useNetwork, stunAddr, conn.RemoteAddr().String(), xorAddr.String())

			// 2. 将成功的结果（包括连接和客户端）发送到 channel
			// 注意：UDP连接是无状态的，不需要保留。TCP连接需要保留用于打洞。
			// 这里我们统一将 client 和 conn 传出，由主循环决定如何处理。
			results <- result{
				index:  i,
				local:  conn.LocalAddr().String(),
				nat:    xorAddr.String(),
				client: client,
				conn:   conn,
			}

		}(i, addr)

		if bind != "" && !strings.HasSuffix(bind, ":0") && strings.HasPrefix(netProto, "udp") {
			//由于UDP SO_REUSEADDR明确端口的话，只有一个能收到回复数据，所以只选第一个可用的stunServer
			break
		}
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// 3. for-select 循环
	for {
		select {
		case <-ctx.Done():
			// 超时或被主动取消。
			// 启动一个 goroutine 来排空 channel，确保所有子 goroutine 都能退出。
			go func() {
				for r := range results {
					// 丢弃所有剩余结果
					if r.client != nil {
						if r.conn != nil {
							if tcpConn, ok := r.conn.(*net.TCPConn); ok {
								tcpConn.SetLinger(0) // 立即关闭，发送 RST
							}
						}
						//fmt.Fprintf(os.Stderr, "stun close: %s\n", r.conn.RemoteAddr().String())
						r.client.Close()
					}
				}
			}()
			return -1, "", "", fmt.Errorf("timeout or cancelled while waiting for STUN response")

		case r, ok := <-results:
			if !ok {
				// Channel 已关闭，说明所有 goroutine 都已执行完毕且无一成功。
				return -1, "", "", fmt.Errorf("all STUN servers failed")
			}

			if r.err == nil {
				// **** 找到第一个成功者 ****

				// a. 立即通知其他 goroutine 停止
				cancel()

				// b. 如果是 TCP，且明确了端口，执行保存连接的逻辑
				if bind != "" && !strings.HasSuffix(bind, ":0") && netProto == "tcp" {
					lastStunClientLock.Lock()
					if lastStunClient != nil {
						if tcpConn, ok := lastStunClientConn.(*net.TCPConn); ok {
							_ = tcpConn.SetLinger(0)
						}
						lastStunClient.Close()
					}
					// 重要：接管获胜的 client 和 conn，防止它们被 defer client.Close() 关闭
					lastStunClient = r.client
					lastStunClientConn = r.conn
					lastStunClientLock.Unlock()

					// 启动你的连接保活/监听关闭的 goroutine
					go func(tc net.Conn, sc *stun.Client) {
						buf := make([]byte, 1)
						// 这个 Read 会一直阻塞，直到远端关闭连接或发生错误
						_, _ = tc.Read(buf)
						// 读取到数据或错误后，关闭客户端
						sc.Close()
					}(r.conn, r.client)
				} else {
					// 其他情况，例如TCP随机端口，或UDP，主动关闭
					if tcpConn, ok := r.conn.(*net.TCPConn); ok {
						tcpConn.SetLinger(0) // 立即关闭，发送 RST
					}
					r.client.Close()
				}

				// c. 启动清理 goroutine，排空 channel，关闭其他可能成功的 TCP 连接
				go func() {
					for otherResult := range results {
						if otherResult.client != nil {
							if otherResult.conn != nil {
								if tcpConn, ok := otherResult.conn.(*net.TCPConn); ok {
									tcpConn.SetLinger(0) // 立即关闭，发送 RST
								}
							}
							//fmt.Fprintf(os.Stderr, "stun close: %s\n", otherResult.conn.RemoteAddr().String())
							otherResult.client.Close()
						}
					}
				}()

				// d. 返回成功结果
				return r.index, r.local, r.nat, nil
			}
			// 如果 r.err != nil，忽略该错误结果，继续等待下一个
		}
	}
}

type P2PAddressInfo struct {
	Network   string
	LocalLAN  string
	LocalNAT  string
	RemoteLAN string
	RemoteNAT string
	SharedKey [32]byte
}

type securePayload struct {
	Nonce string `json:"nonce"`
	Data  string `json:"data"`
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

func deriveKeyForPayload(uid string) string {
	h := sha256.New()
	h.Write([]byte("gonc-p2p-payload"))
	h.Write([]byte(CalculateMD5(uid)))
	return hex.EncodeToString(h.Sum(nil))[:8]
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

func MQTT_Exchange_Symmetric(sendData, sessionUid string, brokerServers []string, timeout time.Duration) (recvData string, recvIndex int, err error) {
	var qos byte = 1
	topic := TopicExchange + deriveKeyForTopic("mqtt-topic-gonc-ex", sessionUid)

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

// ipInfo 用于在并发协程中保存 GetPublicIP 的结果
type ipInfo struct {
	localAddr string
	natAddr   string
	err       error
}

// exchangePayload 是用于在 Broker 上交换的统一数据结构
// 它包含了所有网络类型的地址信息和一个公钥
type exchangePayload struct {
	// 键是网络类型 (e.g., "tcp4"), 值是包含 lan 和 nat 地址的 map
	Addresses map[string]map[string]string `json:"addrs"`
	// 公钥的 Base64 编码字符串
	PubKey string `json:"pk"`
}

func Do_autoP2PEx(networks []string, sessionUid string, stunServers, brokerServers []string, timeout time.Duration, needSharedKey, verb bool) ([]*P2PAddressInfo, error) {
	// 定义要并发查询的网络类型
	myAddrResults := make(map[string]ipInfo, len(networks))
	var mu sync.Mutex
	var wg sync.WaitGroup

	if verb {
		fmt.Fprintf(os.Stderr, "    Getting local & public IP ...")
	}

	// **步骤 1: 并发获取所有网络类型的公网IP地址**
	for _, network := range networks {
		wg.Add(1)
		go func(net string) {
			defer wg.Done()
			// 为 GetPublicIP 设置独立的超时，应小于总超时
			_, local, nat, err := GetPublicIP(net, "", stunServers, 7*time.Second)

			mu.Lock()
			myAddrResults[net] = ipInfo{localAddr: local, natAddr: nat, err: err}
			mu.Unlock()
		}(network)
	}
	wg.Wait() // 等待所有 GetPublicIP 调用完成

	// **步骤 2: 准备要交换的数据**
	myInfoForExchange := exchangePayload{
		Addresses: make(map[string]map[string]string),
	}

	// 汇总所有成功获取到的地址
	nets := make([]string, 0, len(myAddrResults)) // 预分配容量
	hasSuccessfulLookup := false
	for net, info := range myAddrResults {
		if info.err == nil && info.localAddr != "" && info.natAddr != "" {
			myInfoForExchange.Addresses[net] = map[string]string{
				"lan": info.localAddr,
				"nat": info.natAddr,
			}
			nets = append(nets, net)
			hasSuccessfulLookup = true
		}
	}

	// 如果所有网络类型都获取地址失败，则没有必要继续
	if !hasSuccessfulLookup {
		if verb {
			fmt.Fprintf(os.Stderr, "Failed\n")
		}
		return nil, fmt.Errorf("failed to get any local/NAT address from STUN servers")
	} else {
		if verb {
			fmt.Fprintf(os.Stderr, "OK (Got %s).\n", strings.Join(nets, ","))
		}
	}

	var priv *ecdsa.PrivateKey
	var err error

	// 如果需要共享密钥，则生成一对ECC密钥（只需一次）
	if needSharedKey {
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
		}
		pubBytes := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
		myInfoForExchange.PubKey = base64.StdEncoding.EncodeToString(pubBytes)
	}

	// 使用一个固定的key来加密交换信息，这里用 sessionUid + "p2p"
	// 注意：原函数 deriveKey 使用了 network，这里需要修改或统一
	myKey := deriveKey("p2p-exchange", sessionUid)
	infoBytes, _ := json.Marshal(myInfoForExchange)
	encPayload, _ := encryptAES(myKey[:], infoBytes)
	encPayloadBytes, _ := json.Marshal(encPayload)

	// **步骤 3: 通过 Broker 交换信息**
	if verb {
		fmt.Fprintf(os.Stderr, "    Exchanging address info ...")
	}
	remoteInfoRaw, srvIndex, err := MQTT_Exchange_Symmetric(string(encPayloadBytes), sessionUid, brokerServers, timeout)
	if err != nil {
		if verb {
			fmt.Fprintf(os.Stderr, "Failed: %v\n", err)
		}
		return nil, err
	}
	if verb {
		fmt.Fprintf(os.Stderr, "OK (via %s)\n", brokerServers[srvIndex])
	}

	// **步骤 4: 解析对方的回复并计算共享密钥**
	var remoteSecurePayload securePayload
	if err = json.Unmarshal([]byte(remoteInfoRaw), &remoteSecurePayload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal remote secure payload: %w", err)
	}

	plain, err := decryptAES(myKey[:], &remoteSecurePayload)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt remote payload: %w", err)
	}

	var remotePayload exchangePayload
	if err = json.Unmarshal(plain, &remotePayload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal remote exchange payload: %w", err)
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

	// **步骤 5: 组合最终结果**
	var finalResults []*P2PAddressInfo
	// 遍历我们自己成功获取的地址
	for net, myInfo := range myAddrResults {
		if myInfo.err != nil {
			continue // 跳过获取失败的网络类型
		}

		// 检查对方是否也返回了相同网络类型的信息
		if remoteNetInfo, ok := remotePayload.Addresses[net]; ok {
			finalResults = append(finalResults, &P2PAddressInfo{
				Network:   net,
				LocalLAN:  myInfo.localAddr,
				LocalNAT:  myInfo.natAddr,
				RemoteLAN: remoteNetInfo["lan"],
				RemoteNAT: remoteNetInfo["nat"],
				SharedKey: sharedKey, // 共享密钥对所有网络类型都是一样的
			})
		}
	}

	if len(finalResults) == 0 {
		return nil, fmt.Errorf("no common network types found with peer")
	}

	return finalResults, nil
}

func Do_autoP2P(network string, sessionUid string, stunServers, brokerServers []string, timeout time.Duration, needSharedKey, verb bool) (*P2PAddressInfo, error) {
	p2pInfos, err := Do_autoP2PEx([]string{network}, sessionUid, stunServers, brokerServers, timeout, needSharedKey, verb)
	if err != nil {
		return nil, err
	}

	return p2pInfos[0], nil
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

func isSamePort(addr1, addr2 string) bool {
	_, port1, err1 := net.SplitHostPort(addr1)
	_, port2, err2 := net.SplitHostPort(addr2)

	if err1 != nil || err2 != nil {
		return false
	}

	return port1 == port2
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
	return strings.Compare(CalculateMD5(p2pInfo.LocalLAN+p2pInfo.LocalNAT), CalculateMD5(p2pInfo.RemoteLAN+p2pInfo.RemoteNAT)) <= 0
}

func p2pCanDirect(p2pInfo *P2PAddressInfo, ensureEasy bool) bool {

	if p2pInfo.LocalNAT == "" || p2pInfo.RemoteNAT == "" {
		return false
	}
	if p2pInfo.LocalLAN == "" || p2pInfo.RemoteLAN == "" {
		return false
	}

	sameNAT, similarLAN := CompareP2PAddresses(p2pInfo)
	if sameNAT && similarLAN {
		return true
	}

	isLocalNatPortChanged := !isSamePort(p2pInfo.LocalLAN, p2pInfo.LocalNAT)
	isRemoteNatPortChanged := !isSamePort(p2pInfo.RemoteLAN, p2pInfo.RemoteNAT)

	if isLocalNatPortChanged && isRemoteNatPortChanged {
		return false
	}

	if ensureEasy {
		if isLocalNatPortChanged || isRemoteNatPortChanged {
			return false
		}
	}

	return true
}

func p2pInfoPrint(p2pInfo *P2PAddressInfo) {
	fmt.Fprintf(os.Stderr, "  - %-14s: %s\n", "Network", p2pInfo.Network)
	fmt.Fprintf(os.Stderr, "  - %-14s: %s (LAN) / %s (NAT)\n", "Local Address", p2pInfo.LocalLAN, p2pInfo.LocalNAT)
	fmt.Fprintf(os.Stderr, "  - %-14s: %s (LAN) / %s (NAT)\n", "Remote Address", p2pInfo.RemoteLAN, p2pInfo.RemoteNAT)
}

// Helper function to convert the result slice from Do_autoP2PEx to a map for easy lookups.
func p2pInfoMap(infos []*P2PAddressInfo) map[string]*P2PAddressInfo {
	m := make(map[string]*P2PAddressInfo)
	for _, info := range infos {
		if info != nil {
			m[info.Network] = info
		}
	}
	return m
}

func Easy_P2P(network, sessionUid string, stunServers, brokerServers []string) (net.Conn, bool, []byte, error) {
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

	fmt.Fprintf(os.Stderr, "=== Checking NAT reachability ===\n")

	// --- 2. Get address information for all required networks in one go ---
	p2pInfos, err := Do_autoP2PEx(networksToTryStun, sessionUid, stunServers, brokerServers, 25*time.Second, true, true)
	if err != nil {
		// If we can't even get the address info, we can't proceed.
		return nil, false, nil, fmt.Errorf("failed to get P2P address info: %w", err)
	}
	// Convert the result slice to a map for O(1) lookups.
	availableInfos := p2pInfoMap(p2pInfos)

	// --- 3. Iterate through the ordered list and attempt connection ---
	var p2pInfo *P2PAddressInfo
	var ok, triedAtLeast bool

	switch {
	case strings.HasPrefix(network, "any"):
		p2pInfo, ok = availableInfos["tcp6"]
		if ok {
			conn, isRoleClient, _, err_tcp6 := Auto_P2P_TCP_NAT_Traversal("tcp6", sessionUid, p2pInfo,
				stunServers, brokerServers, false, 1)
			if err_tcp6 == nil {
				return conn, isRoleClient, p2pInfo.SharedKey[:], nil
			}
			triedAtLeast = true
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err_tcp6)
			time.Sleep(1 * time.Second)
		} else {
			p2pInfo, ok = availableInfos["tcp4"]
			if ok && p2pCanDirect(p2pInfo, true) {
				conn, isRoleClient, _, err_tcp4 := Auto_P2P_TCP_NAT_Traversal("tcp4", sessionUid, p2pInfo,
					stunServers, brokerServers, false, 1)
				if err_tcp4 == nil {
					return conn, isRoleClient, p2pInfo.SharedKey[:], nil
				}
				triedAtLeast = true
				fmt.Fprintf(os.Stderr, "ERROR: %v\n", err_tcp4)
				time.Sleep(1 * time.Second)
			}
		}
		p2pInfo, ok = availableInfos["udp4"]
		if ok {
			conn, isRoleClient, _, err_udp := Auto_P2P_UDP_NAT_Traversal("udp4", sessionUid, p2pInfo,
				stunServers, brokerServers, false, 2)
			if err_udp == nil {
				return conn, isRoleClient, p2pInfo.SharedKey[:], nil
			}
			triedAtLeast = true
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err_udp)
		}
	case network == "tcp":
		p2pInfo, ok = availableInfos["tcp6"]
		if ok {
			conn, isRoleClient, _, err_tcp6 := Auto_P2P_TCP_NAT_Traversal("tcp6", sessionUid, p2pInfo,
				stunServers, brokerServers, false, 1)
			if err_tcp6 == nil {
				return conn, isRoleClient, p2pInfo.SharedKey[:], nil
			}
			triedAtLeast = true
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err_tcp6)
			time.Sleep(1 * time.Second)
		} else {
			p2pInfo, ok = availableInfos["tcp4"]
			if ok {
				conn, isRoleClient, _, err_tcp4 := Auto_P2P_TCP_NAT_Traversal("tcp4", sessionUid, p2pInfo,
					stunServers, brokerServers, false, 2)
				if err_tcp4 == nil {
					return conn, isRoleClient, p2pInfo.SharedKey[:], nil
				}
				triedAtLeast = true
				fmt.Fprintf(os.Stderr, "ERROR: %v\n", err_tcp4)
				time.Sleep(1 * time.Second)
			}
		}

	case network == "udp":
		p2pInfo, ok = availableInfos["udp6"]
		if ok {
			conn, isRoleClient, _, err_udp6 := Auto_P2P_UDP_NAT_Traversal("udp6", sessionUid, p2pInfo,
				stunServers, brokerServers, false, 1)
			if err_udp6 == nil {
				return conn, isRoleClient, p2pInfo.SharedKey[:], nil
			}
			triedAtLeast = true
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err_udp6)
			time.Sleep(1 * time.Second)
		} else {
			p2pInfo, ok = availableInfos["udp4"]
			if ok {
				conn, isRoleClient, _, err_udp4 := Auto_P2P_UDP_NAT_Traversal("udp4", sessionUid, p2pInfo,
					stunServers, brokerServers, false, 2)
				if err_udp4 == nil {
					return conn, isRoleClient, p2pInfo.SharedKey[:], nil
				}
				triedAtLeast = true
				fmt.Fprintf(os.Stderr, "ERROR: %v\n", err_udp4)
				time.Sleep(1 * time.Second)
			}
		}

	case network == "tcp6" || network == "tcp4":
		p2pInfo, ok = availableInfos[network]
		if ok {
			conn, isRoleClient, _, attemptErr := Auto_P2P_TCP_NAT_Traversal(network, sessionUid, p2pInfo,
				stunServers, brokerServers, false, 2)
			if attemptErr == nil {
				return conn, isRoleClient, p2pInfo.SharedKey[:], nil
			}
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", attemptErr)
			triedAtLeast = true
		}
	case network == "udp6" || network == "udp4":
		p2pInfo, ok = availableInfos[network]
		if ok {
			conn, isRoleClient, _, attemptErr := Auto_P2P_UDP_NAT_Traversal(network, sessionUid, p2pInfo,
				stunServers, brokerServers, false, 2)
			if attemptErr == nil {
				return conn, isRoleClient, p2pInfo.SharedKey[:], nil
			}
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", attemptErr)
			triedAtLeast = true
		}
	default:
		return nil, false, nil, fmt.Errorf("unsupported network type: '%s'", network)
	}

	if !triedAtLeast {
		for _, netType := range networksToTryStun {
			p2pInfo, ok := availableInfos[netType]
			if ok {
				if strings.HasPrefix(netType, "tcp") {
					conn, isRoleClient, _, attemptErr := Auto_P2P_TCP_NAT_Traversal(netType, sessionUid, p2pInfo,
						stunServers, brokerServers, false, 2)
					if attemptErr == nil {
						return conn, isRoleClient, p2pInfo.SharedKey[:], nil
					}
					fmt.Fprintf(os.Stderr, "ERROR: %v\n", attemptErr)
				} else if strings.HasPrefix(netType, "udp") {
					conn, isRoleClient, _, attemptErr := Auto_P2P_UDP_NAT_Traversal(netType, sessionUid, p2pInfo,
						stunServers, brokerServers, false, 2)
					if attemptErr == nil {
						return conn, isRoleClient, p2pInfo.SharedKey[:], nil
					}
					fmt.Fprintf(os.Stderr, "ERROR: %v\n", attemptErr)
				} else {
					continue
				}
			}
		}
	}

	return nil, false, nil, fmt.Errorf("direct P2P connection failed")
}

func generateRandomPorts(count int) []int {
	const (
		minPort = 1024
		maxPort = 65535
	)

	r := mathrand.New(mathrand.NewSource(secureSeed()))
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

func Auto_P2P_UDP_NAT_Traversal(network, sessionUid string, p2pInfo *P2PAddressInfo, stunServers, brokerServers []string, needSharedKey bool, maxRound int) (net.Conn, bool, []byte, error) {
	var isClient bool
	var sharedKey []byte
	var count = 10
	var err error
	const (
		RPP_TIMEOUT = 7
	)
	punchPayload := []byte(deriveKeyForPayload(sessionUid))
	for round := 1; round <= maxRound; round++ {

		fmt.Fprintf(os.Stderr, "=== Round %d: Trying P2P(%s) Connection ===\n", round, network)

		// 交换 NAT 信息
		if round == 1 && p2pInfo != nil {
			//使用外面传进来的p2pInfo
		} else {
			p2pInfo, err = Do_autoP2P(network, sessionUid, stunServers, brokerServers, 25*time.Second, needSharedKey, true)
			if err != nil {
				return nil, false, nil, fmt.Errorf("P2P info exchange failed: %v", err)
			}
		}

		if needSharedKey {
			sharedKey = p2pInfo.SharedKey[:]
		}

		if round == 1 {
			//第一轮确定当前彼此角色
			isClient = SelectRole(p2pInfo)
		} else {
			isClient = !isClient
		}

		// 选择最佳目标地址（内网优先）
		sameNAT, similarLAN := CompareP2PAddresses(p2pInfo)
		remoteAddr := p2pInfo.RemoteNAT // 默认公网
		routeReason := "different network"
		inSameLAN := false
		if sameNAT && similarLAN {
			remoteAddr = p2pInfo.RemoteLAN // 同内网
			routeReason = "same NAT & similar LAN"
			inSameLAN = true
		}

		localMaybeNAT4 := !isSamePort(p2pInfo.LocalLAN, p2pInfo.LocalNAT)
		remoteMaybeNAT4 := !isSamePort(p2pInfo.RemoteLAN, p2pInfo.RemoteNAT)

		randomSrcPort := false
		ttl := 64
		randDstPorts := []int{}
		if !inSameLAN {
			if !localMaybeNAT4 && remoteMaybeNAT4 {
				//C->S
				randDstPorts = generateRandomPorts(PunchingRandomPortCount)
			} else if localMaybeNAT4 && !remoteMaybeNAT4 {
				//S->C
				randomSrcPort = true
			} else if localMaybeNAT4 && remoteMaybeNAT4 {
				if isClient {
					randDstPorts = generateRandomPorts(PunchingRandomPortCount)
				} else {
					randomSrcPort = true
				}
			}
		}
		if isClient {
			//只有先发包的，适合用小ttl值。
			ttl = PunchingShortTTL
		}
		if !inSameLAN && (localMaybeNAT4 || remoteMaybeNAT4) {
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
		// 打印详细连接信息
		p2pInfoPrint(p2pInfo)
		fmt.Fprintf(os.Stderr, "  - %-14s: %s (reason: %s)\n", "Best Route", remoteAddr, routeReason)
		if isClient {
			fmt.Fprintf(os.Stderr, "  - %-14s: sending PING every 1s (start immediately)\n", "Client Mode")
		} else {
			fmt.Fprintf(os.Stderr, "  - %-14s: sending PING every 1s (start after 2s)\n", "Server Mode")
		}
		fmt.Fprintf(os.Stderr, "  - %-14s: %ds\n", "Timeout", count)

		// 启动读写协程
		ctxStopPunching, stopPunching := context.WithCancel(context.Background())
		ctxRound, cancel := context.WithTimeout(context.Background(), time.Duration(count)*time.Second)
		defer cancel()
		defer stopPunching()

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
				fmt.Fprintf(os.Stderr, "  ↑ Sent PING(TTL=%d) (%d)\n", ttl, i+1)
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
					if len(randDstPorts) > 0 {
						fmt.Fprintf(os.Stderr, "  ↑ Sending random dst ports hole-punching packets. TTL=%d; total=%d; ...", ttl, PunchingRandomPortCount)
						for i := 0; i < PunchingRandomPortCount; i++ {
							addrStr := net.JoinHostPort(remoteNatIP, strconv.Itoa(randDstPorts[i]))
							peerAddr, _ := net.ResolveUDPAddr(network, addrStr)
							uconn.WriteToUDP(punchPayload, peerAddr)
						}
						fmt.Fprintf(os.Stderr, "completed.\n")
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

				fmt.Fprintf(os.Stderr, "  ↑ Sending Random Src Ports hole-punching packets. TTL=%d; ", ttl)

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
				fmt.Fprintf(os.Stderr, "total=%d !\n", len(conns))

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
						} else if len(randDstPorts) > 0 {
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
		select {
		case addrPair := <-gotHoleCh:
			buconn.Close()
			uconn, err = net.ListenUDP(network, addrPair.Local)
			if err != nil {
				return nil, false, nil, fmt.Errorf("error binding UDP address: %v", err)
			}
			buconn = NewBoundUDPConn(uconn, addrPair.Remote.String(), false)
			fmt.Fprintf(os.Stderr, "P2P(UDP) connection established (RSP)!\n")
			SetUDPTTL(uconn, 64)
			return buconn, isClient, sharedKey, nil
		case <-recvChan:
			fmt.Fprintf(os.Stderr, "P2P(UDP) connection established!\n")
			SetUDPTTL(uconn, 64)
			return buconn, isClient, sharedKey, nil
		case err := <-errChan:
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			buconn.Close()
		case <-ctxRound.Done():
			fmt.Fprintf(os.Stderr, "Round %d timeout (%ds)\n", round, count)
			buconn.Close()
		}
		fmt.Fprintf(os.Stderr, "\n")
		cancel()
		stopPunching()
	}
	return nil, false, nil, fmt.Errorf("P2P UDP hole punching failed after %d rounds", maxRound)
}

func Auto_P2P_TCP_NAT_Traversal(network, sessionUid string, p2pInfo *P2PAddressInfo, stunServers, brokerServers []string, needSharedKey bool, maxRound int) (net.Conn, bool, []byte, error) {
	var isClient bool
	var sharedKey []byte
	var err, errConn error
	for round := 1; round <= maxRound; round++ {

		fmt.Fprintf(os.Stderr, "=== Round %d: Trying P2P(%s) Connection ===\n", round, network)

		// 1. 交换 NAT 信息
		if round == 1 && p2pInfo != nil {
			//使用外面传进来的p2pInfo
		} else {
			p2pInfo, err = Do_autoP2P(network, sessionUid, stunServers, brokerServers, 25*time.Second, needSharedKey, true)
			if err != nil {
				return nil, false, nil, fmt.Errorf("P2P info exchange failed: %v", err)
			}
		}

		if needSharedKey {
			sharedKey = p2pInfo.SharedKey[:]
		}
		if round == 1 {
			//第一轮确定当前彼此角色
			isClient = SelectRole(p2pInfo)
		} else {
			isClient = !isClient
		}

		// 选择最佳目标地址（内网优先）
		sameNAT, similarLAN := CompareP2PAddresses(p2pInfo)
		remoteAddr := p2pInfo.RemoteNAT // 默认公网
		routeReason := "different network"
		if sameNAT && similarLAN {
			remoteAddr = p2pInfo.RemoteLAN // 同内网
			routeReason = "same NAT & similar LAN"
		}

		// 打印详细连接信息
		p2pInfoPrint(p2pInfo)
		fmt.Fprintf(os.Stderr, "  - %-14s: %s (reason: %s)\n", "Best Route", remoteAddr, routeReason)

		// 解析本地地址
		localAddr, err := net.ResolveTCPAddr(network, p2pInfo.LocalLAN)
		if err != nil {
			return nil, false, nil, fmt.Errorf("failed to resolve local address: %v", err)
		}

		if isClient {
			fmt.Fprintf(os.Stderr, "  - %-14s: connect start immediately\n", "Active Mode")
		} else {
			fmt.Fprintf(os.Stderr, "  - %-14s: connect start after 2s\n", "Passive Mode")
		}

		// 创建拨号器
		dialer := &net.Dialer{
			LocalAddr: localAddr,
			Control:   ControlTCP,
			Timeout:   6 * time.Second,
		}

		var listener net.Listener

		lc := net.ListenConfig{
			Control: ControlTCP,
		}

		var acceptedConn net.Conn
		acceptChan := make(chan bool)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		listener, err = lc.Listen(ctx, network, localAddr.String())
		if err == nil {
			defer listener.Close()
			go func() {
				deadline := time.Now().Add(12 * time.Second)
				listener.(*net.TCPListener).SetDeadline(deadline)
				acceptedConn, _ = listener.Accept()
				cancel()
				acceptChan <- true
			}()
		}

		if !isClient {
			// NAT打洞时，服务端延迟发包
			time.Sleep(2 * time.Second)
		}

		// 尝试主动连接
		maxAttempts := 2 // 最多尝试 2 次
		for attempt := 0; attempt < maxAttempts; attempt++ {
			conn, err := dialer.DialContext(ctx, network, remoteAddr)
			if err == nil {
				if listener != nil {
					listener.Close()
					<-acceptChan
					if acceptedConn != nil {
						acceptedConn.Close()
					}
				}
				fmt.Fprintf(os.Stderr, "P2P(TCP) connection established (dial)!\n")
				return conn, isClient, sharedKey, nil
			}
			errConn = err
			if attempt+1 < maxAttempts {
				time.Sleep(1 * time.Second)
			}
		}

		if listener != nil {
			listener.Close()
			<-acceptChan
			if acceptedConn != nil {
				// 检查是否是对端连接（仅比较 IP，忽略端口）
				clientIP, _, err2 := net.SplitHostPort(acceptedConn.RemoteAddr().String())
				if err2 == nil {
					expectedIP, _, _ := net.SplitHostPort(remoteAddr)
					if (clientIP == expectedIP) ||
						(sameNAT && similarLAN && IsSameLAN(clientIP, expectedIP)) {
						fmt.Fprintf(os.Stderr, "P2P(TCP) connection established (accept)!\n")
						return acceptedConn, isClient, sharedKey, nil
					} else {
						err2 = fmt.Errorf("unexpected peer connection address")
					}
				}
				errConn = err2
			}
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", errConn)
		cancel()
	}

	return nil, false, nil, fmt.Errorf("P2P TCP Simultaneous Open failed after %d rounds", maxRound)
}

func logStderr(msg string, args ...interface{}) {
	timestamp := time.Now().Format("20060102-150405")
	fmt.Fprintf(os.Stderr, "%s ", timestamp)
	fmt.Fprintf(os.Stderr, msg, args...)
}

func MqttWait(sessionUid string, brokerServers []string, timeout time.Duration) (string, error) {
	uid := deriveKeyForTopic("mqtt-topic-gonc-wait", sessionUid)
	topic := TopicExchangeWait + uid
	logStderr("Waiting for event on topic: %s across %d servers\n", topic, len(brokerServers))

	msgReceived := make(chan string, 1)
	var clients []mqtt.Client
	var clientsMutex sync.Mutex

	baseClientID := deriveKeyForTopic("mqtt-topic-gonc-waiter", sessionUid)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for i, server := range brokerServers {
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
						logStderr("Failed to subscribe to topic %s on %s: %v\n", topic, brokerAddr, token.Error())
					} else {
						logStderr("Subscribed to topic %s on %s\n", topic, brokerAddr)
					}
				}).
				SetConnectionLostHandler(func(c mqtt.Client, err error) {
					logStderr("MQTT connection lost from %s: %v\n", brokerAddr, err)
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
				logStderr("MQTT connect to %s failed: %v\n", brokerAddr, token.Error())
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
		logStderr("Received event: %s\n", string(plain))
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

func MqttPush(msg, sessionUid string, brokerServers []string) error {
	uid := deriveKeyForTopic("mqtt-topic-gonc-wait", sessionUid)
	topic := TopicExchangeWait + uid

	fmt.Fprintf(os.Stderr, "MQTT: Pushing to topic %s across %d servers: %s\n", topic, len(brokerServers), msg)

	myKey := deriveKey("hello", sessionUid)
	encPayload, _ := encryptAES(myKey[:], []byte(msg))
	encPayloadBytes, _ := json.Marshal(encPayload)
	payload := string(encPayloadBytes)

	var successCount int32
	var wg sync.WaitGroup

	errChan := make(chan struct{}, len(brokerServers)) // 用于通知“失败发生”
	successNotify := make(chan struct{}, 1)            // 用于通知“至少两个成功”
	var once sync.Once

	for _, server := range brokerServers {
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

	fmt.Fprintf(os.Stderr, "MQTT: Push operation completed. Successes: %d\n", successes)
	return nil
}
