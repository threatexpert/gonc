package misc

import (
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
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
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
)

func GetPublicIP(network, bind, turnServer string, timeout time.Duration) (localaddress, nataddress string, err error) {

	lastStunClientLock.Lock()
	defer lastStunClientLock.Unlock()

	if lastStunClient != nil {
		if tcpConn, ok := lastStunClientConn.(*net.TCPConn); ok {
			tcpConn.SetLinger(0) // 立即关闭，发送 RST
		}
		lastStunClient.Close()
		time.Sleep(100 * time.Millisecond)
	}

	var laddr net.Addr

	switch network {
	case "tcp":
		laddr, err = net.ResolveTCPAddr("tcp", bind)
		if err != nil {
			return "", "", fmt.Errorf("resolve local tcp addr failed: %v", err)
		}
	case "udp":
		laddr, err = net.ResolveUDPAddr("udp", bind)
		if err != nil {
			return "", "", fmt.Errorf("resolve local udp addr failed: %v", err)
		}
	default:
		return "", "", fmt.Errorf("unsupported network: %s", network)
	}

	d := &net.Dialer{
		LocalAddr: laddr,
		Timeout:   timeout,
	}

	switch network {
	case "tcp":
		d.Control = ControlTCP
	case "udp":
		d.Control = ControlUDP
	}

	conn, err := d.Dial(network, turnServer)
	if err != nil {
		return "", "", fmt.Errorf("STUN dial failed: %v", err)
	}

	c, err := stun.NewClient(conn)
	if err != nil {
		conn.Close()
		return "", "", fmt.Errorf("STUN NewClient failed: %v", err)
	}

	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	var xorAddr stun.XORMappedAddress
	var err2 error
	if err := c.Do(message, func(res stun.Event) {
		if res.Error != nil {
			err2 = fmt.Errorf("STUN error: %v", res.Error)
			return
		}
		// 解析XOR-MAPPED-ADDRESS属性
		if err := xorAddr.GetFrom(res.Message); err != nil {
			err2 = fmt.Errorf("failed to get XOR-MAPPED-ADDRESS: %v", err)
			return
		}
	}); err != nil {
		c.Close()
		return "", "", fmt.Errorf("STUN Do failed: %v", err)
	}
	if err2 != nil {
		c.Close()
		return "", "", err2
	}

	//tcp不关闭连接，保持连接可能有助于NAT穿透，如果有连接关闭了可能NAT打开的洞也关闭
	if network == "tcp" {
		lastStunClient = c
		lastStunClientConn = conn
		go func(tc net.Conn, sc *stun.Client) {
			buf := make([]byte, 1)
			_, _ = tc.Read(buf)
			//如果对方挥手，我即时挥手，避免RST导致NAT打开的洞也关闭
			//如果程序中断，本地会发出RST，没有 TIME_WAIT，这有助于立刻重新绑定到原地址
			sc.Close()
		}(conn, c)
	} else {
		c.Close()
	}

	return conn.LocalAddr().String(), xorAddr.String(), nil
}

type P2PAddressInfo struct {
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

func MQTT_Exchange_Symmetric(sendData, sessionUid, brokerServer string, timeout time.Duration) (recvData string, err error) {
	topic := TopicExchange + deriveKeyForTopic("mqtt-topic-gonc-ex", sessionUid)

	opts := mqtt.NewClientOptions().AddBroker(brokerServer)
	opts.SetClientID(deriveKeyForTopic("mqtt-topic-gonc-cid", sessionUid) + fmt.Sprint(time.Now().UnixNano()))
	client := mqtt.NewClient(opts)

	if token := client.Connect(); token.Wait() && token.Error() != nil {
		return "", token.Error()
	}
	defer func() {
		client.Disconnect(250)             // 等待最多 250ms 尝试发送未完成的消息
		time.Sleep(500 * time.Millisecond) // 再额外等 500ms，确保清理后台 goroutine
	}()
	recvRemoteData := make(chan string, 1)

	// 订阅
	if token := client.Subscribe(topic, 0, func(_ mqtt.Client, msg mqtt.Message) {
		recvRemoteData <- string(msg.Payload())
	}); token.Wait() && token.Error() != nil {
		return "", token.Error()
	}

	//发布数据
	client.Publish(topic, 0, false, sendData)
	stopPublish := make(chan struct{})
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopPublish:
				return
			case <-ticker.C:
				client.Publish(topic, 0, false, sendData)
			}
		}
	}()

	var remoteData string
	gotRemote := false
	timeoutTimer := time.NewTimer(timeout)
	defer timeoutTimer.Stop()

	for !gotRemote {
		select {
		case remoteData = <-recvRemoteData:
			if remoteData != sendData {
				gotRemote = true
				client.Publish(topic, 1, false, sendData)
			}
		case <-timeoutTimer.C:
			close(stopPublish) //等待确认超时了则停止发布数据
			return "", errors.New("timeout waiting for remote data exchange")
		}
	}

	//退出循环了说明确认了，停止发布数据
	close(stopPublish)

	return remoteData, nil
}

func deriveKey(salt, uid string) [32]byte {
	salt0 := "nc-p2p-tool"
	h := sha256.New()
	h.Write([]byte(salt0))
	h.Write([]byte(salt))
	h.Write([]byte(uid))
	return sha256.Sum256(h.Sum(nil))
}

func Do_autoP2P(network, sessionUid, turnServer, brokerServer string, timeout time.Duration, needSharedKey, verb bool) (*P2PAddressInfo, error) {

	var priv *ecdsa.PrivateKey
	var sharedKey [32]byte
	myKey := deriveKey(network, sessionUid)

	if verb {
		fmt.Fprintf(os.Stderr, "    Getting local & public IP...\n")
	}
	localAddr, natAddr, err := GetPublicIP(network, "", turnServer, 5*time.Second)
	if err != nil {
		return nil, err
	}
	myInfo := map[string]string{"lan": localAddr, "nat": natAddr, "pk": ""}
	if needSharedKey {
		// ECC key gen
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		pubBytes := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
		myInfo["pk"] = base64.StdEncoding.EncodeToString(pubBytes)
	}
	infoBytes, _ := json.Marshal(myInfo)
	encPayload, _ := encryptAES(myKey[:], infoBytes)
	encPayloadBytes, _ := json.Marshal(encPayload)

	if verb {
		fmt.Fprintf(os.Stderr, "    Sending encrypted address info...\n")
	}
	remoteInfoRaw, err := MQTT_Exchange_Symmetric(string(encPayloadBytes), sessionUid, brokerServer, timeout)
	if err != nil {
		return nil, err
	}

	var remotePayload securePayload
	err = json.Unmarshal([]byte(remoteInfoRaw), &remotePayload)
	if err != nil {
		return nil, err
	}
	plain, err := decryptAES(myKey[:], &remotePayload)
	if err != nil {
		return nil, err
	}
	var remoteInfo map[string]string
	err = json.Unmarshal(plain, &remoteInfo)
	if err != nil {
		return nil, err
	}
	lan, ok1 := remoteInfo["lan"]
	nat, ok2 := remoteInfo["nat"]
	remotePubRaw, ok3 := remoteInfo["pk"]
	if !ok1 || !ok2 || !ok3 {
		return nil, fmt.Errorf("missing required remote address fields")
	}
	if needSharedKey {
		if len(remotePubRaw) == 0 {
			return nil, fmt.Errorf("missing pk data")
		}
		remotePubBytes, err := base64.StdEncoding.DecodeString(remotePubRaw)
		if err != nil {
			return nil, err
		}
		x, y := elliptic.Unmarshal(elliptic.P256(), remotePubBytes)
		sharedX, _ := priv.PublicKey.Curve.ScalarMult(x, y, priv.D.Bytes())
		sharedKey = sha256.Sum256(sharedX.Bytes())
	}

	return &P2PAddressInfo{
		LocalLAN:  localAddr,
		LocalNAT:  natAddr,
		RemoteLAN: lan,
		RemoteNAT: nat,
		SharedKey: sharedKey,
	}, nil
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

// 判断两个 IP 是否属于同一个 /24 网段（前 3 段相同）
func IsSameLAN(ip1, ip2 string) bool {
	parsed1 := net.ParseIP(ip1)
	parsed2 := net.ParseIP(ip2)
	if parsed1 == nil || parsed2 == nil {
		return false
	}

	if parsed1.IsLoopback() || parsed2.IsLoopback() {
		return false
	}

	// 检查是否都在私有地址段
	if parsed1.IsPrivate() && parsed2.IsPrivate() {
		// 针对常见私网段用合理掩码判断
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
	if len(parts1) != 4 || len(parts2) != 4 {
		return false
	}
	return parts1[0] == parts2[0] && parts1[1] == parts2[1] && parts1[2] == parts2[2]
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

func SelectRole(p2pInfo *P2PAddressInfo) bool {
	return strings.Compare(CalculateMD5(p2pInfo.LocalLAN+p2pInfo.LocalNAT), CalculateMD5(p2pInfo.RemoteLAN+p2pInfo.RemoteNAT)) <= 0
}

func Simple_P2P(network, sessionUid, turnServer string, brokerServer string) (net.Conn, bool, error) {
	fmt.Fprintf(os.Stderr, "Exchanging NAT address info via MQTT...\n")
	p2pInfo, err := Do_autoP2P(network, sessionUid, turnServer, brokerServer, 25*time.Second, false, true)
	if err != nil {
		return nil, false, err
	}
	isClient := SelectRole(p2pInfo)
	sameNAT, similarLAN := CompareP2PAddresses(p2pInfo)
	remoteAddr := p2pInfo.RemoteNAT // 默认公网
	routeReason := "different network"
	if sameNAT && similarLAN {
		remoteAddr = p2pInfo.RemoteLAN // 同内网
		routeReason = "same NAT & similar LAN"
	}
	if sameNAT && similarLAN {
		remoteAddr = p2pInfo.RemoteLAN // 同内网
	}

	fmt.Fprintf(os.Stderr, "  - %-14s: %s (LAN) / %s (NAT)\n", "Local Address", p2pInfo.LocalLAN, p2pInfo.LocalNAT)
	fmt.Fprintf(os.Stderr, "  - %-14s: %s (LAN) / %s (NAT)\n", "Remote Address", p2pInfo.RemoteLAN, p2pInfo.RemoteNAT)
	fmt.Fprintf(os.Stderr, "  - %-14s: %s (reason: %s)\n", "Best Route", remoteAddr, routeReason)
	if network == "tcp" {
		if isClient {
			fmt.Fprintf(os.Stderr, "  - %-14s: connect start immediately\n", "Active Mode")
		} else {
			fmt.Fprintf(os.Stderr, "  - %-14s: connect start after 2s\n", "Passive Mode")
		}
	}

	dialer := &net.Dialer{}
	var localTcpAddr *net.TCPAddr
	switch network {
	case "tcp":
		dialer.Control = ControlTCP
		localTcpAddr, err = net.ResolveTCPAddr("tcp", p2pInfo.LocalLAN)
		if err != nil {
			return nil, false, err
		}
		dialer.LocalAddr = localTcpAddr
	case "udp":
		dialer.Control = ControlUDP
		localAddr, err := net.ResolveUDPAddr("udp", p2pInfo.LocalLAN)
		if err != nil {
			return nil, false, err
		}
		dialer.LocalAddr = localAddr
	}

	var listener net.Listener

	if !isClient {
		if network == "tcp" {
			lc := net.ListenConfig{
				Control: ControlTCP,
			}
			listener, err = lc.Listen(context.Background(), "tcp", localTcpAddr.String())
			if err != nil {
				return nil, false, err
			}

			// 设置accept超时
			deadline := time.Now().Add(10 * time.Second)
			listener.(*net.TCPListener).SetDeadline(deadline)
		}
		time.Sleep(2 * time.Second)
	}
	conn, err := dialer.Dial(network, remoteAddr)
	if err == nil {
		return conn, isClient, nil
	}

	if listener != nil {
		var err2 error
		conn, err2 = listener.Accept()
		listener.Close()
		if err2 == nil {
			// 检查是否是对端连接（仅比较 IP，忽略端口）
			clientIP, _, err2 := net.SplitHostPort(conn.RemoteAddr().String())
			if err2 == nil {
				expectedIP, _, _ := net.SplitHostPort(remoteAddr)
				if clientIP == expectedIP {
					return conn, isClient, nil
				}
			}
			conn.Close() // 不是目标连接，关闭
			conn = nil
		}
	}

	return nil, false, err
}

func Auto_P2P_UDP_NAT_Traversal(sessionUid, turnServer, brokerServer string, needSharedKey bool) (net.Conn, bool, []byte, error) {
	var isClient bool
	var sharedKey []byte
	var count = 12
	for round := 1; round <= 4; round++ {

		fmt.Fprintf(os.Stderr, "=== Round %d: Trying UDP-P2P Connection ===\n", round)

		// 1. 交换 NAT 信息
		p2pInfo, err := Do_autoP2P("udp", sessionUid, turnServer, brokerServer, 25*time.Second, needSharedKey, true)
		if err != nil {
			return nil, false, nil, fmt.Errorf("P2P info exchange failed: %v", err)
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

		// 2. 解析本地地址
		localAddr, err := net.ResolveUDPAddr("udp", p2pInfo.LocalLAN)
		if err != nil {
			return nil, false, nil, fmt.Errorf("failed to resolve local address: %v", err)
		}

		// 3. 创建拨号器
		dialer := &net.Dialer{
			LocalAddr: localAddr,
			Control:   ControlUDP,
			Timeout:   5 * time.Second,
		}

		// 4. 选择最佳目标地址（内网优先）
		sameNAT, similarLAN := CompareP2PAddresses(p2pInfo)
		remoteAddr := p2pInfo.RemoteNAT // 默认公网
		routeReason := "different network"
		if sameNAT && similarLAN {
			remoteAddr = p2pInfo.RemoteLAN // 同内网
			routeReason = "same NAT & similar LAN"
		}

		// 5. 建立 UDP 连接
		conn, err := dialer.Dial("udp", remoteAddr)
		if err != nil {
			return nil, false, nil, fmt.Errorf("failed to dial remote: %v", err)
		}

		// 6. 打印详细连接信息
		fmt.Fprintf(os.Stderr, "  - %-14s: %s (LAN) / %s (NAT)\n", "Local Address", p2pInfo.LocalLAN, p2pInfo.LocalNAT)
		fmt.Fprintf(os.Stderr, "  - %-14s: %s (LAN) / %s (NAT)\n", "Remote Address", p2pInfo.RemoteLAN, p2pInfo.RemoteNAT)
		fmt.Fprintf(os.Stderr, "  - %-14s: %s (reason: %s)\n", "Best Route", remoteAddr, routeReason)

		if isClient {
			fmt.Fprintf(os.Stderr, "  - %-14s: sending PING every 1s (start immediately)\n", "Client Mode")
		} else {
			fmt.Fprintf(os.Stderr, "  - %-14s: sending PING every 1s (start after 2s)\n", "Server Mode")
		}

		fmt.Fprintf(os.Stderr, "  - %-14s: %ds\n", "Timeout", count)

		// 7. 启动读写协程
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(count)*time.Second)
		defer cancel()

		recvChan := make(chan bool)
		errChan := make(chan error)

		// 读协程：收包，类似TCP三次握手等待TCP SYN+ACK
		go func() {
			buf := make([]byte, 1024)
			for {
				n, err := conn.Read(buf)
				if err != nil {
					errChan <- err
					return
				}
				if n >= 4 && string(buf[:4]) == "ping" {
					fmt.Fprintf(os.Stderr, "Received PING from peer!\n")
					conn.Write([]byte("ping")) //类似TCP三次握手收到SYN+ACK后，发送个ACK
					recvChan <- true
					return
				}
			}
		}()

		// 写协程：按角色发包，类似TCP三次握手发送 SYN
		go func() {
			if isClient {
				// 客户端：立即发 ping
				for i := 0; i < count; i++ {
					select {
					case <-ctx.Done():
						return
					default:
						if _, err := conn.Write([]byte("ping")); err != nil {
							errChan <- err
							return
						}
						fmt.Fprintf(os.Stderr, "  ↑ Sent PING (%d/%d)\n", i+1, count)
						time.Sleep(1 * time.Second)
					}
				}
			} else {
				// 服务端：2秒后发 ping
				time.Sleep(2 * time.Second)
				for i := 0; i < (count - 2); i++ {
					select {
					case <-ctx.Done():
						return
					default:
						if _, err := conn.Write([]byte("ping")); err != nil {
							errChan <- err
							return
						}
						fmt.Fprintf(os.Stderr, "  ↑ Sent PING (%d/%d)\n", i+1, count-2)
						time.Sleep(1 * time.Second)
					}
				}
			}
		}()

		// 8. 等待结果
		select {
		case <-recvChan:
			fmt.Fprintf(os.Stderr, "UDP-P2P connection established!\n")
			return conn, isClient, sharedKey, nil
		case err := <-errChan:
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			conn.Close()
		case <-ctx.Done():
			fmt.Fprintf(os.Stderr, "Round %d timeout (%ds)\n", round, count)
			conn.Close()
		}
		fmt.Fprintf(os.Stderr, "\n")
	}
	return nil, false, nil, fmt.Errorf("P2P UDP hole punching failed after 4 rounds")
}

func Auto_P2P_TCP_NAT_Traversal(sessionUid, turnServer, brokerServer string, needSharedKey bool) (net.Conn, bool, []byte, error) {
	var isClient bool
	var sharedKey []byte
	var conn net.Conn
	for round := 1; round <= 4; round++ {

		fmt.Fprintf(os.Stderr, "=== Round %d: Trying TCP-P2P Connection ===\n", round)

		// 1. 交换 NAT 信息
		p2pInfo, err := Do_autoP2P("tcp", sessionUid, turnServer, brokerServer, 25*time.Second, needSharedKey, true)
		if err != nil {
			return nil, false, nil, fmt.Errorf("P2P info exchange failed: %v", err)
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
		fmt.Fprintf(os.Stderr, "  - %-14s: %s (LAN) / %s (NAT)\n", "Local Address", p2pInfo.LocalLAN, p2pInfo.LocalNAT)
		fmt.Fprintf(os.Stderr, "  - %-14s: %s (LAN) / %s (NAT)\n", "Remote Address", p2pInfo.RemoteLAN, p2pInfo.RemoteNAT)
		fmt.Fprintf(os.Stderr, "  - %-14s: %s (reason: %s)\n", "Best Route", remoteAddr, routeReason)

		// 解析本地地址
		localAddr, err := net.ResolveTCPAddr("tcp", p2pInfo.LocalLAN)
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
		if !isClient {
			lc := net.ListenConfig{
				Control: ControlTCP,
			}
			listener, err = lc.Listen(context.Background(), "tcp", localAddr.String())
			if err != nil {
				return nil, false, nil, fmt.Errorf("listen failed: %v", err)
			}

			// 设置accept超时
			deadline := time.Now().Add(10 * time.Second)
			listener.(*net.TCPListener).SetDeadline(deadline)

			// NAT打洞时，服务端延迟发包
			time.Sleep(2 * time.Second)
		}

		// 尝试主动连接
		maxAttempts := 2 // 最多尝试 2 次
		for attempt := 0; attempt < maxAttempts; attempt++ {
			conn, err = dialer.Dial("tcp", remoteAddr)
			if err == nil {
				fmt.Fprintf(os.Stderr, "TCP-P2P connection established (dial)!\n")
				return conn, isClient, sharedKey, nil
			}
			time.Sleep(1 * time.Second)
		}

		if listener != nil {
			var err2 error
			conn, err2 = listener.Accept()
			listener.Close()
			if err2 == nil {
				// 检查是否是对端连接（仅比较 IP，忽略端口）
				clientIP, _, err2 := net.SplitHostPort(conn.RemoteAddr().String())
				if err2 == nil {
					expectedIP, _, _ := net.SplitHostPort(remoteAddr)
					if clientIP == expectedIP {
						fmt.Fprintf(os.Stderr, "TCP-P2P connection established (accept)!\n")
						return conn, isClient, sharedKey, nil
					}
				}
				conn.Close() // 不是目标连接，关闭
				conn = nil
			}
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}

	return nil, false, nil, fmt.Errorf("P2P TCP Simultaneous Open failed after 4 rounds")
}

func logStderr(msg string, args ...interface{}) {
	timestamp := time.Now().Format("20060102-150405")
	fmt.Fprintf(os.Stderr, "%s ", timestamp)
	fmt.Fprintf(os.Stderr, msg, args...)
}

func MqttWait(sessionUid, brokerServer string, timeout time.Duration) (string, error) {
	uid := deriveKeyForTopic("mqtt-topic-gonc-wait", sessionUid)
	topic := TopicExchangeWait + uid
	logStderr("Waiting for event on topic: %s\n", topic)

	msgReceived := make(chan string, 1)

	opts := mqtt.NewClientOptions().
		AddBroker(brokerServer).
		SetClientID(deriveKeyForTopic("mqtt-topic-gonc-waiter", sessionUid)).
		SetAutoReconnect(true).
		SetConnectRetry(true).
		SetConnectRetryInterval(3 * time.Second).
		SetOnConnectHandler(func(c mqtt.Client) {
			if token := c.Subscribe(topic, 0, func(client mqtt.Client, msg mqtt.Message) {
				select {
				case msgReceived <- string(msg.Payload()):
				default:
				}
			}); token.Wait() && token.Error() != nil {
				logStderr("Failed to re-subscribe on connect: %v\n", token.Error())
			} else {
				logStderr("Subscribed (or re-subscribed) to topic: %v\n", topic)
			}
		}).
		SetConnectionLostHandler(func(c mqtt.Client, err error) {
			logStderr("MQTT connection lost: %v\n", err)
		})

	client := mqtt.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		return "", fmt.Errorf("MQTT connect failed: %w", token.Error())
	}
	defer func() {
		client.Disconnect(250)             // 等待最多 250ms 尝试发送未完成的消息
		time.Sleep(500 * time.Millisecond) // 再额外等 500ms，确保清理后台 goroutine
	}()

	myKey := deriveKey("hello", sessionUid)
	var payloadRaw string
	var plain []byte
	var err error
	select {
	case payloadRaw = <-msgReceived:
		var remotePayload securePayload
		err = json.Unmarshal([]byte(payloadRaw), &remotePayload)
		if err != nil {
			return "", err
		}
		plain, err = decryptAES(myKey[:], &remotePayload)
		if err != nil {
			return "", err
		}
		logStderr("Received event: %s\n", string(plain))
	case <-time.After(timeout):
		return "", fmt.Errorf("timeout waiting for MQTT event")
	}

	return string(plain), nil
}

// MqttPush 连接到 MQTT 服务器并发送消息到指定 topic
func MqttPush(msg, sessionUid, brokerServer string) error {
	uid := deriveKeyForTopic("mqtt-topic-gonc-wait", sessionUid)
	topic := TopicExchangeWait + uid

	fmt.Fprintf(os.Stderr, "MQTT: pushing to topic %s: %s\n", topic, msg)

	opts := mqtt.NewClientOptions().
		AddBroker(brokerServer).
		SetClientID(deriveKeyForTopic("mqtt-topic-gonc-push", sessionUid)).
		SetConnectTimeout(5 * time.Second)

	client := mqtt.NewClient(opts)

	token := client.Connect()
	if token.Wait() && token.Error() != nil {
		return fmt.Errorf("MQTT connect failed: %v", token.Error())
	}
	defer client.Disconnect(250)

	myKey := deriveKey("hello", sessionUid)

	encPayload, _ := encryptAES(myKey[:], []byte(msg))
	encPayloadBytes, _ := json.Marshal(encPayload)

	pub := client.Publish(topic, 1, false, string(encPayloadBytes))
	if pub.Wait() && pub.Error() != nil {
		return fmt.Errorf("MQTT publish failed: %v", pub.Error())
	}

	fmt.Fprintf(os.Stderr, "MQTT: pushed successfully\n")
	return nil
}
