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
	"errors"
	"fmt"
	mathrand "math/rand"
	"net"
	"os"
	"strconv"
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

	DebugServerRole         string
	PunchingShortTTL        int = 5
	PunchingRandomPortCount int = 600
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

	if network == "tcp" || network == "udp" {
		//传参不明确时统一用ipv4
		network += "4"
	}

	switch {
	case strings.HasPrefix(network, "tcp"):
		laddr, err = net.ResolveTCPAddr(network, bind)
		if err != nil {
			return "", "", fmt.Errorf("resolve local tcp addr failed: %v", err)
		}
	case strings.HasPrefix(network, "udp"):
		laddr, err = net.ResolveUDPAddr(network, bind)
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

	switch {
	case strings.HasPrefix(network, "tcp"):
		d.Control = ControlTCP
	case strings.HasPrefix(network, "udp"):
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
	if strings.HasPrefix(network, "tcp") {
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

func deriveKeyForPayload(uid string) string {
	h := sha256.New()
	h.Write([]byte("gonc-p2p-payload"))
	h.Write([]byte(CalculateMD5(uid)))
	return hex.EncodeToString(h.Sum(nil))[:8]
}

func MQTT_Exchange_Symmetric(sendData, sessionUid, brokerServer string, timeout time.Duration) (recvData string, err error) {
	var qos byte = 2
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
	if token := client.Subscribe(topic, qos, func(_ mqtt.Client, msg mqtt.Message) {
		recvRemoteData <- string(msg.Payload())
	}); token.Wait() && token.Error() != nil {
		return "", token.Error()
	}

	//发布数据
	if token := client.Publish(topic, qos, false, sendData); token.Wait() && token.Error() != nil {
		return "", token.Error()
	}
	stopPublish := make(chan struct{})
	defer close(stopPublish)
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopPublish:
				return
			case <-ticker.C:
				client.Publish(topic, qos, false, sendData)
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
				token := client.Unsubscribe(topic)
				token.Wait()
				client.Publish(topic, qos, false, sendData)
			}
		case <-timeoutTimer.C:
			return "", errors.New("timeout waiting for remote data exchange")
		}
	}

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

	var err, pubIPErr error
	var priv *ecdsa.PrivateKey
	var sharedKey [32]byte
	myKey := deriveKey(network, sessionUid)

	if verb {
		fmt.Fprintf(os.Stderr, "    Getting local & public IP (using STUN server: %s)...", turnServer)
	}
	localAddr, natAddr, pubIPErr := GetPublicIP(network, "", turnServer, 5*time.Second)
	if pubIPErr != nil {
		if verb {
			fmt.Fprintf(os.Stderr, "Failed\n")
		}
	} else {
		if verb {
			fmt.Fprintf(os.Stderr, "OK\n")
		}
	}
	//即使GetPublicIP失败了，localAddr和natAddr为空时也通过MQTT告诉对方
	myInfo := map[string]string{"lan": localAddr, "nat": natAddr, "pk": ""}
	if pubIPErr == nil && needSharedKey {
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
		fmt.Fprintf(os.Stderr, "    Exchanging address info (using MQTT: %s)...", brokerServer)
	}
	remoteInfoRaw, err := MQTT_Exchange_Symmetric(string(encPayloadBytes), sessionUid, brokerServer, timeout)
	if err != nil {
		if verb {
			fmt.Fprintf(os.Stderr, "Failed\n")
		}
		return nil, err
	}
	if verb {
		fmt.Fprintf(os.Stderr, "OK\n")
	}

	if pubIPErr != nil {
		return nil, pubIPErr
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
		return nil, fmt.Errorf("missing required remote address fields from peer")
	}
	if lan == "" || nat == "" {
		return nil, fmt.Errorf("the peer did not provide LAN or NAT %s address", network)
	}
	if needSharedKey {
		if len(remotePubRaw) == 0 {
			return nil, fmt.Errorf("missing pk field from peer")
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

func p2pCanDirect(p2pInfo *P2PAddressInfo) bool {

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

	return true
}

func Easy_P2P(network, sessionUid, turnServer string, brokerServer string) (net.Conn, bool, error) {
	var conn net.Conn
	var isRoleClient bool
	var p2pInfo *P2PAddressInfo
	tcp6Tried := false
	tcp4Tried := false
	var err_tcp6, err_tcp4, err_udp error
	finetwork := "tcp"

	if network == "any" || strings.HasSuffix(network, "6") {
		finetwork += "6"
		fmt.Fprintf(os.Stderr, "=== Checking IPv6 reachability ===\n")
	} else {
		finetwork += "4"
	}

	p2pInfo, err_tcp6 = Do_autoP2P(finetwork, sessionUid, turnServer, brokerServer, 25*time.Second, false, true)
	if err_tcp6 == nil {
		fmt.Fprintf(os.Stderr, "  - %-14s: %s (LAN) / %s (NAT)\n", "Local Address", p2pInfo.LocalLAN, p2pInfo.LocalNAT)
		fmt.Fprintf(os.Stderr, "  - %-14s: %s (LAN) / %s (NAT)\n", "Remote Address", p2pInfo.RemoteLAN, p2pInfo.RemoteNAT)
		if p2pCanDirect(p2pInfo) {
			if finetwork == "tcp4" {
				tcp4Tried = true
			} else if finetwork == "tcp6" {
				tcp6Tried = true
			}
			time.Sleep(3 * time.Second)
			conn, isRoleClient, _, err_tcp6 = Auto_P2P_TCP_NAT_Traversal(finetwork, sessionUid,
				turnServer, brokerServer, false, 2)
			if err_tcp6 == nil {
				return conn, isRoleClient, nil
			}
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err_tcp6)
			time.Sleep(3 * time.Second)
		} else {
			//tcp4、6都不需要再尝试了
			tcp4Tried = true
			tcp6Tried = true
		}
	} else {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err_tcp6)
		time.Sleep(3 * time.Second)
	}

	if network == "any" || strings.HasSuffix(network, "4") {
		if finetwork == "tcp6" && !tcp4Tried && !tcp6Tried {
			//如果是没有共同的IPv6的条件，则尝试IPv4的tcp
			conn, isRoleClient, _, err_tcp4 = Auto_P2P_TCP_NAT_Traversal("tcp4", sessionUid,
				turnServer, brokerServer, false, 2)
			if err_tcp4 == nil {
				return conn, isRoleClient, nil
			}
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err_tcp4)
			time.Sleep(3 * time.Second)
		}

		conn, isRoleClient, _, err_udp = Auto_P2P_UDP_NAT_Traversal("udp4", sessionUid,
			turnServer, brokerServer, false, 2)
		if err_udp == nil {
			return conn, isRoleClient, nil
		}
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err_udp)
	}

	return nil, false, fmt.Errorf("direct P2P connection failed after both TCP and UDP attempts")
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

func Auto_P2P_UDP_NAT_Traversal(network, sessionUid, turnServer, brokerServer string, needSharedKey bool, maxRound int) (net.Conn, bool, []byte, error) {
	var isClient bool
	var sharedKey []byte
	var count = 10
	const (
		RPP_TIMEOUT = 7
	)
	punchPayload := []byte(deriveKeyForPayload(sessionUid))
	for round := 1; round <= maxRound; round++ {

		fmt.Fprintf(os.Stderr, "=== Round %d: Trying P2P(%s) Connection ===\n", round, network)

		// 交换 NAT 信息
		p2pInfo, err := Do_autoP2P(network, sessionUid, turnServer, brokerServer, 25*time.Second, needSharedKey, true)
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

		if !inSameLAN && (localMaybeNAT4 || remoteMaybeNAT4) {
			if isClient {
				//只有先发包的，适合用小ttl值。
				ttl = PunchingShortTTL
			}
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
		fmt.Fprintf(os.Stderr, "  - %-14s: %s (LAN) / %s (NAT)\n", "Local Address", p2pInfo.LocalLAN, p2pInfo.LocalNAT)
		fmt.Fprintf(os.Stderr, "  - %-14s: %s (LAN) / %s (NAT)\n", "Remote Address", p2pInfo.RemoteLAN, p2pInfo.RemoteNAT)
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

func Auto_P2P_TCP_NAT_Traversal(network, sessionUid, turnServer, brokerServer string, needSharedKey bool, maxRound int) (net.Conn, bool, []byte, error) {
	var isClient bool
	var sharedKey []byte
	var errConn error
	for round := 1; round <= maxRound; round++ {

		fmt.Fprintf(os.Stderr, "=== Round %d: Trying P2P(%s) Connection ===\n", round, network)

		// 1. 交换 NAT 信息
		p2pInfo, err := Do_autoP2P(network, sessionUid, turnServer, brokerServer, 25*time.Second, needSharedKey, true)
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
