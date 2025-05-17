package misc

import (
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
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/pion/stun"
)

func GetPublicIP(network, bind, turnServer string, timeout time.Duration) (localaddress, nataddress string, err error) {

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
		return "", "", fmt.Errorf("STUN Do failed: %v", err)
	}
	if err2 != nil {
		return "", "", err2
	}

	//tcp不关闭连接，保持连接有助于NAT穿透，如果有连接关闭了可能NAT打开的洞也关闭
	if network == "tcp" {
		go func() {
			buf := make([]byte, 1)
			_, _ = conn.Read(buf)
			c.Close()
		}()
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

func MQTT_Exchange(sendData, localUid, remoteUid, brokerServer string, timeout time.Duration) (recvData string, err error) {
	localTopic := "nat-exchange/" + CalculateMD5(localUid)
	remoteTopic := "nat-exchange/" + CalculateMD5(remoteUid)
	localAckTopic := "nat-ack/" + CalculateMD5(localUid)
	remoteAckTopic := "nat-ack/" + CalculateMD5(remoteUid)

	opts := mqtt.NewClientOptions().AddBroker(brokerServer)
	opts.SetClientID(CalculateMD5(localUid) + fmt.Sprint(time.Now().UnixNano()))
	client := mqtt.NewClient(opts)

	if token := client.Connect(); token.Wait() && token.Error() != nil {
		return "", token.Error()
	}
	defer client.Disconnect(250)

	recvRemoteData := make(chan string, 1)
	recvAck := make(chan struct{}, 1)

	if token := client.Subscribe(remoteTopic, 0, func(_ mqtt.Client, msg mqtt.Message) {
		recvRemoteData <- string(msg.Payload())
	}); token.Wait() && token.Error() != nil {
		return "", token.Error()
	}

	if token := client.Subscribe(localAckTopic, 0, func(_ mqtt.Client, msg mqtt.Message) {
		recvAck <- struct{}{}
	}); token.Wait() && token.Error() != nil {
		return "", token.Error()
	}

	stopPublish := make(chan struct{})
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopPublish:
				return
			default:
				client.Publish(localTopic, 0, false, sendData)
				time.Sleep(2 * time.Second)
			}
		}
	}()

	var remoteData string
	gotRemote := false
	gotAck := false
	timeoutTimer := time.NewTimer(timeout)
	defer timeoutTimer.Stop()

	for !(gotRemote && gotAck) {
		select {
		case remoteData = <-recvRemoteData:
			gotRemote = true
			client.Publish(remoteAckTopic, 0, false, "ok")
		case <-recvAck:
			gotAck = true
		case <-timeoutTimer.C:
			close(stopPublish)
			return "", errors.New("timeout waiting for remote data exchange")
		}
	}

	close(stopPublish)

	return remoteData, nil
}

func Do_autoP2P(network, localUid, remoteUid, turnServer, brokerServer string, timeout time.Duration, verb bool) (*P2PAddressInfo, error) {
	// ECC key gen
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubBytes := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)

	if verb {
		fmt.Fprintf(os.Stderr, "    Exchanging public keys...\n")
	}
	remotePubRaw, err := MQTT_Exchange(base64.StdEncoding.EncodeToString(pubBytes), localUid+"pubkey", remoteUid+"pubkey", brokerServer, timeout)
	if err != nil {
		return nil, err
	}
	remotePubBytes, err := base64.StdEncoding.DecodeString(remotePubRaw)
	if err != nil {
		return nil, err
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), remotePubBytes)
	sharedX, _ := priv.PublicKey.Curve.ScalarMult(x, y, priv.D.Bytes())
	sharedKey := sha256.Sum256(sharedX.Bytes())

	if verb {
		fmt.Fprintf(os.Stderr, "    Getting local & public IP...\n")
	}
	localAddr, natAddr, err := GetPublicIP(network, "", turnServer, 5*time.Second)
	if err != nil {
		return nil, err
	}
	myInfo := map[string]string{"lan": localAddr, "nat": natAddr}
	infoBytes, _ := json.Marshal(myInfo)
	encPayload, _ := encryptAES(sharedKey[:], infoBytes)
	encPayloadBytes, _ := json.Marshal(encPayload)

	if verb {
		fmt.Fprintf(os.Stderr, "    Sending encrypted address info...\n")
	}
	remoteInfoRaw, err := MQTT_Exchange(string(encPayloadBytes), localUid, remoteUid, brokerServer, timeout)
	if err != nil {
		return nil, err
	}

	var remotePayload securePayload
	err = json.Unmarshal([]byte(remoteInfoRaw), &remotePayload)
	if err != nil {
		return nil, err
	}
	plain, err := decryptAES(sharedKey[:], &remotePayload)
	if err != nil {
		return nil, err
	}
	var remoteInfo map[string]string
	err = json.Unmarshal(plain, &remoteInfo)
	if err != nil {
		return nil, err
	}
	return &P2PAddressInfo{
		LocalLAN:  localAddr,
		LocalNAT:  natAddr,
		RemoteLAN: remoteInfo["lan"],
		RemoteNAT: remoteInfo["nat"],
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
