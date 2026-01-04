package secure

import (
	"bytes"
	"context"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/threatexpert/gonc/v2/netx"

	"github.com/pion/dtls/v3"
	"github.com/xtaci/kcp-go/v5"
)

type NegotiationConfig struct {
	Label                     string
	IsClient                  bool
	SecureLayer               string //tls tls13 dtls ss
	Certs                     []tls.Certificate
	TlsSNI                    string
	InsecureSkipVerify        bool
	KcpWithUDP                bool
	KcpEncryption             bool //是否开启kcp加密
	FramedTCP                 bool
	Key                       string
	KeyType                   string // ECDHE or PSK
	ErrorOnFailKeyingMaterial bool   //如果keyingMaterial异常，协商要报错
	UdpOutputBlockSize        int
	KcpWindowSize             int
	KeepAlive                 int
	UdpKeepAlivePayload       string
	KCPIdleTimeoutSecond      int
	UDPIdleTimeoutSecond      int
}

const DefaultKCPIdleTimeoutSecond = 41
const DefaultUDPIdleTimeoutSecond = 60 * 5
const DefaultUdpOutputBlockSize = 1320

var (
	UdpOutputBlockSize   int    = DefaultUdpOutputBlockSize
	KcpWindowSize        int    = 1500
	UdpKeepAlivePayload  string = "ping\n"
	KCPIdleTimeoutSecond int    = DefaultKCPIdleTimeoutSecond
	UDPIdleTimeoutSecond int    = DefaultUDPIdleTimeoutSecond
)

func NewNegotiationConfig() *NegotiationConfig {
	return &NegotiationConfig{
		InsecureSkipVerify:   true,
		UdpOutputBlockSize:   UdpOutputBlockSize,
		KcpWindowSize:        KcpWindowSize,
		UdpKeepAlivePayload:  UdpKeepAlivePayload,
		KCPIdleTimeoutSecond: KCPIdleTimeoutSecond,
		UDPIdleTimeoutSecond: UDPIdleTimeoutSecond,
	}
}

type NegotiatedConn struct {
	ctx                  context.Context
	cancel               context.CancelFunc
	Config               *NegotiationConfig
	KeyingMaterial       [32]byte
	TopLayer             net.Conn
	ConnStack            []string
	ConnLayers           []net.Conn
	IsUDP                bool
	IsFramed             bool
	WithKCP              bool
	MQTTHelloCtrlPayload string
	MQTTHelloAppPayload  string
	OnClose              func()
}

func (nconn *NegotiatedConn) Close() error {
	if nconn.cancel != nil {
		nconn.cancel()
	}
	for _, c := range nconn.ConnLayers {
		c.Close()
	}
	nconn.Config = nil
	nconn.ConnStack = []string{}
	nconn.ConnLayers = []net.Conn{}
	nconn.ctx = nil
	nconn.cancel = nil

	onCloseCallback := nconn.OnClose
	if onCloseCallback != nil {
		nconn.OnClose = nil
		onCloseCallback()
	}
	return nil
}

func (nconn *NegotiatedConn) Read(b []byte) (int, error) {
	return nconn.TopLayer.Read(b)
}

func (nconn *NegotiatedConn) Write(b []byte) (int, error) {
	return nconn.TopLayer.Write(b)
}

func (nconn *NegotiatedConn) CloseWrite() error {
	if cw, ok := nconn.TopLayer.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nconn.TopLayer.Close()
}

func (nconn *NegotiatedConn) LocalAddr() net.Addr {
	return nconn.TopLayer.LocalAddr()
}

func (nconn *NegotiatedConn) RemoteAddr() net.Addr {
	return nconn.TopLayer.RemoteAddr()
}

func (nconn *NegotiatedConn) SetDeadline(t time.Time) error {
	return nconn.TopLayer.SetDeadline(t)
}

func (nconn *NegotiatedConn) SetReadDeadline(t time.Time) error {
	return nconn.TopLayer.SetReadDeadline(t)
}

func (nconn *NegotiatedConn) SetWriteDeadline(t time.Time) error {
	return nconn.TopLayer.SetWriteDeadline(t)
}

func DoNegotiation(cfg *NegotiationConfig, rawconn net.Conn, logWriter io.Writer) (*NegotiatedConn, error) {
	nconn := &NegotiatedConn{
		Config:     cfg,
		ConnLayers: []net.Conn{rawconn},
	}
	var connStack []string
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		if nconn.cancel == nil {
			cancel()
			for i, c := range nconn.ConnLayers {
				if i != len(nconn.ConnLayers)-1 { // 最后一个连接是原始连接，发送错误时不关闭，还给调用者处置
					c.Close()
				}
			}
		}
	}()

	if strings.HasPrefix(rawconn.LocalAddr().Network(), "udp") {
		nconn.IsUDP = true
		configUDPConn(rawconn)
	} else {
		configTCPKeepalive(rawconn, cfg.KeepAlive)
	}

	timeout_sec := 20
	ctxTimeout, cancelTimeout := context.WithTimeout(context.Background(), time.Duration(timeout_sec)*time.Second)
	defer cancelTimeout()
	var keyingMaterial [32]byte
	switch {
	case strings.HasPrefix(cfg.SecureLayer, "tls"):
		conn_tls := doTLS(ctxTimeout, cfg, nconn.ConnLayers[0], &keyingMaterial, logWriter)
		if conn_tls == nil {
			return nil, fmt.Errorf("failed to establish TLS connection")
		}
		nconn.ConnLayers = append([]net.Conn{conn_tls}, nconn.ConnLayers...)
		connStack = append(connStack, cfg.SecureLayer)
	case cfg.SecureLayer == "dtls":
		conn_dtls := doDTLS(ctxTimeout, cfg, nconn.ConnLayers[0], &keyingMaterial, logWriter)
		if conn_dtls == nil {
			return nil, fmt.Errorf("failed to establish DTLS connection")
		}
		nconn.ConnLayers = append([]net.Conn{conn_dtls}, nconn.ConnLayers...)
		connStack = append(connStack, cfg.SecureLayer)
	case cfg.SecureLayer == "ss" || cfg.SecureLayer == "dss":
		switch cfg.KeyType {
		case "ECDHE":
			copy(keyingMaterial[:], []byte(cfg.Key))
		case "PSK":
			k, err := DerivePSK(cfg.Key)
			if err != nil {
				fmt.Fprintf(logWriter, "%sFailed to derive key for secure stream: %v\n", cfg.Label, err)
				return nil, err
			}
			copy(keyingMaterial[:], k)
		default:
			fmt.Fprintf(logWriter, "%sMissing key type for secure stream\n", cfg.Label)
			return nil, fmt.Errorf("missing key type for secure stream")
		}

		if cfg.SecureLayer == "dss" {
			connss, err := NewSecurePacketConn(nconn.ConnLayers[0], keyingMaterial)
			if err != nil {
				return nil, err
			}
			nconn.ConnLayers = append([]net.Conn{connss}, nconn.ConnLayers...)
			fmt.Fprintf(logWriter, "%sCommunication(Datagram) is encrypted(%s) with AES.\n", cfg.Label, cfg.KeyType)
		} else {
			connss, err := NewSecureStreamConn(nconn.ConnLayers[0], keyingMaterial)
			if err != nil {
				return nil, err
			}
			nconn.ConnLayers = append([]net.Conn{connss}, nconn.ConnLayers...)
			fmt.Fprintf(logWriter, "%sCommunication(Stream) is encrypted(%s) with AES.\n", cfg.Label, cfg.KeyType)
		}
		connStack = append(connStack, cfg.SecureLayer)
	default:
	}

	if nconn.IsUDP {
		if cfg.KcpWithUDP {
			sess_kcp := doKCP(ctx, cfg, nconn.ConnLayers[0], 30*time.Second, logWriter)
			if sess_kcp == nil {
				return nil, fmt.Errorf("failed to establish KCP session")
			}
			if cfg.KcpEncryption {
				k, err := DerivePSK(cfg.Key)
				if err != nil {
					fmt.Fprintf(logWriter, "%sFailed to derive key for keyingMaterial: %v\n", cfg.Label, err)
					return nil, err
				}
				copy(keyingMaterial[:], k)
			}
			nconn.ConnLayers = append([]net.Conn{sess_kcp}, nconn.ConnLayers...)
			nconn.WithKCP = true
			connStack = append(connStack, "kcp")
		} else {
			isWrappered := false
			if nconn, ok := rawconn.(*NegotiatedConn); ok {
				if len(nconn.ConnStack) > 0 {
					isWrappered = true
				}
			}
			if !isWrappered {
				pktconn := netx.NewPacketConnWrapper(nconn.ConnLayers[0], nconn.ConnLayers[0].RemoteAddr())

				if cfg.KeepAlive > 0 {
					startUDPKeepAlive(ctx, pktconn, nconn.ConnLayers[0].RemoteAddr(),
						[]byte(cfg.UdpKeepAlivePayload),
						time.Duration(cfg.KeepAlive)*time.Second, make(chan time.Duration, 1))
				}

				buconn := netx.NewBoundUDPConn(pktconn, nconn.ConnLayers[0].RemoteAddr().String(), false)
				if cfg.UDPIdleTimeoutSecond != 0 {
					buconn.SetIdleTimeout(time.Duration(cfg.UDPIdleTimeoutSecond) * time.Second)
				}
				nconn.ConnLayers = append([]net.Conn{buconn}, nconn.ConnLayers...)
			}
		}
	} else {
		if cfg.FramedTCP {
			framedConn := netx.NewFramedConn(nconn.ConnLayers[0], nconn.ConnLayers[0])
			nconn.ConnLayers = append([]net.Conn{framedConn}, nconn.ConnLayers...)
			connStack = append(connStack, "framed")
			nconn.IsFramed = true
		}
	}

	nconn.ctx = ctx
	nconn.cancel = cancel
	nconn.TopLayer = nconn.ConnLayers[0]
	nconn.ConnStack = connStack
	nconn.KeyingMaterial = keyingMaterial
	//fmt.Fprintf(logWriter, "%skeyingMaterial: %x\n", cfg.Label, keyingMaterial)
	return nconn, nil
}

func doTLS(ctx context.Context, config *NegotiationConfig, conn net.Conn, storeKeyingMaterial *[32]byte, logWriter io.Writer) net.Conn {
	// 获取所有安全加密套件
	safeCiphers := tls.CipherSuites()
	// 获取所有不安全加密套件
	insecureCiphers := tls.InsecureCipherSuites()
	// 合并两个列表
	var allCiphers []uint16
	for _, cipher := range safeCiphers {
		allCiphers = append(allCiphers, cipher.ID)
	}
	for _, cipher := range insecureCiphers {
		allCiphers = append(allCiphers, cipher.ID)
	}

	// 创建 TLS 配置
	tlsConfig := &tls.Config{
		CipherSuites:             allCiphers,
		InsecureSkipVerify:       config.InsecureSkipVerify,
		MinVersion:               tls.VersionTLS10, // 至少 TLSv1
		MaxVersion:               tls.VersionTLS13, // 最大支持 TLSv1.3
		PreferServerCipherSuites: true,             // 优先使用服务器的密码套件
	}
	if config.SecureLayer == "tls10" {
		tlsConfig.MinVersion = tls.VersionTLS10
		tlsConfig.MaxVersion = tls.VersionTLS10
	}
	if config.SecureLayer == "tls11" {
		tlsConfig.MinVersion = tls.VersionTLS11
		tlsConfig.MaxVersion = tls.VersionTLS11
	}
	if config.SecureLayer == "tls12" {
		tlsConfig.MinVersion = tls.VersionTLS12
		tlsConfig.MaxVersion = tls.VersionTLS12
	}
	if config.SecureLayer == "tls13" {
		tlsConfig.MinVersion = tls.VersionTLS13
		tlsConfig.MaxVersion = tls.VersionTLS13
	}
	// 使用 TLS 握手
	var conn_tls *tls.Conn
	var certs []tls.Certificate = config.Certs

	if !config.IsClient {
		tlsConfig.Certificates = config.Certs
		if config.Key != "" && config.KeyType == "PSK" {
			tlsConfig.ClientAuth = tls.RequireAnyClientCert
			tlsConfig.VerifyPeerCertificate = VerifyPeerCertificateByPSK(config.Key)
			fmt.Fprintf(logWriter, "%sPerforming TLS-S handshake (PSK-based mutual authentication)...", config.Label)
		} else {
			fmt.Fprintf(logWriter, "%sPerforming TLS-S handshake...", config.Label)
		}
		conn_tls = tls.Server(conn, tlsConfig)
	} else {
		tlsConfig.ServerName = config.TlsSNI
		if config.Key != "" && config.KeyType == "PSK" {
			tlsConfig.Certificates = certs
			tlsConfig.VerifyPeerCertificate = VerifyPeerCertificateByPSK(config.Key)
			fmt.Fprintf(logWriter, "%sPerforming TLS-C handshake (PSK-based mutual authentication)...", config.Label)
		} else {
			fmt.Fprintf(logWriter, "%sPerforming TLS-C handshake...", config.Label)
		}
		conn_tls = tls.Client(conn, tlsConfig)
	}
	if err := conn_tls.HandshakeContext(ctx); err != nil {
		fmt.Fprintf(logWriter, "failed: %v\n", err)
		conn_tls.Close()
		return nil
	}
	fmt.Fprintf(logWriter, "completed.\n")

	if storeKeyingMaterial != nil {
		state := conn_tls.ConnectionState()
		label := "EXPERIMENTAL-SERVER-KEY"
		keyingMaterial, err := state.ExportKeyingMaterial(label, nil, 32)
		if err != nil {
			if config.ErrorOnFailKeyingMaterial {
				fmt.Fprintf(logWriter, "failed to export keying material: %v\n", err)
				conn_tls.Close()
				return nil
			}
		} else {
			copy(storeKeyingMaterial[:], keyingMaterial)
		}
	}
	return conn_tls
}

func doDTLS(ctx context.Context, config *NegotiationConfig, conn net.Conn, storeKeyingMaterial *[32]byte, logWriter io.Writer) net.Conn {
	// 支持的 CipherSuites（pion 这里和 crypto/tls 不同）
	allCiphers := []dtls.CipherSuiteID{
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}

	// DTLS 配置
	dtlsConfig := &dtls.Config{
		CipherSuites:         allCiphers,
		InsecureSkipVerify:   config.InsecureSkipVerify,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		FlightInterval:       2 * time.Second,
	}

	// DTLS Server / Client 模式
	var dtlsConn *dtls.Conn
	var err error
	pktconn := netx.NewPacketConnWrapper(conn, conn.RemoteAddr())

	if !config.IsClient {
		dtlsConfig.Certificates = config.Certs
		if config.Key != "" && config.KeyType == "PSK" {
			dtlsConfig.ClientAuth = dtls.RequireAnyClientCert
			dtlsConfig.VerifyPeerCertificate = VerifyPeerCertificateByPSK(config.Key)
			fmt.Fprintf(logWriter, "%sPerforming DTLS-S handshake (PSK-based mutual authentication)...", config.Label)
		} else {
			fmt.Fprintf(logWriter, "%sPerforming DTLS-S handshake...", config.Label)
		}
		dtlsConn, err = dtls.Server(pktconn, conn.RemoteAddr(), dtlsConfig)
	} else {
		dtlsConfig.ServerName = config.TlsSNI
		if config.Key != "" && config.KeyType == "PSK" {
			dtlsConfig.Certificates = config.Certs
			dtlsConfig.VerifyPeerCertificate = VerifyPeerCertificateByPSK(config.Key)
			fmt.Fprintf(logWriter, "%sPerforming DTLS-C handshake (PSK-based mutual authentication)...", config.Label)
		} else {
			fmt.Fprintf(logWriter, "%sPerforming DTLS-C handshake...", config.Label)
		}
		dtlsConn, err = dtls.Client(pktconn, conn.RemoteAddr(), dtlsConfig)
	}
	if err != nil {
		fmt.Fprintf(logWriter, "DTLS initialization failed: %v\n", err)
		return nil
	}

	//dtlsConn.HandshakeContext似乎有bug，无法在ctx取消后返回，
	//dtlsConn.SetDeadline似乎也有bug
	//这里从conn加一个SetDeadline
	conn.SetDeadline(time.Now().Add(20 * time.Second)) // 设置握手超时
	firstRefusedLogged := false
	for {
		if err = dtlsConn.HandshakeContext(ctx); err != nil {
			if netx.IsConnRefused(err) {
				if !firstRefusedLogged {
					fmt.Fprintf(logWriter, "(ECONNREFUSED)...")
					firstRefusedLogged = true
				}
				time.Sleep(500 * time.Millisecond)
				continue
			}
			fmt.Fprintf(logWriter, "failed: %v\n", err)
			dtlsConn.Close()
			return nil
		}
		break
	}
	conn.SetDeadline(time.Time{}) // 取消握手超时
	fmt.Fprintf(logWriter, "completed.\n")

	if storeKeyingMaterial != nil {
		state, ok := dtlsConn.ConnectionState()
		if !ok {
			if config.ErrorOnFailKeyingMaterial {
				fmt.Fprintf(logWriter, "failed to get DTLS connection state\n")
				dtlsConn.Close()
				return nil
			}
		} else {
			label := "EXPERIMENTAL-SERVER-KEY"
			keyingMaterial, err := state.ExportKeyingMaterial(label, nil, 32)
			if err != nil {
				if config.ErrorOnFailKeyingMaterial {
					fmt.Fprintf(logWriter, "failed to export keying material: %v\n", err)
					dtlsConn.Close()
					return nil
				}
			} else {
				copy(storeKeyingMaterial[:], keyingMaterial)
			}
		}
	}
	return dtlsConn
}

func createKCPBlockCrypt(passphrase string, salt []byte) (kcp.BlockCrypt, error) {
	// 使用 PBKDF2 派生 32 字节密钥
	key, err := pbkdf2.Key(sha1.New, passphrase, salt, 1024, 32)
	if err != nil {
		return nil, fmt.Errorf("pbkdf2 key derivation failed: %v", err)
	}

	// 使用派生密钥创建 AES 加密器
	blockCrypt, err := kcp.NewAESBlockCrypt(key)
	if err != nil {
		return nil, fmt.Errorf("kcp NewAESBlockCrypt failed: %v", err)
	}

	return blockCrypt, nil
}

func createKCPBlockCryptFromKey(key []byte) (kcp.BlockCrypt, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: expected 32, got %d", len(key))
	}
	blockCrypt, err := kcp.NewAESBlockCrypt(key[:]) // key[:] 转为 []byte
	if err != nil {
		return nil, fmt.Errorf("kcp NewAESBlockCrypt failed: %v", err)
	}
	return blockCrypt, nil
}

// 1、建立message模式的KCP，传进来的conn背后通常是个UDPConn，这里不希望封装后变成会粘包的net.Conn。
// 2、因为Close KCP会话对方无感知的问题，这里会再封装一层netx.FramedConn，每次发送的数据都增加2字节的长度头，所以结束时对方还可以收到个长度为0的EOF帧
func doKCP(ctx context.Context, config *NegotiationConfig, conn net.Conn, timeout time.Duration, logWriter io.Writer) net.Conn {
	var sess *kcp.UDPSession
	var err error
	var blockCrypt kcp.BlockCrypt
	if config.KcpEncryption {
		switch config.KeyType {
		case "ECDHE":
			blockCrypt, err = createKCPBlockCryptFromKey([]byte(config.Key))
			if err != nil {
				fmt.Fprintf(logWriter, "%screateKCPBlockCryptFromKey failed: %v\n", config.Label, err)
				return nil
			}
		case "PSK":
			blockCrypt, err = createKCPBlockCrypt(config.Key, []byte("1234567890abcdef"))
			if err != nil {
				fmt.Fprintf(logWriter, "%screateKCPBlockCrypt failed: %v\n", config.Label, err)
				return nil
			}
		}
	}

	// 通知keepalive调整间隔
	intervalChange := make(chan time.Duration, 1)

	// 启动 keepalive

	pktconn := netx.NewPacketConnWrapper(conn, conn.RemoteAddr())
	startUDPKeepAlive(ctx, pktconn, conn.RemoteAddr(), []byte(config.UdpKeepAlivePayload), 2*time.Second, intervalChange)
	buconn := netx.NewBoundUDPConn(pktconn, conn.RemoteAddr().String(), false)
	if config.KCPIdleTimeoutSecond > 0 {
		buconn.SetIdleTimeout(time.Duration(config.KCPIdleTimeoutSecond) * time.Second)
	}

	if !config.IsClient {
		if blockCrypt == nil {
			fmt.Fprintf(logWriter, "%sPerforming KCP-S handshake...", config.Label)
		} else {
			fmt.Fprintf(logWriter, "%sPerforming encrypted(%s) KCP-S handshake...", config.Label, config.KeyType)
		}
	} else {
		if blockCrypt == nil {
			fmt.Fprintf(logWriter, "%sPerforming KCP-C handshake...", config.Label)
		} else {
			fmt.Fprintf(logWriter, "%sPerforming encrypted(%s) KCP-C handshake...", config.Label, config.KeyType)
		}
	}
	sess, err = kcp.NewConn4(0, conn.RemoteAddr(), blockCrypt, 10, 3, true, buconn)
	if err != nil {
		fmt.Fprintf(logWriter, "NewConn failed: %v\n", err)
		return nil
	}

	// 简单握手
	handshake := []byte("HELLO")
	_, err = sess.Write(handshake)
	if err != nil {
		fmt.Fprintf(logWriter, "send handshake failed: %v\n", err)
		sess.Close()
		return nil
	}

	// 设置握手超时
	sess.SetReadDeadline(time.Now().Add(timeout))

	buf := make([]byte, len(handshake))
	n, err := io.ReadFull(sess, buf)
	if err != nil || n != len(handshake) || !bytes.Equal(buf, handshake) {
		fmt.Fprintf(logWriter, "recv handshake failed: %v\n", err)
		sess.Close()
		return nil
	}
	fmt.Fprintf(logWriter, "completed.\n")

	// 取消超时（恢复成无超时）
	sess.SetReadDeadline(time.Time{})

	// 告诉keep alive协程，把间隔调成13秒
	select {
	case intervalChange <- 13 * time.Second:
	default:
	}

	sess.SetNoDelay(1, 10, 2, 1)
	sess.SetWindowSize(config.KcpWindowSize, config.KcpWindowSize)
	//kcp header 24字节SetMtu时就暗含其中。但实际发出包可能还多出28字节。根据情况把mtu再调小，防止超过udpOutputBlockSize
	mtu := config.UdpOutputBlockSize - 8 // 8: fecHeaderSizePlus2
	if blockCrypt != nil {
		mtu -= 20 //20: nonceSize+crcSize
	}
	if strings.Contains(config.SecureLayer, "tls") {
		mtu -= 60
	}
	mtu -= 2         //KCPStreamConn: len header
	sess.SetMtu(mtu) //如果用户-udp-size设置的值比较大，超过KCP内部限制的1500，会设置失败。

	return netx.NewFramedConn(sess, sess)
}

func configTCPKeepalive(conn net.Conn, keepAlive int) {
	if keepAlive > 0 {
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			ka := net.KeepAliveConfig{
				Enable:   true,
				Idle:     time.Duration(1+keepAlive/2) * time.Second, // 空闲多久后开始探测
				Count:    1 + (keepAlive / 2 / 5),                    // 最多发几次探测包
				Interval: 5 * time.Second,                            // 探测包之间的间隔
			}
			tcpConn.SetKeepAliveConfig(ka)

		}
	}
}

func configUDPConn(conn net.Conn) {
	udpConn, ok := conn.(*net.UDPConn)
	if ok {
		udpConn.SetReadBuffer(512 * 1024)
		udpConn.SetWriteBuffer(512 * 1024)
	}
}

func startUDPKeepAlive(ctx context.Context, conn net.PacketConn, raddr net.Addr, data []byte, initInterval time.Duration, intervalChange <-chan time.Duration) {

	go func() {
		keepAliveInterval := initInterval
		ticker := time.NewTicker(keepAliveInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case newInterval := <-intervalChange:
				ticker.Stop()
				keepAliveInterval = newInterval
				ticker = time.NewTicker(keepAliveInterval)
			case <-ticker.C:
				if _, err := conn.WriteTo(data, raddr); err != nil {
					// 不退出，继续重试
				}
			}
		}
	}()
}
