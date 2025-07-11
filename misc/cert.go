package misc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"reflect"
	"time"
)

// DeriveECDSAPrivateKey 从预共享密钥（PSK）派生出一个 ECDSA 私钥（secp256r1）
func DeriveECDSAPrivateKey(psk string) (*ecdsa.PrivateKey, error) {
	curve := elliptic.P256()

	// 用 HMAC 生成一个与曲线阶相适配的整数
	h := hmac.New(sha256.New, []byte(psk))
	h.Write([]byte("ecdsa-psk-derive"))
	digest := h.Sum(nil)

	// 将 digest 作为 big.Int 并做 mod 运算以适配曲线阶
	d := new(big.Int).SetBytes(digest)
	n := curve.Params().N
	d.Mod(d, n)

	// 构造私钥
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = curve
	priv.D = d
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())

	return priv, nil
}

func VerifyPeerCertificateByPSK(psk string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("no server certificate provided")
		}

		// 解析服务端证书
		serverCert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}

		// 根据 PSK 派生 ECDSA 私钥
		priv, err := DeriveECDSAPrivateKey(psk)
		if err != nil {
			return err
		}

		expectedPub := &priv.PublicKey

		// 对比公钥是否一致（即服务端是基于这个 PSK 派生出来的）
		if !reflect.DeepEqual(serverCert.PublicKey, expectedPub) {
			return errors.New("PSK identity mismatch: invalid server certificate or possible MITM")
		}

		return nil
	}
}

func GenerateRSACACertificate(CN string) ([]byte, []byte, error) {
	// 生成 RSA 密钥对
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	// 生成随机序列号
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	// 准备自签名证书模板
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: CN,
		},
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// 生成自签名 CA 证书
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	key := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return cert, key, nil
}

func GenerateRSACertificate(sni string) (*tls.Certificate, error) {
	ca_data, cakey_data, err := GenerateRSACACertificate("Root CA")
	if err != nil {
		return nil, err
	}
	caCertBlock, _ := pem.Decode(ca_data)
	caKeyBlock, _ := pem.Decode(cakey_data)
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, err
	}
	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	// // 生成 RSA 密钥对
	// privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	// if err != nil {
	// 	return nil, err
	// }
	// 直接使用 CA 证书的私钥，而不生成新的私钥
	privateKey := caKey

	// 生成随机序列号
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	// 创建证书
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: sni,
		},
		NotBefore:   time.Now().AddDate(-1, 0, 0),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{sni},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &privateKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// 将证书和私钥组合为 tls.Certificate
	certificate, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		return nil, err
	}

	return &certificate, nil
}

// 生成自签名 ECDSA CA 证书
func GenerateECDSACACertificate(CN, psk string) ([]byte, []byte, error) {
	var privateKey *ecdsa.PrivateKey
	var err error
	// 生成 ECDSA 密钥对
	if psk != "" {
		privateKey, err = DeriveECDSAPrivateKey(psk)
	} else {
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		return nil, nil, err
	}
	// 生成序列号
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	// 证书模板
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: CN,
		},
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// 自签发
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privKeyBytes})

	return certPEM, keyPEM, nil
}

// 使用 ECDSA CA 生成 TLS 证书（可用于服务端）
func GenerateECDSACertificate(sni, psk string) (*tls.Certificate, error) {
	caData, caKeyData, err := GenerateECDSACACertificate("Root CA", psk)
	if err != nil {
		return nil, err
	}

	caCertBlock, _ := pem.Decode(caData)
	caKeyBlock, _ := pem.Decode(caKeyData)

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, err
	}

	caKey, err := x509.ParseECPrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	// 使用 CA 密钥作为 leaf cert 的密钥（如果你想单独生成新的，可以改这里）
	privateKey := caKey

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: sni,
		},
		NotBefore:   time.Now().AddDate(-1, 0, 0),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{sni},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &privateKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyPEM := new(bytes.Buffer)
	privKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	pem.Encode(keyPEM, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privKeyBytes})

	certificate, err := tls.X509KeyPair(certPEM.Bytes(), keyPEM.Bytes())
	if err != nil {
		return nil, err
	}

	return &certificate, nil
}

func LoadCertificate(certPath, keyPath string) (*tls.Certificate, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}
