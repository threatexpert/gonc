package apps

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/threatexpert/gonc/v2/secure"
)

func setupLinkTLSRuntimeForTest(t *testing.T, conf string) *linkRuntimeConfig {
	t.Helper()
	scheme, _, params, err := parseLinkConfig(conf)
	if err != nil {
		t.Fatalf("parseLinkConfig: %v", err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	muxcfg := &MuxSessionConfig{AppMuxConfig: AppMuxConfig{Logger: log.New(io.Discard, "", 0)}}
	runtimeConfig, err := setupLinkRuntimeConfig(muxcfg, scheme, params, ln)
	if err != nil {
		t.Fatalf("setupLinkRuntimeConfig: %v", err)
	}
	return runtimeConfig
}

func leafCertificateForTest(t *testing.T, runtimeConfig *linkRuntimeConfig) *x509.Certificate {
	t.Helper()
	if runtimeConfig.NtConfig == nil || len(runtimeConfig.NtConfig.Certs) != 1 {
		t.Fatal("link TLS runtime did not contain exactly one certificate")
	}
	leaf, err := x509.ParseCertificate(runtimeConfig.NtConfig.Certs[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}
	return leaf
}

func TestLinkTLSDefaultsCertificateSNIToLocalhost(t *testing.T) {
	runtimeConfig := setupLinkTLSRuntimeForTest(t, "x+tls://127.0.0.1:0")
	leaf := leafCertificateForTest(t, runtimeConfig)
	if runtimeConfig.TLSCertSNI != "localhost" {
		t.Fatalf("TLSCertSNI = %q, want localhost", runtimeConfig.TLSCertSNI)
	}
	if leaf.Subject.CommonName != "localhost" || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "localhost" {
		t.Fatalf("certificate identity = CN %q SAN %v, want localhost", leaf.Subject.CommonName, leaf.DNSNames)
	}
}

func TestLinkTLSAcceptsCustomCertificateSNIAndPSK(t *testing.T) {
	const psk = "link-proxy-test-secret"
	runtimeConfig := setupLinkTLSRuntimeForTest(t, "x+tls://127.0.0.1:0?sni=proxy.example.com&psk="+url.QueryEscape(psk))
	leaf := leafCertificateForTest(t, runtimeConfig)

	if runtimeConfig.TLSCertSNI != "proxy.example.com" {
		t.Fatalf("TLSCertSNI = %q", runtimeConfig.TLSCertSNI)
	}
	if leaf.Subject.CommonName != "proxy.example.com" || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "proxy.example.com" {
		t.Fatalf("certificate identity = CN %q SAN %v", leaf.Subject.CommonName, leaf.DNSNames)
	}
	if runtimeConfig.NtConfig.KeyType != "PSK" || runtimeConfig.NtConfig.Key != psk {
		t.Fatalf("TLS PSK config = type %q key %q", runtimeConfig.NtConfig.KeyType, runtimeConfig.NtConfig.Key)
	}
	if !runtimeConfig.NtConfig.ErrorOnFailKeyingMaterial {
		t.Fatal("TLS-PSK link listener did not require exporter keying material")
	}
	if err := secure.VerifyPeerCertificateByPSK(psk)([][]byte{runtimeConfig.NtConfig.Certs[0].Certificate[0]}, nil); err != nil {
		t.Fatalf("generated certificate is not compatible with gonc PSK verification: %v", err)
	}
}

func TestLinkTLSReadsPSKFileOnListenerSide(t *testing.T) {
	const psk = "link-proxy-file-secret"
	pskPath := filepath.Join(t.TempDir(), "proxy.psk")
	if err := os.WriteFile(pskPath, []byte(psk+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	conf := "x+tls://127.0.0.1:0?psk=" + url.QueryEscape("@"+pskPath)
	runtimeConfig := setupLinkTLSRuntimeForTest(t, conf)
	if runtimeConfig.NtConfig.Key != psk {
		t.Fatalf("PSK read from file = %q, want %q", runtimeConfig.NtConfig.Key, psk)
	}
}

func TestLinkPSKRequiresXPlusTLS(t *testing.T) {
	tests := []string{
		"x://127.0.0.1:0?psk=secret",
		"f+tls://127.0.0.1:0?to=127.0.0.1:1&psk=secret",
	}
	for _, conf := range tests {
		t.Run(conf, func(t *testing.T) {
			scheme, _, params, err := parseLinkConfig(conf)
			if err != nil {
				t.Fatal(err)
			}
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			muxcfg := &MuxSessionConfig{AppMuxConfig: AppMuxConfig{Logger: log.New(io.Discard, "", 0)}}
			if _, err := setupLinkRuntimeConfig(muxcfg, scheme, params, ln); err == nil {
				t.Fatal("link PSK configuration unexpectedly succeeded")
			}
		})
	}
}

func TestLinkTLSPSKFailClosedSchemeMarker(t *testing.T) {
	const original = "x+tls://127.0.0.1:3183?psk=secret"
	marked := requireLinkSchemeModifier(original, "psk")
	if marked != "x+tls+psk://127.0.0.1:3183?psk=secret" {
		t.Fatalf("marked config = %q", marked)
	}
	scheme, _, params, err := parseLinkConfig(marked)
	if err != nil {
		t.Fatalf("new parser rejected fail-closed marker: %v", err)
	}
	if scheme != "x" || params.Get("_tls") != "1" || params.Get("_require_tls_psk") != "1" {
		t.Fatalf("marked config parsed as scheme=%q params=%v", scheme, params)
	}
	if got := requireLinkSchemeModifier(marked, "psk"); got != marked {
		t.Fatalf("adding marker twice changed config to %q", got)
	}
}

func TestLinkTLSPSKSchemeMarkerRequiresPSK(t *testing.T) {
	for _, conf := range []string{
		"x+psk://127.0.0.1:3183?psk=secret",
		"x+tls+psk://127.0.0.1:3183",
	} {
		if _, _, _, err := parseLinkConfig(conf); err == nil {
			t.Fatalf("parseLinkConfig(%q) unexpectedly succeeded", conf)
		}
	}
}

func TestLinkTLSPSKIsRedactedFromLogs(t *testing.T) {
	got := redactLinkConfigForLog("x+tls+psk://127.0.0.1:3183?psk=top-secret&owner=abc\n")
	if strings.Contains(got, "top-secret") || !strings.Contains(got, "psk=REDACTED") {
		t.Fatalf("redacted config = %q", got)
	}
}

func TestLinkTLSPSKNegotiationExportsMatchingUDPKey(t *testing.T) {
	const psk = "link-proxy-negotiation-secret"
	runtimeConfig := setupLinkTLSRuntimeForTest(t, "x+tls://127.0.0.1:0?psk="+url.QueryEscape(psk))

	clientCert, err := secure.GenerateECDSACertificate("127.0.0.1", psk)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig := secure.NewNegotiationConfig()
	clientConfig.IsClient = true
	clientConfig.SecureLayer = "tls"
	clientConfig.KeyType = "PSK"
	clientConfig.Key = psk
	clientConfig.Certs = []tls.Certificate{*clientCert}
	clientConfig.TlsSNI = "127.0.0.1"
	clientConfig.ErrorOnFailKeyingMaterial = true

	serverSide, clientSide := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type result struct {
		conn *secure.NegotiatedConn
		err  error
	}
	serverResult := make(chan result, 1)
	go func() {
		conn, err := secure.DoNegotiationContext(ctx, runtimeConfig.NtConfig, serverSide, nil)
		serverResult <- result{conn: conn, err: err}
	}()
	clientConn, err := secure.DoNegotiationContext(ctx, clientConfig, clientSide, nil)
	if err != nil {
		t.Fatalf("client TLS-PSK negotiation: %v", err)
	}
	defer clientConn.Close()
	server := <-serverResult
	if server.err != nil {
		t.Fatalf("server TLS-PSK negotiation: %v", server.err)
	}
	defer server.conn.Close()
	if clientConn.KeyingMaterial == [32]byte{} || clientConn.KeyingMaterial != server.conn.KeyingMaterial {
		t.Fatalf("TLS exporter keys did not match: client=%x server=%x", clientConn.KeyingMaterial, server.conn.KeyingMaterial)
	}

	udpServer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	secureServer, err := secure.NewSecureUDPConn(udpServer, server.conn.KeyingMaterial)
	if err != nil {
		t.Fatal(err)
	}
	defer secureServer.Close()
	udpClient, err := net.DialUDP("udp4", nil, udpServer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	secureClient, err := secure.NewSecurePacketConn(udpClient, clientConn.KeyingMaterial)
	if err != nil {
		t.Fatal(err)
	}
	defer secureClient.Close()
	deadline := time.Now().Add(2 * time.Second)
	_ = secureServer.SetDeadline(deadline)
	_ = secureClient.SetDeadline(deadline)
	if _, err := secureClient.Write([]byte("udp-through-tls-exporter")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, clientAddr, err := secureServer.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "udp-through-tls-exporter" {
		t.Fatalf("decrypted UDP payload = %q", got)
	}
	if _, err := secureServer.WriteTo([]byte("udp-response"), clientAddr); err != nil {
		t.Fatal(err)
	}
	n, err = secureClient.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "udp-response" {
		t.Fatalf("decrypted UDP response = %q", got)
	}
}
