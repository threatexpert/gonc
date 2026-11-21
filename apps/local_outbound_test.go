package apps

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/threatexpert/gonc/v2/easyp2p"
	"github.com/threatexpert/gonc/v2/internal/testdns"
)

func outboundTestIP(t *testing.T) string {
	t.Helper()
	// Darwin needs an explicit alias for 127.0.0.2; do not modify interfaces.
	if runtime.GOOS == "darwin" {
		return "127.0.0.1"
	}
	return "127.0.0.2"
}

func TestSTUNListUsesGlobalDNSAndLocal(t *testing.T) {
	t.Run("endpoint", func(t *testing.T) {
		local := outboundTestIP(t)
		testBoundSTUNList(t, local+":0", local)
	})
	t.Run("interface", func(t *testing.T) {
		if runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
			t.Skip("desktop interface binding")
		}
		interfaces, err := net.Interfaces()
		if err != nil {
			t.Fatal(err)
		}
		for _, iface := range interfaces {
			if iface.Flags&net.FlagLoopback != 0 && iface.Flags&net.FlagUp != 0 {
				testBoundSTUNList(t, iface.Name, "127.0.0.1")
				return
			}
		}
		t.Skip("no active loopback interface")
	})
}

func testBoundSTUNList(t *testing.T, binding, local string) {
	t.Helper()
	preserveGlobalDNS(t)
	oldSTUN, oldMQTT := easyp2p.STUNServers, easyp2p.MQTTBrokerServers
	t.Cleanup(func() { easyp2p.STUNServers, easyp2p.MQTTBrokerServers = oldSTUN, oldMQTT })
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("NO_PROXY", "*")
	dns := testdns.Start(t, [4]byte{127, 0, 0, 1}, false)
	seen := make(chan string, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		seen <- host
		if r.URL.Path == "/start" {
			_, port, _ := net.SplitHostPort(r.Host)
			http.Redirect(w, r, "http://redirect-list.invalid:"+port+"/list", http.StatusFound)
			return
		}
		fmt.Fprint(w, "stun.example.invalid:3478\n")
	}))
	defer server.Close()
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	_, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{"-dns", dns.Address, "-local", binding, "-stunsrv", "http://stun-list.invalid:" + port + "/start", "outer.invalid", "80"})
	if err != nil {
		t.Fatal(err)
	}
	if len(easyp2p.STUNServers) != 1 || easyp2p.STUNServers[0] != "stun.example.invalid:3478" {
		t.Fatal(easyp2p.STUNServers)
	}
	for range 2 {
		select {
		case got := <-seen:
			if got != local {
				t.Fatalf("HTTP source %s, want %s", got, local)
			}
		case <-time.After(time.Second):
			t.Fatal("missing download/redirect")
		}
	}
	if dns.UDPSource.Load() != local {
		t.Fatalf("DNS source %v", dns.UDPSource.Load())
	}
}

func TestBoundHTTPSRedirect(t *testing.T) {
	preserveGlobalDNS(t)
	dns := testdns.Start(t, [4]byte{127, 0, 0, 1}, false)
	local := outboundTestIP(t)
	if err := setDns(dns.Address, local); err != nil {
		t.Fatal(err)
	}
	seen := make(chan string, 2)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		seen <- host
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/list", http.StatusFound)
			return
		}
		fmt.Fprint(w, "stun.example.invalid:3478")
	}))
	defer server.Close()
	client, closeIdle, err := newBoundHTTPClient(local, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer closeIdle()
	tr := client.Transport.(*http.Transport)
	tr.Proxy = nil
	tr.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	// The httptest certificate contains example.com; trust only its test CA.
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	resp, err := client.Get("https://example.com:" + port + "/start")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	for range 2 {
		if got := <-seen; got != local {
			t.Fatalf("HTTPS source %s, want %s", got, local)
		}
	}
	if dns.UDPSource.Load() != local {
		t.Fatalf("DNS source %v", dns.UDPSource.Load())
	}
}

func TestRelayLocalTCPAndUDP(t *testing.T) {
	for _, flag := range []string{"-x", "-x2"} {
		for _, urlForm := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/url=%v", flag, urlForm), func(t *testing.T) {
				preserveGlobalDNS(t)
				local := outboundTestIP(t)
				dns := testdns.Start(t, [4]byte{127, 0, 0, 1}, false)
				ln, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer udp.Close()
				controlSource := make(chan string, 1)
				serverDone := make(chan error, 1)
				go func() {
					serverDone <- func() error {
						ln.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
						c, err := ln.Accept()
						if err != nil {
							return err
						}
						defer c.Close()
						c.SetDeadline(time.Now().Add(3 * time.Second))
						host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
						controlSource <- host
						var header [2]byte
						if _, err := io.ReadFull(c, header[:]); err != nil {
							return err
						}
						if _, err := io.CopyN(io.Discard, c, int64(header[1])); err != nil {
							return err
						}
						if _, err := c.Write([]byte{5, 0}); err != nil {
							return err
						}
						var request [10]byte
						if _, err := io.ReadFull(c, request[:]); err != nil {
							return err
						}
						if request[1] != 3 {
							return fmt.Errorf("expected UDP ASSOCIATE")
						}
						port := udp.LocalAddr().(*net.UDPAddr).Port
						if _, err := c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)}); err != nil {
							return err
						}
						_, err = io.Copy(io.Discard, c)
						return err
					}()
				}()
				_, port, _ := net.SplitHostPort(ln.Addr().String())
				proxyAddr := "relay.invalid:" + port
				if urlForm {
					proxyAddr = "socks5://" + proxyAddr
				}
				c, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{"-p2p", "LocalRelayTest123!", "-dns", dns.Address, "-local", local + ":0", flag, proxyAddr})
				if err != nil {
					t.Fatal(err)
				}
				pc, err := createSocks5UDPClientWithTimeout(c.arg_proxyc_Config, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer pc.Close()
				if got := <-controlSource; got != local {
					t.Fatalf("TCP source %s, want %s", got, local)
				}
				pc.SetDeadline(time.Now().Add(time.Second))
				udp.SetDeadline(time.Now().Add(time.Second))
				if _, err := pc.WriteTo([]byte("probe"), &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 3478}); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 1024)
				n, src, err := udp.ReadFrom(buf)
				if err != nil {
					t.Fatal(err)
				}
				if got := src.(*net.UDPAddr).IP.String(); got != local {
					t.Fatalf("UDP source %s, want %s", got, local)
				}
				if _, err := udp.WriteTo(buf[:n], src); err != nil {
					t.Fatal(err)
				}
				n, _, err = pc.ReadFrom(buf)
				if err != nil || string(buf[:n]) != "probe" {
					t.Fatalf("relay reply %q %v", buf[:n], err)
				}
				pc.Close()
				if err := <-serverDone; err != nil {
					t.Fatal(err)
				}
				if dns.UDPSource.Load() != local {
					t.Fatalf("DNS source %v", dns.UDPSource.Load())
				}
			})
		}
	}
}

func TestLocalDoesNotBypassConfiguredTCPProxy(t *testing.T) {
	local := outboundTestIP(t)
	c, err := AppNetcatConfigByArgs(io.Discard, "gonc", []string{"-local", local + ":0", "-x", "127.0.0.1:1080", "-w", "1", "192.0.2.1", "80"})
	if err != nil {
		t.Fatal(err)
	}
	for _, builtin := range []bool{false, true} {
		called := false
		c.arg_proxyc_Config.UpstreamDialer = &relayPreparationDialer{dial: func(time.Duration) (net.Conn, error) { called = true; return nil, context.Canceled }}
		a, b := net.Pipe()
		var code int
		if builtin {
			code = App_s5c_main_withconfig(a, [32]byte{}, &AppS5CConfig{AppNetcatConfig: c}, nil, nil)
		} else {
			code = runDialModeOnce(a, c, c.network, c.host, c.port)
		}
		a.Close()
		b.Close()
		if code == 0 || !called {
			t.Fatalf("-local skipped -x (s5c=%v)", builtin)
		}
	}
}

func TestBoundHTTPInvalidLocalFails(t *testing.T) {
	if _, _, err := newBoundHTTPClient("invalid", time.Second); err == nil {
		t.Fatal("invalid local accepted")
	}
	// A nonexistent source cannot silently fall back to an unbound connection.
	client, closeIdle, err := newBoundHTTPClient("192.0.2.123", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer closeIdle()
	client.Transport.(*http.Transport).Proxy = nil
	_, err = client.Get("http://127.0.0.1:1/")
	if err == nil || !strings.Contains(err.Error(), "local interface") {
		t.Fatalf("expected binding failure, got %v", err)
	}
}
