package easyp2p

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/threatexpert/gonc/v2/internal/testdns"
	"github.com/threatexpert/gonc/v2/netx"
)

func globalDNSTestLocalIP() string {
	if runtime.GOOS == "darwin" {
		return "127.0.0.1"
	}
	return "127.0.0.2"
}

// The process resolver is configured before MQTT starts. Run each transport
// in its own process: Paho ConnectRetry can outlive Close, so restoring a global
// resolver while its asynchronous dial is still running would race.
func TestMQTTUsesGlobalDNS(t *testing.T) {
	if scheme := os.Getenv("GONC_TEST_MQTT_GLOBAL_DNS"); scheme != "" {
		testMQTTGlobalDNS(t, scheme)
		return
	}
	for _, scheme := range []string{"tcp", "tls"} {
		t.Run(scheme, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestMQTTUsesGlobalDNS$", "-test.timeout=15s")
			cmd.Env = append(os.Environ(), "GONC_TEST_MQTT_GLOBAL_DNS="+scheme)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("MQTT subprocess: %v\n%s", err, output)
			}
		})
	}
}

func testMQTTGlobalDNS(t *testing.T, scheme string) {
	local := globalDNSTestLocalIP()
	t.Setenv("all_proxy", "")
	t.Setenv("ALL_PROXY", "")

	dns := testdns.Start(t, [4]byte{127, 0, 0, 1}, false)
	r, err := netx.NewBoundResolver(dns.Address, local)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	accepted := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			c.Close()
			accepted <- host
		}
	}()
	net.DefaultResolver = r
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s, _, _, err := startMQTTSignalSession(ctx, []string{scheme + "://broker-global.invalid:" + port}, "dns-test", local, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	select {
	case got := <-accepted:
		if got != local {
			t.Fatalf("MQTT source %s, want %s", got, local)
		}
	case <-ctx.Done():
		t.Fatal("MQTT did not resolve through global DNS")
	}
	cancel()
	if dns.UDPSource.Load() != local || net.DefaultResolver != r {
		t.Fatal("incorrect DNS ownership")
	}
}

func TestSTUNUsesGlobalDNS(t *testing.T) {
	local := globalDNSTestLocalIP()
	before := net.DefaultResolver
	original := STUNServers
	defer func() { STUNServers = original }()
	dns := testdns.Start(t, [4]byte{127, 0, 0, 1}, false)
	r, err := netx.NewBoundResolver(dns.Address, local)
	if err != nil {
		t.Fatal(err)
	}
	net.DefaultResolver = r
	defer func() { net.DefaultResolver = before }()
	response := func(raw []byte) []byte {
		request := &stun.Message{Raw: raw}
		if request.Decode() != nil {
			return nil
		}
		return stun.MustBuild(stun.NewTransactionIDSetter(request.TransactionID), stun.BindingSuccess, &stun.XORMappedAddress{IP: net.ParseIP("203.0.113.10"), Port: 45678}).Raw
	}
	for _, network := range []string{"tcp4", "udp4"} {
		t.Run(network, func(t *testing.T) {
			var address string
			seen := make(chan string, 16)
			if network == "tcp4" {
				ln, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				address = ln.Addr().String()
				go func() {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					defer c.Close()
					host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
					seen <- host
					c.SetDeadline(time.Now().Add(2 * time.Second))
					header := make([]byte, 20)
					if _, err := io.ReadFull(c, header); err != nil {
						return
					}
					body := make([]byte, int(binary.BigEndian.Uint16(header[2:4])))
					if _, err := io.ReadFull(c, body); err != nil {
						return
					}
					c.Write(response(append(header, body...)))
				}()
			} else {
				pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer pc.Close()
				address = pc.LocalAddr().String()
				go func() {
					b := make([]byte, 2048)
					for {
						n, a, err := pc.ReadFrom(b)
						if err != nil {
							return
						}
						host, _, _ := net.SplitHostPort(a.String())
						select {
						case seen <- host:
						default:
						}
						pc.WriteTo(response(b[:n]), a)
					}
				}()
			}
			_, port, _ := net.SplitHostPort(address)
			STUNServers = []string{"stun-global.invalid:" + port}
			ctx := context.Background()
			results, err := GetPublicIPsContext(ctx, network, local+":0", 2*time.Second, false, nil)
			if err != nil || len(results) != 1 || results[0].Err != nil || results[0].Nat != "203.0.113.10:45678" {
				t.Fatalf("STUN %s: %+v %v", network, results, err)
			}
			select {
			case got := <-seen:
				if got != local {
					t.Fatalf("STUN source %s, want %s", got, local)
				}
			case <-time.After(time.Second):
				t.Fatal("missing STUN request")
			}
		})
	}
	if dns.UDPQueries.Load() < 2 || dns.UDPSource.Load() != local || net.DefaultResolver != r {
		t.Fatal("incorrect STUN DNS ownership")
	}
}
