package tunengine

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/engine"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"
)

func TestUpdateProxyValidationAndLifecycle(t *testing.T) {
	var current proxy.Proxy
	c := controller{
		insert: func(*engine.Key) {}, start: func() error { return nil }, stop: func() error { return nil },
		setProxy: func(p proxy.Proxy) { current = p },
	}
	if err := c.UpdateProxy(testConfig().Proxy); !errors.Is(err, ErrNotRunning) {
		t.Fatal(err)
	}
	if err := c.Start(testConfig()); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"127.0.0.1:1080", "socks5://[::1]:1080", "socks5://user:p%40ss@localhost:1080"} {
		previous := current
		if err := c.UpdateProxy(address); err != nil {
			t.Fatalf("%s: %v", address, err)
		}
		if current == nil || current == previous {
			t.Fatal("new proxy not installed")
		}
	}
	for _, address := range []string{"", "socks5://", "socks5://a", "socks5://a:0", "socks5://a:65536", "socks5://:1080", "socks5://a:abc", "http://a:80", "direct://", "socks5://a:80/path", "socks5://a:80?x=y", "socks5://a:80#x", "socks5://u:secret@a:invalid", "socks5://a%zz:80"} {
		previous := current
		if err := c.UpdateProxy(address); err == nil {
			t.Fatalf("accepted %q", address)
		}
		if current != previous {
			t.Fatal("invalid update changed proxy")
		}
	}
	if err := c.Stop(); err != nil {
		t.Fatal(err)
	}
	previous := current
	if err := c.UpdateProxy(testConfig().Proxy); !errors.Is(err, ErrNotRunning) || current != previous {
		t.Fatal("update after stop", err)
	}
	c.start = func() error { return errors.New("start failed") }
	if err := c.Start(testConfig()); err == nil {
		t.Fatal("expected start failure")
	}
	if err := c.UpdateProxy(testConfig().Proxy); !errors.Is(err, ErrNotRunning) {
		t.Fatal("update after failed start", err)
	}
}

// Each fixture returns its own marker through TCP CONNECT and UDP ASSOCIATE,
// allowing the test to distinguish endpoints without inspecting proxy fields.
func socksEndpoint(t *testing.T, marker byte) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	clients := make(map[net.Conn]bool)
	closed := false
	t.Cleanup(func() {
		ln.Close()
		udp.Close()
		mu.Lock()
		closed = true
		for c := range clients {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 11 {
				continue
			}
			buf[n-1] = marker
			udp.WriteTo(buf[:n], addr)
		}
	}()
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				c.Close()
				return
			}
			clients[c] = true
			wg.Add(1)
			mu.Unlock()
			go func() {
				defer wg.Done()
				defer func() { c.Close(); mu.Lock(); delete(clients, c); mu.Unlock() }()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				var greeting [2]byte
				if _, err := io.ReadFull(c, greeting[:]); err != nil {
					return
				}
				if _, err := io.ReadFull(c, make([]byte, int(greeting[1]))); err != nil {
					return
				}
				if _, err := c.Write([]byte{5, 0}); err != nil {
					return
				}
				var request [10]byte // Tests use IPv4 destinations.
				if _, err := io.ReadFull(c, request[:]); err != nil {
					return
				}
				if request[0] != 5 || request[3] != 1 {
					return
				}
				port := udp.LocalAddr().(*net.UDPAddr).Port
				if _, err := c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)}); err != nil {
					return
				}
				if request[1] == 3 {
					io.Copy(io.Discard, c)
					return
				}
				var b [1]byte
				for {
					if _, err := io.ReadFull(c, b[:]); err != nil {
						return
					}
					if _, err := c.Write([]byte{marker}); err != nil {
						return
					}
				}
			}()
		}
	}()
	return "socks5://" + ln.Addr().String()
}

func TestUpdateProxySwitchesTCPAndUDPWithoutRestart(t *testing.T) {
	a, b := socksEndpoint(t, 'A'), socksEndpoint(t, 'B')
	tun := tunnel.New(nil, nil)
	restore := tunnel.ReplaceGlobal(tun)
	defer restore()
	// Exercise the public UpdateProxy entry point with the real SetProxy hook;
	// engine lifecycle hooks are replaced so this test requires no TUN privileges.
	oldInsert, oldStart, oldStop := shared.insert, shared.start, shared.stop
	starts, stops, inserts := 0, 0, 0
	shared.insert = func(*engine.Key) { inserts++ }
	shared.start = func() error { starts++; return nil }
	shared.stop = func() error { stops++; return nil }
	t.Cleanup(func() {
		Stop()
		shared.insert, shared.start, shared.stop = oldInsert, oldStart, oldStop
	})
	if err := Start(testConfig()); err != nil {
		t.Fatal(err)
	}
	if err := UpdateProxy(a); err != nil {
		t.Fatal(err)
	}
	metadata := &M.Metadata{Network: M.TCP, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 80}
	dialTCP := func() net.Conn {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		conn, err := tun.Proxy().DialContext(ctx, metadata)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	dialUDP := func() net.PacketConn {
		conn, err := tun.Proxy().DialUDP(&M.Metadata{Network: M.UDP, DstIP: metadata.DstIP, DstPort: metadata.DstPort})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	checkTCP := func(c net.Conn, want byte) {
		t.Helper()
		c.SetDeadline(time.Now().Add(time.Second))
		if _, err := c.Write([]byte{'?'}); err != nil {
			t.Fatal(err)
		}
		var got [1]byte
		if _, err := io.ReadFull(c, got[:]); err != nil || got[0] != want {
			t.Fatalf("TCP: %q %v, want %c", got, err, want)
		}
	}
	checkUDP := func(c net.PacketConn, want byte) {
		t.Helper()
		c.SetDeadline(time.Now().Add(time.Second))
		if _, err := c.WriteTo([]byte{'?'}, &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 80}); err != nil {
			t.Fatal(err)
		}
		var got [64]byte
		n, _, err := c.ReadFrom(got[:])
		if err != nil || n != 1 || got[0] != want {
			t.Fatalf("UDP: %q %v, want %c", got[:n], err, want)
		}
	}
	oldTCP, oldUDP := dialTCP(), dialUDP()
	checkTCP(oldTCP, 'A')
	checkUDP(oldUDP, 'A')
	if err := UpdateProxy(b); err != nil {
		t.Fatal(err)
	}
	checkTCP(dialTCP(), 'B')
	checkUDP(dialUDP(), 'B')
	checkTCP(oldTCP, 'A')
	checkUDP(oldUDP, 'A')
	if err := UpdateProxy("socks5://bad:0"); err == nil {
		t.Fatal("accepted invalid endpoint")
	}
	checkTCP(dialTCP(), 'B')
	checkUDP(dialUDP(), 'B')
	if starts != 1 || inserts != 1 || stops != 0 {
		t.Fatalf("update restarted engine: %d starts, %d inserts, %d stops", starts, inserts, stops)
	}
}

func TestUpdateProxySerializesWithStop(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	c := controller{running: true, setProxy: func(proxy.Proxy) { close(entered); <-release }, stop: func() error { return nil }}
	updated, stopped := make(chan error, 1), make(chan error, 1)
	go func() { updated <- c.UpdateProxy(testConfig().Proxy) }()
	<-entered
	go func() { stopped <- c.Stop() }()
	select {
	case <-stopped:
		t.Fatal("Stop ran during update")
	default:
	}
	close(release)
	if err := <-updated; err != nil {
		t.Fatal(err)
	}
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	if err := c.UpdateProxy(testConfig().Proxy); !errors.Is(err, ErrNotRunning) {
		t.Fatal(err)
	}
}
