package tunengine

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/engine"
)

func testConfig() Config {
	return Config{Device: "tun://test", Proxy: "socks5://127.0.0.1:1080"}
}

func TestConfigModesAndDefaults(t *testing.T) {
	for _, deferred := range []bool{false, true} {
		for _, reject := range []bool{false, true} {
			cfg := testConfig()
			cfg.RejectIPv6 = reject
			if deferred {
				cfg.DeferredTCP = &DeferredTCPConfig{}
			}
			key, err := cfg.key()
			if err != nil {
				t.Fatal(err)
			}
			if key.TCPDeferredHandshake != deferred || key.RejectIPv6 != reject || key.Device != cfg.Device || key.Proxy != cfg.Proxy || key.MTU != 1400 || key.LogLevel != "warn" {
				t.Fatalf("wrong configuration: %+v", key)
			}
			if deferred {
				if key.TCPProxyHandshakeTimeout != 21*time.Second || key.TCPFailureCacheTTL != 30*time.Second || key.TCPFailureCacheCapacity != 4096 {
					t.Fatalf("wrong defaults: %+v", key)
				}
				if *cfg.DeferredTCP != (DeferredTCPConfig{}) {
					t.Fatal("mutated caller config")
				}
			} else if key.TCPProxyHandshakeTimeout != 0 || key.TCPFailureCacheTTL != 0 || key.TCPFailureCacheCapacity != 0 {
				t.Fatal("legacy policy changed")
			}
		}
	}
}

func TestCustomAndInvalidConfig(t *testing.T) {
	cfg := testConfig()
	cfg.MTU, cfg.LogLevel = 1500, "debug"
	cfg.DeferredTCP = &DeferredTCPConfig{time.Minute, 10 * time.Second, 128}
	key, err := cfg.key()
	if err != nil {
		t.Fatal(err)
	}
	if key.MTU != 1500 || key.LogLevel != "debug" || key.TCPProxyHandshakeTimeout != time.Minute || key.TCPFailureCacheTTL != 10*time.Second || key.TCPFailureCacheCapacity != 128 {
		t.Fatalf("custom settings lost: %+v", key)
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.Device = " " }, func(c *Config) { c.Proxy = "" }, func(c *Config) { c.MTU = -1 },
		func(c *Config) { c.DeferredTCP = &DeferredTCPConfig{ProxyHandshakeTimeout: -1} },
		func(c *Config) { c.DeferredTCP = &DeferredTCPConfig{FailureCacheTTL: -1} },
		func(c *Config) { c.DeferredTCP = &DeferredTCPConfig{FailureCacheCapacity: -1} },
	} {
		c := testConfig()
		change(&c)
		ctrl := controller{insert: func(*engine.Key) { t.Fatal("invalid config reached engine") }}
		if err := ctrl.Start(c); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
}

func TestLifecycleErrorsAndRestart(t *testing.T) {
	startErr, stopErr := errors.New("start"), errors.New("stop")
	var injectedStart, injectedStop error
	var keys []*engine.Key
	stops := 0
	c := controller{insert: func(k *engine.Key) { keys = append(keys, k) }, start: func() error { return injectedStart }, stop: func() error { stops++; return injectedStop }}
	injectedStart = startErr
	if err := c.Start(testConfig()); !errors.Is(err, startErr) {
		t.Fatal(err)
	}
	if err := c.Stop(); err != nil || stops != 1 {
		t.Fatal("partial-start cleanup not forwarded", err)
	}
	injectedStart = nil
	cfg := testConfig()
	cfg.DeferredTCP = &DeferredTCPConfig{}
	cfg.RejectIPv6 = true
	if err := c.Start(cfg); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(cfg); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatal(err)
	}
	injectedStop = stopErr
	if err := c.Stop(); !errors.Is(err, stopErr) {
		t.Fatal(err)
	}
	if err := c.Start(cfg); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatal("failed stop lost running state", err)
	}
	injectedStop = nil
	if err := c.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := c.Stop(); err != nil {
		t.Fatal("repeated stop", err)
	}
	cfg.RejectIPv6 = false
	if err := c.Start(cfg); err != nil {
		t.Fatal(err)
	}
	if keys[len(keys)-1].RejectIPv6 || !keys[len(keys)-2].RejectIPv6 {
		t.Fatal("stale or mutated policy on restart")
	}
}

func TestConcurrentStartsOnlyStartOnce(t *testing.T) {
	starts := 0
	c := controller{insert: func(*engine.Key) {}, start: func() error { starts++; return nil }, stop: func() error { return nil }}
	var wg sync.WaitGroup
	results := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- c.Start(testConfig()) }()
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrAlreadyRunning) {
			t.Fatal(err)
		}
	}
	if starts != 1 || success != 1 {
		t.Fatalf("starts=%d success=%d", starts, success)
	}
}

func TestStopWaitsForStart(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	started, stopped := make(chan error, 1), make(chan error, 1)
	c := controller{insert: func(*engine.Key) {}, start: func() error { close(entered); <-release; return nil }, stop: func() error { return nil }}
	go func() { started <- c.Start(testConfig()) }()
	<-entered
	go func() { stopped <- c.Stop() }()
	select {
	case <-stopped:
		t.Fatal("stop raced with start")
	default:
	}
	close(release)
	if err := <-started; err != nil {
		t.Fatal(err)
	}
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	if c.running {
		t.Fatal("stop did not clear running state")
	}
}
