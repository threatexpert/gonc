package tunengine

import (
	"errors"
	"sync"

	"github.com/xjasonlyu/tun2socks/v2/engine"
)

// ErrAlreadyRunning protects the single engine in this process. Stop before
// restarting with a different policy. This API does not support multiple TUNs.
var ErrAlreadyRunning = errors.New("tunengine: engine is already running")

type controller struct {
	mu      sync.Mutex
	running bool
	insert  func(*engine.Key)
	start   func() error
	stop    func() error
}

var shared = controller{insert: engine.Insert, start: engine.Start, stop: engine.Stop}

// Start installs the config and starts the engine under one lock. OS-specific
// setup and rollback remain the caller's responsibility, including FD ownership
// on errors. Start errors are returned unchanged. The upstream engine can be
// partially initialized on failure; callers using engine-owned devices should
// call Stop during rollback, as they would when using the engine directly.
func Start(config Config) error { return shared.Start(config) }

// Stop serializes shutdown with Start and forwards shutdown errors. It also
// calls the underlying idempotent stop after a failed start, for partial cleanup.
func Stop() error { return shared.Stop() }

func (c *controller) Start(config Config) error {
	key, err := config.key()
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return ErrAlreadyRunning
	}
	c.insert(key)
	if err := c.start(); err != nil {
		return err
	}
	c.running = true
	return nil
}

func (c *controller) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.stop(); err != nil {
		return err
	}
	c.running = false
	return nil
}
