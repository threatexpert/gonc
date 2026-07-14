# LAN Lazy Punch-Port Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Select one shared punch-port candidate per active or passive LAN discovery round only after the first authenticated peer message requires a port.

**Architecture:** Add a concurrency-safe lazy selector owned by one `lanDiscover` invocation and shared by its initiator and responder workers. Keep `GetFreePort` as a non-reserving probe and leave TCP/UDP traversal unchanged; inject the allocator into an internal discovery helper so timing is testable without relying on OS-assigned ports.

**Tech Stack:** Go 1.25, standard-library `sync.Once`, existing `easyp2p` LAN discovery and Go testing framework.

## Global Constraints

- Apply the behavior to both `-lan` and `-lan-passive` through their shared discovery implementation.
- Do not pre-bind or transfer a UDP socket or TCP listener.
- Do not change the LAN discovery wire format or TCP/UDP traversal behavior.
- One discovery round returns at most one connection and owns exactly one lazy selector.
- Initiator and responder paths in the same round must receive the same port or allocation error.
- A keep-open round started after a successful connection must create a new selector.
- The initial multicast log must not claim that a punch port has been selected or is listening.

---

### Task 1: Add the concurrency-safe lazy selector

**Files:**
- Modify: `easyp2p/lan.go` near `lanSelfFilter`
- Test: `easyp2p/lan_test.go`

**Interfaces:**
- Consumes: `GetFreePort() (int, error)` and `*log.Logger`
- Produces: `newLanPunchPortSelector(allocate func() (int, error), logger *log.Logger) *lanPunchPortSelector` and `(*lanPunchPortSelector).Get() (int, error)`

- [ ] **Step 1: Write failing selector tests**

Add these imports to `easyp2p/lan_test.go`:

```go
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)
```

Add the tests:

```go
func TestLanPunchPortSelectorIsLazyAndShared(t *testing.T) {
	var calls atomic.Int32
	var output bytes.Buffer
	selector := newLanPunchPortSelector(func() (int, error) {
		calls.Add(1)
		return 42042, nil
	}, log.New(&output, "[LAN] ", 0))

	if got := calls.Load(); got != 0 {
		t.Fatalf("allocator called during construction: %d", got)
	}

	const workers = 32
	ports := make(chan int, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			port, err := selector.Get()
			ports <- port
			errs <- err
		}()
	}
	wg.Wait()
	close(ports)
	close(errs)

	if got := calls.Load(); got != 1 {
		t.Fatalf("allocator calls = %d, want 1", got)
	}
	for port := range ports {
		if port != 42042 {
			t.Fatalf("port = %d, want 42042", port)
		}
	}
	for err := range errs {
		if err != nil {
			t.Fatalf("Get returned error: %v", err)
		}
	}
	if got := strings.Count(output.String(), "Selected punchPort=42042 after authenticated peer discovery"); got != 1 {
		t.Fatalf("selection log count = %d, output = %q", got, output.String())
	}
}

func TestLanPunchPortSelectorSharesAllocationError(t *testing.T) {
	sentinel := errors.New("no test port")
	var calls atomic.Int32
	selector := newLanPunchPortSelector(func() (int, error) {
		calls.Add(1)
		return 0, sentinel
	}, log.New(&bytes.Buffer{}, "", 0))

	for i := 0; i < 2; i++ {
		port, err := selector.Get()
		if port != 0 {
			t.Fatalf("port = %d, want 0", port)
		}
		if !errors.Is(err, sentinel) {
			t.Fatalf("error = %v, want wrapped sentinel", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("allocator calls = %d, want 1", got)
	}
}
```

- [ ] **Step 2: Run the tests and verify that they fail**

Run:

```powershell
go test ./easyp2p -run 'TestLanPunchPortSelector' -count=1
```

Expected: compilation fails because `newLanPunchPortSelector` is undefined.

- [ ] **Step 3: Implement the selector**

Add this code after `lanSelfFilter` in `easyp2p/lan.go`:

```go
type lanPunchPortSelector struct {
	once     sync.Once
	allocate func() (int, error)
	logger   *log.Logger
	port     int
	err      error
}

func newLanPunchPortSelector(allocate func() (int, error), logger *log.Logger) *lanPunchPortSelector {
	if allocate == nil {
		allocate = GetFreePort
	}
	return &lanPunchPortSelector{allocate: allocate, logger: logger}
}

func (s *lanPunchPortSelector) Get() (int, error) {
	s.once.Do(func() {
		s.port, s.err = s.allocate()
		if s.err != nil {
			s.err = fmt.Errorf("allocate LAN punch port: %w", s.err)
			return
		}
		if s.logger != nil {
			s.logger.Printf("Selected punchPort=%d after authenticated peer discovery\n", s.port)
		}
	})
	return s.port, s.err
}
```

- [ ] **Step 4: Run the selector tests and race detector**

Run:

```powershell
go test -race ./easyp2p -run 'TestLanPunchPortSelector' -count=1
```

Expected: both selector tests pass and the race detector reports no race.

- [ ] **Step 5: Commit the selector**

```powershell
git add -- easyp2p/lan.go easyp2p/lan_test.go
git commit -m "feat: add lazy LAN punch port selector"
```

### Task 2: Select the port at the authenticated handshake boundary

**Files:**
- Modify: `easyp2p/lan.go:405-710`
- Test: `easyp2p/lan_test.go`

**Interfaces:**
- Consumes: `*lanPunchPortSelector` from Task 1
- Produces: `lanDiscoverWithPortAllocator(ctx context.Context, sessionKey, transportPref string, timeout time.Duration, passive bool, logWriter io.Writer, allocate func() (int, error)) (*LANDiscoverResult, error)`
- Preserves: `LANDiscover`, `LANDiscoverPassive`, `Easy_P2P_LAN`, and `Easy_P2P_LAN_Passive` signatures

- [ ] **Step 1: Write a failing no-peer allocation-timing test**

Add this test to `easyp2p/lan_test.go`:

```go
func TestLANDiscoverDefersPunchPortSelectionUntilPeer(t *testing.T) {
	for _, passive := range []bool{false, true} {
		passive := passive
		t.Run(fmt.Sprintf("passive=%t", passive), func(t *testing.T) {
			var calls atomic.Int32
			var output bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
			defer cancel()

			_, err := lanDiscoverWithPortAllocator(
				ctx,
				fmt.Sprintf("deferred-port-%t-%d", passive, time.Now().UnixNano()),
				"",
				time.Second,
				passive,
				&output,
				func() (int, error) {
					calls.Add(1)
					return 42042, nil
				},
			)
			if err == nil {
				t.Fatal("discovery without a peer unexpectedly succeeded")
			}
			if got := calls.Load(); got != 0 {
				t.Fatalf("allocator called without an authenticated peer: %d", got)
			}
			if strings.Contains(output.String(), "punchPort=") {
				t.Fatalf("initial logs claim a selected punch port: %q", output.String())
			}
		})
	}
}
```

- [ ] **Step 2: Run the timing test and verify that it fails**

Run:

```powershell
go test ./easyp2p -run TestLANDiscoverDefersPunchPortSelectionUntilPeer -count=1
```

Expected: compilation fails because `lanDiscoverWithPortAllocator` is undefined.

- [ ] **Step 3: Add the injectable discovery wrapper and remove eager allocation**

Replace the current internal `lanDiscover` function with these complete functions:

```go
func lanDiscover(ctx context.Context, sessionKey, transportPref string, timeout time.Duration, passive bool, logWriter io.Writer) (*LANDiscoverResult, error) {
	return lanDiscoverWithPortAllocator(ctx, sessionKey, transportPref, timeout, passive, logWriter, GetFreePort)
}

func lanDiscoverWithPortAllocator(
	ctx context.Context,
	sessionKey, transportPref string,
	timeout time.Duration,
	passive bool,
	logWriter io.Writer,
	allocate func() (int, error),
) (*LANDiscoverResult, error) {
	logger := misc.NewLog(logWriter, "[LAN] ", log.LstdFlags|log.Lmsgprefix)
	key := lanDeriveKey(sessionKey)
	sid := lanDeriveSessionID(sessionKey)
	sf := newSelfFilter()
	punchPorts := newLanPunchPortSelector(allocate, logger)

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	mc, err := newLanMcast(logger)
	if err != nil {
		return nil, err
	}
	defer mc.Close()

	logger.Printf("Multicast %s:%d, %d ifaces\n", LANMulticastIP, LANMulticastPort, len(mc.ifaces))
	logger.Printf("Interfaces: %s\n", mc.ifaceSummary())

	disp := newLanDispatcher()
	go disp.run(ctx, mc, key)

	type dr struct {
		r   *LANDiscoverResult
		err error
	}
	ch := make(chan dr, 2)

	const workers = 2
	initiatorRole := "Initiator"
	if passive {
		initiatorRole = "Passive"
		logger.Printf("Mode: passive startup burst, then beacon every %s\n", lanPassiveBeaconInterval)
	} else {
		logger.Printf("Mode: active beacon every %s for %s, then every %s\n",
			lanActiveBeaconInterval, lanActiveFastBeaconWindow, lanActiveSlowBeaconInterval)
	}

	go func() {
		r, e := lanInitiator(ctx, mc, disp, key, sid, transportPref, punchPorts, sf, logger, passive, initiatorRole)
		ch <- dr{r, e}
	}()
	go func() {
		r, e := lanResponder(ctx, mc, disp, key, sid, transportPref, punchPorts, sf, logger)
		ch <- dr{r, e}
	}()

	var lastErr error
	for i := 0; i < workers; i++ {
		select {
		case d := <-ch:
			if d.err == nil && d.r != nil {
				cancel()
				return d.r, nil
			}
			if d.err != nil {
				lastErr = d.err
			}
		case <-ctx.Done():
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, fmt.Errorf("LAN discovery timeout")
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("LAN discovery failed")
}
```

- [ ] **Step 4: Move initiator and responder allocation to valid-peer processing**

Change the relevant portion of the initiator signature to:

```go
func lanInitiator(
	ctx context.Context, mc *lanMcast, disp *lanDispatcher,
	key []byte, sid, tp string, punchPorts *lanPunchPortSelector,
	sf *lanSelfFilter, logger *log.Logger,
	passive bool, roleName string,
) (*LANDiscoverResult, error) {
```

In `lanInitiator`, immediately after calculating `localIP` and `finalTP`, add:

```go
	punchPort, err := punchPorts.Get()
	if err != nil {
		return nil, err
	}
```

This occurs only after a Response has decoded successfully and its `NonceA` matches the initiator's nonce, and before Confirm is constructed.

In `lanResponder`, immediately after the Beacon select block has validated session ID, self-filter, source IP, route selection, and assigned `beaconSrc`, add:

```go
	punchPort, err := punchPorts.Get()
	if err != nil {
		return nil, err
	}
```

Change the relevant portion of the responder signature to:

```go
func lanResponder(
	ctx context.Context, mc *lanMcast, disp *lanDispatcher,
	key []byte, sid, tp string, punchPorts *lanPunchPortSelector,
	sf *lanSelfFilter, logger *log.Logger,
) (*LANDiscoverResult, error) {
```

The local `punchPort` returned by `Get()` is then used in these existing fields without changing the wire structures:

```go
respData := lanEncode(key, lanMsgResponse, lanResponse{
	NonceA: b.NonceA, NonceB: nonceB, Transport: tp,
	IP: localIP, Port: punchPort,
})

confirmData := lanEncode(key, lanMsgConfirm, lanConfirm{
	NonceB: resp.NonceB, Transport: finalTP,
	IP: localIP, Port: punchPort,
})

return &LANDiscoverResult{
	LocalIP: localIP, LocalPort: punchPort,
	RemoteIP: resp.IP, RemotePort: resp.Port,
	Transport: finalTP, IsInitiator: true,
}, nil

return &LANDiscoverResult{
	LocalIP: localIP, LocalPort: punchPort,
	RemoteIP: confirm.IP, RemotePort: confirm.Port,
	Transport: confirm.Transport, IsInitiator: false,
}, nil
```

- [ ] **Step 5: Run formatting and focused tests**

Run:

```powershell
gofmt -w easyp2p/lan.go easyp2p/lan_test.go
go test ./easyp2p -run 'TestLanPunchPortSelector|TestLANDiscoverDefersPunchPortSelectionUntilPeer' -count=1
```

Expected: all focused tests pass. The no-peer cases time out without calling their injected allocators or logging `punchPort=`.

- [ ] **Step 6: Run package regression tests**

Run:

```powershell
go test ./easyp2p ./apps -count=1
```

Expected: both packages pass.

- [ ] **Step 7: Verify the final diff and commit**

Run:

```powershell
git diff --check
git diff -- easyp2p/lan.go easyp2p/lan_test.go
```

Expected: no whitespace errors; the diff contains no traversal-layer or wire-format changes.

Commit:

```powershell
git add -- easyp2p/lan.go easyp2p/lan_test.go
git commit -m "fix: defer LAN punch port selection"
```
