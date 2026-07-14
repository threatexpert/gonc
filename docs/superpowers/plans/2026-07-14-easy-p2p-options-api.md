# Easy P2P Options API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the untagged nine-argument `Easy_P2P_MPWithOptions` API with required `ctx`/`network`/`sessionUID` arguments plus a value-type options structure while preserving the released entry points.

**Architecture:** Expand `EasyP2PMPOptions` to own every optional setting and normalize its zero value before the existing P2P algorithm runs. Keep `Easy_P2P` and `Easy_P2P_MP` unchanged as compatibility adapters, and migrate the sole repository caller of `Easy_P2P_MPWithOptions` to named option fields.

**Tech Stack:** Go 1.25, standard-library `context`, `io`, and `testing`; existing `easyp2p` and `apps` packages.

## Global Constraints

- Preserve the public signatures and behavior of `Easy_P2P` and `Easy_P2P_MP`.
- Change `Easy_P2P_MPWithOptions` directly to `func(context.Context, string, string, EasyP2PMPOptions) (*P2PConnInfo, error)`; it is not in a released tag.
- Keep `ctx`, `network`, and `sessionUID` explicit; do not default an empty `network`.
- A zero-value `EasyP2PMPOptions` is valid; normalize a nil `LogWriter` to `io.Discard`.
- Preserve signaling-session and relay-connection ownership and callback timing.
- Do not change signaling, NAT traversal, multipath, LAN discovery, wire formats, mobile APIs, or embedded APIs.
- Do not add functional options, a nested hooks type, or live-network requirements to unit tests.

---

## File Map

- Modify `easyp2p/p2p.go`: expand and normalize `EasyP2PMPOptions`; adapt the released wrapper; consume the new signature without changing the traversal body.
- Create `easyp2p/p2p_options_test.go`: test zero-value normalization and compile-check old and new public function signatures.
- Modify `apps/nc.go`: replace the pointer/nil options convention with a value and named fields at the sole new-API call site.

### Task 1: Define a zero-value-safe Easy P2P options object

**Files:**
- Modify: `easyp2p/p2p.go:838-840`
- Create: `easyp2p/p2p_options_test.go`

**Interfaces:**
- Consumes: existing `RelayPacketConn`, `MQTTSignalSession`, and `io.Writer` types.
- Produces: `EasyP2PMPOptions` with fields `Bind`, `MultipathEnabled`, `RelayConn`, `LogWriter`, `Signal`, and `OnAddressExchangeDone`; unexported `func (EasyP2PMPOptions) normalized() EasyP2PMPOptions`.

- [ ] **Step 1: Write the failing normalization test**

Create `easyp2p/p2p_options_test.go`:

```go
package easyp2p

import (
	"bytes"
	"testing"
)

func TestEasyP2PMPOptionsNormalized(t *testing.T) {
	relay := &RelayPacketConn{}
	signal := &MQTTSignalSession{}
	hookCalled := false
	options := EasyP2PMPOptions{
		Bind:             "127.0.0.1:0",
		MultipathEnabled: true,
		RelayConn:        relay,
		Signal:           signal,
		OnAddressExchangeDone: func() {
			hookCalled = true
		},
	}

	normalized := options.normalized()
	if normalized.LogWriter == nil {
		t.Fatal("nil LogWriter was not normalized")
	}
	if _, err := normalized.LogWriter.Write([]byte("discarded")); err != nil {
		t.Fatalf("normalized LogWriter.Write: %v", err)
	}
	if options.LogWriter != nil {
		t.Fatal("normalization mutated the input value")
	}
	if normalized.Bind != options.Bind || !normalized.MultipathEnabled {
		t.Fatalf("network options changed: %+v", normalized)
	}
	if normalized.RelayConn != relay || normalized.Signal != signal {
		t.Fatal("injected dependencies changed during normalization")
	}
	if normalized.OnAddressExchangeDone == nil {
		t.Fatal("callback was lost during normalization")
	}
	normalized.OnAddressExchangeDone()
	if !hookCalled {
		t.Fatal("normalized callback is not the supplied callback")
	}

	var logs bytes.Buffer
	options.LogWriter = &logs
	normalized = options.normalized()
	if normalized.LogWriter != &logs {
		t.Fatal("normalization replaced a supplied LogWriter")
	}
}
```

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```bash
go test ./easyp2p -run '^TestEasyP2PMPOptionsNormalized$' -count=1
```

Expected: compilation fails because the new option fields and `normalized` method do not exist.

- [ ] **Step 3: Expand and normalize the options type**

Replace the current one-field declaration in `easyp2p/p2p.go` with:

```go
// EasyP2PMPOptions configures optional dependencies and behavior for
// Easy_P2P_MPWithOptions. Its zero value is valid.
type EasyP2PMPOptions struct {
	Bind             string
	MultipathEnabled bool

	// RelayConn is caller-owned and is not closed by this API.
	RelayConn *RelayPacketConn
	// LogWriter receives diagnostics. Nil is normalized to io.Discard.
	LogWriter io.Writer
	// Signal is caller-owned when non-nil. A nil value makes this API create
	// and close an internal signaling session.
	Signal *MQTTSignalSession
	// OnAddressExchangeDone runs after address exchange succeeds and before
	// traversal attempts begin.
	OnAddressExchangeDone func()
}

func (options EasyP2PMPOptions) normalized() EasyP2PMPOptions {
	if options.LogWriter == nil {
		options.LogWriter = io.Discard
	}
	return options
}
```

Do not change either function signature in this task.

- [ ] **Step 4: Format and verify GREEN**

Run:

```bash
gofmt -w easyp2p/p2p.go easyp2p/p2p_options_test.go
go test ./easyp2p -run '^TestEasyP2PMPOptionsNormalized$' -count=1
```

Expected: `ok github.com/threatexpert/gonc/v2/easyp2p`.

- [ ] **Step 5: Commit the independently tested options type**

```bash
git add easyp2p/p2p.go easyp2p/p2p_options_test.go
git diff --cached --check
git commit -m "refactor: expand Easy P2P options"
```

### Task 2: Shorten the API and migrate its sole caller

**Files:**
- Modify: `easyp2p/p2p.go:850-969`
- Modify: `easyp2p/p2p_options_test.go`
- Modify: `apps/nc.go:3396-3412,3489`

**Interfaces:**
- Consumes: the `EasyP2PMPOptions` and `normalized` method produced by Task 1.
- Produces: `func Easy_P2P_MPWithOptions(ctx context.Context, network, sessionUID string, options EasyP2PMPOptions) (*P2PConnInfo, error)` while preserving the two released function types.

- [ ] **Step 1: Add compile-time public signature assertions**

Extend the imports and add these declarations to `easyp2p/p2p_options_test.go`:

```go
import (
	"bytes"
	"context"
	"io"
	"testing"
)

var (
	_ func(string, string, *RelayPacketConn, io.Writer) (*P2PConnInfo, error) = Easy_P2P
	_ func(context.Context, string, string, string, bool, *RelayPacketConn, io.Writer, *MQTTSignalSession) (*P2PConnInfo, error) = Easy_P2P_MP
	_ func(context.Context, string, string, EasyP2PMPOptions) (*P2PConnInfo, error) = Easy_P2P_MPWithOptions
)
```

Keep the normalization test from Task 1 below these assertions.

- [ ] **Step 2: Run the package test and verify RED**

Run:

```bash
go test ./easyp2p -run '^TestEasyP2PMPOptionsNormalized$' -count=1
```

Expected: compilation fails because `Easy_P2P_MPWithOptions` still has the old nine-argument function type. The two released signature assertions must compile.

- [ ] **Step 3: Turn the released MP function into a compatibility adapter**

Replace the wrapper and new-entry signature in `easyp2p/p2p.go` with:

```go
func Easy_P2P_MP(ctx context.Context, network, bind, sessionUid string, multipathEnabled bool, relayConn *RelayPacketConn, logWriter io.Writer, signal *MQTTSignalSession) (*P2PConnInfo, error) {
	return Easy_P2P_MPWithOptions(ctx, network, sessionUid, EasyP2PMPOptions{
		Bind:             bind,
		MultipathEnabled: multipathEnabled,
		RelayConn:        relayConn,
		LogWriter:        logWriter,
		Signal:           signal,
	})
}

func Easy_P2P_MPWithOptions(ctx context.Context, network, sessionUid string, options EasyP2PMPOptions) (*P2PConnInfo, error) {
	options = options.normalized()
	bind := options.Bind
	multipathEnabled := options.MultipathEnabled
	relayConn := options.RelayConn
	logWriter := options.LogWriter
	signal := options.Signal

	networksToTryStun, err := NetworksForStun(network)
	if err != nil {
		return nil, err
	}

	fmt.Fprintf(logWriter, "=== Checking NAT reachability ===\n")
```

Keep the existing body from `if signal == nil` onward in its current order, except for the callback check specified next. This retains the exact signaling, address-exchange, retry, and traversal implementation while changing only where its local inputs come from.

At the existing callback site, replace the pointer/nil check with:

```go
	if options.OnAddressExchangeDone != nil {
		options.OnAddressExchangeDone()
	}
```

Do not reorder address exchange, context-cause checking, traversal attempts, retries, or connection-result construction.

- [ ] **Step 4: Migrate the `apps/nc.go` options value and call**

Replace:

```go
	var p2pOptions *easyp2p.EasyP2PMPOptions
```

with:

```go
	p2pOptions := easyp2p.EasyP2PMPOptions{}
```

Replace the conditional pointer construction with a direct callback assignment:

```go
		if !extendCandidateWindow {
			p2pOptions.OnAddressExchangeDone = func() {
				candidateOwnsPath = candidate.disarm(candidateToken)
			}
		}
```

Immediately before the P2P call, populate the optional dependencies and use the new signature:

```go
		p2pOptions.Bind = ncconfig.localbind
		p2pOptions.RelayConn = relayConn
		p2pOptions.LogWriter = ncconfig.LogWriter
		p2pOptions.Signal = mqttSignalSession
		connInfo, err = easyp2p.Easy_P2P_MPWithOptions(
			p2pCtx,
			ncconfig.network,
			ncconfig.p2pSessionKey+topicSalt,
			p2pOptions,
		)
```

Leave `MultipathEnabled` at its zero value because this call currently passes `false`.

- [ ] **Step 5: Format and run focused package verification**

Run:

```bash
gofmt -w easyp2p/p2p.go easyp2p/p2p_options_test.go apps/nc.go
go test ./easyp2p ./apps -count=1
```

Expected: both packages report `ok`; no live peer, MQTT broker, STUN server, or relay is required by the new test.

- [ ] **Step 6: Run full regression verification**

Run:

```bash
go test ./... -count=1
git diff --check
```

Expected: all packages pass and `git diff --check` emits no errors.

- [ ] **Step 7: Review the compatibility and behavior diff**

Run:

```bash
git diff -- easyp2p/p2p.go easyp2p/p2p_options_test.go apps/nc.go
rg -n "Easy_P2P_MPWithOptions|Easy_P2P_MP\\(" easyp2p apps
```

Confirm from the output that:

- `Easy_P2P` and `Easy_P2P_MP` still match the compile-time assertions;
- every optional value reaches the same existing local variable;
- the callback remains after successful address exchange and before the context-cause/traversal checks;
- the only direct `Easy_P2P_MPWithOptions` caller uses the new signature;
- `apps/portrotate.go` still uses the compatible released wrapper.

- [ ] **Step 8: Commit the API migration**

```bash
git add easyp2p/p2p.go easyp2p/p2p_options_test.go apps/nc.go
git diff --cached --check
git commit -m "refactor: simplify Easy P2P options API"
```

## Final Verification Gate

After both task commits, run from a clean worktree:

```bash
go test ./... -count=1
git status --short
git log -2 --oneline
```

Expected: all tests pass, status is clean, and the two plan commits are the latest implementation commits.
