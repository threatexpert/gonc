# LAN Probe Error Grace Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give an in-progress inbound LAN probe connection up to one second to win after another candidate path reports an error, without extending the existing five-second `LANProbeOnly` traversal timeout.

**Architecture:** Add a small context-aware error delivery helper that waits for a configurable grace period before sending to `errChan`. Use a one-second grace only for `LANProbeOnly`; ordinary TCP traversal errors remain immediate, while connection success, parent cancellation, or the existing five-second traversal timeout cancels pending error delivery.

**Tech Stack:** Go, `context`, `time.Timer`, existing TCP traversal and loopback integration tests.

## Global Constraints

- Work directly on the current `main` branch as explicitly approved.
- Preserve the pre-existing `apps/nc.go` change and the completed MQTT role fix.
- Do not classify platform-specific socket errors or parse error strings.
- Do not change the existing three-second dial timeout or five-second `LANProbeOnly` total timeout.
- Do not commit; leave changes available for user review.

---

### Task 1: Reproduce the inbound-wins race

**Files:**
- Modify: `easyp2p/p2p_context_test.go`

**Interfaces:**
- Consumes: `Auto_P2P_TCP_NAT_Traversal`
- Produces: `TestAutoP2PTCPLANProbeOnlyAllowsInboundDuringErrorGrace`

- [x] **Step 1: Write the failing integration test**

Start a `LANProbeOnly` traversal whose outbound target has no listener, wait until its own listener is ready, then connect inbound after 100 milliseconds and complete the existing punch ACK handshake. Assert that traversal returns the inbound connection instead of the early outbound error.

- [x] **Step 2: Verify RED**

Run:

```powershell
go test ./easyp2p -run TestAutoP2PTCPLANProbeOnlyAllowsInboundDuringErrorGrace -count=1
```

Expected: FAIL because the outbound LAN probe error closes traversal before the delayed inbound connection arrives.

### Task 2: Add context-aware error grace

**Files:**
- Modify: `easyp2p/p2p.go`
- Modify: `easyp2p/p2p_tcp_delay_test.go`

**Interfaces:**
- Produces: `lanProbeErrorGracePeriod = time.Second`
- Produces: `reportTraversalError(ctx context.Context, errCh chan<- error, err error, grace time.Duration)`
- Consumes: existing `attemptCtx`, `errChan`, and `p2pInfo.LANProbeOnly`

- [x] **Step 1: Write helper behavior tests**

Add tests proving that error delivery waits for its grace period, context cancellation suppresses the pending error, and a context deadline shorter than the grace prevents error delivery beyond that deadline.

- [x] **Step 2: Verify RED**

Run:

```powershell
go test ./easyp2p -run "TestReportTraversalError|TestLANProbeErrorGracePeriod" -count=1
```

Expected: compilation fails because the helper and constant do not exist.

- [x] **Step 3: Implement minimal helper and integration**

Implement:

```go
const lanProbeErrorGracePeriod = time.Second

func reportTraversalError(ctx context.Context, errCh chan<- error, err error, grace time.Duration) {
    if err == nil {
        return
    }
    if grace > 0 {
        timer := time.NewTimer(grace)
        defer timer.Stop()
        select {
        case <-ctx.Done():
            return
        case <-timer.C:
        }
    }
    select {
    case errCh <- err:
    case <-ctx.Done():
    }
}
```

Set `grace` to one second only when `p2pInfo.LANProbeOnly` is true and use the helper from the existing traversal-local `reportErr` closure.

- [x] **Step 4: Verify GREEN**

Run:

```powershell
go test ./easyp2p -run "TestAutoP2PTCPLANProbeOnlyAllowsInboundDuringErrorGrace|TestReportTraversalError|TestLANProbeErrorGracePeriod" -count=1
go test ./easyp2p -count=1
```

Expected: PASS.

### Task 3: Verification and review

**Files:**
- Verify: `easyp2p/p2p.go`
- Verify: `easyp2p/p2p_context_test.go`
- Verify: `easyp2p/p2p_tcp_delay_test.go`

**Interfaces:**
- Produces: verified working-tree changes for review

- [x] **Step 1: Format and audit**

Run:

```powershell
gofmt -w easyp2p/p2p.go easyp2p/p2p_context_test.go easyp2p/p2p_tcp_delay_test.go
git diff --check
```

- [x] **Step 2: Run full repository tests**

Run:

```powershell
go test ./... -count=1
```

Expected: PASS.

- [x] **Step 3: Confirm scope**

Verify the diff does not alter MQTT candidate selection, dial timeout, traversal timeout, public APIs, or the pre-existing `apps/nc.go` change.
