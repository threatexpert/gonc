# Same-LAN TCP Immediate Dialing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make both TCP P2P roles begin outbound dialing immediately whenever the existing route selection classifies the peers as being on the same LAN.

**Architecture:** Extract the TCP active-dial stagger into one internal duration policy based on role, `inSameLAN`, and `LANProbeOnly`. `Auto_P2P_TCP_NAT_Traversal` will calculate that duration once and use it for both its timing log and context-aware wait, leaving listener startup and all other traversal behavior unchanged.

**Tech Stack:** Go 1.25, standard `testing` package, existing `netx.WaitContext` cancellation helper.

## Global Constraints

- Apply the behavior only to TCP traversal; do not change the UDP server's two-second PING stagger.
- A TCP server with `inSameLAN == true` must use zero active-dial delay, including ordinary `-p2p` candidates classified as same-LAN.
- A TCP server with `inSameLAN == false` and `LANProbeOnly == false` must retain the exact two-second delay.
- Client and `LANProbeOnly` paths must preserve their existing zero-delay behavior.
- Do not change route classification, role selection, LAN discovery, MQTT synchronization, handshake, connection winner selection, timeout values, CLI flags, or public APIs.
- Do not modify or stage the existing user-owned changes in `apps/nc.go` or `apps/p2p_with_lan_test.go`.

---

## File Structure

- Create `easyp2p/p2p_tcp_delay_test.go` for the table-driven active-dial policy regression test.
- Modify `easyp2p/p2p.go` to define `tcpActiveDialDelay` and consume its result in the TCP traversal log and wait paths.
- Do not split or otherwise restructure `p2p.go`; this is a focused policy change within the existing traversal implementation.

### Task 1: Apply One Tested TCP Active-Dial Delay Policy

**Files:**
- Create: `easyp2p/p2p_tcp_delay_test.go`
- Modify: `easyp2p/p2p.go:1738-2020`
- Test: `easyp2p/p2p_tcp_delay_test.go`
- Regression test: `easyp2p/p2p_context_test.go`

**Interfaces:**
- Consumes: `isClient bool`, the existing local `inSameLAN bool`, and `P2PAddressInfo.LANProbeOnly bool`.
- Produces: `func tcpActiveDialDelay(isClient, inSameLAN, lanProbeOnly bool) time.Duration`.
- Preserves: `Auto_P2P_TCP_NAT_Traversal(...) (net.Conn, bool, error)` without a signature change.

- [ ] **Step 1: Write the failing delay-policy test**

Create `easyp2p/p2p_tcp_delay_test.go` with the complete table below:

```go
package easyp2p

import (
	"testing"
	"time"
)

func TestTCPActiveDialDelay(t *testing.T) {
	tests := []struct {
		name         string
		isClient     bool
		inSameLAN    bool
		lanProbeOnly bool
		want         time.Duration
	}{
		{
			name:     "client on non-LAN route starts immediately",
			isClient: true,
			want:     0,
		},
		{
			name:      "server on same-LAN route starts immediately",
			inSameLAN: true,
			want:      0,
		},
		{
			name:         "LAN-probe-only server starts immediately",
			lanProbeOnly: true,
			want:         0,
		},
		{
			name: "server on non-LAN route keeps stagger",
			want: 2 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tcpActiveDialDelay(tt.isClient, tt.inSameLAN, tt.lanProbeOnly)
			if got != tt.want {
				t.Fatalf("tcpActiveDialDelay() = %s, want %s", got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run the focused test and verify the red state**

Run:

```powershell
go test ./easyp2p -run '^TestTCPActiveDialDelay$' -count=1
```

Expected: build failure containing `undefined: tcpActiveDialDelay`. A different failure must be investigated before production code is changed.

- [ ] **Step 3: Add the minimal policy and wire it into TCP traversal**

Immediately before `Auto_P2P_TCP_NAT_Traversal` in `easyp2p/p2p.go`, add:

```go
func tcpActiveDialDelay(isClient, inSameLAN, lanProbeOnly bool) time.Duration {
	if isClient || inSameLAN || lanProbeOnly {
		return 0
	}
	return 2 * time.Second
}
```

Immediately after the existing `lanProbeEnabled` assignment, calculate the policy once:

```go
activeDialDelay := tcpActiveDialDelay(isClient, inSameLAN, p2pInfo.LANProbeOnly)
```

Replace the TCP `Active Mode` / `Passive Mode` timing log with:

```go
if isClient {
	p2pLogf(logWriter, "  - %-14s: connect start immediately\n", "Active Mode")
} else if activeDialDelay == 0 {
	p2pLogf(logWriter, "  - %-14s: connect start immediately\n", "Passive Mode")
} else {
	p2pLogf(logWriter, "  - %-14s: connect start after %s\n", "Passive Mode", activeDialDelay)
}
```

Replace the wait at the beginning of `doPunching` with:

```go
if activeDialDelay > 0 {
	if err := netx.WaitContext(attemptCtx, activeDialDelay); err != nil {
		return
	}
}
```

Do not modify the similarly shaped UDP wait in `Auto_P2P_UDP_NAT_Traversal`.

- [ ] **Step 4: Format the changed Go files and verify the focused test is green**

Run:

```powershell
gofmt -w easyp2p/p2p.go easyp2p/p2p_tcp_delay_test.go
go test ./easyp2p -run '^TestTCPActiveDialDelay$' -count=1
```

Expected: `ok github.com/threatexpert/gonc/v2/easyp2p`.

- [ ] **Step 5: Run the existing TCP traversal ownership and cancellation regressions**

Run:

```powershell
go test ./easyp2p -run '^(TestTCPActiveDialDelay|TestAutoP2PTCPTraversalCancellationClosesHandshakeCandidate|TestAutoP2PTCPTraversalSuccessfulOwnershipTransfer)$' -count=1
```

Expected: all three tests pass. This checks the new timing policy while retaining listener cancellation, handshake cleanup, and connection ownership transfer behavior.

- [ ] **Step 6: Run package-wide verification and inspect the exact diff**

Run:

```powershell
go test ./easyp2p -count=1
go test ./... -count=1
git diff --check -- easyp2p/p2p.go easyp2p/p2p_tcp_delay_test.go
git diff -- easyp2p/p2p.go easyp2p/p2p_tcp_delay_test.go
```

Expected: both test commands pass, `git diff --check` prints nothing, and the diff contains only the helper, its single calculation, the two consumers, and the focused test. The two pre-existing `apps` modifications must remain outside this diff.

- [ ] **Step 7: Commit only the implementation files**

Run:

```powershell
git add -- easyp2p/p2p.go easyp2p/p2p_tcp_delay_test.go
git diff --cached --check
git diff --cached --name-only
git commit -m "fix: dial immediately on same-LAN TCP routes"
```

Expected staged names before commit:

```text
easyp2p/p2p.go
easyp2p/p2p_tcp_delay_test.go
```

After the commit, `apps/nc.go` and `apps/p2p_with_lan_test.go` remain modified and unstaged as user-owned work.
