# Same-LAN TCP Immediate Dialing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Start both same-LAN TCP P2P roles immediately while making unsynchronized `round == 0` traversal retry for an eight-second window instead of failing before the peer listener exists.

**Architecture:** Keep one policy for the role-based active-dial delay and add one policy for total TCP traversal timeout. Treat `round == 0 && inSameLAN` as the only unsynchronized same-LAN case: its first direct dial is immediate, failed dials retry every 250 milliseconds, and the concurrent accept path remains alive until success, cancellation, or the eight-second timeout. Normal `round > 0` traversal continues relying on its post-listen MQTT synchronization and retains existing error convergence.

**Tech Stack:** Go 1.25, standard `testing` package, existing `netx.WaitContext` cancellation helper.

## Final Review Amendment

The original delayed-listener test in Steps 5, 6, and 8 observed a log emitted before `DialContext`, so its fixed 100-millisecond sleep did not causally prove that a failed first dial occurred. Those test instructions are superseded by two deterministic real-TCP regressions: one listener resets the first outbound candidate and completes the second to prove retry and its 250-millisecond interval; a separate test resets the first inbound candidate and completes the second to prove Accept remains active. Final review also requires same-LAN candidate failures not to override another committing candidate, validates an accepted peer before its handshake can consume selection, and replaces the Server-side `sync.Once` selector with commit-after-success selection so a failed ACK write does not poison later retries.

## Global Constraints

- Apply the behavior only to TCP traversal; do not change the UDP server's two-second PING stagger.
- Every TCP server with `inSameLAN == true` must use zero initial active-dial delay, including ordinary `-p2p` candidates.
- Only `round == 0 && inSameLAN` retries failed direct dials; retry every exactly `250 * time.Millisecond`.
- An unsynchronized same-LAN traversal must retain its concurrent Accept path and must not report `all connection attempts failed` for an individual failed outbound attempt.
- The total timeout for `round == 0 && inSameLAN` is exactly `8 * time.Second`; it governs both listener deadline and result timer.
- `LANProbeOnly` retains zero initial delay and its existing `5 * time.Second` timeout.
- All other TCP traversal retains its existing `25 * time.Second` timeout.
- A TCP server with `inSameLAN == false` and `LANProbeOnly == false` retains the exact two-second active-dial delay.
- Do not change route classification, role selection, LAN discovery wire format, MQTT synchronization, handshake, connection winner selection, CLI flags, or public APIs.
- Do not add MQTT to explicit LAN mode and do not pre-bind a traversal listener during LAN discovery.
- Do not modify or stage the existing user-owned changes in `apps/nc.go` or `apps/p2p_with_lan_test.go`.

---

## Resumed TDD State

Task 1 previously completed and recorded the first RED/GREEN cycle before the synchronization gap was diagnosed:

- `easyp2p/p2p_tcp_delay_test.go` was created and failed with `undefined: tcpActiveDialDelay` before production code changed.
- The uncommitted `tcpActiveDialDelay` implementation and its log/wait consumers make that focused test pass.
- With zero same-LAN delay, the existing cancellation and paired ownership regressions now fail deterministically with `all connection attempts failed`; this is the required RED evidence for the retry behavior.
- No implementation commit exists. Preserve this valid uncommitted work and continue TDD from it.

## File Structure

- Modify `easyp2p/p2p_tcp_delay_test.go` to retain the active-delay table and add the total-timeout policy table.
- Modify `easyp2p/p2p.go` to add `tcpTraversalTimeout`, apply duration-based deadlines, and retry only unsynchronized same-LAN direct dials.
- Modify only the timing comment in `easyp2p/lan.go` so it no longer claims the multicast handshake synchronizes listeners.
- Extend `easyp2p/p2p_context_test.go` with deterministic rejected-outbound and rejected-inbound candidate cases; retain its existing early-start cancellation and later-peer ownership regressions.

### Task 1: Complete Unsynchronized Same-LAN TCP Retry Handling

**Files:**
- Modify: `easyp2p/p2p_tcp_delay_test.go`
- Modify: `easyp2p/p2p.go:1738-2235`
- Modify comment only: `easyp2p/lan.go:803-814`
- Modify test: `easyp2p/p2p_context_test.go`

**Interfaces:**
- Consumes: `round int`, `isClient bool`, the local `inSameLAN bool`, and `P2PAddressInfo.LANProbeOnly bool`.
- Preserves: `func tcpActiveDialDelay(isClient, inSameLAN, lanProbeOnly bool) time.Duration`.
- Produces: `func tcpTraversalTimeout(round int, inSameLAN, lanProbeOnly bool) time.Duration`.
- Produces: internal constant `tcpUnsynchronizedSameLANRetryInterval = 250 * time.Millisecond`.
- Preserves: `Auto_P2P_TCP_NAT_Traversal(...) (net.Conn, bool, error)` without a signature change.

- [ ] **Step 1: Add the failing total-timeout policy test**

Retain `TestTCPActiveDialDelay` and append this complete test to `easyp2p/p2p_tcp_delay_test.go`:

```go
func TestTCPTraversalTimeout(t *testing.T) {
	tests := []struct {
		name         string
		round        int
		inSameLAN    bool
		lanProbeOnly bool
		want         time.Duration
	}{
		{
			name:      "unsynchronized same-LAN traversal uses eight seconds",
			inSameLAN: true,
			want:      8 * time.Second,
		},
		{
			name:         "LAN-probe-only keeps five seconds",
			inSameLAN:    true,
			lanProbeOnly: true,
			want:         5 * time.Second,
		},
		{
			name:      "synchronized same-LAN traversal keeps default",
			round:     1,
			inSameLAN: true,
			want:      25 * time.Second,
		},
		{
			name: "round zero non-LAN traversal keeps default",
			want: 25 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tcpTraversalTimeout(tt.round, tt.inSameLAN, tt.lanProbeOnly)
			if got != tt.want {
				t.Fatalf("tcpTraversalTimeout() = %s, want %s", got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run the focused policy tests and verify the new RED state**

Run:

```powershell
go test ./easyp2p -run '^(TestTCPActiveDialDelay|TestTCPTraversalTimeout)$' -count=1
```

Expected: build failure containing `undefined: tcpTraversalTimeout`. `TestTCPActiveDialDelay` was already observed RED before its helper existed and is now expected to compile.

- [ ] **Step 3: Implement and consume the total-timeout policy**

Next to `tcpActiveDialDelay` in `easyp2p/p2p.go`, add:

```go
const tcpUnsynchronizedSameLANRetryInterval = 250 * time.Millisecond

func tcpTraversalTimeout(round int, inSameLAN, lanProbeOnly bool) time.Duration {
	if lanProbeOnly {
		return 5 * time.Second
	}
	if round == 0 && inSameLAN {
		return 8 * time.Second
	}
	return 25 * time.Second
}
```

Replace the integer timeout initialization with:

```go
timeoutMax := tcpTraversalTimeout(round, inSameLAN, p2pInfo.LANProbeOnly)
timeoutPerconn := 6
```

Delete the later assignment that changes `timeoutMax` to `5` for `LANProbeOnly`; the helper now owns that existing policy. Change the listener deadline and result timer to consume the duration directly:

```go
deadline := time.Now().Add(timeoutMax)
```

```go
timer := time.NewTimer(timeoutMax)
```

- [ ] **Step 4: Format and verify the timeout-policy GREEN state**

Run:

```powershell
gofmt -w easyp2p/p2p.go easyp2p/p2p_tcp_delay_test.go
go test ./easyp2p -run '^(TestTCPActiveDialDelay|TestTCPTraversalTimeout)$' -count=1
```

Expected: `ok github.com/threatexpert/gonc/v2/easyp2p`.

- [ ] **Step 5 (superseded): Add a focused failing delayed-listener retry test**

First extend the existing test log writer so the test can observe when the first direct dial begins without using a long scheduling sleep:

```go
type readyLogWriter struct {
	once     sync.Once
	ready    chan struct{}
	dialOnce sync.Once
	dialing  chan struct{}
}

func newReadyLogWriter() *readyLogWriter {
	return &readyLogWriter{
		ready:   make(chan struct{}),
		dialing: make(chan struct{}),
	}
}

func (w *readyLogWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("Best Route")) {
		w.once.Do(func() {
			close(w.ready)
		})
	}
	if bytes.Contains(p, []byte("Trying direct dial")) {
		w.dialOnce.Do(func() {
			close(w.dialing)
		})
	}
	return len(p), nil
}
```

Then append this test to `easyp2p/p2p_context_test.go`. It starts one traversal, waits for its first outbound attempt while the target port is closed, confirms traversal remains alive, then starts a peer listener that never dials back; only an outbound retry can complete the handshake:

```go
func TestAutoP2PTCPTraversalRetriesUntilPeerListenerStarts(t *testing.T) {
	t.Setenv("ROLE_DEBUG", "C")

	localAddr, remoteAddr := reserveTCPAddrPair(t)
	info := loopbackP2PInfo(localAddr, remoteAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	result := make(chan traversalResult, 1)
	ready := newReadyLogWriter()
	go runTCPTraversal(ctx, info, ready, result)

	select {
	case <-ready.dialing:
	case <-time.After(2 * time.Second):
		t.Fatal("TCP traversal did not start its first direct dial")
	}

	time.Sleep(100 * time.Millisecond)
	select {
	case got := <-result:
		if got.conn != nil {
			_ = got.conn.Close()
		}
		t.Fatalf("traversal returned before peer listener started: %v", got.err)
	default:
	}

	peerListener, err := net.Listen("tcp4", remoteAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer peerListener.Close()
	if err := peerListener.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	peer, err := peerListener.Accept()
	if err != nil {
		t.Fatalf("retry did not reach delayed peer listener: %v", err)
	}
	defer peer.Close()

	payload := []byte(deriveKeyForPayload("tcp-context-test", false))
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(peer, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatal("retry connection sent an invalid handshake payload")
	}
	if _, err := peer.Write(payload); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-result:
		if got.err != nil {
			t.Fatalf("retried traversal failed: %v", got.err)
		}
		if got.conn == nil {
			t.Fatal("retried traversal returned a nil connection")
		}
		_ = got.conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("retried traversal did not return its connection")
	}
}
```

- [ ] **Step 6 (historical RED evidence): Reconfirm the behavioral RED state before adding retries**

Run:

```powershell
go test ./easyp2p -run '^(TestAutoP2PTCPTraversalRetriesUntilPeerListenerStarts|TestAutoP2PTCPTraversalCancellationClosesHandshakeCandidate|TestAutoP2PTCPTraversalSuccessfulOwnershipTransfer)$' -count=1
```

Expected before the retry loop is implemented: all three tests fail because traversal returns `P2P TCP hole punching failed: all connection attempts failed` before the delayed peer listener, cancellation, or second traversal can act. The two existing failures were already reproduced deterministically, including five consecutive ownership-test failures.

- [ ] **Step 7: Retry direct dialing only for unsynchronized same-LAN traversal**

After `lanProbeEnabled` and `activeDialDelay` are calculated, add the retry-mode predicate:

```go
unsynchronizedSameLAN := round == 0 && inSameLAN
```

Replace the current single direct-dial attempt inside the `inSameLAN || easy/easy` block with this loop. Keep the existing non-LAN fallback immediately after it:

```go
p2pLogf(logWriter, "  ↑ Trying direct dial to peer...\n")
for {
	select {
	case <-attemptCtx.Done():
		return
	case workerChan <- struct{}{}:
	}
	wg.Add(1)
	if tryConnect(remoteAddr, localAddr, true, timeoutPerconn, isClient, "dial") {
		return
	}
	triedDirectDial = true
	if !unsynchronizedSameLAN {
		break
	}
	if err := netx.WaitContext(attemptCtx, tcpUnsynchronizedSameLANRetryInterval); err != nil {
		return
	}
}
```

The complete surrounding branch must retain the existing non-LAN behavior:

```go
if !inSameLAN {
	if isClient {
		if err := netx.WaitContext(attemptCtx, 3*time.Second); err != nil {
			return
		}
		randomDstPort = true
	} else {
		randomSrcPort = true
	}
}
```

For `unsynchronizedSameLAN`, the loop exits only after commit or cancellation, so control never reaches the final `reportErr("all connection attempts failed")` while Accept remains viable. For all other routes, the loop executes once and preserves the existing terminal path.

- [ ] **Step 8 (superseded verification set): Verify retry, Accept lifetime, cancellation, and ownership transfer**

Run the two behavioral regressions repeatedly together with the policy tests:

```powershell
go test ./easyp2p -run '^(TestTCPActiveDialDelay|TestTCPTraversalTimeout|TestAutoP2PTCPTraversalRetriesUntilPeerListenerStarts|TestAutoP2PTCPTraversalCancellationClosesHandshakeCandidate|TestAutoP2PTCPTraversalSuccessfulOwnershipTransfer)$' -count=5
```

Expected: all five tests pass in all five repetitions. The delayed-listener test proves a later outbound retry succeeds without a reverse dial; the cancellation test proves the early peer remains alive after initial refusal and still returns `context.Canceled`; the ownership test proves the later peer can connect and both traversals transfer one winning connection.

- [ ] **Step 9: Correct the obsolete LAN timing comment and format**

Replace the `round=0` timing claim in `easyp2p/lan.go` with:

```go
// round=0 makes traversal skip Mqtt_P2P_Round_Sync because explicit LAN mode
// has no MQTT signal session. The multicast handshake authenticates and
// exchanges addresses, but it finishes before traversal binds TCP listeners.
// TCP traversal therefore retries round-0 same-LAN direct dials while keeping
// its accept path active.
```

Run:

```powershell
gofmt -w easyp2p/p2p.go easyp2p/p2p_tcp_delay_test.go easyp2p/p2p_context_test.go easyp2p/lan.go
git diff --check -- easyp2p/p2p.go easyp2p/p2p_tcp_delay_test.go easyp2p/p2p_context_test.go easyp2p/lan.go
```

Expected: no formatting or whitespace errors.

- [ ] **Step 10: Run package-wide and repository-wide verification**

Run:

```powershell
go test ./easyp2p -count=1
go test ./... -count=1
go vet ./easyp2p ./apps
git diff -- easyp2p/p2p.go easyp2p/p2p_tcp_delay_test.go easyp2p/p2p_context_test.go easyp2p/lan.go
```

Expected: all tests and vet commands pass. The diff contains only the two timing-policy helpers, their consumers, the unsynchronized same-LAN retry loop, focused policy tests, and the corrected LAN timing comment. The user-owned `apps` changes remain outside this diff.

- [ ] **Step 11: Commit only the implementation files**

Run:

```powershell
git add -- easyp2p/p2p.go easyp2p/p2p_tcp_delay_test.go easyp2p/p2p_context_test.go easyp2p/lan.go
git diff --cached --check
git diff --cached --name-only
git commit -m "fix: retry unsynchronized same-LAN TCP dialing"
```

Expected staged names before commit:

```text
easyp2p/lan.go
easyp2p/p2p.go
easyp2p/p2p_context_test.go
easyp2p/p2p_tcp_delay_test.go
```

After the commit, `apps/nc.go` and `apps/p2p_with_lan_test.go` remain modified and unstaged as user-owned work.
