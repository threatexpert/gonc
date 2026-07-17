# ShowPublicIP Shared STUN Query Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `ShowPublicIP` reuse `GetPublicIPs` with a 3500ms total timeout, select one successful result, and remove the redundant exported `GetPublicIP` and `GetPublicIPContext` APIs.

**Architecture:** Keep `GetPublicIPs` unchanged as the sole STUN query implementation. Add a small application-layer selector that validates and returns the first usable result from the collected results. Move the existing successful-TCP-connection cleanup coverage to the plural API before deleting the singular implementation.

**Tech Stack:** Go, Pion STUN, standard `testing` package.

## Global Constraints

- Do not change the signature or collection semantics of `GetPublicIPs`.
- Use exactly `3500*time.Millisecond` as the total `ShowPublicIP` STUN timeout.
- Delete exported `GetPublicIP` and `GetPublicIPContext`; this breaking API removal is explicitly approved.
- Preserve the existing `ShowPublicIP` success output format.
- Preserve `GetPublicIPs` connection cleanup, context handling, STUN validation, and TCP `SetLinger(0)` behavior.
- Preserve unrelated and already-present context/MQTT work in the dirty worktree.
- Inspect staged diffs before any commit because the touched STUN files already contain approved uncommitted changes.

---

### Task 1: Migrate `ShowPublicIP` to the shared plural query

**Files:**
- Modify: `apps/nc.go:3338`
- Create: `apps/stun_test.go`

- [ ] **Step 1: Write failing result-selection tests**

Create `apps/stun_test.go` with focused unit tests for the application-layer selection policy:

```go
package apps

import (
	"errors"
	"testing"

	"github.com/threatexpert/gonc/v2/easyp2p"
)

func TestFirstSuccessfulSTUNResultSkipsFailures(t *testing.T) {
	want := &easyp2p.STUNResult{Index: 1, Nat: "203.0.113.10:45678"}
	results := []*easyp2p.STUNResult{
		{Index: 0, Err: errors.New("server unavailable")},
		want,
	}

	got, err := firstSuccessfulSTUNResult(results)
	if err != nil {
		t.Fatalf("firstSuccessfulSTUNResult returned error: %v", err)
	}
	if got != want {
		t.Fatalf("firstSuccessfulSTUNResult returned %#v, want %#v", got, want)
	}
}

func TestFirstSuccessfulSTUNResultRejectsAllFailures(t *testing.T) {
	results := []*easyp2p.STUNResult{
		nil,
		{Index: 0, Err: errors.New("server unavailable")},
		{Index: 1},
	}

	if _, err := firstSuccessfulSTUNResult(results); err == nil {
		t.Fatal("firstSuccessfulSTUNResult returned nil error")
	}
}

func TestFirstSuccessfulSTUNResultRejectsInvalidServerIndex(t *testing.T) {
	results := []*easyp2p.STUNResult{
		{Index: len(easyp2p.STUNServers), Nat: "203.0.113.10:45678"},
	}

	if _, err := firstSuccessfulSTUNResult(results); err == nil {
		t.Fatal("firstSuccessfulSTUNResult returned nil error")
	}
}
```

- [ ] **Step 2: Run the new test and confirm the expected failure**

Run:

```powershell
go test ./apps -run FirstSuccessfulSTUNResult -count=1
```

Expected: build fails because `firstSuccessfulSTUNResult` is undefined.

- [ ] **Step 3: Implement the selector and migrate `ShowPublicIP`**

Add this helper near `ShowPublicIP` in `apps/nc.go`:

```go
func firstSuccessfulSTUNResult(results []*easyp2p.STUNResult) (*easyp2p.STUNResult, error) {
	var failures []error
	for _, result := range results {
		if result == nil {
			continue
		}
		if result.Err != nil {
			failures = append(failures, result.Err)
			continue
		}
		if result.Nat == "" {
			failures = append(failures, fmt.Errorf("STUN server %d returned an empty public address", result.Index))
			continue
		}
		if result.Index < 0 || result.Index >= len(easyp2p.STUNServers) {
			return nil, fmt.Errorf("STUN result server index %d is out of range", result.Index)
		}
		return result, nil
	}
	if len(failures) > 0 {
		return nil, fmt.Errorf("all STUN servers failed: %w", errors.Join(failures...))
	}
	return nil, fmt.Errorf("no STUN results returned")
}
```

Replace the singular call inside `ShowPublicIP` with:

```go
results, err := easyp2p.GetPublicIPs(network, bind, 3500*time.Millisecond, false, nil)
if err != nil {
	return err
}
result, err := firstSuccessfulSTUNResult(results)
if err != nil {
	return err
}
```

Use `result.Nat`, `result.Local`, and `easyp2p.STUNServers[result.Index]` in the existing logger call so its text and fields remain unchanged. `apps/nc.go` already imports `errors`, `fmt`, and `time`; do not add duplicate imports.

- [ ] **Step 4: Format and run focused tests**

Run:

```powershell
gofmt -w apps/nc.go apps/stun_test.go
go test ./apps -run 'FirstSuccessfulSTUNResult|ShowPublicIP' -count=1
```

Expected: tests pass.

- [ ] **Step 5: Review the application diff**

Run:

```powershell
git diff -- apps/nc.go apps/stun_test.go
```

Confirm the timeout is exactly 3500ms, collection order determines the selected success, invalid indices cannot reach the logger lookup, and the output format is unchanged.

---

### Task 2: Remove the redundant singular STUN API

**Files:**
- Modify: `easyp2p/stun.go:48-267`
- Modify: `easyp2p/stun_test.go`

- [ ] **Step 1: Move successful TCP cleanup coverage to `GetPublicIPs`**

Rename `TestGetPublicIPContextClosesSuccessfulTCPConnection` to `TestGetPublicIPsClosesSuccessfulTCPConnection` and replace its singular invocation/assertions with:

```go
results, err := GetPublicIPs("tcp4", ":0", 2*time.Second, false, nil)
if err != nil {
	t.Fatalf("GetPublicIPs returned error: %v", err)
}
if len(results) != 1 {
	t.Fatalf("GetPublicIPs returned %d results, want 1", len(results))
}
if results[0].Err != nil {
	t.Fatalf("GetPublicIPs result error: %v", results[0].Err)
}
if results[0].Nat != "203.0.113.10:45678" {
	t.Fatalf("GetPublicIPs returned NAT address %q", results[0].Nat)
}
```

Keep the server-side EOF assertion. It proves the remaining production implementation closes a successful TCP STUN connection.

Remove the `single public IP` subtest from `TestNATDiscoveryContextCancellationPropagates`; the plural and NAT-detection cancellation cases continue to cover live exported behavior.

- [ ] **Step 2: Run the migrated cleanup test before deleting code**

Run:

```powershell
gofmt -w easyp2p/stun_test.go
go test ./easyp2p -run 'GetPublicIPsClosesSuccessfulTCPConnection|NATDiscoveryContextCancellationPropagates' -count=1
```

Expected: tests pass against the existing `GetPublicIPs` implementation.

- [ ] **Step 3: Delete both exported singular implementations**

Delete the complete `GetPublicIP` and `GetPublicIPContext` function bodies and their comments from `easyp2p/stun.go`. Do not alter `GetPublicIPs`, `GetPublicIPsContext`, or their helpers.

- [ ] **Step 4: Prove no singular production references remain**

Run:

```powershell
rg -n 'GetPublicIP(Context)?\(' -g '*.go'
```

Expected: no matches.

- [ ] **Step 5: Run focused STUN and application tests**

Run:

```powershell
gofmt -w easyp2p/stun.go easyp2p/stun_test.go
go test ./easyp2p ./apps -count=1
```

Expected: both packages pass.

- [ ] **Step 6: Inspect the complete affected diff before staging**

Run:

```powershell
git diff -- apps/nc.go apps/stun_test.go easyp2p/stun.go easyp2p/stun_test.go
```

Confirm the deletion does not accidentally revert the already-approved context propagation and TCP cleanup work. If committing, stage only after this review; these files contain earlier approved changes as well as this task's changes.

---

### Task 3: Verify repository-wide behavior and API removal

**Files:**
- Verify only; no planned modifications.

- [ ] **Step 1: Run the complete test suite**

Run:

```powershell
go test ./... -count=1
```

Expected: all tests pass.

- [ ] **Step 2: Run static analysis**

Run:

```powershell
go vet ./...
```

Expected: no new warnings. The pre-existing `mobilegonc/source.go:22` `Seek` signature warning may remain and is outside this task.

- [ ] **Step 3: Check patch hygiene and exported API removal**

Run:

```powershell
git diff --check
rg -n 'GetPublicIP(Context)?\(' -g '*.go'
git status --short
```

Expected: `git diff --check` succeeds, the singular API search has no matches, and status contains only intended files plus previously known dirty changes.

- [ ] **Step 4: Review final changes**

Run:

```powershell
git diff --stat
git diff -- apps/nc.go apps/stun_test.go easyp2p/stun.go easyp2p/stun_test.go
```

Confirm all approved outcomes are present: shared plural query, 3500ms total timeout, one valid displayed result, singular APIs removed, and connection cleanup still tested.

- [ ] **Step 5: Commit only with explicit user approval**

Because implementation files include earlier uncommitted context/MQTT work, do not create an implementation commit implicitly. If the user requests a commit, inspect the staged diff and use a message such as:

```powershell
git commit -m "refactor: consolidate public IP STUN queries"
```
