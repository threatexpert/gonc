# P2P Role Sync Candidate Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ensure both peers select mirrored `LANProbeOnly` candidates before MQTT round synchronization, including compatibility with peers that implement the legacy first-match selection.

**Architecture:** Extract the existing base candidate construction into a pure helper that retains every eligible LAN-only candidate instead of discarding all but the first. Select one candidate either with a direction-independent canonical key when the peer advertises `lan-probe-canonical-v2`, or by reproducing the legacy peer's remote-first traversal order when it only advertises `lan-probe`.

**Tech Stack:** Go, existing `easyp2p` package tests, MQTT capability strings carried in `exchangeAddressPayload.Caps`.

## Global Constraints

- Modify the current `main` working tree as explicitly approved by the user.
- Preserve the pre-existing `apps/nc.go` version change.
- Do not modify the separate LAN probe early-failure race in this task.
- Do not change MQTT topics, encryption, synchronization payloads, or public APIs.
- Do not create a commit; leave the working tree ready for user review.

---

### Task 1: Canonical LAN-only candidate selection

**Files:**
- Modify: `easyp2p/lan_probe.go`
- Modify: `easyp2p/p2p.go`
- Create: `easyp2p/p2p_candidate_test.go`

**Interfaces:**
- Produces: `CapCanonicalLANProbe`
- Produces: `lanProbeCandidate`
- Produces: `buildBaseP2PCandidates(localAddresses, remoteAddresses []PunchingAddressInfo, peerSupportsLANProbe bool)`
- Produces: `selectLANProbeCandidate(candidates []lanProbeCandidate, peerSupportsCanonical bool) *P2PAddressInfo`

- [x] **Step 1: Write the failing multi-exit regression test**

Create address lists matching the reported incident:

```go
localA := []PunchingAddressInfo{
    {Network: "tcp4", Lan: "10.192.156.114:64568", Nat: "106.39.145.5:43320", NatType: "hard"},
    {Network: "tcp4", Lan: "10.192.156.114:64568", Nat: "223.71.76.129:3336", NatType: "symm"},
}
localB := []PunchingAddressInfo{
    {Network: "tcp4", Lan: "10.192.156.114:64571", Nat: "106.39.145.5:40070", NatType: "symm"},
    {Network: "tcp4", Lan: "10.192.156.114:64571", Nat: "223.71.76.129:30144", NatType: "hard"},
}
```

Build candidates from both directions, select with canonical mode, assert that the selected candidates are exact mirrors and that `SelectRole` returns opposite roles.

- [x] **Step 2: Run the regression test to verify RED**

Run:

```powershell
go test ./easyp2p -run TestCanonicalLANProbeSelectionKeepsPeerRolesComplementary -count=1
```

Expected: compilation fails because the pure candidate builder and selector do not exist.

- [x] **Step 3: Implement collection and canonical selection**

Add `CapCanonicalLANProbe = "lan-probe-canonical-v2"` and advertise it with `CapLANProbe`.

Extract the nested candidate-building loop from `Do_autoP2PEx2` into:

```go
type lanProbeCandidate struct {
    info        *P2PAddressInfo
    localOrder  int
    remoteOrder int
}
```

Retain all eligible LAN-only candidates. Select the lexicographically smallest key formed from the network and two sorted endpoint descriptors:

```text
network NUL min(natType|lan|nat) NUL max(natType|lan|nat)
```

Append only the selected candidate to `finalResults` before empty-result validation and existing multipath filtering.

- [x] **Step 4: Run the regression test to verify GREEN**

Run:

```powershell
go test ./easyp2p -run TestCanonicalLANProbeSelectionKeepsPeerRolesComplementary -count=1
```

Expected: PASS.

### Task 2: Legacy peer compatibility

**Files:**
- Modify: `easyp2p/p2p.go`
- Modify: `easyp2p/p2p_candidate_test.go`

**Interfaces:**
- Consumes: `lanProbeCandidate`
- Consumes: `selectLANProbeCandidate`
- Produces: legacy selection ordered by `remoteOrder`, then `localOrder`

- [x] **Step 1: Write the failing legacy compatibility test**

Using the same incident address lists, select from A's candidates with canonical mode disabled. Assert that A chooses `A2 ↔ B1`, which is the mirror of the first candidate selected by legacy B's local-first traversal.

- [x] **Step 2: Run the legacy test to verify RED**

Run:

```powershell
go test ./easyp2p -run TestLANProbeSelectionMirrorsLegacyPeerTraversal -count=1
```

Expected: FAIL because non-canonical selection does not yet reproduce the peer's traversal order.

- [x] **Step 3: Implement legacy peer traversal selection**

When `peerSupportsCanonical` is false, select the candidate with the lowest `remoteOrder`; break ties with `localOrder`. This mirrors the old peer's outer-local/inner-remote traversal because the peer's local list is the new side's remote list.

- [x] **Step 4: Run focused and package tests**

Run:

```powershell
go test ./easyp2p -run "TestCanonicalLANProbeSelectionKeepsPeerRolesComplementary|TestLANProbeSelectionMirrorsLegacyPeerTraversal" -count=1
go test ./easyp2p -count=1
```

Expected: PASS.

### Task 3: Verification and scope audit

**Files:**
- Verify: `easyp2p/lan_probe.go`
- Verify: `easyp2p/p2p.go`
- Verify: `easyp2p/p2p_candidate_test.go`

**Interfaces:**
- Consumes: completed candidate selection behavior
- Produces: verified working-tree changes for user review

- [x] **Step 1: Format modified Go files**

Run:

```powershell
gofmt -w easyp2p/lan_probe.go easyp2p/p2p.go easyp2p/p2p_candidate_test.go
```

- [x] **Step 2: Run full repository tests**

Run:

```powershell
go test ./... -count=1
```

Expected: PASS.

- [x] **Step 3: Audit the diff**

Run:

```powershell
git status --short
git diff --check
git diff -- easyp2p/lan_probe.go easyp2p/p2p.go easyp2p/p2p_candidate_test.go
```

Expected: no whitespace errors, no changes to the LAN probe timeout/failure coordinator, and the pre-existing `apps/nc.go` change remains untouched.
