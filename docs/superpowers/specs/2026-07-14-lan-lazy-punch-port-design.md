# LAN Lazy Punch-Port Selection Design

## Goal

Delay punch-port selection in both `-lan` and `-lan-passive` modes until an authenticated peer has been discovered. This removes the unnecessary port selection performed while LAN discovery is idle while keeping the existing short, accepted race between checking that a port is free and the traversal code binding it.

## Scope

This change applies to the shared LAN discovery implementation used by active and passive modes. It changes only LAN discovery and its tests. The TCP and UDP traversal implementations remain unchanged, and no socket or listener is pre-bound during discovery.

Public API compatibility is not a requirement, but no public API change is needed for this design. Internal function signatures may change where they currently accept a fixed `punchPort int`.

## Selected Approach

Remove the eager `GetFreePort()` call at the beginning of `lanDiscover`. Create one concurrency-safe lazy punch-port selector for each `lanDiscover` invocation and share it between the initiator and responder workers.

The selector calls `GetFreePort()` at most once:

- The responder first requests the port after receiving and validating a matching Beacon, and before constructing its Response.
- The initiator first requests the port after receiving and validating the matching Response, and before constructing its Confirm.
- If both workers reach this point concurrently, both receive the same port or the same allocation error.
- If no authenticated peer message arrives, `GetFreePort()` is never called.

The selected integer remains a candidate rather than a reservation. The current traversal code binds it after discovery completes. This deliberately accepts a short time-of-check/time-of-use window in exchange for avoiding pre-bound-resource ownership and handoff complexity.

## Components

### Lazy selector

Add an internal helper in `easyp2p/lan.go`, conceptually:

```go
type lanPunchPortSelector struct {
	once sync.Once
	port int
	err  error
}

func (s *lanPunchPortSelector) Get() (int, error) {
	s.once.Do(func() {
		s.port, s.err = GetFreePort()
	})
	return s.port, s.err
}
```

The production selector may accept an injected allocation function so tests can count and control allocations without depending on the operating system's ephemeral-port behavior. The default allocator is `GetFreePort`.

### Discovery orchestration

`lanDiscover` constructs one selector after setting up its context and passes the same selector to `lanInitiator` and `lanResponder`. It no longer selects a port before multicast setup and no longer includes `punchPort` in the initial multicast status line.

### Initiator

The initiator continues broadcasting Beacons without a punch port. After accepting the Response whose nonce matches its own Beacon, it determines the local IP and negotiated transport, then requests the shared candidate port. If allocation succeeds, it includes that port in Confirm and eventually in `LANDiscoverResult`.

### Responder

The responder does not allocate for malformed messages, messages with a different session ID, self-originated messages, messages without a usable source IP, or messages for which a local route cannot be selected. After those checks pass, it requests the shared candidate port and includes it in Response and eventually in `LANDiscoverResult`.

## Concurrency Invariant

Initiator and responder run concurrently and may both complete valid handshakes when two peers start at the same time. They must not independently select different local ports: one process could finish as initiator while its peer finishes as initiator, causing each side to use a port advertised by the locally cancelled responder path.

Sharing one `sync.Once`-protected selector preserves the existing invariant that every handshake path within one LAN discovery invocation advertises the same local punch port.

## Discovery-Round Lifetime

One `lanDiscover` invocation produces at most one connection. It does not concurrently admit multiple clients. The selector therefore belongs to that single discovery round:

- Retransmissions and the concurrent initiator/responder paths within the round reuse its one candidate port.
- A valid handshake that later times out may resume discovery within the same round and continue using that candidate.
- After a connection succeeds, `lanDiscover` returns and the selector is discarded.
- In passive keep-open mode, the application starts a new `lanDiscover` invocation for the next client; that new round creates a new selector and chooses a new candidate after its first authenticated peer message.

Existing established connections may run concurrently at the application layer, but new-client discovery remains one round at a time.

## Data Flow

```text
Start active/passive LAN discovery
  -> bind multicast discovery endpoint only
  -> send/listen for authenticated discovery messages
  -> receive first valid peer Beacon or Response
  -> shared selector calls GetFreePort once
  -> put candidate port in Response or Confirm
  -> complete four-message discovery handshake
  -> return the same candidate in LANDiscoverResult
  -> existing TCP/UDP traversal code binds that candidate
```

## Logging

The initial line reports only multicast state:

```text
[LAN] Multicast 239.255.255.250:19730, 2 ifaces
```

When the selector actually runs, log the selected candidate once:

```text
[LAN] Selected punchPort=36921 after authenticated peer discovery
```

The wording must not imply that the port is already bound or listening.

## Error Handling

If `GetFreePort()` fails, every caller of the shared selector receives the same error. The relevant worker returns an error wrapped with LAN punch-port context, and discovery terminates according to its existing worker/error handling.

No cleanup is required for the selector because `GetFreePort()` closes its probe sockets before returning. Context cancellation and multicast cleanup remain unchanged.

The residual race is intentional: another process may occupy the candidate before traversal binds it. Normally this window begins only after a valid peer appears and lasts through the remaining discovery handshake. A stalled authenticated handshake can make it longer, up to the current discovery timeout. Binding failures continue to be reported by the existing traversal code.

## Testing

Add focused tests covering:

1. Constructing and waiting in LAN discovery does not invoke the port allocator before a valid peer message.
2. Concurrent calls to the selector invoke its allocator exactly once and return the same port.
3. An allocator failure is invoked once and returned consistently to all callers.
4. Initiator allocation occurs only after a nonce-matching valid Response.
5. Responder allocation occurs only after session, self-filter, source-address, and route checks pass.
6. Response, Confirm, and `LANDiscoverResult.LocalPort` use the shared selected port.
7. The existing LAN transport negotiation, multicast, active/passive flag, and package test suites continue to pass.

## Non-Goals

- Reserving the candidate port during discovery.
- Passing a pre-bound UDP socket or TCP listener into traversal.
- Changing TCP or UDP hole-punching behavior.
- Retrying the entire discovery exchange after a later bind collision.
- Changing the LAN discovery wire format.
