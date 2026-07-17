# Immediate TCP Dialing on Same-LAN Routes Design

## Goal

Remove the two-second server-side active-dial stagger whenever TCP P2P traversal selects a same-LAN route. Both roles may begin outbound TCP connection attempts immediately while the existing listener continues accepting inbound connections from the start.

## Scope

This change applies to `Auto_P2P_TCP_NAT_Traversal` when its existing route selection sets `inSameLAN` to true. It therefore covers:

- explicit `-lan` mode;
- explicit `-lan-passive` mode;
- the LAN candidate in `-p2p-with-lan` mode; and
- ordinary `-p2p` when address comparison determines that both peers are on the same LAN.

This deliberately supersedes the earlier narrower scope that would have preserved the delay for ordinary `-p2p`. The user selected the broader same-LAN behavior.

UDP P2P timing, non-LAN TCP traversal, role selection, the LAN discovery wire protocol, MQTT round synchronization, and connection authentication remain unchanged.

## Current Behavior

TCP traversal starts its listener and accept loop immediately for both roles. The selected client role also begins outbound dialing immediately. The selected server role waits two seconds before outbound dialing unless `LANProbeOnly` is set.

Consequently, a same-LAN server can accept an incoming connection immediately but does not initiate its own direct-LAN connection attempt during the first two seconds.

Normal STUN/MQTT P2P attempts increment `round` before entering traversal, so their first round is `1`. TCP traversal binds its listener before `Mqtt_P2P_Round_Sync`; receiving the peer's round message therefore acts as a post-listen readiness barrier.

Explicit LAN traversal passes `round == 0` and has no MQTT signal session. Its multicast discovery handshake exchanges and authenticates addresses, but it completes before traversal creates either TCP listener. The initiator can return on the first ACK while the responder is still retransmitting ACKs, so the two peers may enter traversal hundreds of milliseconds apart.

## Selected Approach

Use the existing `inSameLAN` route decision directly. A TCP active-dial delay policy will return zero when any of the following is true:

- this side has the client role;
- `inSameLAN` is true; or
- `LANProbeOnly` is true, preserving its existing immediate behavior.

Only a server on a route that is not considered same-LAN and is not `LANProbeOnly` retains the two-second delay.

No new mode flag or `P2PAddressInfo` field is introduced. This is intentional: the chosen behavior is based on the selected route, not on which CLI or discovery path produced the candidate.

Treat `round == 0 && inSameLAN` as an unsynchronized same-LAN traversal. It starts its first direct dial immediately, retains the concurrent accept path, and retries failed direct dials every 250 milliseconds. A failed individual dial is not terminal in this mode. Retrying continues until a connection commits, the parent context is canceled, or the mode's eight-second total traversal timeout expires.

Same-LAN attempts with `round > 0` retain the normal single direct-dial sequence and error convergence because MQTT round synchronization has already established peer readiness. `LANProbeOnly` retains its existing dedicated behavior and five-second timeout.

## Delay Policy

Add a small internal helper, conceptually:

```go
func tcpActiveDialDelay(isClient, inSameLAN, lanProbeOnly bool) time.Duration {
	if isClient || inSameLAN || lanProbeOnly {
		return 0
	}
	return 2 * time.Second
}
```

Calculate the delay once after route and role selection. Use the same value for both:

- the `Active Mode` / `Passive Mode` status log; and
- the context-aware wait at the beginning of `doPunching`.

Sharing the policy prevents the displayed timing from diverging from the actual timing.

## Timeout Policy

Centralize the TCP traversal timeout policy in an internal helper:

```go
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

The returned duration controls both the listener deadline and the traversal result timer. `LANProbeOnly` takes precedence defensively, although production candidates do not combine it with an already selected same-LAN route.

## Connection Flow

For a same-LAN TCP candidate:

```text
select client/server roles
  -> select the existing same-LAN route
  -> start listener and accept loop
  -> both roles start outbound direct-LAN dialing immediately
  -> if round is zero and a direct dial fails, wait 250ms and retry
  -> first authenticated successful connection wins
  -> cancel traversal attempt and close losing connections
```

The change does not close or delay the listener. In unsynchronized same-LAN mode, outbound failure does not close the listener or send `all connection attempts failed`; the accept and retry paths remain viable for the full eight-second window.

## Concurrent-Connection Behavior

Without the stagger, both same-LAN peers can establish crossed TCP connections at nearly the same time. This is an accepted consequence of the selected approach.

The traversal already arbitrates concurrent accept and dial results through its single-commit path. The first connection successfully committed is returned, attempt cancellation stops remaining work, and connections that lose the race are closed. This existing ownership behavior is not redesigned by this change.

## Logging

For both roles on a same-LAN route, the timing line reports immediate start. Non-LAN server routes continue to report a two-second delayed start.

Representative same-LAN server output:

```text
  - Passive Mode  : connect start immediately
```

`LANProbeOnly` logging and its five-second traversal timeout remain unchanged.

## Error and Cancellation Handling

The initial zero-delay path performs no wait. The two-second public-path stagger and the 250-millisecond same-LAN retry interval both use `netx.WaitContext`, so cancellation interrupts either wait promptly.

For `round == 0 && inSameLAN`, connection refusal, handshake failure, or another failed outbound attempt returns to the retry loop. These failures do not enter `errChan` while the accept path is still viable. Success cancels the retry loop through the existing commit path. Parent cancellation returns its existing cause. If neither direction succeeds, the existing timeout result is returned after eight seconds.

All other routes retain their existing `all connection attempts failed` reporting, accept behavior, cleanup, and timeout values.

## Testing

Add focused table-driven tests for the delay policy:

1. Client role, non-LAN route: zero delay.
2. Server role, same-LAN route: zero delay.
3. Server role, `LANProbeOnly`: zero delay.
4. Server role, non-LAN and not `LANProbeOnly`: two-second delay.

Add timeout-policy cases covering:

1. `round == 0 && inSameLAN`: eight seconds.
2. `LANProbeOnly`: five seconds.
3. Every other TCP traversal: twenty-five seconds.

Use the existing TCP cancellation regression to prove an unsynchronized same-LAN traversal survives initial connection refusal and returns the parent cancellation instead of `all connection attempts failed`. Use the existing paired ownership regression to prove the first peer remains alive until the later peer starts, after which one authenticated connection wins. Run the focused tests repeatedly, the `easyp2p` package tests, and the full repository suite.

## Non-Goals

- Changing the UDP server's two-second PING stagger.
- Removing the TCP stagger for public or otherwise non-LAN routes.
- Adding a new CLI flag or public API option.
- Changing `LANProbeOnly` selection or timeout behavior.
- Changing how `CompareP2PAddresses` decides `sameNAT` and `similarLAN`.
- Redesigning winner selection when accept and dial succeed concurrently.
- Adding MQTT as a dependency of explicit LAN mode.
- Changing the LAN discovery wire format or pre-binding a traversal listener during discovery.
