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

UDP P2P timing, non-LAN TCP traversal, role selection, LAN discovery, MQTT round synchronization, and connection authentication remain unchanged.

## Current Behavior

TCP traversal starts its listener and accept loop immediately for both roles. The selected client role also begins outbound dialing immediately. The selected server role waits two seconds before outbound dialing unless `LANProbeOnly` is set.

Consequently, a same-LAN server can accept an incoming connection immediately but does not initiate its own direct-LAN connection attempt during the first two seconds.

## Selected Approach

Use the existing `inSameLAN` route decision directly. A TCP active-dial delay policy will return zero when any of the following is true:

- this side has the client role;
- `inSameLAN` is true; or
- `LANProbeOnly` is true, preserving its existing immediate behavior.

Only a server on a route that is not considered same-LAN and is not `LANProbeOnly` retains the two-second delay.

No new mode flag or `P2PAddressInfo` field is introduced. This is intentional: the chosen behavior is based on the selected route, not on which CLI or discovery path produced the candidate.

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

## Connection Flow

For a same-LAN TCP candidate:

```text
select client/server roles
  -> select the existing same-LAN route
  -> start listener and accept loop
  -> both roles start outbound direct-LAN dialing immediately
  -> first authenticated successful connection wins
  -> cancel traversal attempt and close losing connections
```

The change does not close or delay the listener. It only removes the wait before the server role's outbound dialing goroutine proceeds.

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

The zero-delay path performs no wait. The two-second path continues to use `netx.WaitContext`, so cancellation during the stagger exits promptly. Dial, accept, commit, cleanup, and error reporting retain their existing behavior.

## Testing

Add focused table-driven tests for the delay policy:

1. Client role, non-LAN route: zero delay.
2. Server role, same-LAN route: zero delay.
3. Server role, `LANProbeOnly`: zero delay.
4. Server role, non-LAN and not `LANProbeOnly`: two-second delay.

Retain or add a regression case demonstrating that ordinary candidates classified as same-LAN use zero delay regardless of whether they originated from explicit LAN discovery. Run the `easyp2p` package tests and the broader repository test suite appropriate to the affected code.

## Non-Goals

- Changing the UDP server's two-second PING stagger.
- Removing the TCP stagger for public or otherwise non-LAN routes.
- Adding a new CLI flag or public API option.
- Changing `LANProbeOnly` selection or timeout behavior.
- Changing how `CompareP2PAddresses` decides `sameNAT` and `similarLAN`.
- Redesigning winner selection when accept and dial succeed concurrently.
