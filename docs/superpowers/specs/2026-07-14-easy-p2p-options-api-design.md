# Easy P2P Options API Design

## Goal

Reduce the nine-argument `Easy_P2P_MPWithOptions` call to an API whose required inputs remain explicit and whose optional behavior is configured with named fields. Preserve the signatures and behavior of the already released `Easy_P2P` and `Easy_P2P_MP` entry points.

## Scope

This change reshapes the untagged `Easy_P2P_MPWithOptions` API, expands `EasyP2PMPOptions`, updates its one repository caller in `apps/nc.go`, and adds focused API tests. It does not change signaling, NAT traversal, relay selection, multipath behavior, LAN discovery, wire formats, or mobile bindings.

## Selected API

Keep the inputs that identify and control one operation as positional arguments, and move the remaining optional settings into a value-type options structure:

```go
type EasyP2PMPOptions struct {
	Bind                  string
	MultipathEnabled      bool
	RelayConn             *RelayPacketConn
	LogWriter             io.Writer
	Signal                *MQTTSignalSession
	OnAddressExchangeDone func()
}

func Easy_P2P_MPWithOptions(
	ctx context.Context,
	network string,
	sessionUID string,
	options EasyP2PMPOptions,
) (*P2PConnInfo, error)
```

`ctx`, `network`, and `sessionUID` remain explicit because they are required for every operation. The options argument is a value rather than a pointer so its zero value is directly usable and callers do not need a `nil` convention.

`network` retains its existing validation and has no new implicit default. An empty or unsupported value continues to return the existing unsupported-network error.

## Compatibility

The signatures of these released functions remain unchanged:

```go
func Easy_P2P(network, sessionUID string, relayConn *RelayPacketConn, logWriter io.Writer) (*P2PConnInfo, error)

func Easy_P2P_MP(ctx context.Context, network, bind, sessionUID string, multipathEnabled bool, relayConn *RelayPacketConn, logWriter io.Writer, signal *MQTTSignalSession) (*P2PConnInfo, error)
```

`Easy_P2P_MP` becomes a compatibility adapter that constructs `EasyP2PMPOptions` and calls the reshaped `Easy_P2P_MPWithOptions`. `Easy_P2P` continues to call `Easy_P2P_MP`, so existing users retain the same behavior and resource ownership.

`Easy_P2P_MPWithOptions` was introduced after the latest tag and has only one repository caller, so its signature can be changed directly without adding another transitional API.

## Option Semantics

- `Bind` preserves the current optional local bind address.
- `MultipathEnabled` preserves the legacy wrapper's behavior even though repository callers currently pass `false`.
- `RelayConn` remains an optional caller-owned relay transport. The callee does not acquire general ownership of it.
- `Signal` remains an optional caller-owned MQTT signaling session. When it is nil, the callee creates and closes its own session exactly as it does today; when it is non-nil, the callee does not close it.
- `LogWriter` receives diagnostics. A nil value is normalized to `io.Discard`, making the options zero value safe without changing non-nil logging behavior.
- `OnAddressExchangeDone` remains optional and fires at the existing point: after address exchange succeeds and before traversal attempts begin.

The callback remains a direct field. A nested hooks structure would add ceremony for a single event and is outside the current need.

## Call-Site Migration

The P2P path in `apps/nc.go` replaces its optional `*EasyP2PMPOptions` variable with a value. It assigns `OnAddressExchangeDone` only when candidate coordination requires it, then supplies `Bind`, `RelayConn`, `LogWriter`, and `Signal` as named fields when calling the new signature.

The port-rotation path continues to call the released `Easy_P2P_MP` compatibility entry point and needs no migration.

## Data Flow

```text
legacy Easy_P2P / Easy_P2P_MP caller
  -> compatibility wrapper builds EasyP2PMPOptions
  -> Easy_P2P_MPWithOptions

new caller
  -> required ctx/network/sessionUID + named EasyP2PMPOptions
  -> normalize nil LogWriter to io.Discard
  -> existing address exchange and traversal implementation
```

The reshaped entry point reads all behavior from the options value. The underlying address exchange and traversal calls receive the same values they receive before this refactor.

## Error Handling and Ownership

No new operational error class is introduced. Existing network validation, signaling, context cancellation, address exchange, and traversal errors retain their wrapping and propagation.

Normalizing a nil `LogWriter` avoids a nil-writer failure path. It does not suppress logs when the caller supplies a writer.

Resource ownership remains explicit in API documentation:

- internally created signaling sessions are closed by the callee;
- injected signaling sessions are not closed by the callee;
- relay connection cleanup remains the caller's responsibility under the existing success and failure rules.

## Testing

Add focused tests that:

1. Compile-check the unchanged signatures of `Easy_P2P` and `Easy_P2P_MP`.
2. Compile-check the new four-argument `Easy_P2P_MPWithOptions` signature.
3. Verify option normalization replaces a nil `LogWriter` with `io.Discard` while preserving every supplied option field.
4. Build all repository call sites after migrating `apps/nc.go`.
5. Run the existing `easyp2p`, `apps`, and full repository test suites to demonstrate that signaling, cancellation, and traversal behavior is unchanged.

The refactor must not require live MQTT, STUN, relay, or peer connectivity in its new unit tests.

## Non-Goals

- Renaming the underscore-style public functions.
- Removing the released compatibility functions.
- Implementing or removing multipath behavior.
- Adding defaults for `network` or `sessionUID`.
- Introducing functional options or a nested hook framework.
- Changing relay or signaling-session ownership.
- Modifying mobile or embedded public APIs.
