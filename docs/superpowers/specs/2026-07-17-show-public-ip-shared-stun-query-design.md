# ShowPublicIP Shared STUN Query Design

## Goal

Remove the duplicate `GetPublicIP` query implementation and make the `-stun`
display path use the existing `GetPublicIPs` implementation.

## API Changes

- Delete exported `easyp2p.GetPublicIP`.
- Delete exported `easyp2p.GetPublicIPContext`.
- Do not change the signatures or collection behavior of `GetPublicIPs` and
  `GetPublicIPsContext`.

This is an intentional breaking API change. The repository has no production
caller other than `ShowPublicIP`.

## ShowPublicIP Behavior

`apps.ShowPublicIP` calls:

```go
results, err := easyp2p.GetPublicIPs(network, bind, 3500*time.Millisecond, false, nil)
```

The STUN requests remain concurrent. The operation returns when all matching
requests finish or the 3500 ms timeout expires. `ShowPublicIP` scans the
returned slice in collection order and selects the first item whose `Err` is
nil and whose `Nat` is non-empty.

On success it preserves the current output format:

```text
Public Address: <nat-address> (via <configured-stun-server>)
```

The server name is selected with the successful result's `Index` after bounds
validation.

## Error Handling

- If `GetPublicIPs` returns a non-nil top-level error, return it.
- If the result slice contains no successful item, return a descriptive error
  even when the top-level error is nil. This is required because
  `GetPublicIPs` may return per-server failures in the result slice.
- Ignore individual failed entries when at least one valid success exists.
- Reject an out-of-range successful result index instead of indexing
  `STUNServers` unsafely.

## Resource Lifetime

All STUN clients and connections continue to be owned and closed by
`GetPublicIPs`. The P2P-specific TCP `SetLinger(0)` behavior remains unchanged.
`ShowPublicIP` does not receive or retain any connection object.

## Tests

- Replace the `GetPublicIPContext` successful-TCP-close test with an equivalent
  `GetPublicIPs` resource-lifetime test where applicable.
- Remove `GetPublicIPContext` cancellation assertions.
- Add `ShowPublicIP` tests for selecting a successful result among failures and
  returning an error when all results fail.
- Run the STUN/context tests, `apps` tests, and `go test ./...`.
