# Seccomp On-Block FD Ownership — Design Spec

**Date:** 2026-04-20
**Status:** Approved
**Author:** design session between Eran Sandler and Codex

## Problem

The post-merge `main` integration job is still flaky after the container-start
retry work. The remaining failure is in
`internal/integration/seccomp_onblock_test.go`, specifically
`TestSeccompOnBlock_LogAndKill`.

The observed failure pair is:

- wrapper side: `ACK handshake failed: expected 1 ACK byte, got 0`
- test side: `ACK: invalid argument` or `RecvFD: bad file descriptor`

This is not a product-path seccomp failure. It is a descriptor ownership bug in
the integration test helper `startWrappedChild`.

## Goal

Fix the root cause in the integration helper by making socket ownership
unambiguous during the notify-fd handoff and ACK exchange, so the
`log_and_kill` integration path is stable under GC pressure and CI load.

## Non-Goals

- Do not change runtime product behavior in `agentsh-unixwrap`,
  `internal/cli/wrap_linux.go`, or server notify handling.
- Do not change the fd-passing API in `internal/netmonitor/unix/fdpass.go`
  unless the local refactor proves insufficient.
- Do not broaden this work into unrelated integration flake cleanup.

## Root Cause

`startWrappedChild` creates a socketpair as raw integer fds, then mixes those
ints with `*os.File` wrappers that refer to the same underlying descriptors.

Current pattern:

- keep `parentFD` as a raw int
- create `parentEnd := os.NewFile(uintptr(parentFD), "parent-end")`
- pass `parentEnd` to `unixmon.RecvFD`
- write the ACK using `unix.Write(parentFD, []byte{1})`

That split ownership is unsafe because `parentEnd` owns the same descriptor as
`parentFD`. Once `parentEnd` becomes unreachable, its finalizer may close the fd
before the raw-int ACK write runs. Under GC pressure this produces exactly the
observed failures:

- the ACK write can hit a closed or recycled descriptor and return
  `EINVAL` / `EBADF`
- the wrapper then sees EOF while waiting for the ACK and aborts the handshake

This explains why the failure is intermittent and why it becomes reproducible
with aggressive GC settings.

## Recommended Design

### 1. Refactor `startWrappedChild` to use single-owner `*os.File` handles

Immediately wrap each socketpair end in `*os.File` and treat that wrapper as the
only owner for reads, writes, and close operations.

Concretely:

- replace the raw-int `parentFD` / `childFD` usage with `parentEnd` and
  `childEnd` handles
- use `parentEnd` for both `unixmon.RecvFD` and the ACK write
- stop mixing raw `unix.Write` calls with a short-lived `os.NewFile` wrapper for
  the same descriptor

This mirrors the safer ownership pattern already used in
`internal/cli/wrap_linux.go`, where the same `*os.File` wrapper is used for fd
receive and ACK write.

### 2. Keep the fix local to the integration helper

The bug is in the test helper, not the shared fd-passing API.

For this change, the refactor should stay within
`internal/integration/seccomp_onblock_test.go` unless implementation reveals a
second call site with the same broken ownership pattern. The goal is to remove
the ambiguous lifetime bug without expanding the change surface unnecessarily.

### 3. Add regression coverage for GC-sensitive handoff behavior

Add a focused regression test around the helper path so this exact ownership
bug does not reappear silently.

The regression should:

- exercise the `log_and_kill` handoff path repeatedly
- run under aggressive GC settings or otherwise force collection pressure
- fail if the helper returns `ACK: invalid argument`, `RecvFD: bad file descriptor`,
  or wrapper-side ACK EOF errors

The important property is not the exact GC mechanism used, but that the test
proves the helper no longer depends on accidental object liveness.

## Why this is better than the alternatives

### Alternative A: add `runtime.KeepAlive(parentEnd)` around the ACK write

Rejected as the primary fix.

It can mask this specific race, but it preserves the confusing split ownership
model where both a raw int and a `*os.File` appear to own the same descriptor.
That leaves the helper fragile and makes the next change easy to get wrong.

### Alternative B: redesign `unixmon.RecvFD` and related APIs

Rejected for now.

That would be broader than the actual bug requires. The shared API is not the
thing causing the flake; the integration helper is.

### Alternative C: skip or soften the failing test in CI

Rejected.

The test is valid. The failure comes from the helper’s fd lifetime bug, not from
an inherently unreliable assertion.

## Proposed Code Shape

`startWrappedChild` should follow this ownership model:

1. create socketpair
2. wrap both ends immediately with `os.NewFile`
3. pass `childEnd` via `ExtraFiles`
4. keep `parentEnd` alive for:
   - `RecvFD`
   - ACK write
   - eventual close

No subsequent code in the helper should refer back to the original raw socket
integers once the wrappers are created.

## Testing Plan

### Primary verification

Run:

- `go test -tags=integration ./internal/integration -run '^TestSeccompOnBlock_LogAndKill$' -count=1`
- `GOGC=1 GOMEMLIMIT=64MiB go test -tags=integration ./internal/integration -run '^TestSeccompOnBlock_LogAndKill$' -count=50`

The second command is the regression guard because it reproduced the failure
locally before the fix.

### Suite-level verification

Run:

- `go test -tags=integration ./internal/integration -run 'TestSeccompOnBlock_(Errno|Kill|Log|LogAndKill|LogAndKill_ConcurrentCalls)$' -count=1`

This ensures the ownership refactor does not break the surrounding `on_block`
coverage.

## Risks

The main risk is accidental double-close after the ownership cleanup.

That risk is manageable if the refactor follows one rule consistently:

- once a socket fd is wrapped in `*os.File`, that wrapper is the only closer

If implementation preserves that invariant, the fix remains local and low-risk.
