# Wrap AGENTSH_IN_SESSION Gating Design

## Summary

`agentsh wrap` currently launches child processes with `AGENTSH_SESSION_ID` but not
`AGENTSH_IN_SESSION`. The shell shim uses `AGENTSH_IN_SESSION=1` as its recursion
guard and direct-bypass signal.

At first glance this looks like a straightforward consistency bug. It is not.
`wrap` supports both strong interception modes and weak/fallback modes:

- Strong modes already control descendant `exec` activity outside the shim.
- Weak modes still rely on the shim for command steering.

Setting `AGENTSH_IN_SESSION=1` unconditionally under `wrap` would bypass the shim
in weak modes and can reduce enforcement. The fix must therefore be capability-
gated, not blanket.

## Problem

Today there are three overlapping facts:

1. The shim treats `AGENTSH_IN_SESSION=1` as "safe to bypass shim logic and exec
   the real shell directly."
2. The normal `agentsh exec` path injects `AGENTSH_IN_SESSION=1`.
3. `agentsh wrap` does not.

This creates an inconsistency, but not all wrap sessions are equivalent:

- `wrap` can fall back to direct launch when interception setup fails.
- Linux `wrap` can run with seccomp wrapping but with `seccomp.execve.enabled=false`.
- `seccomp.execve.enabled` is default-off.

In those cases, the wrapped process may still need shim-based command steering for
nested shells. A blanket env var change would be unsafe.

## Goal

Make `wrap` set `AGENTSH_IN_SESSION=1` only when nested shells can safely bypass
the shim because descendant exec policy is already enforced by the active wrap
mechanism.

## Non-Goals

- Do not change shim semantics.
- Do not redefine `AGENTSH_SESSION_ID` to mean "already in session."
- Do not force all wrapped sessions to behave identically if their enforcement
  capabilities differ.
- Do not broaden fallback behavior to look "consistent" at the cost of weaker
  enforcement.

## Design Principle

The controlling invariant is:

> `wrap` may bypass the shell shim only when descendant exec policy is already
> enforced outside the shim.

This keeps weak modes fail-safe and strong modes efficient.

## Recommended Design

### 1. Add an Explicit Server-to-CLI Capability Signal

Add a boolean field to `types.WrapInitResponse`:

- Candidate names:
  - `ExecInterceptionActive`
  - `SafeToBypassShellShim`

Recommended name: `SafeToBypassShellShim`.

Reasoning:

- The server already knows the real enforcement mode.
- The CLI should not infer safety from incidental fields like `WrapperBinary`,
  `PtraceMode`, or parsed seccomp JSON.
- Keeping the decision server-side avoids duplicate capability logic and drift.

### 2. Compute the Boolean From Real Enforcement Capability

The server sets `SafeToBypassShellShim=true` only when descendant exec policy is
already enforced outside the shim.

Initial mode matrix:

- Direct launch fallback: `false`
- Linux ptrace wrap: `true`
- Linux seccomp wrap with `execve` disabled: `false`
- Linux seccomp wrap with `execve` enabled: `true`
- Windows driver wrap: `true`
- macOS: `false` until descendant exec enforcement equivalence is explicitly
  proven

This defaults ambiguous or weak modes to fail-safe behavior.

### 3. Use Only That Boolean In The CLI

The CLI should append `AGENTSH_IN_SESSION=1` only when
`SafeToBypassShellShim=true`.

This applies to:

- Linux `platformSetupWrap`
- macOS `platformSetupWrap`
- Windows `platformSetupWrap`
- Any non-intercepting launch config that is still built from wrap-init data

It must not apply to the direct-launch fallback in `runWrap` when interception
setup fails and `wrapCfg == nil`.

### 4. Keep Shim Semantics Unchanged

The shim should continue to interpret `AGENTSH_IN_SESSION=1` as:

> "Do not re-enter shim enforcement; execute the real shell directly."

No new shim-side heuristics should be added for `AGENTSH_SESSION_ID`.

## Why This Is Better Than The Alternatives

### Alternative A: Always Set `AGENTSH_IN_SESSION`

Rejected because it is unsafe in fallback and weak modes. It would bypass the
shim even when `wrap` is not independently enforcing descendant exec policy.

### Alternative B: Never Set `AGENTSH_IN_SESSION` Under `wrap`

Rejected because it preserves the current mismatch and keeps redundant shim
re-entry even in strong modes where `wrap` already owns descendant exec policy.

### Alternative C: Teach The Shim That `AGENTSH_SESSION_ID` Implies In-Session

Rejected because it overloads session identity with enforcement capability.
`AGENTSH_SESSION_ID` means "which session," not "safe to bypass shim."

## Data Flow

1. `wrap-init` determines the active enforcement mode.
2. The server computes `SafeToBypassShellShim`.
3. The flag is returned in `WrapInitResponse`.
4. The CLI builds the launch environment.
5. The CLI injects `AGENTSH_IN_SESSION=1` only when the flag is true.
6. Nested shells bypass the shim only in strong interception modes.

## Testing Plan

### Server Tests

Add tests for the wrap-init response flag:

- ptrace mode returns `true`
- Linux seccomp + execve enabled returns `true`
- Linux seccomp + execve disabled returns `false`
- Windows driver mode returns `true`
- macOS returns `false` in the initial rollout

### CLI Tests

Extend wrap launch config tests to assert:

- `AGENTSH_IN_SESSION=1` is present when `SafeToBypassShellShim=true`
- `AGENTSH_IN_SESSION=1` is absent when `SafeToBypassShellShim=false`

### Fallback Test

Add or extend a test confirming:

- when interception setup fails and `runWrap` falls back to direct launch,
  `AGENTSH_IN_SESSION` is not injected

### Integration Coverage

Add at least:

- one Linux integration test with `seccomp.execve.enabled=false` showing wrap
  works and does not set the bypass marker
- one Linux integration test in a strong interception mode showing the marker is
  set

## Documentation Changes

Update wrap-related docs to say:

- wrapped sessions are not all equivalent
- nested shells bypass the shim only in strong interception modes
- direct/fallback or no-exec-interception modes retain shim steering

Do not change docs to imply that `AGENTSH_SESSION_ID` alone means "in session."

## Open Question

macOS remains intentionally conservative in the initial design. The first
version should treat macOS as `SafeToBypassShellShim=false` unless the team can
demonstrate that wrapped descendant exec policy is fully enforced outside the
shim.

## Success Criteria

- `wrap` no longer relies on an implicit or accidental relationship between
  session identity and shim bypass behavior.
- Strong interception modes avoid redundant shim re-entry.
- Weak and fallback modes retain shim steering.
- The CLI/server boundary contains a single explicit capability signal.
