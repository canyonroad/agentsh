# Wrap Seccomp Config Parity — Design Spec

**Date:** 2026-04-20
**Status:** Approved
**Author:** design session between Eran Sandler and Codex

## Problem

`seccompWrapperConfig` is assembled in two places:

- `internal/api/core.go` for the `exec` path
- `internal/api/wrap.go` for the `wrap-init` path

The two construction sites have drifted.

The `exec` path sets these file-monitor-related fields:

- `FileMonitorEnabled`
- `InterceptMetadata`
- `BlockIOUring`

The `wrap-init` path omits them.

That omission is not cosmetic. `cmd/agentsh-unixwrap` copies those JSON fields
directly into `unixmon.FilterConfig`, and the seccomp filter only traps file and
metadata syscalls when the corresponding booleans are set. As a result,
`agentsh wrap` can create a server-side file handler from config, but the
wrapper never installs the notify rules needed to send those syscalls to the
handler.

Effect:

- Landlock still enforces coarse directory boundaries.
- Fine-grained `file_rules` decisions do not run on the `wrap` path.
- `intercept_metadata` is silently ignored on the `wrap` path.
- `block_io_uring` is silently ignored on the `wrap` path.

## Goal

Make `wrap-init` and `exec` derive `seccompWrapperConfig` from the same shared
logic for all config-driven fields, so file-monitor behavior is consistent and
future fields cannot drift the same way.

## Non-Goals

- Do not change the existing runtime semantics of `UnixSocketEnabled`,
  `ExecveEnabled`, or `SignalFilterEnabled` beyond what is required to remove
  the current file-monitor bug.
- Do not change the wrapper JSON schema.
- Do not change Landlock policy derivation logic.
- Do not change file-monitor enforcement semantics themselves.

## Root Cause

The bug is structural, not a one-off typo.

`seccompWrapperConfig` has become a shared transport object, but the logic that
fills it is duplicated. The duplication spans:

- file-monitor option defaulting
- Landlock config wiring
- block-list transport
- runtime-only flags

The current bug happened because a field was added to one constructor but not
the other. If this remains duplicated, the same class of bug is likely to recur
for future fields.

## Recommended Design

### 1. Introduce a shared builder for `seccompWrapperConfig`

Add a private helper in `internal/api` that builds the config object from:

- `App`
- `session.Session`
- a small params struct containing runtime-specific booleans

Proposed shape:

```go
type seccompWrapperParams struct {
    UnixSocketEnabled   bool
    ExecveEnabled       bool
    SignalFilterEnabled bool
}

func (a *App) buildSeccompWrapperConfig(
    s *session.Session,
    p seccompWrapperParams,
) seccompWrapperConfig
```

The helper owns all config-derived fields and policy/session-derived Landlock
fields.

### 2. Keep path-specific runtime decisions in the callers

The callers continue to decide values that are genuinely path-dependent:

- `UnixSocketEnabled`
- `ExecveEnabled`
- `SignalFilterEnabled`

This is intentional.

The current `wrap-init` path and `exec` path do not compute all of those fields
the same way, and this design does not try to "clean up" those semantics as part
of the bugfix. The helper removes duplication only for the parts that should be
identical.

### 3. Move all config/defaulting logic into the shared helper

The helper should populate:

- `BlockedSyscalls`
- `OnBlock`
- `FileMonitorEnabled`
- `InterceptMetadata`
- `BlockIOUring`
- `ServerPID`
- all Landlock fields:
  - `LandlockEnabled`
  - `LandlockABI`
  - `Workspace`
  - `AllowExecute`
  - `AllowRead`
  - `AllowWrite`
  - `DenyPaths`
  - `AllowNetwork`
  - `AllowBind`

File-monitor sub-option defaulting must remain exactly as it is on the `exec`
path today:

- `fmDefault := FileMonitorBoolWithDefault(EnforceWithoutFUSE, false)`
- `InterceptMetadata := FileMonitorBoolWithDefault(InterceptMetadata, fmDefault)`
- `BlockIOUring := FileMonitorBoolWithDefault(BlockIOUring, fmDefault)`

That logic should exist in one place only after the change.

### 4. Make both call sites use the helper

`internal/api/core.go`

- compute the runtime booleans as it does today
- pass them into the helper
- stop doing file-monitor and Landlock field assembly inline

`internal/api/wrap.go`

- compute the runtime booleans as it does today
- pass them into the helper
- stop doing file-monitor and Landlock field assembly inline

This should leave each call site responsible only for:

- local gating
- socket creation
- runtime capability decisions
- marshaling / env plumbing

## Why this is better than the alternatives

### Alternative A: patch `wrapInitCore` only

Rejected because it fixes this specific bug but leaves the duplication intact.
The next added field can drift again.

### Alternative B: add parity tests only

Rejected because tests would detect future drift, but only after the code has
already diverged. The production defect still comes from duplicated derivation
logic.

### Alternative C: move all runtime toggles into the helper too

Rejected for this change because it risks altering unrelated wrap-vs-exec
behavior. The bugfix should eliminate config drift without broadening scope.

## Data Flow After The Change

### Exec path

```
config + session + runtime booleans
  → buildSeccompWrapperConfig(...)
  → json.Marshal
  → AGENTSH_SECCOMP_CONFIG
  → agentsh-unixwrap
  → unixmon.FilterConfig
```

### Wrap path

```
config + session + runtime booleans
  → buildSeccompWrapperConfig(...)
  → json.Marshal
  → WrapInitResponse.SeccompConfig / WrapperEnv
  → agentsh-unixwrap
  → unixmon.FilterConfig
```

The important property is that both paths now share the same config derivation
for file-monitor and Landlock fields.

## Testing Plan

### Wrap-path regression test

Strengthen `TestWrapInit_SeccompConfigContent` in `internal/api/wrap_test.go`
from a string-contains smoke test into JSON assertions.

It should assert at least:

- `file_monitor_enabled`
- `intercept_metadata`
- `block_io_uring`

Use a config that exercises the existing defaulting behavior:

- `Enabled = true`
- `EnforceWithoutFUSE = true`
- leave `InterceptMetadata` unset
- leave `BlockIOUring` unset

Expected result:

- `file_monitor_enabled == true`
- `intercept_metadata == true`
- `block_io_uring == true`

That proves the wrap path is using the same defaulting logic as the exec path.

### Exec-path regression test

Add a corresponding `setupSeccompWrapper` JSON test in `internal/api` that
asserts the same three fields for the `exec` path.

This is partly redundant once the helper is shared, but it keeps both public
integration surfaces covered.

### Optional focused helper test

If the extraction makes the helper clean to test directly without excessive
fixture setup, a narrow unit test is acceptable. It is not required.

The integration tests above are the required boundary.

## Files Expected To Change

**Modify:**

- `internal/api/core.go`
- `internal/api/wrap.go`
- `internal/api/wrap_test.go`
- one `internal/api/*test.go` file covering `setupSeccompWrapper`

**Create only if needed:**

- a small shared helper file in `internal/api` if extracting the builder there
  is cleaner than placing it beside one caller

## Risks

- **Accidentally changing runtime flag semantics.**
  Mitigation: keep `UnixSocketEnabled`, `ExecveEnabled`, and
  `SignalFilterEnabled` as caller-provided params.

- **Over-refactoring unrelated wrap logic.**
  Mitigation: extract only config assembly, not socket setup or caller flow.

- **Tests only checking field presence, not values.**
  Mitigation: parse JSON and assert concrete booleans, especially the
  `EnforceWithoutFUSE`-driven defaults.

## Success Criteria

- `agentsh wrap` sets `file_monitor_enabled` the same way as the `exec` path.
- `agentsh wrap` sets `intercept_metadata` and `block_io_uring` the same way as
  the `exec` path.
- Fine-grained `file_rules` enforcement is restored on the `wrap` path.
- Future `seccompWrapperConfig` fields have one shared derivation path instead
  of two independent constructors.
