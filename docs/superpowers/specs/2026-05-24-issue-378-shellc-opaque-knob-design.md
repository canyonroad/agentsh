# `sandbox.seccomp.shellc.opaque` — operator control over opaque shell-c handling Design

Issue: #378

## Summary

On the kernel-install (`unixwrap`) shell-shim path, agentsh fail-closes on any `sh -c` / `bash -c` payload it cannot statically resolve to a single command (`rule=shellc-opaque-script`, exit 126) — but only when the policy has a restrictive command rule **and** runtime per-exec enforcement is not active. On sandbox-API platforms (Blaxel, E2B, Daytona, Runloop) the shim is the only shell and the platform always launches `/bin/sh -c "<command>"`, an invocation shape the integrator cannot change. The net effect is that anything with a pipe, redirect, `$VAR`, `&&`/`;`, or glob is denied before it runs, and there is no operator override.

The "run opaque scripts under per-exec enforcement" behavior the issue asks for **already exists implicitly** (added in #375): when `execveEnforcementActive()` is true, opaque scripts are not pre-denied — they run and every inner `execve` is policed by `CheckExecve`. The gap is that (a) there is no way for an operator to express intent when runtime enforcement is unavailable, and (b) the deny is opaque, giving no remediation guidance.

This design adds an explicit knob, `sandbox.seccomp.shellc.opaque: deny | enforce | allow`, defaulting to `enforce` (today's behavior, no regression). `allow` is an audited escape hatch that runs opaque scripts even with no runtime enforcement. The deny message is enriched to name the remedy.

## Goals

- Give operators explicit control over opaque shell-c handling via `sandbox.seccomp.shellc.opaque`.
- Default (`enforce`) is byte-for-byte the current behavior — no regression for any existing deployment.
- `allow` lets opaque scripts run on platforms that cannot run execve interception, with a logged warning preserving visibility of the accepted bypass risk.
- `deny` gives operators a stricter-than-today posture (refuse opaque scripts even when enforcement is active).
- Replace the mystery exit-126 with a deny message that names the two remedies.
- Regression tests so the matrix of modes × enforcement × rule-presence cannot silently change.

## Non-Goals

- **No auto-activation of execve interception.** Turning on `seccomp.execve` + `unix_sockets` (or attaching ptrace) in a mode the operator chose as `minimal` is a large, risky surface (filter-stacking / unixwrap deadlock pitfalls, platform portability) and is deferred. Operators who want enforcement can already enable it via existing config, at which point `enforce` runs opaque scripts under policy.
- Do not change the `hasRestrictiveCommandRule` gate semantics: policies with no restrictive command rule continue to run opaque scripts regardless of the knob.
- Do not change `shellc-wrapper-bypass`, `shellc-depth-exceeded`, or any non-opaque classification.
- Do not change `evaluate`/`deny` symlink handling or any unrelated path.

## Background

The decision lives in `internal/policy/engine.go` `checkCommand` (the `else if` at ~line 635):

```go
} else if e.hasRestrictiveCommandRule && !execveEnforcementActive && shellparse.IsOpaqueShellC(cur, curArgs) {
    msg := "opaque shell script cannot be safely parsed for policy pre-check"
    if reason := shellparse.OpaqueReason(cur, curArgs); reason != "" {
        msg = "opaque shell script: contains " + reason
    }
    denyDec := e.wrapDecision(string(types.DecisionDeny), "shellc-opaque-script", msg, nil)
    if dec := denyDec; decisionStrictness(dec.PolicyDecision) > resultStrictness {
        result = dec
        resultStrictness = decisionStrictness(dec.PolicyDecision)
    }
}
```

Key facts:
- `execveEnforcementActive` is supplied per-call by the App (`internal/api/session_policy.go:66`): true iff a ptrace tracer is attached, or `seccomp.execve.enabled && unix_sockets enabled`. It is computed per-call because a ptrace tracer can attach/detach.
- `hasRestrictiveCommandRule` (engine.go:53, set ~line 272) is true iff any command rule decides `deny`/`redirect`/`soft_delete`/`approve`/`audit` — even a single `audit` rule trips it.
- The engine is constructed by the App via `policy.NewEngine(...)` (`internal/api/app.go:1636`), where the sandbox config is reachable. The opaque mode is **static config**, so it belongs on the engine as a field set at construction — unlike `execveEnforcementActive`, which is dynamic and stays a per-call parameter.
- `sandbox.seccomp` (`SandboxSeccompConfig`, `internal/config/config.go:490`) already groups feature sub-knobs: `execve`, `file_monitor`, `socket_rules`, `blocked_socket_families`. A `shellc` sibling fits this shape and sits next to `execve`, the knob that determines whether `enforce` can run scripts under interception.

## Design

### 1. Config schema

Add to `internal/config/config.go`:

```go
// SandboxSeccompShellcConfig controls how the shell-shim handles opaque
// `sh -c`/`bash -c` payloads that cannot be statically resolved to a single
// command for policy pre-check (issue #378).
type SandboxSeccompShellcConfig struct {
    // Opaque selects handling for opaque shell-c scripts when the policy has a
    // restrictive command rule:
    //   "enforce" (default) — run only when per-exec enforcement is active
    //                         (ptrace, or seccomp.execve + unix_sockets);
    //                         otherwise deny shellc-opaque-script.
    //   "allow"             — run even without per-exec enforcement (accepts
    //                         the bypass risk; emits a warning).
    //   "deny"              — always deny opaque scripts.
    Opaque string `yaml:"opaque"`
}
```

and a field on `SandboxSeccompConfig`: `Shellc SandboxSeccompShellcConfig `yaml:"shellc"``.

`applyDefaults` sets `Opaque` to `"enforce"` when empty. `validateConfig` rejects any value other than `deny`/`enforce`/`allow` (with the existing `sandbox config:`-style wrapping is not needed here; use a clear `seccomp.shellc.opaque` message), consistent with the #376 principle that config-schema invariants validate in `validateConfig`.

### 2. Engine: opaque mode field + decision logic

Add a typed mode to the policy package and a field on `Engine`:

```go
type ShellCOpaqueMode int

const (
    ShellCOpaqueEnforce ShellCOpaqueMode = iota // default (zero value) = today's behavior
    ShellCOpaqueAllow
    ShellCOpaqueDeny
)
```

The zero value is `Enforce`, so an engine constructed without explicit configuration keeps current behavior. The App maps the config string to the mode and sets it on the engine after `NewEngine` (a small `engine.SetShellCOpaqueMode(mode)` setter, or a parameter — implementation detail for the plan). `CheckCommand` (no-execve platform paths) and `CheckCommandWithExecve` both consult the field.

Replace the `else if` condition so the `hasRestrictiveCommandRule` gate is preserved (allow-only policies unaffected) and the mode picks the outcome:

```go
} else if e.hasRestrictiveCommandRule && e.shellCOpaqueMode != ShellCOpaqueAllow && shellparse.IsOpaqueShellC(cur, curArgs) {
    deny := e.shellCOpaqueMode == ShellCOpaqueDeny ||
        (e.shellCOpaqueMode == ShellCOpaqueEnforce && !execveEnforcementActive)
    if deny {
        // ...enriched msg... wrapDecision(deny, "shellc-opaque-script", msg, nil), strictness-merge as today
    }
}
```

Behavior matrix (the `hasRestrictiveCommandRule == true` column; with no restrictive rule, opaque is always allowed regardless of mode):

| Mode | enforcement active | enforcement inactive |
|------|--------------------|----------------------|
| `enforce` (default) | allow (run under per-exec policy) | **deny** `shellc-opaque-script` |
| `allow` | allow | **allow** (no per-exec policing) |
| `deny` | **deny** | **deny** |

`enforce` reproduces today's behavior exactly.

### 3. Diagnostics

- **Enriched deny message.** Append remediation to the `shellc-opaque-script` message: e.g. `"opaque shell script: contains <reason>; set sandbox.seccomp.shellc.opaque=allow to run it without per-exec enforcement, or enable execve enforcement (seccomp.execve + unix_sockets, or ptrace) to run it under policy"`.
- **`allow` warning.** When `allow` lets an opaque script run that `enforce` would have denied (restrictive rule present and `!execveEnforcementActive`), emit a `slog.Warn` naming the script reason, so the accepted bypass risk stays visible in logs. The operator opted in, so a per-occurrence warn is acceptable; rate-limiting is a possible later refinement, not required.

### Why not other approaches

- **Auto-activate execve interception in `minimal` mode:** changes the contract of a mode the operator deliberately chose, risks known seccomp filter-stacking/unixwrap deadlocks, and isn't portable across sandbox platforms. Operators can already enable enforcement via existing config. Deferred as a non-goal.
- **Per-rule policy field instead of a global knob:** the deny is a function of the runtime enforcement situation (a host/runtime property), not of any individual rule, so a `sandbox.*` knob models it more faithfully and avoids repeating it across rules.

## Error handling

No new error types. `validateConfig` returns a clear error for an invalid `opaque` value. The engine reclassifies opaque handling per the matrix above; all non-opaque classifications and the no-restrictive-rule path are unchanged. The `allow` warning is a log line, not an error.

## Testing

`internal/policy` (model on the existing shellc engine tests, e.g. `command_shellc_test.go`):
- For each mode (`enforce`, `allow`, `deny`) × enforcement active/inactive, with a restrictive command rule present, assert the decision and rule:
  - `enforce` + active → allow; `enforce` + inactive → deny `shellc-opaque-script`.
  - `allow` + active → allow; `allow` + inactive → allow.
  - `deny` + active → deny; `deny` + inactive → deny.
- With **no** restrictive command rule, all three modes → allow (gate preserved).
- A simple (non-opaque) `sh -c "ls"` is unaffected in all modes.

`internal/config` (model on the #376 `validate_sandbox_signing_test.go`):
- Empty `opaque` defaults to `enforce` after `applyDefaults`.
- `deny`/`enforce`/`allow` validate cleanly.
- Any other value fails `validateConfig` with a message naming `seccomp.shellc.opaque`.

Confirm existing `internal/policy`, `internal/config`, and `internal/api` suites stay green, and `GOOS=windows go build ./...` succeeds.

## Affected files

- `internal/config/config.go` — `SandboxSeccompShellcConfig` + `Shellc` field; `applyDefaults` default-to-enforce; `validateConfig` value check.
- `internal/policy/engine.go` — `ShellCOpaqueMode` type, `shellCOpaqueMode` field + setter, the mode-aware `else if` branch, enriched message, `allow` warning.
- `internal/api/app.go` (and/or `session_policy.go`) — map `cfg.Sandbox.Seccomp.Shellc.Opaque` to the mode and set it on the engine at construction.
- `internal/policy/<new>_test.go`, `internal/config/<new>_test.go` — regression tests.
