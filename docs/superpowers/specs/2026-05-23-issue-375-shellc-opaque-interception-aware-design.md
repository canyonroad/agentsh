# Interception-Aware Opaque Shell-C Pre-Check Design

Issue: #375

## Summary

The shell-shim policy pre-check (`policy.Engine.CheckCommand`) statically denies any `bash -c` / `sh -c` invocation whose script it cannot fully parse, with `rule=shellc-opaque-script` (exit 126). The "opaque" classifier treats almost any shell-significant byte — pipes, `$`, redirects, `&&`, `$(…)`, globs, `;` — as un-parseable, so a large range of ordinary commands is rejected. On platforms that run every command as `bash -c "<script>"` (e.g. Daytona) this breaks most of the command surface. It is a regression from v0.18.0 and reproduces on current `main`.

This design makes the opaque pre-deny **interception-aware**: when runtime `execve` enforcement is active for the session, the static pre-deny is skipped and the script is allowed to run, because every inner `execve` is already evaluated against the same command policy at runtime (`CheckExecve(filename, argv, depth)`, enforced with `EACCES`). When no `execve` interception is active, behavior is unchanged — the static hard-deny remains the security boundary.

## Goals

- Stop denying benign `bash -c` / `sh -c` scripts (pipes, variables, redirects, `&&`, `$(…)`, loops) when runtime `execve` enforcement will police the inner commands.
- Preserve the exact current behavior when no `execve` interception is active.
- No security regression: every binary the policy forbids is still blocked, just precisely at `execve` time instead of via a blunt static pre-deny.
- Add regression tests covering both the interception-on and interception-off paths.

## Non-Goals

- No new policy/config knob (e.g. `shellc_opaque: allow|deny|require_interception`).
- No widening of the opaque-byte allow-set (`isUnquotedAllowedByte`).
- No change to the `shellc-wrapper-bypass` or `shellc-depth-exceeded` denials — this targets only `shellc-opaque-script`.
- No change to the no-interception code path.

## Background: the two enforcement layers

1. **Static pre-check** — `policy.Engine.CheckCommand` (`internal/policy/engine.go:583`). Runs at session/command start. Walks `sh -c` forms via `shellparse`; if the script is opaque and `e.hasRestrictiveCommandRule` is set, fails closed with `shellc-opaque-script` (`engine.go:618-633`). This fires regardless of whether runtime interception is active — the bug.
2. **Runtime per-execve check** — `policy.Engine.CheckExecve(filename, argv, depth)` (`engine.go:1289`). Invoked by the seccomp `USER_NOTIF` execve handler (`internal/netmonitor/unix/execve_handler.go:350`) and the ptrace execve handler (`internal/api/ptrace_handlers.go:114`). Evaluates each inner `execve` against the same compiled command rules with depth context; a `deny` returns `EACCES` and blocks the exec. Covered by `internal/integration/execve_interception_test.go` (nested `curl` blocked at depth 1, allowed at depth 0).

The static pre-deny is a blunt failsafe ("can't parse → deny all"). When layer 2 is active it is redundant and over-broad.

## Design

### Core change

In the `CheckCommand` derive loop, gate the opaque deny on the absence of runtime enforcement:

```go
} else if e.hasRestrictiveCommandRule && !e.execveEnforcementActive && shellparse.IsOpaqueShellC(cur, curArgs) {
    // ... existing shellc-opaque-script deny ...
}
```

When `execveEnforcementActive` is true, the opaque script falls through to normal command-rule matching (typically the operator's `allow sh`/`allow bash` rule) and runs; its inner `execve` calls are policed by `CheckExecve` at depth.

### Plumbing `execveEnforcementActive`

`execve` enforcement is a property of the **execution path**, not of the policy itself, so the signal is passed in at the command pre-check call site rather than stored on the engine:

- Refactor `CheckCommand` into an internal `checkCommand(command, args, execveEnforcementActive bool)` holding the existing logic, with the opaque gate becoming `... && !execveEnforcementActive && shellparse.IsOpaqueShellC(...)`.
- `CheckCommand(command, args)` stays as a thin wrapper calling `checkCommand(command, args, false)` — every existing caller (tests, non-Linux platform adapters, `context_eval`) is untouched and keeps today's hard-deny behavior.
- Add `CheckCommandWithExecve(command, args, execveEnforcementActive bool)` calling `checkCommand(command, args, execveEnforcementActive)`.
- Add an `App` helper computing the signal once:

```
func (a *App) execveEnforcementActive() bool {
    return a.cfg.Sandbox.Seccomp.Execve.Enabled || a.ptraceTracer != nil
}
```

  - `cfg.Sandbox.Seccomp.Execve.Enabled` is the seccomp-execve intent; a runtime probe failure fails closed in `agentsh-unixwrap` (see security analysis), so the config bool is safe to trust.
  - `a.ptraceTracer != nil` is the App's existing *runtime* signal that ptrace is attached (the same check `core.go` uses), rather than the config intent `Sandbox.Ptrace.Enabled`, so a ptrace that failed to initialize does not wrongly relax the pre-check.
  - (`sandbox.seccomp.execve` and `sandbox.ptrace` are mutually exclusive per config validation, so at most one term is true.)
- Update the command pre-check call sites that run the Linux execve-intercepted path to call `CheckCommandWithExecve(cmd, args, a.execveEnforcementActive())`: `internal/api/exec_stream.go`, `internal/api/pty_core.go`, `internal/api/grpc.go`, the two sites in `internal/api/core.go`, **and the shim wrap-init guard in `internal/api/wrap.go` (`wrapInitCore`, the `req.Mode == "shim"` branch)**. All have `App` access. Non-execution callers keep `CheckCommand` (i.e. `false`).

  The shim wrap-init guard is essential, not optional: it is the pre-check the shell-shim kernel-install path hits (the reporter's exact scenario — Daytona runs every command as `bash -c "<script>"`). Without making it interception-aware, an opaque shim command is denied here, returns HTTP 403, and the shim falls back to the `agentsh exec` path — so the command runs but **bypasses the kernel-install wrapper entirely**, defeating the enforcement path for essentially all of the reporter's traffic. Making the guard interception-aware lets wrap-init proceed so the shim runs the wrapper directly, with inner execs policed at depth. Genuinely-denied *derivable* commands (e.g. `sh -c "shutdown"`) still derive to their deny rule and 403 as before; only the blunt opaque deny is relaxed.

### Why this is safe (security analysis)

- **Precise instead of blunt.** With interception active, `sh -c "shutdown; :"` runs `sh` (allowed), then `shutdown` execs at depth 1 → `CheckExecve` denies it with `EACCES` *iff* the policy denies `shutdown`. That is identical to the operator running `shutdown` directly — consistent, not a bypass. The pre-deny previously blocked all opaque scripts whether or not their inner commands were actually forbidden.
- **The command policy guards new binaries; that is exactly what layer 2 covers** at every depth. Pure shell builtins (`echo`, redirects) spawn no binary, so the command policy has nothing to enforce on them anyway; filesystem effects remain governed by Landlock/fsmonitor, unchanged.
- **Fail-closed end-to-end.** If `execve` interception is *configured* but the runtime probe fails (e.g. AppArmor blocks the seccomp notify ioctl), `agentsh-unixwrap` already `Fatal`s before exec (`cmd/agentsh-unixwrap/main.go`), so "pre-check allowed it" cannot translate into unpoliced execution.

### Edge cases

- `exec shutdown` (in-place execve via the `exec` builtin) is still an `execve` → evaluated by `CheckExecve` against the `shutdown` rules. Caught.
- Depth-scoped rules (`MinDepth`/`MaxDepth`) continue to apply at runtime exactly as today.
- `shellc-depth-exceeded` and `shellc-wrapper-bypass` are deliberately unchanged; only `shellc-opaque-script` becomes interception-aware.

## Testing

1. **Engine unit tests** (`internal/policy`), with a restrictive command rule present:
   - `execveEnforcementActive=false` → opaque `sh -c "echo $HOME | head"` still denied `shellc-opaque-script` (current behavior preserved).
   - `execveEnforcementActive=true` → same script is **not** pre-denied (falls through to the allow-shell rule).
   - `execveEnforcementActive=true` + a `deny shutdown` rule → `CheckExecve("shutdown", …, depth=1)` still denies (inner enforcement intact).
2. **Reporter battery** as a table test, asserting the pre-check no longer denies when enforcement is active: `echo $HOME`, `ls /tmp | head`, `echo x > /tmp/a`, `true && true`, `echo $(date)`, `for i in 1 2; do echo $i; done`.
3. Confirm `internal/integration/execve_interception_test.go` still passes (depth-1 denial unaffected).

## Affected files

- `internal/policy/engine.go` — split `CheckCommand` into `checkCommand(…, execveEnforcementActive bool)` + `CheckCommand` (passes `false`) + `CheckCommandWithExecve`; gate the opaque-deny branch on `!execveEnforcementActive`.
- `internal/api` — add `App.execveEnforcementActive()`; switch the six command pre-check call sites (`exec_stream.go`, `pty_core.go`, `grpc.go`, two in `core.go`, and the shim wrap-init guard in `wrap.go`) to `CheckCommandWithExecve`.
- Tests in `internal/policy` (and a confirmation run of `internal/integration`).

## Out of scope (tracked separately if desired)

- Config knob for explicit operator override.
- Narrowing the opaque-byte allow-set to let benign literals through on the no-interception path.
