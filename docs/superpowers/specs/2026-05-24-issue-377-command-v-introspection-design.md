# Allow `command -v` / `command -V` introspection in shell-c pre-check Design

Issue: #377 (part 1 of 2)

## Summary

On the shell-shim path, `bash -c 'command -v ls'` is denied as `shellc-wrapper-bypass` (exit 126). `command -v NAME` / `command -V NAME` are common, read-only ways to check whether a binary exists or print its type; they do **not** execute NAME. Denying them breaks ordinary setup/probe scripts. This design makes the shell-c parser treat `command -v`/`-V` as benign builtin introspection so it falls through to the operator's `allow sh`/`bash` rule instead of being flagged as a wrapper-bypass.

This is part 1 of #377. Part 2 (`symlink_escape: deny` blocking commands on a symlinked cwd) is a separate, independent fix tracked under #377 and handled in its own spec/PR.

## Goals

- `bash -c 'command -v NAME'` and `bash -c 'command -V NAME'` are no longer denied as `shellc-wrapper-bypass`; they run under the operator's allow-shell rule.
- Keep `command -p NAME …` (which executes NAME under a default PATH) classified as a bypass — conservative, unchanged.
- Keep `command NAME …` (no flag, which executes NAME) deriving to NAME so command rules (e.g. `deny shutdown`) still fire.
- Regression tests so the introspection allowance and the conservative `-p`/no-flag behavior cannot silently regress.

## Non-Goals

- Do not change handling of other wrappers (`exec`, `nohup`, `nice`, `time`, `env`).
- Do not allow `command -p` (it executes a command and alters PATH resolution).
- Do not touch part 2 of #377 (symlink cwd).

## Background

`internal/shellparse/parseSimpleShellC` classifies a `<shell> -c "<script>"` invocation as `statusOK` (derivable target), `statusBypass`, `statusOpaque`, or `statusFallback` (hand back to the outer shell rule). The policy engine denies `statusBypass` as `shellc-wrapper-bypass` (`internal/policy/engine.go:622-633`).

For `command -v ls`: the script tokenizes to `["command","-v","ls"]` (no opaque bytes), then `stripWrappers` sees the transparent wrapper `command` followed by a flag (`-v`) and returns bypass (`shellparse.go` `stripWrappers`, the catch-all `return nil, true`). Hence `statusBypass` → deny.

Key facts:
- `command` is in both the transparent-wrapper set (`isTransparentWrapper`) — because `command NAME args` forwards-executes NAME — and the shell-builtin set (`isShellBuiltin`).
- `parseSimpleShellC` already returns `statusFallback` for a leading shell builtin: `if isShellBuiltin(tokens[0]) { return "", nil, statusFallback }` (after `stripWrappers`).
- `command -v NAME` / `command -V NAME` is pure introspection: it performs a name lookup and prints the result; it never executes NAME. So allowing it leaks nothing even for `command -v shutdown` — nothing runs.

## Design

In `internal/shellparse/shellparse.go`, in `stripWrappers`, add a guard immediately before the catch-all `return nil, true`:

```go
// `command -v`/`-V NAME` is introspection: it prints whether NAME exists /
// its type and does NOT execute it. Stop stripping so the builtin classifier
// (isShellBuiltin("command")) hands this back to the outer shell rule rather
// than flagging a wrapper-bypass. `command -p` (which executes NAME under a
// default PATH) is intentionally NOT included. Issue #377.
if wrapper == "command" && (next == "-v" || next == "-V") {
    return tokens, false
}
```

Returning `(tokens, false)` leaves `command` as `tokens[0]`. Back in `parseSimpleShellC`, the existing `isShellBuiltin(tokens[0])` check matches (`command` is a builtin) and returns `statusFallback`. The engine then finds `DerivePolicyTarget` ok=false, `IsShellCBypassAttempt` false, and `IsOpaqueShellC` false, so it applies the operator's allow-shell rule → the command runs.

### Why not other approaches

- **Drop `command` from the transparent-wrapper set:** unsafe — `command shutdown` would then no longer derive to `shutdown`, so a `deny shutdown` rule wouldn't fire (a real bypass).
- **Detect the introspection form up in `parseSimpleShellC`:** more code for the same effect; the fix belongs in `stripWrappers`, where the bypass currently originates.

## Error handling

No new errors. The change only reclassifies `command -v`/`-V` from `statusBypass` to `statusFallback`; all other inputs are unchanged.

## Testing

`internal/shellparse` (model on existing `shellparse_test.go`):
- `IsShellCBypassAttempt("/bin/sh", []string{"-c", "command -v ls"})` → false.
- `IsShellCBypassAttempt("/bin/sh", []string{"-c", "command -V ls"})` → false.
- `IsShellCBypassAttempt("/bin/sh", []string{"-c", "command -p ls"})` → true (still bypass).
- `DerivePolicyTarget("/bin/sh", []string{"-c", "command shutdown"})` → derives to `shutdown` (no-flag forwarding preserved).

`internal/policy` (model on `command_shellc_test.go`, which builds a policy with `deny-shutdown` + `allow sh`):
- `CheckCommand("/bin/sh", []string{"-c", "command -v ls"})` → allow (rule is the allow-shell rule, NOT `shellc-wrapper-bypass`).
- `CheckCommand("/bin/sh", []string{"-c", "command shutdown"})` → deny `deny-shutdown` (bypass-via-no-flag still caught).

Confirm existing `internal/shellparse` and `internal/policy` suites stay green.

## Affected files

- `internal/shellparse/shellparse.go` — the `stripWrappers` guard (~5 lines).
- `internal/shellparse/command_v_test.go` (new) — shellparse-level regression tests.
- `internal/policy/command_v_introspection_test.go` (new) — engine-level allow assertion (modeled on `command_shellc_test.go`).
