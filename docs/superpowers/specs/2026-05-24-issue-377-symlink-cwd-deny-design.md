# `symlink_escape: deny` should not blanket-deny commands run from a symlinked cwd Design

Issue: #377 (part 2 of 2)

## Summary

When `policies.symlink_escape: deny` is set and the agent's working directory is itself a symlink whose target resolves outside the FUSE workspace mount, **every** command run from that cwd is denied as `workspace-escape`. The shim path resolves each exec's working directory through FUSE; `checkWithExist` sees the cwd symlink escape the mount and, in `deny` mode, returns the blanket `workspace-escape` deny before any `file_rules` get a chance to apply. The operator sees an opaque "everything is denied" failure with no indication that the cwd is the culprit.

This is the common Daytona / devcontainer layout where `/workspace` is a symlink to a real path the mount doesn't cover. `evaluate` mode (the default) does not have this problem — it falls through to `file_rules` via `evalEscapedSymlink`. Only `deny` mode is broken, and only for escapes that resolve *through the process cwd*.

This design makes `deny` mode treat the process cwd **and its subtree** like `evaluate` mode does: escapes that resolve through the cwd subtree fall through to `file_rules`; escapes *outside* the cwd subtree keep the blanket `workspace-escape` deny. A one-time-per-session diagnostic explains when the cwd-subtree special-case engages, so the previously-opaque failure mode becomes self-describing.

This is part 2 of #377. Part 1 (`command -v`/`-V` shell-c over-deny) was merged separately (#384).

## Goals

- With `symlink_escape: deny`, a command whose path resolves through the process cwd (the cwd directory or anything under it) is evaluated against `file_rules` instead of being blanket-denied as `workspace-escape`.
- Escapes *outside* the cwd subtree (e.g. `/workspace/evil -> /etc/shadow` when cwd is `/workspace/proj`) keep the blanket `workspace-escape` deny — `deny` mode's core protection is preserved.
- A clear, one-time-per-session diagnostic fires when the cwd-subtree special-case engages, naming the cwd-as-escaping-symlink situation.
- `evaluate` mode behavior is byte-for-byte unchanged.
- Regression tests so neither the cwd-subtree allowance nor the outside-cwd blanket-deny can silently regress.

## Non-Goals

- Do not change `evaluate` mode at all.
- Do not relax `..`-style escapes (paths above the workspace root) or resolution failures (broken link, missing parent): `evalEscapedSymlink` returns `""` for those, so they stay a hard deny even within the cwd subtree.
- Do not touch the RPC-path `resolveWorkingDir` (`internal/api/exec.go`) — it is the non-shim path and is out of scope for the reported Daytona/shim scenario.
- Do not change `command -v` handling (#377 part 1, already merged).

## Background

`internal/fsmonitor/fuse.go` `checkWithExist` (L471-525) resolves a virtual path to a real path under the workspace root, then runs the policy check on the resolved path. When `resolveRealPathUnderRoot` fails because a workspace symlink points outside the root, the escape branch (L501-515) decides what to do:

```go
escapeDeny := n.hooks != nil && n.hooks.SymlinkEscapeDeny
var escaped string
if !escapeDeny {
    escaped = evalEscapedSymlink(realRoot, virtPath, n.vroot())
}
if escaped != "" {
    policyPath = escaped            // evaluate mode: fall through to file_rules
} else {
    return policy.Decision{          // deny mode (or unresolvable): blanket deny
        PolicyDecision:    types.DecisionDeny,
        EffectiveDecision: types.DecisionDeny,
        Rule:              "workspace-escape",
        Message:           err.Error(),
    }
}
```

In `deny` mode `escapeDeny == true`, so `escaped` stays `""` and the function blanket-denies. Because the shim resolves each exec's cwd through FUSE, a symlinked-escaping cwd makes this fire for every command.

Verified facts:
- `virtPath` (the path being checked) and `session.Cwd` are **both virtual-space** paths (`/workspace/...`). `Cwd` defaults to `/workspace`, and `cd` only sets it to a target validated to be under the virtual root. So they are directly comparable.
- `Hooks` (fuse.go:30) carries `Session *session.Session` (fuse.go:32) and `SymlinkEscapeDeny bool`. The same `*Hooks` / `*session.Session` is shared across the session's nodes.
- `pathutil.IsUnderRoot(path, root)` returns `path == root || strings.HasPrefix(path, root+"/")` and returns `false` for an empty `root` (fail-closed). It already subsumes the `virtPath == cwd` case.
- `evalEscapedSymlink(realRoot, virtPath, virtualRoot)` (path.go:88) resolves the escaped symlink target and returns `""` for `..`-escapes / broken links — the same helper `evaluate` mode uses.
- `Session.Cwd` (manager.go:40) is guarded by `s.mu sync.Mutex` (manager.go:30). The only existing accessor, `GetCwdEnvHistory()` (manager.go:954), also copies the env map and history slice — wasteful on this path, which venvs hit on every `python` exec.

## Design

### 1. Two small Session accessors

In `internal/session/manager.go`:

```go
// GetCwd returns the session's current virtual working directory. It is a
// lightweight accessor (no env/history copy) for hot-path callers such as the
// FUSE symlink-escape check (#377).
func (s *Session) GetCwd() string {
    s.mu.Lock()
    defer s.mu.Unlock()
    return s.Cwd
}

// FirstCwdEscapeWarn reports true exactly once per session. The FUSE layer
// uses it to emit a single diagnostic when the process cwd is a symlink whose
// target escapes the workspace mount under symlink_escape="deny" (#377), so
// the otherwise-opaque "everything denied" failure is self-describing.
func (s *Session) FirstCwdEscapeWarn() bool {
    first := false
    s.cwdEscapeWarnOnce.Do(func() { first = true })
    return first
}
```

with a `cwdEscapeWarnOnce sync.Once` field added to the `Session` struct.

### 2. cwd-subtree gate in `checkWithExist`

Replace the escape branch's gate so that, in `deny` mode, escapes resolving through the cwd subtree fall through to `file_rules` exactly as `evaluate` mode does, while escapes elsewhere stay blanket-denied:

```go
// In symlink_escape="deny" mode we normally blanket-deny any symlink whose
// target escapes the workspace mount. But when the process cwd is itself such
// a symlink (common in Daytona/devcontainer layouts where /workspace is a
// symlink), that blanket deny rejects EVERY command run from the cwd. Treat the
// cwd and its subtree like evaluate mode: resolve the escaped target and let
// file_rules decide. Escapes OUTSIDE the cwd subtree stay blanket-denied, so
// deny mode's core protection is preserved. (#377)
escapeDeny := n.hooks != nil && n.hooks.SymlinkEscapeDeny
inCwdSubtree := false
if escapeDeny && n.hooks.Session != nil {
    if cwd := n.hooks.Session.GetCwd(); pathutil.IsUnderRoot(virtPath, cwd) {
        inCwdSubtree = true
        if n.hooks.Session.FirstCwdEscapeWarn() {
            slog.Warn("symlink_escape=deny: process cwd is a symlink escaping the workspace mount; evaluating its subtree against file_rules instead of blanket-denying",
                "session", n.hooks.SessionID, "cwd", cwd)
        }
    }
}
var escaped string
if !escapeDeny || inCwdSubtree {
    escaped = evalEscapedSymlink(realRoot, virtPath, n.vroot())
}
if escaped != "" {
    policyPath = escaped
} else {
    return policy.Decision{
        PolicyDecision:    types.DecisionDeny,
        EffectiveDecision: types.DecisionDeny,
        Rule:              "workspace-escape",
        Message:           err.Error(),
    }
}
```

Net effect by mode:

| Mode | Escape in cwd subtree | Escape outside cwd subtree | `..`-escape / broken link |
|------|-----------------------|----------------------------|---------------------------|
| `evaluate` (`escapeDeny=false`) | file_rules (unchanged) | file_rules (unchanged) | deny (unchanged) |
| `deny` (`escapeDeny=true`) | **file_rules (new)** | `workspace-escape` deny | `workspace-escape` deny |

The diagnostic fires only for the `deny` + in-cwd-subtree case, once per session.

### Why not other approaches

- **Special-case only the exact cwd, not its subtree:** breaks the moment a command references a relative path under the cwd (`./venv/bin/python`), which is the dominant case. The subtree is the legitimate unit.
- **Resolve the cwd once at session start and compare real paths:** more state to keep coherent across `cd`, and `Cwd` is already maintained in virtual space and updated on `cd`. Comparing in virtual space is simpler and always current.
- **Drop the diagnostic:** the opaque failure is exactly what made this issue hard to diagnose in the field; the one-time warning is cheap and high-value.

## Error handling

No new error types. The change only reclassifies one case (deny mode, escape through the cwd subtree) from a `workspace-escape` deny to a normal `file_rules` evaluation. All other inputs — including escapes outside the cwd subtree and unresolvable escapes — return exactly what they do today. The diagnostic is a `slog.Warn`, not an error, and is rate-limited to once per session.

## Testing

In `internal/fsmonitor/check_symlink_test.go` (model on `TestCheck_SymlinkEscapeDenyRestoresBlanketDeny`). Add a Session-aware node helper (a variant of `newCheckTestNodeWithEscape` that also sets `hooks.Session = &session.Session{Cwd: cwd}`), then:

1. **deny + cwd is the escaping symlink → evaluated, allowed.** cwd = the escaping path; a workspace symlink under the cwd escapes the mount; `file_rules` allow the resolved target. `check()` returns allow (not `workspace-escape`).
2. **deny + cwd subtree, file_rules deny the target → denied by that rule.** Same setup but `file_rules` deny the resolved target → decision is deny with the *file rule's* name, not `workspace-escape` (proves we fell through to evaluation, not blanket deny).
3. **deny + escape OUTSIDE the cwd subtree → still `workspace-escape`.** cwd is a normal in-mount dir; a sibling symlink escapes → blanket `workspace-escape` deny (unchanged protection).
4. **deny + `..`-escape under the cwd → still denied.** `evalEscapedSymlink` returns `""`, so even within the cwd subtree it stays a `workspace-escape` deny.
5. **evaluate mode unchanged.** Existing `evaluate`-mode tests still pass (escapes fall through regardless of cwd).

In `internal/session` (model on existing manager tests):

6. **`GetCwd` returns the current cwd; `FirstCwdEscapeWarn` returns true exactly once** (true on first call, false thereafter).

Confirm the existing `internal/fsmonitor` and `internal/session` suites stay green, and `GOOS=windows go build ./...` succeeds (`pathutil.IsUnderRoot` is already cross-platform).

## Affected files

- `internal/session/manager.go` — add `cwdEscapeWarnOnce sync.Once` field plus `GetCwd()` and `FirstCwdEscapeWarn()` accessors.
- `internal/fsmonitor/fuse.go` — the cwd-subtree gate in `checkWithExist`'s escape branch (~12 lines); add the `pathutil` and `log/slog` imports if not already present.
- `internal/fsmonitor/check_symlink_test.go` — Session-aware node helper + the four deny-mode regression tests.
- `internal/session/manager_cwd_test.go` (new, or appended to an existing session test file) — `GetCwd` / `FirstCwdEscapeWarn` unit tests.
