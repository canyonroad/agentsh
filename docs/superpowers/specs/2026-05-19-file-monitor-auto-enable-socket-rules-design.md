# Skip file_monitor auto-enable when socket_rules are configured

**Issue:** [#304](https://github.com/canyonroad/agentsh/issues/304)
**Date:** 2026-05-19

## Problem

When `sandbox.seccomp.enabled: true` and `sandbox.seccomp.file_monitor.enabled`
is omitted (nil), `applyDefaults` in `internal/config/config.go` auto-enables
file monitoring. The auto-enable installs `SECCOMP_RET_USER_NOTIF` rules for
file syscalls in the unixwrap's seccomp filter.

When `socket_rules` are also configured, this causes `agentsh wrap -- COMMAND`
to deadlock during seccomp setup:

1. Unixwrap installs the filter (with file-notify rules from auto-enable).
2. Unixwrap calls `sendFD(sockFD, notifFD)` to hand the notify FD to the server.
3. A file syscall during that send (libc resolution, path lookup) triggers a
   notify rule.
4. Unixwrap blocks in `seccomp_do_user_notification` waiting for the server.
5. The server never gets the notify FD — that was step 2 — so it can't respond.

The existing workaround is to explicitly set `file_monitor.enabled: false` in
any config that uses `socket_rules` without policy file rules.

## Goal

Stop the auto-enable from silently turning on a notify-based file monitor when
the operator's config indicates they want socket-only enforcement. The
operator's explicit settings (`enabled: true` / `enabled: false`) continue to
win.

## Non-goals

- Fixing the underlying unixwrap deadlock when file_monitor is *explicitly*
  enabled alongside socket_rules. That's a runtime sequencing issue and out of
  scope here.
- Gating auto-enable on whether the session policy has `file_rules`. Session
  policy isn't available at `applyDefaults` time, so this would require
  threading policy state into config-default resolution. Tracked for later.
- Updating example demo configs (e.g. `examples/demo-cve-2026-43284/`) to drop
  the workaround. That's a follow-up cleanup, not part of the fix.

## Design

### Code change

In `internal/config/config.go`, replace the existing auto-enable block (lines
1721–1735) with one that adds `len(cfg.Sandbox.Seccomp.SocketRules) == 0` as a
precondition:

```go
// Auto-enable file_monitor when seccomp is on AND the operator hasn't
// configured socket_rules. socket_rules indicates the user wants
// socket-level enforcement only; auto-installing file-notify rules on
// top would deadlock the unixwrap during seccomp setup (issue #304).
// Explicit `file_monitor.enabled: false` still wins (Enabled != nil).
if cfg.Sandbox.Seccomp.Enabled &&
    cfg.Sandbox.Seccomp.FileMonitor.Enabled == nil &&
    len(cfg.Sandbox.Seccomp.SocketRules) == 0 {
    cfg.Sandbox.Seccomp.FileMonitor.Enabled = boolPtr(true)
}
```

### Behavior matrix

| `seccomp.enabled` | `socket_rules` | `file_monitor.enabled` (input) | `file_monitor.enabled` (after defaults) |
|---|---|---|---|
| `true` | none | omitted | `true` (auto-enable preserved) |
| `true` | none | `false` | `false` (explicit wins) |
| `true` | none | `true` | `true` |
| `true` | configured | omitted | **`nil` (new behavior — was `true`)** |
| `true` | configured | `false` | `false` |
| `true` | configured | `true` | `true` (operator opt-in respected) |
| `false` | * | * | unchanged |

### Tests

In `internal/config/seccomp_test.go`:

- **Keep** `TestFileMonitorAutoEnable_Omitted` — verifies auto-enable when no
  socket_rules. Unaffected.
- **Keep** `TestFileMonitorAutoEnable_ExplicitFalse` — explicit false still
  preserved.
- **Add** `TestFileMonitorAutoEnable_SkippedWhenSocketRulesPresent` — config
  with `seccomp.enabled: true` and a `socket_rules` entry but no
  `file_monitor` block. After `applyDefaults`, `FileMonitor.Enabled` must
  remain nil, and `FileMonitorBoolWithDefault(..., false)` must be `false`.
- **Add** `TestFileMonitorAutoEnable_ExplicitTrueWithSocketRulesRespected` —
  config with both `socket_rules` and explicit `file_monitor.enabled: true`.
  After `applyDefaults`, `FileMonitor.Enabled` must be `*true` (the gate only
  affects the implicit-default path).

### Verification

Standard pre-commit checks per `CLAUDE.md`:

- `go test ./internal/config/...`
- `go test ./...` (full suite — verify nothing else relied on the auto-enable
  triggering when socket_rules are present).
- `GOOS=windows go build ./...` (cross-compile gate).

## Risks

- **Operators who have configs with both `seccomp.enabled: true`,
  `socket_rules`, AND were relying on the implicit file_monitor:** they will
  see file monitoring silently turn off. Mitigation: this is exactly the
  config that hits the deadlock today, so anyone running it successfully has
  already set `file_monitor.enabled: false` (the documented workaround) or
  is hung. We're not regressing a working setup.
- **Future tests that depend on the old behavior:** none found in initial
  grep; full suite will surface any.

## Rollout

Single commit on a feature branch, PR to `main`, normal review. No flag, no
migration. The change is a strict relaxation of an implicit default — explicit
config is untouched.
