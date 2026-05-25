# Detect honesty for uninstallable seccomp Design

Issue: #390 (follow-up to #388)

## Summary

After #388, `agentsh detect` distinguishes "kernel supports user-notify"
(`seccomp_user_notify_kernel`) from "a real `NEW_LISTENER` filter installs here"
(`SeccompInstallable`). The per-backend `✓/-` marks now read correctly. But the
**domain scoring and the active-backend label still overstate** protection where
the install probe fails (e.g. Daytona, `EBUSY`): `agentsh detect` reports
`COMMAND CONTROL 25/25` with `active backend: seccomp-execve` while the
`seccomp-execve` backend itself shows `-`, and the overall Protection Score does
not drop.

Three spots on the mode-selection / detect path never consumed the
`SeccompInstallable` signal:

1. `SelectMode()` keys `ModeFull` off `c.Seccomp` (kernel-supported), not
   `c.SeccompInstallable`.
2. `commandActive` in `buildLinuxDomains` is hard-wired to `"seccomp-execve"`
   unless `ModePtrace`.
3. The `ptrace` Command Control backend's `Available: caps.Ptrace` means
   *capability present*, not *actively enforcing* — so `ComputeScore`
   (full weight if **any** backend `Available`) awards Command Control its
   full 25 on the strength of a latent, unengaged capability.

This design makes the two Command Control backends' `Available` flags **honest**
so the existing any-backend `ComputeScore` naturally yields the right number, and
makes `SelectMode` report the mode that actually applies. `ComputeScore` and the
darwin/windows domain builders are **not touched**.

## Goals

- On a host where the seccomp `NEW_LISTENER` install fails but the kernel
  supports user-notify (Daytona/`EBUSY`): `agentsh detect` reports
  `COMMAND CONTROL 0/25`, no `active backend` line for Command Control, and the
  overall Protection Score drops accordingly.
- The `✓/-` marks, the `active backend` label, and the domain score **agree**:
  what shows `-` does not contribute to the score.
- The startup-reported security mode is honest: on such a host the server
  reports `landlock` (or lower), not `full`; `WarnDegraded` fires; strict/minimum
  mode validation evaluates against the real mode (fail-fast at startup rather
  than per-command failures later).
- The ptrace *capability* remains visible to operators in the flat
  `CAPABILITIES` section (`ptrace ✓`), with an actionable detail in the domain
  view explaining why the domain backend shows `-`.

## Non-Goals

- **No change to what actually gets installed at runtime.** The seccomp filter
  install is gated by config (`sandbox.seccomp.*.enabled`), not by the mode
  string. This design changes reporting + the mode-selection/validation gates
  only. A command that succeeded/failed before still does so.
- **No runtime seccomp→ptrace auto-fallback.** When seccomp can't install,
  command-control is simply reported as not enforced; the operator must enable
  ptrace explicitly to regain it. (Considered and explicitly deferred — see
  "Decisions" below.)
- **No change to `ComputeScore`'s semantics** (stays "full weight if any backend
  `Available`") and **no change to the darwin/windows domain builders.** Those
  builders omit `Active` on several domains, so reinterpreting `ComputeScore`
  around `Active` would zero their scores — out of scope and unnecessary here.
- No change to the `seccomp_user_notify` / `seccomp_user_notify_kernel`
  capability split from #388.

## Background

- `SelectMode()` (`internal/capabilities/security_caps.go:109`) is shared by
  **both** `agentsh detect` (`detect_linux.go:65,305`) and the server runtime
  (`internal/server/security.go:22`, via `DetectAndValidateSecurityMode`). It
  feeds: the reported mode, `WarnDegraded` (`security.go:40`, warns when
  `mode != ModeFull`), and `ValidateStrictMode`/`ValidateMinimumMode`
  (`security.go:26-37`). It does **not** gate the seccomp install — a grep for
  `ModeFull` / `mode == "full"` shows no install gate keys off it.
- `buildLinuxDomains` (`detect_linux.go:48`) is used **only** by `agentsh
  detect`. The server uses `DetectSecurityCapabilities` + `SelectMode` directly,
  not the domain builder. So the ptrace-backend and `commandActive` edits affect
  detect output only.
- `ComputeScore` (`internal/capabilities/detect_result.go:74`): each domain
  scores its full `Weight` if **any** backend has `Available == true`, else 0.
  Shared across linux/darwin/windows.
- `backwardCompatCaps` (`detect_linux.go:237`) sets `"ptrace": caps.Ptrace`
  directly from the capability flag and does **not** read the ptrace domain
  backend — so changing the domain backend's `Available` does not affect the
  `CAPABILITIES` map; `ptrace ✓` stays.
- `applyWrapperAvailability` (`detect_linux.go:165`) already re-derives Command
  Control's `Active` as `"ptrace"` only when `mode == ModePtrace`
  (`detect_linux.go:212`), consistent with the `commandActive` change below.
- In `agentsh detect`, `DetectSecurityCapabilities` never sets `PtraceEnabled`
  (it is a config-derived flag set in the server flow), so it is `false` in
  detect. The ptrace domain backend therefore shows `-` in `agentsh detect` on
  every host; the actionable detail explains this.

## Design

### 1. `SelectMode()` consumes installability

`internal/capabilities/security_caps.go`:

```go
func (c *SecurityCapabilities) SelectMode() string {
    // Full mode requires a seccomp NEW_LISTENER filter that actually installs
    // here, not merely kernel user-notify support (issue #390).
    if c.SeccompInstallable && c.EBPF && c.FUSE {
        return ModeFull
    }
    if c.Ptrace && c.PtraceEnabled {
        return ModePtrace
    }
    if c.Landlock && c.FUSE {
        return ModeLandlock
    }
    if c.Landlock {
        return ModeLandlockOnly
    }
    return ModeMinimal
}
```

Only the first condition changes (`c.Seccomp` → `c.SeccompInstallable`).

### 2. Honest Command Control backends in `buildLinuxDomains`

`internal/capabilities/detect_linux.go`.

Replace the hard-wired `commandActive` (currently `:66-69`) with a
priority chain mirroring the existing `networkActive` block:

```go
mode := caps.SelectMode()

commandActive := ""
if caps.SeccompInstallable {
    commandActive = "seccomp-execve"
} else if mode == ModePtrace {
    commandActive = "ptrace"
}
```

Add a helper for the ptrace backend detail:

```go
// ptraceBackendDetail explains the ptrace Command Control backend's verdict.
// ptrace enforcement is opt-in (config: sandbox ptrace mode), so detect — which
// is config-agnostic — reports the capability as present-but-not-active. The
// capability itself remains visible in the flat CAPABILITIES section
// (caps.Ptrace). Issue #390.
func ptraceBackendDetail(caps *SecurityCapabilities) string {
    if caps.Ptrace && caps.PtraceEnabled {
        return "" // actively enforcing; the ✓ speaks for itself
    }
    if caps.Ptrace {
        return "available, not active (enable ptrace mode)"
    }
    return "" // capability absent; the - speaks for itself
}
```

Change the ptrace backend in the Command Control domain (currently `:113`):

```go
{Name: "ptrace", Available: caps.Ptrace && caps.PtraceEnabled, Detail: ptraceBackendDetail(caps), Description: "syscall tracing", CheckMethod: "probe"},
```

The `seccomp-execve` backend is unchanged (`Available: caps.SeccompInstallable`,
from #388). `commandActive` continues to be assigned to the domain's `Active`.

### 3. `ComputeScore` — no change

With both Command Control backends now honest:
- seccomp installs here → `seccomp-execve` Available → Command Control 25.
- seccomp can't install, ptrace not actively enforcing → both backends
  unavailable → Command Control 0.
- seccomp can't install, ptrace actively enforcing (`Ptrace && PtraceEnabled`,
  `mode == ModePtrace`) → ptrace Available → Command Control 25, active=ptrace.

### Resulting Daytona output

```
COMMAND CONTROL                          0/25
  seccomp-execve  -  kernel supports user-notify, but NEW_LISTENER ...EBUSY  execve interception
  ptrace          -  available, not active (enable ptrace mode)              syscall tracing
```

No `active backend` line (`Active == ""`; `Table()` already suppresses
empty/`none`). Overall Protection Score drops by the Command Control weight
(e.g. 85 → 60). `CAPABILITIES` still shows `ptrace ✓`.

## Decisions

- **Honest reporting, not auto-fallback.** When seccomp can't install and ptrace
  is a present-but-unengaged capability, the fix reports Command Control as
  unenforced (active=none, 0/25) rather than auto-engaging ptrace. Auto-engaging
  ptrace is a larger runtime-enforcement change with real overhead and its own
  unverified behavior on the affected platforms; it is deferred.
- **`Available` means "counts toward this domain's protection."** Making the
  ptrace backend's `Available` track actual enforcement (rather than mere
  capability) keeps the `✓/-` marks, the `active backend` label, and the score
  mutually consistent — the exact inconsistency #390 reports. The capability is
  not lost; it remains in the `CAPABILITIES` section.
- **Linux-only, `ComputeScore` untouched.** The darwin/windows builders omit
  `Active` on several domains; an `Active`-based scorer would regress them.
  Keeping the any-backend scorer and fixing the linux backends' honesty avoids
  cross-platform scope and risk.

## Behavior changes

- On a host where seccomp can't install, the server reports `landlock`
  (or lower) instead of `full`; `WarnDegraded` (if configured) fires.
- `Security.Strict` (or `MinimumMode`) requiring a level seccomp can't provide
  now fails at **startup** rather than surfacing as per-command seccomp install
  failures later. This is the intended fail-fast.
- `agentsh detect` shows the ptrace Command Control backend as `-` with the
  detail `available, not active (enable ptrace mode)` (it is opt-in and detect
  is config-agnostic).

## Error handling

No new error paths. `SeccompInstallable` is already fail-safe (true only on a
clean exit-0 install probe; #388). The changes are pure boolean/label derivation.

## Testing

`internal/capabilities/security_caps_test.go`:
- `{Seccomp:true, SeccompInstallable:false, EBPF:true, FUSE:true}` ⇒ `SelectMode()`
  is **not** `ModeFull` (lands on `ModeLandlock`, since `Landlock`/`FUSE` per the
  case).
- `{SeccompInstallable:true, EBPF:true, FUSE:true}` ⇒ `ModeFull`.
- Update any existing case that set only `Seccomp:true` and expected `ModeFull`
  to also set `SeccompInstallable:true`.

`internal/capabilities/detect_linux_test.go`:
- ptrace backend `Available == false` when `{Ptrace:true, PtraceEnabled:false}`,
  and its `Detail == "available, not active (enable ptrace mode)"`.
- ptrace backend `Available == true` when `{Ptrace:true, PtraceEnabled:true}`.
- `commandActive`/Command Control `Active`:
  - `SeccompInstallable:true` ⇒ `"seccomp-execve"`.
  - `SeccompInstallable:false`, not ptrace mode ⇒ `""`.
- Integration: a Daytona-like `SecurityCapabilities`
  (`Seccomp:true, SeccompInstallable:false, FUSE:true, Landlock:true, EBPF:true,
  Ptrace:true, PtraceEnabled:false`) run through `buildLinuxDomains` +
  `ComputeScore` ⇒ Command Control domain `Score == 0`; the same caps with
  `SeccompInstallable:true` ⇒ Command Control `Score == 25`.
- Confirm a host with `SeccompInstallable:true` still reports
  `active backend: seccomp-execve` and Command Control 25 (no regression).

Confirm existing `internal/capabilities`, `internal/server` suites stay green,
darwin/windows detect tests are untouched, and `GOOS=windows go build ./...`
succeeds (the changed files are `//go:build linux`).

## Affected files

- `internal/capabilities/security_caps.go` — `SelectMode()` first condition.
- `internal/capabilities/detect_linux.go` — `commandActive` priority chain,
  `ptraceBackendDetail` helper, ptrace backend `Available`/`Detail`.
- Tests in `internal/capabilities/security_caps_test.go`,
  `internal/capabilities/detect_linux_test.go`.
- `ComputeScore`, darwin/windows builders, `backwardCompatCaps`, and the runtime
  install path are intentionally **unchanged**.
