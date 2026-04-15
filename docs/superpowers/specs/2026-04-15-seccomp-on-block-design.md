# Seccomp `on_block` Config — Honoring the Advertised Schema

**Status:** Draft (spec)
**Date:** 2026-04-15
**Author:** Eran Sandler (w/ Claude)
**Target environment:** Ubuntu 24.04 arm64 (Mac Virtualization Framework guest) and all other supported Linux targets

## Problem

`sandbox.seccomp.syscalls.on_block` is parsed and defaulted but never wired into filter construction.

| Artifact | Location | State |
|---|---|---|
| YAML field | `internal/config/config.go:496` | Declared, parsed |
| Default | `internal/config/config.go:1159-1160` | `"kill"` |
| Schema doc | `docs/seccomp.md:38` | `kill \| log_and_kill` |
| Actual filter action | `internal/netmonitor/unix/seccomp_linux.go:334` | Hardcoded `ActErrno(EPERM)` |
| Value consumed in filter build? | — | **No.** Grep across repo confirms `OnBlock` is referenced only by the struct field, its default, and one test. |

Downstream consequences:

1. Setting `on_block: kill` does nothing. Operators get silent EPERM.
2. Setting `on_block: log_and_kill` does nothing. No audit record, no kill.
3. Kill-list denials never reach `OnBlocked` hooks (RET_ERRNO is kernel-side; user-notify never fires for these rules), so agentsh's own event store has no record of a blocked `ptrace`/`mount`/etc.
4. `docs/seccomp.md:11` still claims "Immediately terminates processes that attempt blocked syscalls" — inaccurate since commit `b6708353` (Mar 26, 2026) deliberately switched to EPERM for Docker-profile compatibility.

The intent of `b6708353` (graceful EPERM for block-list) was correct as a default, but the config surface was not updated to reflect it and no alternative action (hard kill, audit) was made reachable.

## Goals

- Make `on_block` semantically real: the configured value determines the filter action.
- Preserve today's runtime behavior as the default (no behavior change for deployments that never set `on_block` or left it empty).
- Give operators access to hard-kill and audit modes without cross-session changes to unix-socket / file-monitor / signal paths.
- Keep silent modes (`errno`, `kill`) on the kernel fast path. No user-notify hop unless the operator asks for visibility.
- Update `docs/seccomp.md` so the advertised schema matches reality.

## Non-goals

- Kernel audit-subsystem (`auditd`) integration. `SCMP_ACT_LOG` is not used. The audit surface is agentsh's own event store.
- Per-syscall action overrides (`ptrace: kill, mount: errno`). Single global `on_block`.
- Refactoring `BlockedSyscalls` from `[]int` to a richer struct.
- Changes to unix-socket, file-monitor, signal, or metadata filter paths.

## Design

### Action semantics

Four legal values for `on_block`:

| Value | Kernel action | Userspace behavior | Event emitted |
|---|---|---|---|
| `errno` *(new default)* | `SCMP_ACT_ERRNO(EPERM)` | none — kernel returns EPERM | **no** |
| `kill` | `SCMP_ACT_KILL_PROCESS` | none — kernel kills with SIGSYS | **no** (process is dead) |
| `log` | `SCMP_ACT_NOTIFY` | handler emits event, responds with EPERM | `syscall_blocked` (`outcome=denied`) |
| `log_and_kill` | `SCMP_ACT_NOTIFY` | handler emits event, kills via pidfd, responds with EPERM | `syscall_blocked` (`outcome=killed`) |

The default shifts from `"kill"` to `"errno"` so that upgrading without touching the config produces zero behavioral change. The prior default was aspirational — it never actually mapped to kill in runtime code.

### Config validation

`internal/config/config.go`'s validator rejects unknown `on_block` values with an error listing the four legal values. Today the field silently accepts garbage.

```go
switch cfg.Sandbox.Seccomp.Syscalls.OnBlock {
case "", "errno", "kill", "log", "log_and_kill":
    // ok; "" defaulted to "errno" by existing default-filler
default:
    return fmt.Errorf("invalid sandbox.seccomp.syscalls.on_block %q: must be one of errno, kill, log, log_and_kill",
        cfg.Sandbox.Seccomp.Syscalls.OnBlock)
}
```

### Propagation

`OnBlock` threads from config into the seccomp filter-build config:

```
cfg.Sandbox.Seccomp.Syscalls.OnBlock (string)
  │ translate in internal/api/wrap.go:154 and internal/api/core.go:205
  ▼
seccomp.Config.OnBlock (new typed enum: OnBlockErrno | OnBlockKill | OnBlockLog | OnBlockLogAndKill)
  │
  ▼
internal/netmonitor/unix/seccomp_linux.go buildFilter()
```

`internal/seccomp/filter.go` gains an `OnBlock` field on the config struct. `internal/netmonitor/unix/seccomp_linux.go` `Config` gains an `OnBlockAction` field of the same type. The `BlockedSyscalls []int` field stays as-is.

### Filter construction

The current block-list loop at `seccomp_linux.go:334` is replaced with a switch on `OnBlockAction`:

```go
switch cfg.OnBlockAction {
case OnBlockErrno:
    action := seccomp.ActErrno.SetReturnCode(int16(unix.EPERM))
    for _, nr := range cfg.BlockedSyscalls {
        _ = filt.AddRule(seccomp.ScmpSyscall(nr), action)
    }
case OnBlockKill:
    for _, nr := range cfg.BlockedSyscalls {
        _ = filt.AddRule(seccomp.ScmpSyscall(nr), seccomp.ActKillProcess)
    }
case OnBlockLog, OnBlockLogAndKill:
    for _, nr := range cfg.BlockedSyscalls {
        _ = filt.AddRule(seccomp.ScmpSyscall(nr), seccomp.ActNotify)
    }
    // Dispatch table populated so the notify handler can distinguish
    // block-list syscalls from file/unix/signal/metadata ones.
    for _, nr := range cfg.BlockedSyscalls {
        f.blockList[nr] = cfg.OnBlockAction
    }
default:
    // Defense-in-depth: log warning, fall through to errno.
    slog.Warn("seccomp: unknown on_block action; defaulting to errno",
        "value", cfg.OnBlockAction)
    // ...same as OnBlockErrno branch
}
```

Unknown action at build time degrades to `errno` rather than erroring out — prevents a broken config from producing an open filter.

### Dispatch in the notify handler

The notify loop lives in `internal/netmonitor/unix/handler.go` (`ServeNotify` and `ServeNotifyWithExecve`). Both gain a dispatch-by-syscall-nr check before the existing file/unix/signal/metadata dispatch. The block-list map (`map[uint32]OnBlockAction`, keyed by syscall number) is stored on the `Filter` struct at filter-build time and passed into the serve functions alongside the notify fd.

```go
if action, ok := filter.blockList[req.Data.Nr]; ok {
    handleBlockListNotify(int(fd), req, action, hooks)
    continue
}
// ... existing file/unix/signal/metadata dispatch
```

`handleBlockListNotify` performs:

1. `SECCOMP_IOCTL_NOTIF_ID_VALID(req.ID)` — if not valid (process already dead), `NotifRespondDeny` with EPERM and return without emitting an event. Matches existing file-monitor convention.
2. Resolve syscall name via `seccomp.ScmpSyscall(req.Data.Nr).GetString()`.
3. For `OnBlockLogAndKill` only: open pidfd and send SIGKILL, recording outcome:
   - `pidfd, err := pidfdOpenFn(int(req.Pid))` (function-pointer indirection for test seam — see Testing).
   - On success: `pidfdSendSignalFn(pidfd, unix.SIGKILL)`, `unix.Close(pidfd)`. If signal send succeeds, `outcome = "killed"`. If it fails with `ESRCH`, `outcome = "killed"` (process already dying from prior SIGKILL or equivalent; honor the caller's intent). Any other signal-send error → `outcome = "denied"` with a warning log.
   - On `pidfdOpen` failure with `ESRCH`: `outcome = "killed"` (same reasoning — process is dying).
   - On `pidfdOpen` failure with any other errno: `outcome = "denied"` with a warning log.
   - For `OnBlockLog`: `outcome = "denied"` unconditionally.
4. Build `IOEvent{Type: EventSyscallBlocked, ...}`, invoke `hooks.OnBlocked`. If `hooks.OnBlocked == nil`, skip invocation (startup warning already fired — see Rollout).
5. `NotifRespondDeny(fd, req.ID, int32(unix.EPERM))` unconditionally. For `log_and_kill`, this unblocks the suspended syscall so SIGKILL delivery proceeds; the EPERM return is never observed because the process dies before returning to userspace. `ENOENT` on `NotifRespondDeny` → debug log, no-op (process already reaped).

**Ordering rationale (`log_and_kill`):** kill first, respond second. If we respond first, the kernel resumes the syscall (returns EPERM), and the process may complete its syscall and exit through another path before SIGKILL is delivered — making `outcome=killed` false for observers.

### Event schema

New event type in `internal/events/types.go`:

```go
EventSyscallBlocked EventType = "syscall_blocked"
```

Payload shape:

```json
{
  "type": "syscall_blocked",
  "timestamp": "2026-04-15T18:03:11Z",
  "session_id": "sess_abc123",
  "pid": 12345,
  "syscall": "ptrace",
  "syscall_nr": 101,
  "action": "log_and_kill",
  "outcome": "killed",
  "arch": "aarch64"
}
```

- `syscall` + `syscall_nr` both included — arm64 vs amd64 drift in numeric values, forensics want both.
- `outcome` separates config from effect (`"denied"` = syscall returned EPERM; `"killed"` = process received SIGKILL).
- No syscall arguments captured. Block-list syscalls are categorical denials; arg detail is noise and requires `process_vm_readv` / `seccomp_notif_addfd` cost we don't need.

### arm64 / libseccomp resolution

`BlockedSyscalls` is built by `internal/seccomp/filter.go` by resolving names through `seccomp.GetSyscallFromName`. If a name fails to resolve on the current arch, it's silently skipped today. In-scope for this change: emit a one-time startup warning listing any names that failed to resolve. Minimum fix; not a full refactor of the type.

Tested explicitly on arm64 Ubuntu 24.04 (target environment) plus x86_64 CI.

### pidfd helper

`internal/netmonitor/unix/pidfd_linux.go` (new, small):

```go
//go:build linux

package unix

import (
    gounix "golang.org/x/sys/unix"
)

// Test seams — override in _test.go files to inject failures.
var (
    pidfdOpenFn       = pidfdOpen
    pidfdSendSignalFn = pidfdSendSignal
)

func pidfdOpen(pid int) (int, error) {
    r, _, errno := gounix.Syscall(gounix.SYS_PIDFD_OPEN, uintptr(pid), 0, 0)
    if errno != 0 { return -1, errno }
    return int(r), nil
}

func pidfdSendSignal(pidfd int, sig gounix.Signal) error {
    _, _, errno := gounix.Syscall6(gounix.SYS_PIDFD_SEND_SIGNAL,
        uintptr(pidfd), uintptr(sig), 0, 0, 0, 0)
    if errno != 0 { return errno }
    return nil
}
```

Both syscalls are kernel 5.3+ (far below Ubuntu 24.04's 6.8). Not added to the `unix` stdlib wrapper to avoid a broader refactor — local helper is sufficient. The `*Fn` indirections give test code a seam for simulating `ESRCH`, `EPERM`, and success without spawning real processes.

## Error handling and edge cases

| Case | Handling |
|---|---|
| `NotifRespondDeny` returns `ENOENT` (process exited mid-dispatch) | Debug log, swallow, no event (event already built and emitted at step 4 before step 5's respond call — so the event does land; the `ENOENT` just reports that the reply was unnecessary) |
| `pidfd_open` returns `ESRCH` | `outcome = "killed"` (process is dying, honor the intent); debug log; proceed to emit event and respond |
| `pidfd_open` returns any other errno | `outcome = "denied"`; warning log; proceed to emit event and respond |
| `pidfd_send_signal` returns `ESRCH` | `outcome = "killed"` (process died between open and signal — still counts); debug log |
| `pidfd_send_signal` returns any other errno | `outcome = "denied"`; warning log |
| Unknown `OnBlock` value at runtime | Degrade to `errno` action with warning log; don't crash |
| Syscall name unresolved on arch (at filter build) | Silently skipped today; spec adds one-time startup warning listing skipped names |
| `WaitKillable` flag rejected at filter load | Existing `loadWithRetryOnWaitKillFailure` at `seccomp_linux.go:386` handles retry; unchanged |
| Hook consumer absent but `log` / `log_and_kill` selected | Startup warning: "on_block=log selected but no OnBlocked hook configured; events will be dropped"; filter still builds and runs (EPERM/kill semantics still apply) |
| Default empty `on_block` | Existing default-filler at `config.go:1159` sets `"errno"` (change from `"kill"`) |

## Testing

Four tiers. Names reference existing test files where they'll be extended.

### Tier 1 — Config parsing and validation

File: `internal/config/seccomp_test.go`

- `TestOnBlockDefaultsToErrno` — empty config → `OnBlock == "errno"` (regression-gates the default change).
- `TestOnBlockExplicitValues` — each of `errno`, `kill`, `log`, `log_and_kill` parses from YAML, round-trips through validation, and surfaces on `cfg.Sandbox.Seccomp.Syscalls.OnBlock` with the exact input string.
- `TestOnBlockRejectsUnknown` — `on_block: banana` → validation error mentioning all four legal values.
- `TestOnBlockLegacyKillValueAccepted` — existing configs that set `on_block: kill` still validate and activate the real kill path (documents the semantic change for any early adopter).

### Tier 2 — Filter construction

File: `internal/netmonitor/unix/seccomp_linux_test.go`

- `TestBuildFilterOnBlockErrno` — filter for `errno` installs `ActErrno(EPERM)` rules for every entry in `BlockedSyscalls`.
- `TestBuildFilterOnBlockKill` — filter for `kill` installs `ActKillProcess` rules.
- `TestBuildFilterOnBlockLog` — filter for `log` installs `ActNotify` rules AND populates the `blockList` dispatch map with `OnBlockLog`.
- `TestBuildFilterOnBlockLogAndKill` — same as above with `OnBlockLogAndKill`.
- `TestBuildFilterUnknownOnBlockDegradesToErrno` — pass a nonsense action, assert rules are ErrnoEPERM AND a warning was logged.
- `TestBuildFilterUnresolvedSyscallWarns` — pass a block-list containing an unresolvable name; assert filter builds successfully AND a warning was logged listing the skipped name. Exercises the new arm64-resolution warning path.

### Tier 3 — Behavioral integration (Linux-only, `//go:build linux`)

File: `internal/integration/seccomp_wrapper_test.go`

Each subtest spawns a child under the wrapper with `block: [ptrace]` plus one `on_block` value, then observes the child.

- `TestOnBlockErrno_ReturnsEPERM` — child `ptrace(PTRACE_TRACEME)` returns `-1 errno=EPERM`; child exits 0; no event fires.
- `TestOnBlockKill_ChildDiesWithSIGSYS` — child `ptrace` triggers SIGSYS; `syscall.WaitStatus.Signal() == SIGSYS`; no event fires.
- `TestOnBlockLog_EventFiresAndEPERMReturned` — child `ptrace` returns EPERM; exactly one `syscall_blocked` event captured with `outcome=denied`, `syscall=ptrace`, matching pid and arch.
- `TestOnBlockLogAndKill_EventFiresAndChildKilled` — child `ptrace` causes child death by SIGKILL; exactly one `syscall_blocked` event with `outcome=killed`; wait status confirms SIGKILL not SIGSYS.
- `TestOnBlockLogAndKill_ConcurrentCalls` — child spawns 100 goroutines all calling `ptrace`; exactly one event captured (the race winner); process dies; no deadlock; test completes within 5s.
- `TestOnBlockLog_ExternalKillDuringDispatch` — stall the notify handler on a test-controlled signal, external `kill(pid, SIGKILL)` between receive and dispatch, then release. Handler must: (a) not panic, (b) still call `NotifRespondDeny` (harmless `ENOENT` swallowed), (c) emit an event *or* swallow it — either is acceptable because the race is real — but the event, if emitted, must have valid non-stale fields (syscall name, pid, outcome).
- `TestOnBlockLogAndKill_PidfdOpenFails` — override `pidfdOpenFn` test seam to return `ESRCH`; assert event is emitted with `outcome=killed` (spec says ESRCH means process is dying, honor intent), NotifRespondDeny still sent, no hang, no panic. Repeat with `pidfdOpenFn` returning `EPERM` and assert `outcome=denied` with a warning log.
- `TestOnBlockLogAndKill_PidfdSendSignalFails` — `pidfdOpenFn` succeeds but `pidfdSendSignalFn` returns `EINVAL`; assert `outcome=denied` and warning log. Signals `ESRCH` from sendSignal → `outcome=killed`.
- `TestOnBlockMode_DoesNotAffectFileMonitor` — with `on_block: log_and_kill` and `file_monitor: enabled`, trigger a file-monitor deny; assert file-deny path unchanged (returns EACCES, `file_blocked` event fires, NOT `syscall_blocked`).
- `TestOnBlockMode_DoesNotAffectUnixSocket` — symmetric check for unix socket interception.
- `TestOnBlockMode_DoesNotAffectSignalFilter` — symmetric check for signal filter.

### Tier 4 — Multi-arch smoke

File: `internal/integration/seccomp_wrapper_test.go`

- `TestOnBlock_Arm64SyscallResolution` — on any arch, assert `seccomp.GetSyscallFromName("ptrace") > 0`, `seccomp.GetSyscallFromName("mount") > 0`, and every entry in the default block-list resolves. Breaks loudly if a future libseccomp drops arm64 resolution for one of the defaults.
- Gate the behavioral tests (Tier 3) so they run on both amd64 and arm64 in CI — existing matrix already covers both.

### Coverage summary

| Code path | Covered by |
|---|---|
| Config: default, each explicit value, invalid value, legacy `kill` | Tier 1 |
| Filter build: all four actions + degrade + unresolved-name warning | Tier 2 |
| Runtime: `errno` path | Tier 1 + Tier 3 |
| Runtime: `kill` path (SIGSYS death) | Tier 3 |
| Runtime: `log` path (event + EPERM) | Tier 3 |
| Runtime: `log_and_kill` path (event + SIGKILL) | Tier 3 |
| Concurrency / race handling | Tier 3 |
| pidfd error handling | Tier 3 |
| Non-interference with other seccomp subsystems | Tier 3 |
| arm64 resolution | Tier 4 |

No untested branch in the new code.

## Rollout

- **Behavioral change:** for deployments that never set `on_block` explicitly, none (current EPERM behavior preserved as new default `errno`). For deployments that explicitly set `on_block: kill` expecting the advertised schema, behavior becomes real kill — call out in PR description.
- **No config migration required.** Field stays optional.
- **Startup warning** when `on_block` is `log` / `log_and_kill` but no `OnBlocked` hook is registered, so silent event drops don't surprise operators.
- **No new external dependencies.** libseccomp 2.5.5 (existing floor) supports `SCMP_ACT_KILL_PROCESS` and `SCMP_ACT_NOTIFY`. `pidfd_*` syscalls are kernel 5.3+, well under Ubuntu 24.04's 6.8.

## Doc updates

- `docs/seccomp.md:11` — replace "Immediately terminates processes that attempt blocked syscalls" with "Denies (and optionally kills) processes that attempt blocked syscalls."
- `docs/seccomp.md:38` — expand schema to `errno | kill | log | log_and_kill`, note the default.
- `docs/seccomp.md` — add "Syscall Block Actions" section with the value-→-behavior table from the design.
- `docs/agent-multiplatform-spec.md` — grep for `on_block`, update any references.
- Event-schema: add `syscall_blocked` entry to the docblock in `internal/events/types.go` and to `docs/spec.md` (same locations where `signal_blocked` / `unix_socket_blocked` already live).

## Implementation verification notes

1. Notify-handler dispatch lives in `internal/netmonitor/unix/handler.go` (`ServeNotify` / `ServeNotifyWithExecve`) — confirmed.
2. The `OnBlockAction` enum will live in `internal/seccomp/filter.go` (abstract layer) so both the wrapper and in-process seccomp paths can share it. The concrete `Filter` struct in `internal/netmonitor/unix/seccomp_linux.go` gains a `blockList map[uint32]OnBlockAction` field populated at filter-build time.
3. Event schema doc will land in the `internal/events/types.go` docblock (colocated with existing event-type constants) plus a row in `docs/spec.md` — both already enumerate the other `*_blocked` event shapes.
