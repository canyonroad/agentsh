# Design: Per-Syscall Resume Optimization for Ptrace Prefilter

**Date:** 2026-03-15
**Status:** Draft

---

## 1. Problem

The seccomp prefilter BPF is installed in traced processes but has no performance effect. `allowSyscall` and `resumeTracee` always use `PtraceSyscall`, which traps every syscall exit — including non-traced syscalls that the BPF already allowed at entry. This makes prefilter vs no-prefilter nearly identical (~8-40x overhead vs baseline).

Only ~5 of the ~30 traced syscalls need exit processing:
- `read`, `pread64` — TracerPid masking (`handleReadExit`)
- `openat`, `openat2` — fd tracking for status/TLS files (`handleOpenatExit`)
- `connect` — TLS fd watching (`handleConnectExit`)

Note: `close` is entry-only (fd cleanup in `handleClose` happens at entry). `execve` generates `PTRACE_EVENT_EXEC` (a ptrace event, not a syscall stop) which fires regardless of `PtraceCont` vs `PtraceSyscall`.

The other ~25+ traced syscalls only need entry handling and can be resumed with `PtraceCont`, skipping directly to the next BPF-matched entry.

### Denied/redirected syscalls

`denySyscall` and `redirectExec` already use `PtraceSyscall` directly (they don't go through `allowSyscall`). They set `PendingDenyErrno`, `PendingFakeZero`, `HasPendingReturn`, or `PendingExecStubFD` and always catch the exit for fixup. This optimization only affects `allowSyscall` (allowed syscalls).

## 2. Solution

Add `NeedExitStop bool` to `TraceeState`. At syscall entry, set it for the ~5 exit-needing syscalls. `allowSyscall` and `resumeTracee` check the flag:
- `HasPrefilter && !NeedExitStop` → `PtraceCont` (skip to next seccomp event)
- otherwise → `PtraceSyscall` (catch exit)

At syscall exit, clear `NeedExitStop`.

## 3. Changes

### `needsExitStop(nr int) bool`

New function, derived from actual exit handlers in the codebase:

```go
func needsExitStop(nr int) bool {
    switch nr {
    case unix.SYS_READ, unix.SYS_PREAD64,      // handleReadExit (TracerPid masking)
         unix.SYS_OPENAT, unix.SYS_OPENAT2,     // handleOpenatExit (fd tracking)
         unix.SYS_CONNECT,                       // handleConnectExit (TLS fd watch)
         unix.SYS_EXECVE, unix.SYS_EXECVEAT:     // exec failure needs exit to reset InSyscall
        return true
    }
    return false
}
```

Not included:
- `close` — entry-only handler (`handleClose`)
- `write` — entry-only for TLS SNI rewrite
- `sendto` — entry-only for DNS redirect
- All file/signal/network syscalls — entry-only policy evaluation

Note on execve: successful exec generates `PTRACE_EVENT_EXEC` (fires with `PtraceCont`, resets state via `handleExecEvent`). Failed exec needs the exit stop to reset `InSyscall` — without it, the next seccomp entry would be misclassified as exit. So execve is in the exit-needing set.

### `TraceeState`

Add `NeedExitStop bool`.

### `handleSyscallStop` (entry path)

After determining `entering == true` and reading `nr`, set the flag:

```go
if entering && needsExitStop(nr) {
    state.NeedExitStop = true
}
```

At exit (`entering == false`), clear it:

```go
state.NeedExitStop = false
```

### `handleSeccompStop`

Same — set `NeedExitStop` before dispatching:

```go
if needsExitStop(nr) {
    state.NeedExitStop = true
}
```

### `allowSyscall(tid)`

```go
func (t *Tracer) allowSyscall(tid int) {
    t.mu.Lock()
    hasPrefilter := false
    needExit := false
    if s := t.tracees[tid]; s != nil {
        hasPrefilter = s.HasPrefilter
        needExit = s.NeedExitStop
    }
    t.mu.Unlock()

    var err error
    if hasPrefilter && !needExit {
        err = unix.PtraceCont(tid, 0)
    } else {
        err = unix.PtraceSyscall(tid, 0)
    }
    if err != nil && errors.Is(err, unix.ESRCH) {
        t.handleExit(tid, unix.WaitStatus(0), nil, ExitVanished)
    }
}
```

### `resumeTracee(tid, sig)`

Same pattern:

```go
func (t *Tracer) resumeTracee(tid int, sig int) {
    t.mu.Lock()
    hasPrefilter := false
    needExit := false
    if s := t.tracees[tid]; s != nil {
        hasPrefilter = s.HasPrefilter
        needExit = s.NeedExitStop
    }
    t.mu.Unlock()

    if hasPrefilter && !needExit {
        unix.PtraceCont(tid, sig)
    } else {
        unix.PtraceSyscall(tid, sig)
    }
}
```

## 4. Scope

**Only `internal/ptrace/tracer.go` changes.** No new files. ~40 lines changed.

| Location | Change |
|----------|--------|
| `TraceeState` | Add `NeedExitStop bool` |
| `needsExitStop()` | New function (~10 lines) |
| `handleSyscallStop` | Set `NeedExitStop` at entry, clear at exit |
| `handleSeccompStop` | Set `NeedExitStop` before dispatch |
| `allowSyscall` | Check `HasPrefilter && !NeedExitStop` for `PtraceCont` |
| `resumeTracee` | Same check |

**Unchanged:**
- `denySyscall` — always uses `PtraceSyscall` directly (sets pending fixup states)
- `redirectExec` — always uses `PtraceSyscall` directly
- `handleNewChild` — `NeedExitStop` defaults to false (correct for new children)
- `inject.go`, `attach.go` — no changes
- All API code — no changes

## 5. Testing

- **Benchmark**: re-run 4-mode bench. Target: ptrace+prefilter within 2-3x of baseline (down from 8-40x)
- **Integration**: `make ptrace-test` — all 76 tests pass
- **Regression — exit handlers**: TracerPid masking (`TestIntegration_TracerPidMasked`), DNS redirect (`TestIntegration_DNSConnectRedirect`), connect redirect (`TestIntegration_ConnectRedirect`) — depend on read/connect exit handlers
- **Regression — deny/redirect**: exec deny (`TestIntegration_ExecveDeny`), file deny (`TestIntegration_FileDeny`), exec redirect — use `denySyscall`/`redirectExec` which bypass `allowSyscall` and always use `PtraceSyscall`
- **Regression — exec**: successful exec (`TestIntegration_ExecveAllow`) — state alignment after `PTRACE_EVENT_EXEC` with `PtraceSyscall` for exec exit
- **Unit**: verify `needsExitStop` returns true for exactly the 7 syscalls (read, pread64, openat, openat2, connect, execve, execveat)
