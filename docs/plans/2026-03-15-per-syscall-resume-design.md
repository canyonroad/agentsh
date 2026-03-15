# Design: Per-Syscall Resume Optimization for Ptrace Prefilter

**Date:** 2026-03-15
**Status:** Draft

---

## 1. Problem

The seccomp prefilter BPF is installed in traced processes but has no performance effect. `allowSyscall` and `resumeTracee` always use `PtraceSyscall`, which traps every syscall exit — including non-traced syscalls that the BPF already allowed at entry. This makes prefilter vs no-prefilter nearly identical (~8-40x overhead vs baseline).

Only ~6 of the ~30 traced syscalls need exit processing:
- `read`, `pread64` — TracerPid masking
- `openat`, `openat2` — fd tracking for status/TLS files
- `connect` — TLS fd watching
- `close` — fd cleanup

The other ~24 traced syscalls (execve, unlinkat, kill, bind, etc.) only need entry handling and can be resumed with `PtraceCont`, skipping directly to the next BPF-matched entry.

## 2. Solution

Add `NeedExitStop bool` to `TraceeState`. At syscall entry, set it for the ~6 exit-needing syscalls. `allowSyscall` and `resumeTracee` check the flag:
- `HasPrefilter && !NeedExitStop` → `PtraceCont` (skip to next seccomp event)
- otherwise → `PtraceSyscall` (catch exit)

At syscall exit, clear `NeedExitStop`.

## 3. Changes

### `needsExitStop(nr int) bool`

New function:

```go
func needsExitStop(nr int) bool {
    switch nr {
    case unix.SYS_READ, unix.SYS_PREAD64,
         unix.SYS_OPENAT, unix.SYS_OPENAT2,
         unix.SYS_CONNECT, unix.SYS_CLOSE:
        return true
    }
    return false
}
```

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

**Only `internal/ptrace/tracer.go` changes.** No new files. ~30 lines changed.

| Location | Change |
|----------|--------|
| `TraceeState` | Add `NeedExitStop bool` |
| `needsExitStop()` | New function (~10 lines) |
| `handleSyscallStop` | Set `NeedExitStop` at entry, clear at exit |
| `handleSeccompStop` | Set `NeedExitStop` before dispatch |
| `allowSyscall` | Check `HasPrefilter && !NeedExitStop` for `PtraceCont` |
| `resumeTracee` | Same check |

**Unchanged**: `denySyscall` (deny fixup always needs exit stop via `PtraceSyscall`), `handleNewChild`, `inject.go`, `attach.go`, all API code.

## 5. Testing

- **Benchmark**: re-run 4-mode bench. Target: ptrace+prefilter within 2-3x of baseline (down from 8-40x)
- **Integration**: `make ptrace-test` — all 76 tests pass (exit handlers still work for read/openat/connect/close)
- **Unit**: verify `needsExitStop` returns true for the 6 syscalls
- **Regression**: TracerPid masking, fd tracking, TLS SNI still functional (these depend on exit stops for read/openat/connect)
