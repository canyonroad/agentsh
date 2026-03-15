# Design: Fix Wait4 Conflict Between Ptrace Tracer and Go Runtime

**Date:** 2026-03-15
**Status:** Draft

---

## 1. Problem

When the ptrace tracer runs inside the agentsh server process (server wiring, Phase 5), the tracer's `Wait4(-1, ..., WNOHANG)` event loop races with Go's internal `wait4` used by `cmd.Wait()`. Both compete to reap child process exit events. When the tracer reaps a child's exit status, `cmd.Wait()` hangs forever because the exit event was already consumed.

This does not occur in standalone sidecar mode where the tracer runs in a separate OS process.

### Goals

- Traced processes complete reliably without `cmd.Wait()` hangs
- Exit codes, signals, and resource usage (CPU, memory) are preserved
- Fast-exiting processes don't drop notifications (post-attach; pre-attach race is separate future work)
- Multi-threaded process exit is handled correctly
- Tracer shutdown unblocks all pending waiters

### Non-Goals

- Fixing the pre-attach race window (separate future work — pipe barrier)
- Changing standalone sidecar mode behavior
- Windows/macOS support (ptrace is Linux-only)

## 2. Solution: Tracer-Managed Wait

Instead of calling `cmd.Wait()` for traced processes, the exec path registers an exit notification channel with the tracer and blocks on that. The tracer already detects process exit in `handleExit()` — it signals the channel with the exit status. The tracer owns the full wait lifecycle for all traced processes.

## 3. Exit Channel API

```go
type ExitReason int

const (
    ExitNormal       ExitReason = iota // process exited or was signaled (Code/Signal valid)
    ExitVanished                       // ESRCH — process disappeared (ptrace call failed)
    ExitTracerDown                     // tracer shut down while process was running
)

type ExitStatus struct {
    PID    int
    Code   int            // exit code (0-255) if Reason == ExitNormal
    Signal int            // signal number if killed, 0 otherwise
    Reason ExitReason
    Rusage *unix.Rusage   // resource usage from Wait4 (nil for ExitVanished/ExitTracerDown)
}

func (t *Tracer) RegisterExitNotify(pid int) <-chan ExitStatus
func (t *Tracer) UnregisterExitNotify(pid int)
```

`RegisterExitNotify` creates a buffered channel (size 1), stores it in `t.exitNotify sync.Map` keyed by PID (TGID), and returns the receive end.

### Registration Ordering

`RegisterExitNotify` MUST be called before the process can exit. The call is placed **before** `AttachPID` — this is safe because the process hasn't been attached to the tracer yet and therefore can't generate exit events through the tracer's event loop. By the time the tracer thread processes the attach request and resumes the tracee, the exit channel is already registered.

Updated `ptraceExecAttach` pseudocode:

```go
func ptraceExecAttach(tracer, pid, sessionID, commandID, keepStopped) (exitCh, resume, err) {
    exitCh = tr.RegisterExitNotify(pid)   // ← register BEFORE attach (process can't exit via tracer yet)
    tr.AttachPID(pid, opts...)            // ← enqueue (async)
    if err := tr.WaitAttached(pid); err != nil {
        tr.UnregisterExitNotify(pid)      // ← cleanup on failure
        return err
    }
    if keepStopped {
        return exitCh, func() { tr.ResumePID(pid) }, nil
    }
    return exitCh, func() {}, nil         // already resumed by attachThread
}
```

This ordering is race-free: `RegisterExitNotify` is a simple sync.Map store (no tracer-thread involvement). The tracer thread only sees the PID after processing the `attachQueue` entry. By that time, the exit channel is guaranteed to exist.

### Cleanup on Failure

If `WaitAttached` fails (timeout, ESRCH, tracer shutdown), the exit notify entry must be cleaned up. `ptraceExecAttach` calls `UnregisterExitNotify(pid)` (a simple `LoadAndDelete` on the sync.Map) on all error paths. This prevents stale entries from accumulating.

### Edge Cases

- **Duplicate registration**: Returns the existing channel if one is already registered for the PID (idempotent). Callers must not register the same PID from multiple goroutines concurrently.
- **PID reuse**: Safe because `RegisterExitNotify` is called for a specific known-alive process and consumed before the PID can be recycled. The sync.Map entry is deleted on dispatch or failure cleanup.
- **Late registration** (after exit): Cannot happen due to register-while-stopped ordering above.

## 4. Tracer-Side Exit Dispatch

### WaitStatus and Rusage Propagation

Change `Wait4` call to capture `Rusage`:

```go
var status unix.WaitStatus
var rusage unix.Rusage
tid, err := unix.Wait4(-1, &status, unix.WALL|unix.WNOHANG, &rusage)
```

Pass both `status`, `rusage`, and `reason` through `handleStop` → `handleExit`:

- `handleStop(ctx, tid, status)` → `handleStop(ctx, tid, status, &rusage)`
- `handleExit(tid)` → `handleExit(tid int, status unix.WaitStatus, rusage *unix.Rusage, reason ExitReason)`

Normal exits from `handleStop` pass `reason: ExitNormal`. ESRCH-triggered exits pass `ExitVanished`.

### Last-Thread Exit Notification

Notify when the **last thread** of a TGID exits, not when the leader exits. The leader can exit before other threads (via `pthread_exit` or `exec` in a non-leader thread). The existing `lastThread` logic in `handleExit` already computes this:

```go
func (t *Tracer) handleExit(tid int, status unix.WaitStatus, rusage *unix.Rusage, reason ExitReason) {
    t.mu.Lock()
    state := t.tracees[tid]
    var tgid int
    lastThread := true
    if state != nil {
        tgid = state.TGID
        // ... existing cleanup ...
        for _, other := range t.tracees {
            if other.TGID == tgid {
                lastThread = false
                break
            }
        }
    }
    t.mu.Unlock()

    // Notify exit waiters on last thread exit
    if state != nil && lastThread {
        if v, ok := t.exitNotify.LoadAndDelete(tgid); ok {
            ch := v.(chan ExitStatus)
            ch <- ExitStatus{
                PID:    tgid,
                Code:   exitCodeFromStatus(status),
                Signal: signalFromStatus(status),
                Reason: reason,
                Rusage: rusage,
            }
        }
        // ... existing fd/scratch cleanup ...
    }
}
```

### ESRCH Call Sites

The ~8 call sites that call `handleExit` on `ESRCH` errors (in `allowSyscall`, `denySyscall`, etc.) don't have a `WaitStatus` or `Rusage`. These are abnormal exits — the process vanished mid-operation. Pass `ExitVanished` reason:

```go
t.handleExit(tid, unix.WaitStatus(0), nil, ExitVanished)
```

At the exec layer, `ExitVanished` maps to exit code `-1` (matching Go's `ExitCode()` for signaled processes — the process is gone, most likely killed).

### Tracer Shutdown

On tracer shutdown (context cancelled or `Stop()` called), signal all pending exit channels with an error:

```go
func (t *Tracer) cancelPendingExitWaiters() {
    t.exitNotify.Range(func(key, value any) bool {
        ch := value.(chan ExitStatus)
        select {
        case ch <- ExitStatus{Reason: ExitTracerDown}:
        default:
        }
        t.exitNotify.Delete(key)
        return true
    })
}
```

Called from `defer` in `Run()`, alongside `cancelPendingAttachWaiters`.

## 5. Exec-Side Pipe Draining

`cmd.Wait()` also drains stdout/stderr pipes. Skipping it requires explicit pipe management.

Replace `os/exec`-managed pipes with explicit `os.Pipe()` pairs:

```go
stdoutR, stdoutW, _ := os.Pipe()
stderrR, stderrW, _ := os.Pipe()
cmd.Stdout = stdoutW
cmd.Stderr = stderrW

// After cmd.Start(), close write ends in parent
stdoutW.Close()
stderrW.Close()

// Drain in background
var wg sync.WaitGroup
wg.Add(2)
go func() { defer wg.Done(); io.Copy(stdoutCapture, stdoutR) }()
go func() { defer wg.Done(); io.Copy(stderrCapture, stderrR) }()

// Wait for exit from tracer, then drain pipes
exitStatus := <-exitCh
wg.Wait()
stdoutR.Close()
stderrR.Close()
cmd.Process.Release()
```

When the child exits, the kernel closes the write ends, the read goroutines drain and finish, and `wg.Wait()` completes. `cmd.Process.Release()` tells Go's runtime we're handling cleanup — it won't call `wait4`.

### Pipe Drain Failure

If `io.Copy` encounters a read error during drain, the output is truncated but the exit code is still reported correctly — drain errors are non-fatal. This matches the current `cmd.Wait()` behavior where stdout/stderr pipes are best-effort (kernel may truncate on SIGKILL).

If the context is cancelled (command timeout), the exec path kills the process group as it does today. The kill closes the write ends, draining completes, and `wg.Wait()` returns.

## 6. Resource Usage

Currently `resourcesFromProcessState(cmd.ProcessState)` extracts CPU and memory from `cmd.Wait()`'s `ProcessState.SysUsage()`. Without `cmd.Wait()`, `ProcessState` is nil.

Replace with `Rusage` from the exit notification. Add a helper:

```go
func resourcesFromRusage(ru *unix.Rusage) types.ExecResources {
    if ru == nil {
        return types.ExecResources{}
    }
    return types.ExecResources{
        CPUUserMs:    int64(ru.Utime.Sec)*1000 + int64(ru.Utime.Usec)/1000,
        CPUSystemMs:  int64(ru.Stime.Sec)*1000 + int64(ru.Stime.Usec)/1000,
        MemoryPeakKB: int64(ru.Maxrss),
    }
}
```

The `tracer == nil` path continues using `resourcesFromProcessState` unchanged.

## 7. Exit Code Mapping

Current code derives exit codes from `cmd.Wait()` error:
- `nil` → exit code 0
- `*exec.ExitError` → `ee.ExitCode()` (returns `-1` for signaled processes in Go)
- other error → exit code 127

With tracer-managed wait, derive from `ExitStatus` with the following compatibility mapping:

| Reason | Mapping | Compatibility |
|--------|---------|---------------|
| `ExitNormal`, not signaled | `status.Code` | Identical to `ee.ExitCode()` |
| `ExitNormal`, signaled | `-1` | Identical to `ee.ExitCode()` |
| `ExitVanished` | `-1` | New case (ESRCH); approximated as signaled. Current `cmd.Wait()` path never encounters this. |
| `ExitTracerDown` | `127` | Matches "other error" path in current code |

```go
switch status.Reason {
case ExitNormal:
    if status.Signal != 0 {
        return -1  // matches ee.ExitCode() for signaled processes
    }
    return status.Code
case ExitVanished:
    return -1      // process disappeared — intentional approximation as "signaled"
                   // (current cmd.Wait() path never encounters this case since Go
                   // runtime always reaps its own children successfully)
case ExitTracerDown:
    return 127     // infrastructure failure, matches "other error" path
}
```

This is **compatible** with current behavior for normal and signaled exits. `ExitVanished` is a new case that only occurs under ptrace (see compatibility table above).

Context deadline handling (timeout → kill → exit code 124) remains unchanged — the timeout check happens before reading the exit status.

## 8. Scope

### Changes

| File | Change |
|------|--------|
| `internal/ptrace/tracer.go` | Add `exitNotify sync.Map`, `ExitStatus`, `ExitReason`, `RegisterExitNotify()`, `UnregisterExitNotify()`. Change `Wait4` to capture `Rusage`. Change `handleExit` signature to accept `WaitStatus`, `*Rusage`, `ExitReason`. Dispatch on last-thread exit. Add `cancelPendingExitWaiters`. Update ~8 ESRCH call sites to pass `ExitVanished`. |
| `internal/api/exec.go` | When `tracer != nil`: explicit pipes, register exit notify, block on exit channel, drain pipes, `cmd.Process.Release()`, use `resourcesFromRusage`. Pipe drain errors are non-fatal (output may be truncated but exit code is still reported). |
| `internal/api/exec_stream.go` | Same changes for streaming exec path. |
| `internal/api/exec_ptrace_linux.go` | Update `ptraceExecAttach` to call `RegisterExitNotify` BEFORE `AttachPID`, return exit channel. Cleanup on failure via `UnregisterExitNotify`. |
| `internal/api/process_unix.go` | Add `resourcesFromRusage` alongside existing `resourcesFromProcessState`. |

### Unchanged

- `tracer == nil` path — still uses `cmd.Wait()`
- Wrap path — shell runs in CLI process, not the server
- Standalone sidecar mode — separate process, no conflict
- All other tracer internals except `handleExit` signature and `Wait4` rusage capture

### Testing

- **Unit**: `RegisterExitNotify` + `handleExit` dispatch with mock status/rusage
- **Fast-exit**: Process that exits immediately after resume — verify notification delivered
- **Multi-thread**: Process with multiple threads, leader exits first — verify notification on last thread
- **ESRCH vanished**: Trigger ESRCH-based exit — verify `Reason == ExitVanished` and exit code `-1`
- **Shutdown**: Cancel tracer context while exit notify is pending — verify `Reason == ExitTracerDown` and exit code `127`
- **Signal exit codes**: Kill process with SIGTERM, SIGKILL — verify exit code `-1` (matches `ee.ExitCode()`)
- **Normal exit codes**: Process exits with code 0, 1, 42 — verify exact match
- **Resource accuracy**: Compare `Rusage` values against `cmd.Wait()` path on CPU-bound workload
- **Cleanup on failure**: Attach failure after registration — verify `UnregisterExitNotify` cleans up
- **Registration before attach**: Verify exit channel exists in sync.Map before `AttachPID` is called
- **Regression**: Existing exec tests pass with `tracer == nil` path unchanged
- **Docker integration**: `make ptrace-test` passes; `make bench` completes ptrace mode
