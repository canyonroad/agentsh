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
- Fast-exiting processes don't drop notifications
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
type ExitStatus struct {
    PID    int
    Code   int            // exit code (0-255) or -1 if signaled
    Signal int            // signal number if killed, 0 otherwise
    Rusage *unix.Rusage   // resource usage from Wait4 (CPU time, peak memory)
    Err    error          // non-nil on tracer shutdown or internal failure
}

func (t *Tracer) RegisterExitNotify(pid int) <-chan ExitStatus
```

`RegisterExitNotify` creates a buffered channel (size 1), stores it in `t.exitNotify sync.Map` keyed by PID (TGID), and returns the receive end.

### Registration Ordering

`RegisterExitNotify` MUST be called before the process is resumed (before `ResumePID` or before the non-keepStopped `attachThread` calls `PtraceSyscall`). This guarantees the channel is registered before the process can exit. The exec path already has this ordering naturally:

```
cmd.Start()
  → ptraceExecAttach (AttachPID + WaitAttached, process is stopped)
  → RegisterExitNotify(pid)     ← register while stopped
  → hook (cgroup) if any
  → ResumePID or auto-resume    ← process can now exit
  → <-exitCh                    ← wait for exit
```

For the non-keepStopped path (no cgroup hook), `attachThread` resumes the process at the end of attachment. To ensure registration happens first, `ptraceExecAttach` calls `RegisterExitNotify` between `AttachPID` and `WaitAttached` — the process is stopped by `PTRACE_INTERRUPT` during attachment, so it cannot exit until `attachThread` resumes it after `WaitAttached` returns.

### Edge Cases

- **Duplicate registration**: Second call for the same PID overwrites the channel. Previous channel receives nothing (caller's problem — don't register twice).
- **PID reuse**: Safe because `RegisterExitNotify` is called for a specific known-alive process and consumed before the PID can be recycled. The sync.Map entry is deleted on dispatch.
- **Late registration** (after exit): Cannot happen due to register-before-resume ordering above.

## 4. Tracer-Side Exit Dispatch

### WaitStatus and Rusage Propagation

Change `Wait4` call to capture `Rusage`:

```go
var status unix.WaitStatus
var rusage unix.Rusage
tid, err := unix.Wait4(-1, &status, unix.WALL|unix.WNOHANG, &rusage)
```

Pass both `status` and `rusage` through `handleStop` → `handleExit`:

- `handleStop(ctx, tid, status)` → `handleStop(ctx, tid, status, &rusage)`
- `handleExit(tid)` → `handleExit(tid, status, rusage *unix.Rusage)`

### Last-Thread Exit Notification

Notify when the **last thread** of a TGID exits, not when the leader exits. The leader can exit before other threads (via `pthread_exit` or `exec` in a non-leader thread). The existing `lastThread` logic in `handleExit` already computes this:

```go
func (t *Tracer) handleExit(tid int, status unix.WaitStatus, rusage *unix.Rusage) {
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
                Rusage: rusage,
            }
        }
        // ... existing fd/scratch cleanup ...
    }
}
```

### ESRCH Call Sites

The ~8 call sites that call `handleExit` on `ESRCH` errors (in `allowSyscall`, `denySyscall`, etc.) don't have a `WaitStatus` or `Rusage`. These are abnormal exits detected via failed ptrace calls, not via `Wait4`. Pass zero values: `handleExit(tid, unix.WaitStatus(0), nil)`. The exit notification will have `Code: 0, Signal: 0, Rusage: nil` — callers should treat this as an abnormal exit (the process vanished).

### Tracer Shutdown

On tracer shutdown (context cancelled or `Stop()` called), signal all pending exit channels with an error:

```go
func (t *Tracer) cancelPendingExitWaiters() {
    t.exitNotify.Range(func(key, value any) bool {
        ch := value.(chan ExitStatus)
        select {
        case ch <- ExitStatus{Err: fmt.Errorf("tracer shutting down")}:
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

If the context is cancelled (command timeout), the exec path kills the process group as it does today. The kill closes the write ends, draining completes, and `wg.Wait()` returns. No special handling needed.

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
- `*exec.ExitError` → `ee.ExitCode()`
- other error → exit code 127

With tracer-managed wait, derive from `ExitStatus`:
- `status.Err != nil` → exit code 127 (tracer failure)
- `status.Signal != 0` → exit code 128 + signal (standard convention)
- otherwise → `status.Code`

Context deadline handling (timeout → kill → exit code 124) remains unchanged — the timeout check happens before reading the exit status.

## 8. Scope

### Changes

| File | Change |
|------|--------|
| `internal/ptrace/tracer.go` | Add `exitNotify sync.Map`, `ExitStatus`, `RegisterExitNotify()`. Change `Wait4` to capture `Rusage`. Change `handleExit` signature to accept `WaitStatus` and `*Rusage`. Dispatch on last-thread exit. Add `cancelPendingExitWaiters`. |
| `internal/api/exec.go` | When `tracer != nil`: explicit pipes, register exit notify, block on exit channel, drain pipes, `cmd.Process.Release()`, use `resourcesFromRusage`. |
| `internal/api/exec_stream.go` | Same changes for streaming exec path. |
| `internal/api/exec_ptrace_linux.go` | Helper wrapping pipe setup + exit wait to avoid duplication. Move `RegisterExitNotify` call into `ptraceExecAttach`. |
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
- **Shutdown**: Cancel tracer context while exit notify is pending — verify `Err` delivered
- **Resource accuracy**: Compare `Rusage` values against known workload (CPU-bound loop)
- **Regression**: Existing exec tests pass with `tracer == nil` path unchanged
- **Docker integration**: `make ptrace-test` passes; `make bench` completes ptrace mode
