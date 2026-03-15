# Design: Fix Wait4 Conflict Between Ptrace Tracer and Go Runtime

**Date:** 2026-03-15
**Status:** Draft

---

## 1. Problem

When the ptrace tracer runs inside the agentsh server process (server wiring, Phase 5), the tracer's `Wait4(-1, ..., WNOHANG)` event loop races with Go's internal `wait4` used by `cmd.Wait()`. Both compete to reap child process exit events. When the tracer reaps a child's exit status, `cmd.Wait()` hangs forever because the exit event was already consumed.

This does not occur in standalone sidecar mode where the tracer runs in a separate OS process.

## 2. Solution: Tracer-Managed Wait

Instead of calling `cmd.Wait()` for traced processes, the exec path registers an exit notification channel with the tracer and blocks on that. The tracer already detects process exit in `handleExit()` — it signals the channel with the exit status. The tracer owns the full wait lifecycle for all traced processes.

## 3. Exit Channel API

```go
type ExitStatus struct {
    PID    int
    Code   int  // exit code (0-255) or -1 if signaled
    Signal int  // signal number if killed, 0 otherwise
}

func (t *Tracer) RegisterExitNotify(pid int) <-chan ExitStatus
```

`RegisterExitNotify` creates a buffered channel (size 1), stores it in `t.exitNotify sync.Map` keyed by PID (TGID), and returns the receive end.

## 4. Tracer-Side Exit Dispatch

Pass `WaitStatus` to `handleExit`: signature changes from `handleExit(tid int)` to `handleExit(tid int, status unix.WaitStatus)`.

After existing tracee cleanup, when the exiting TID is the thread group leader (tid == TGID), check for a registered channel and send the exit status:

```go
if state != nil && tid == state.TGID {
    if v, ok := t.exitNotify.LoadAndDelete(state.TGID); ok {
        ch := v.(chan ExitStatus)
        ch <- ExitStatus{
            PID:    state.TGID,
            Code:   exitCodeFromStatus(status),
            Signal: signalFromStatus(status),
        }
    }
}
```

On tracer shutdown, signal all pending exit channels with an error status so callers don't block indefinitely (same pattern as `cancelPendingAttachWaiters`).

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
status := <-exitCh
wg.Wait()
cmd.Process.Release()
```

When the child exits, the kernel closes the write ends, the read goroutines drain and finish, and `wg.Wait()` completes. `cmd.Process.Release()` tells Go's runtime we're handling cleanup.

## 6. Scope

**Changes:**
- `internal/ptrace/tracer.go` — Add `exitNotify sync.Map`, `ExitStatus`, `RegisterExitNotify()`. Pass `WaitStatus` to `handleExit`. Dispatch exit notification for thread group leaders. Cancel pending exit channels on shutdown.
- `internal/api/exec.go` — When `tracer != nil`: explicit pipes, register exit notify, block on exit channel, drain pipes, `cmd.Process.Release()`.
- `internal/api/exec_stream.go` — Same changes for streaming exec path.
- `internal/api/exec_ptrace_linux.go` — Helper wrapping pipe setup + exit wait to avoid duplication.

**Unchanged:**
- `tracer == nil` path — still uses `cmd.Wait()`
- Wrap path — shell runs in CLI process, not the server
- Standalone sidecar mode — separate process, no conflict
- All other tracer internals except `handleExit` signature
