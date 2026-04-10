# IPC/Ptrace Defensive Hardening

Three surgical fixes for race conditions and silent failures in the seccomp wrapper IPC and ptrace resume paths. All changes are Linux-only, defensive in nature, and independently testable.

## Background

Post-mortem analysis of the CGO=1 exec path identified several compounding issues. Most were resolved by prior work (ACK handshake, separate signal filter FDs, etc.), but three remain:

1. A missing `SOCK_CLOEXEC` flag on the API-layer notify socketpair
2. No exit-state or ESRCH handling in `resumeTracedProcess`
3. The signal handler goroutine dying silently on `SetReadDeadline` failure

None of these currently causes the original 30-second hang (that was fixed by the ACK handshake), but each can produce incorrect behavior under race conditions.

## Fix 1: Add `SOCK_CLOEXEC` to `createUnixSocketPair`

**File:** `internal/api/unixsock_unix.go`

**Problem:** The socketpair is created without `SOCK_CLOEXEC`:
```go
sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
```

In a multi-threaded Go process, there is a TOCTOU window between `socketpair()` and `exec` where the parent-end fd could leak into a concurrently-forking child process. Go's `os/exec` closes extraneous fds after fork, so the practical risk is low, but `SOCK_CLOEXEC` eliminates the race atomically.

The CLI layer (`internal/cli/wrap_linux.go:93`) already uses `SOCK_CLOEXEC` correctly. The API layer should match.

**Fix:** Add `unix.SOCK_CLOEXEC` to the socket type flags:
```go
sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
```

The child fd goes into `ExtraFiles` (line 272 of `core.go`), where Go's runtime manages CLOEXEC clearing for inheritance. The parent fd stays in the server process with CLOEXEC set — correct behavior.

**Scope:** 1 line changed.

## Fix 2: Harden `resumeTracedProcess` Against Race Conditions

**File:** `internal/api/process_linux.go`

**Problem:** The function does not handle three race conditions:

1. **`Wait4` returns `ECHILD`** — the tracee was already reaped by another waiter.
2. **`ws.Exited()` or `ws.Signaled()` after `Wait4`** — the tracee ran and exited before we could detach. Calling `PtraceDetach` on a dead process fails with `ESRCH`.
3. **`PtraceDetach` returns `ESRCH`** — the tracee died between `Wait4` and `PtraceDetach`.

The callers (`exec.go:524`, `exec_stream.go:607`) treat any error as fatal — they kill the process and return `exit_code=127`. This means a harmless race (process exited normally) surfaces as a failure.

**Fix:** Handle all three cases with debug-level logging and return nil:

```go
func resumeTracedProcess(pid int) error {
    if pid <= 0 {
        return nil
    }
    var ws syscall.WaitStatus
    _, err := syscall.Wait4(pid, &ws, syscall.WALL, nil)
    if err != nil {
        if errors.Is(err, syscall.ECHILD) {
            slog.Debug("traced process already reaped", "pid", pid)
            return nil
        }
        return fmt.Errorf("wait for traced process: %w", err)
    }
    if ws.Exited() || ws.Signaled() {
        slog.Debug("traced process exited before detach",
            "pid", pid, "exited", ws.Exited(), "signaled", ws.Signaled())
        return nil
    }
    if err := syscall.PtraceDetach(pid); err != nil {
        if errors.Is(err, syscall.ESRCH) {
            slog.Debug("traced process gone during detach", "pid", pid)
            return nil
        }
        return fmt.Errorf("ptrace detach: %w", err)
    }
    return nil
}
```

**Imports:** Add `"errors"` and `"log/slog"` to the import block. Remove `"os"` if no longer needed (it's used by `getProcessComm`, so it stays).

**Scope:** ~15 lines added/changed.

## Fix 3: Signal Handler `SetReadDeadline` — Continue Instead of Return

**File:** `internal/api/signal_handler_linux.go`

**Problem:** The signal handler goroutine returns on `SetReadDeadline` failure:
```go
if err := parentSock.SetReadDeadline(time.Now().Add(recvFDTimeout)); err != nil {
    slog.Debug("failed to set read deadline on signal socket", "error", err)
    return
}
```

`SetReadDeadline` always fails on `os.NewFile`-wrapped socketpair fds because they are not registered with Go's network poller. The notify handler (`notify_linux.go:218-221`) correctly handles this by logging and continuing. The signal handler should match.

When this `return` fires, the goroutine exits, `defer parentSock.Close()` fires, and signal monitoring is silently disabled for the session.

**Fix:** Replace the `return` with a continue-to-RecvFD pattern:
```go
if err := parentSock.SetReadDeadline(time.Now().Add(recvFDTimeout)); err != nil {
    slog.Debug("failed to set read deadline on signal socket (continuing)", "error", err)
    // Don't return - continue to RecvFD
}
```

**Scope:** 2 lines changed (log message updated, `return` removed).

## Testing

- **Fix 1:** Verify with `go build ./...` and `GOOS=windows go build ./...`. The change is in a `!windows` build-tagged file. No behavioral change to test — the fix is atomic flag semantics.
- **Fix 2:** Unit-testable by mocking `Wait4`/`PtraceDetach`, but the function uses raw syscalls. Verify by `go test ./internal/api/...` to ensure no regressions. The race conditions are hard to trigger deterministically.
- **Fix 3:** Verify by `go test ./internal/api/...`. The fix is a control-flow change (remove early return).
- **Cross-compile:** `GOOS=windows go build ./...` to verify no build breakage on non-Linux platforms.

## Non-Goals

- Reordering `applyLandlock`/`exec.LookPath` before seccomp install in the wrapper. The ACK handshake makes this a non-issue.
- Exporting `landlock.ExtractBaseDir`. The private function works correctly for its internal consumers.
- Merging the signal filter into the main seccomp filter. The separate-filter design with separate FDs is correct.
