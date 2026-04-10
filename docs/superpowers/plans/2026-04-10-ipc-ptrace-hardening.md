# IPC/Ptrace Defensive Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix three race conditions and silent failures in the seccomp wrapper IPC and ptrace resume paths.

**Architecture:** Three independent, surgical fixes — each touches exactly one file. All are Linux-only (`//go:build` tagged). No new files, no new dependencies, no new abstractions.

**Tech Stack:** Go, `golang.org/x/sys/unix`, raw syscalls (`Wait4`, `PtraceDetach`, `Socketpair`)

**Spec:** `docs/superpowers/specs/2026-04-10-ipc-ptrace-hardening-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `internal/api/unixsock_unix.go` | Modify line 20 | Add `SOCK_CLOEXEC` to socketpair creation |
| `internal/api/process_linux.go` | Modify lines 1-42 | Add ESRCH/exit-state handling to `resumeTracedProcess` |
| `internal/api/signal_handler_linux.go` | Modify lines 59-62 | Remove early return on `SetReadDeadline` failure |

---

### Task 1: Add `SOCK_CLOEXEC` to `createUnixSocketPair`

**Files:**
- Modify: `internal/api/unixsock_unix.go:20`

- [ ] **Step 1: Apply the fix**

In `internal/api/unixsock_unix.go`, change line 20 from:

```go
sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
```

to:

```go
sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
```

- [ ] **Step 2: Verify build**

Run: `go build ./internal/api/...`
Expected: clean build, no errors.

- [ ] **Step 3: Verify cross-compile**

Run: `GOOS=windows go build ./internal/api/...`
Expected: clean build. The file has a `//go:build !windows` tag so it is excluded on Windows.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/api/...`
Expected: all existing tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/api/unixsock_unix.go
git commit -m "fix: add SOCK_CLOEXEC to API-layer notify socketpair

Atomically sets close-on-exec on the parent fd, eliminating a TOCTOU
race window in multi-threaded Go processes where the fd could leak
into a concurrently-forking child. Matches the CLI layer pattern
(internal/cli/wrap_linux.go:93)."
```

---

### Task 2: Harden `resumeTracedProcess` against race conditions

**Files:**
- Modify: `internal/api/process_linux.go:1-42`

- [ ] **Step 1: Update imports**

In `internal/api/process_linux.go`, change the import block from:

```go
import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)
```

to:

```go
import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)
```

- [ ] **Step 2: Replace `resumeTracedProcess` function body**

Replace the entire function (lines 24-42) with:

```go
// resumeTracedProcess resumes a process that was started with Ptrace=true.
// The process is stopped at the first instruction; this detaches ptrace
// and allows it to continue execution.
// Handles race conditions where the tracee exits before detach:
// - ECHILD on Wait4: tracee already reaped
// - ws.Exited()/ws.Signaled(): tracee ran and exited
// - ESRCH on PtraceDetach: tracee died between wait and detach
func resumeTracedProcess(pid int) error {
	if pid <= 0 {
		return nil
	}
	// Wait for the traced process to be in stopped state
	var ws syscall.WaitStatus
	_, err := syscall.Wait4(pid, &ws, syscall.WALL, nil)
	if err != nil {
		if errors.Is(err, syscall.ECHILD) {
			slog.Debug("traced process already reaped", "pid", pid)
			return nil
		}
		return fmt.Errorf("wait for traced process: %w", err)
	}
	// If the process already exited or was signaled, no detach needed
	if ws.Exited() || ws.Signaled() {
		slog.Debug("traced process exited before detach",
			"pid", pid, "exited", ws.Exited(), "signaled", ws.Signaled())
		return nil
	}
	// Detach from the process, allowing it to continue
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

- [ ] **Step 3: Verify build**

Run: `go build ./internal/api/...`
Expected: clean build, no errors.

- [ ] **Step 4: Verify cross-compile**

Run: `GOOS=windows go build ./internal/api/...`
Expected: clean build. This file has `//go:build linux` so it is excluded. The Windows stub (`process_windows.go`) is unaffected.

- [ ] **Step 5: Run tests**

Run: `go test ./internal/api/...`
Expected: all existing tests pass.

- [ ] **Step 6: Commit**

```bash
git add internal/api/process_linux.go
git commit -m "fix: handle race conditions in resumeTracedProcess

Treat ECHILD (already reaped), exited/signaled status, and ESRCH on
detach as success with debug logging. Previously these races surfaced
as exit_code=127 errors to callers (exec.go, exec_stream.go)."
```

---

### Task 3: Fix signal handler `SetReadDeadline` early return

**Files:**
- Modify: `internal/api/signal_handler_linux.go:59-62`

- [ ] **Step 1: Apply the fix**

In `internal/api/signal_handler_linux.go`, change lines 58-62 from:

```go
		// Set a read deadline to prevent blocking forever if wrapper fails
		if err := parentSock.SetReadDeadline(time.Now().Add(recvFDTimeout)); err != nil {
			slog.Debug("failed to set read deadline on signal socket", "error", err)
			return
		}
```

to:

```go
		// Set a read deadline to prevent blocking forever if wrapper fails.
		// Note: This may fail on os.NewFile-wrapped socketpair fds (not registered
		// with Go's network poller), but we should still continue to RecvFD.
		if err := parentSock.SetReadDeadline(time.Now().Add(recvFDTimeout)); err != nil {
			slog.Debug("failed to set read deadline on signal socket (continuing)", "error", err)
			// Don't return - continue to RecvFD
		}
```

- [ ] **Step 2: Verify build**

Run: `go build ./internal/api/...`
Expected: clean build, no errors.

- [ ] **Step 3: Verify cross-compile**

Run: `GOOS=windows go build ./internal/api/...`
Expected: clean build. This file has `//go:build linux && cgo` so it is excluded. The stub (`signal_handler_stub.go`) is unaffected.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/api/...`
Expected: all existing tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/api/signal_handler_linux.go
git commit -m "fix: signal handler continues on SetReadDeadline failure

SetReadDeadline fails on os.NewFile-wrapped socketpair fds (not
registered with Go's netpoll). The notify handler already handles
this correctly (notify_linux.go:218-221). Match that pattern so
signal monitoring is not silently disabled."
```

---

### Task 4: Final verification

- [ ] **Step 1: Full build**

Run: `go build ./...`
Expected: clean build across all packages.

- [ ] **Step 2: Full cross-compile**

Run: `GOOS=windows go build ./...`
Expected: clean build.

- [ ] **Step 3: Full test suite**

Run: `go test ./...`
Expected: all tests pass. No regressions.
