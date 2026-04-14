# SIGURG Seccomp Preemption Fix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent Go's ~10ms SIGURG async preemption from interrupting seccomp user notifications, causing ERESTARTSYS infinite retry loops on ARM64 VMs.

**Architecture:** Two-layer defense: (1) `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` via `SetWaitKill(true)` at filter install time (kernel 6.0+, graceful fallback), (2) block SIGURG via `rt_sigprocmask` before exec in the wrapper (all kernels).

**Tech Stack:** Go, libseccomp-golang v0.11.0, Linux seccomp user notification

**Spec:** `docs/superpowers/specs/2026-04-13-sigurg-seccomp-preemption-fix-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `go.mod` | Modify | Upgrade libseccomp-golang v0.10.0 → v0.11.0 |
| `internal/netmonitor/unix/addfd_linux.go` | Modify | Add `ProbeWaitKillable()` kernel version check |
| `internal/netmonitor/unix/addfd_linux_test.go` | Modify | Add test for `ProbeWaitKillable()` |
| `internal/netmonitor/unix/seccomp_linux.go` | Modify | Add `SetWaitKill(true)` in `InstallFilterWithConfig()` |
| `cmd/agentsh-unixwrap/main.go` | Modify | Add `blockSIGURG()` + `runtime.LockOSThread()` before exec |
| `cmd/agentsh-unixwrap/sigurg_test.go` | Create | Unit test for `blockSIGURG()` |

**Refinement from spec:** The spec says to call `SetWaitKill(true)` and log if it fails. However, the failure point is actually `filt.Load()` — if the kernel doesn't recognize `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`, the entire filter load fails with EINVAL, not just SetWaitKill. To avoid a retry-on-Load-failure path, we probe the kernel version first (>= 6.0) using the existing `parseKernelVersion()` helper, following the same pattern as `ProbeAddFDSupport()`.

---

### Task 1: Upgrade libseccomp-golang dependency

**Files:**
- Modify: `go.mod:42` (change `v0.10.0` → `v0.11.0`)
- Modify: `go.sum` (auto-updated)

- [ ] **Step 1: Upgrade the dependency**

```bash
cd /home/eran/work/agentsh && go get github.com/seccomp/libseccomp-golang@v0.11.0
```

- [ ] **Step 2: Tidy modules**

```bash
go mod tidy
```

- [ ] **Step 3: Verify build**

```bash
go build ./...
```

Expected: Clean build, no errors. The v0.11.0 API is backward-compatible with v0.10.0.

- [ ] **Step 4: Verify tests pass**

```bash
go test ./...
```

Expected: All existing tests pass. No behavioral changes from the upgrade alone.

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum
git commit -m "deps: upgrade libseccomp-golang v0.10.0 → v0.11.0

Brings in SetWaitKill()/GetWaitKill() for SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
support (kernel 6.0+). Required for the SIGURG preemption fix."
```

---

### Task 2: Add ProbeWaitKillable and SetWaitKill to filter installation

**Files:**
- Modify: `internal/netmonitor/unix/addfd_linux.go` — add `ProbeWaitKillable()`
- Modify: `internal/netmonitor/unix/addfd_linux_test.go` — add test
- Modify: `internal/netmonitor/unix/seccomp_linux.go:217-228` — add `SetWaitKill` in `InstallFilterWithConfig()`

- [ ] **Step 1: Write the failing test for ProbeWaitKillable**

Add to `internal/netmonitor/unix/addfd_linux_test.go`:

```go
func TestProbeWaitKillable_DoesNotPanic(t *testing.T) {
	// ProbeWaitKillable checks kernel version >= 6.0.
	// On any kernel it must return a bool without panicking.
	result := ProbeWaitKillable()
	t.Logf("ProbeWaitKillable() = %v", result)
}

func TestParseKernelVersion_WaitKillable(t *testing.T) {
	tests := []struct {
		release string
		want    bool // major >= 6
	}{
		{"6.0.0-1-arm64", true},
		{"6.8.0-45-generic", true},
		{"5.15.0-1-amd64", false},
		{"5.19.17", false},
		{"7.0.0", true},
	}
	for _, tt := range tests {
		major, _ := parseKernelVersion(tt.release)
		got := major >= 6
		require.Equal(t, tt.want, got, "release=%s major=%d", tt.release, major)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/netmonitor/unix/ -run "TestProbeWaitKillable|TestParseKernelVersion_WaitKillable" -v
```

Expected: FAIL — `ProbeWaitKillable` is undefined.

- [ ] **Step 3: Implement ProbeWaitKillable**

Add to `internal/netmonitor/unix/addfd_linux.go`, after the existing `ProbeAddFDSupport()` function (after line 110):

```go
// ProbeWaitKillable checks if the kernel supports
// SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (kernel 6.0+).
// When supported, seccomp user notification waits use
// wait_for_completion_killable() instead of wait_for_completion_interruptible(),
// preventing non-fatal signals (like Go's SIGURG) from causing ERESTARTSYS.
func ProbeWaitKillable() bool {
	var utsname unix.Utsname
	if err := unix.Uname(&utsname); err != nil {
		return false
	}
	release := unix.ByteSliceToString(utsname.Release[:])
	major, _ := parseKernelVersion(release)
	return major >= 6
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/netmonitor/unix/ -run "TestProbeWaitKillable|TestParseKernelVersion_WaitKillable" -v
```

Expected: PASS.

- [ ] **Step 5: Add SetWaitKill to InstallFilterWithConfig**

In `internal/netmonitor/unix/seccomp_linux.go`, add `"log/slog"` to the imports.

Then in `InstallFilterWithConfig()`, after `seccomp.NewFilter(seccomp.ActAllow)` (line 224) and before the `// Unix socket monitoring` comment (line 229), add:

```go
	// Enable SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (kernel 6.0+).
	// When active, non-fatal signals (including Go's ~10ms SIGURG preemption)
	// cannot interrupt seccomp_do_user_notification, preventing ERESTARTSYS loops.
	// Must probe kernel version first: on older kernels, the flag causes Load() to
	// fail with EINVAL. The wrapper also blocks SIGURG before exec as a fallback.
	if ProbeWaitKillable() {
		if err := filt.SetWaitKill(true); err != nil {
			slog.Debug("seccomp: SetWaitKill failed", "error", err)
		}
	}
```

- [ ] **Step 6: Verify build and tests**

```bash
go build ./... && go test ./internal/netmonitor/unix/ -v -count=1
```

Expected: Build succeeds. All tests pass (including existing seccomp tests).

- [ ] **Step 7: Commit**

```bash
git add internal/netmonitor/unix/addfd_linux.go internal/netmonitor/unix/addfd_linux_test.go internal/netmonitor/unix/seccomp_linux.go
git commit -m "fix(seccomp): enable WAIT_KILLABLE_RECV to prevent SIGURG preemption loops

On kernel 6.0+, set SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV via SetWaitKill(true)
at filter install time. This makes seccomp_do_user_notification use
wait_for_completion_killable() instead of wait_for_completion_interruptible(),
so Go's ~10ms SIGURG async preemption cannot cause ERESTARTSYS.

Graceful fallback: kernel version is probed first; on < 6.0 the flag is not set
and the wrapper's SIGURG block (next commit) provides equivalent protection."
```

---

### Task 3: Add blockSIGURG to wrapper (TDD)

**Files:**
- Create: `cmd/agentsh-unixwrap/sigurg_test.go`
- Modify: `cmd/agentsh-unixwrap/main.go:196-206` — add `blockSIGURG()` function and call before exec

- [ ] **Step 1: Write the failing test**

Create `cmd/agentsh-unixwrap/sigurg_test.go`:

```go
//go:build linux && cgo

package main

import (
	"runtime"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// readSigmask reads the current thread's signal mask via rt_sigprocmask.
func readSigmask() (uint64, error) {
	var oldset [1]uint64
	_, _, errno := unix.RawSyscall6(
		unix.SYS_RT_SIGPROCMASK,
		uintptr(unix.SIG_SETMASK),
		0, // nset = nil (read-only)
		uintptr(unsafe.Pointer(&oldset[0])),
		8,
		0, 0,
	)
	if errno != 0 {
		return 0, errno
	}
	return oldset[0], nil
}

func TestBlockSIGURG(t *testing.T) {
	// Pin goroutine to OS thread — signal masks are per-thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Read mask before.
	before, err := readSigmask()
	require.NoError(t, err)
	sigurgBit := uint64(1) << (unix.SIGURG - 1)
	require.Zero(t, before&sigurgBit, "SIGURG should not be blocked before test")

	// Block SIGURG.
	blockSIGURG()

	// Read mask after.
	after, err := readSigmask()
	require.NoError(t, err)
	require.NotZero(t, after&sigurgBit, "SIGURG should be blocked after blockSIGURG()")

	// Clean up: unblock SIGURG so the thread is returned cleanly.
	var unset [1]uint64
	unset[0] = sigurgBit
	_, _, errno := unix.RawSyscall6(
		unix.SYS_RT_SIGPROCMASK,
		uintptr(unix.SIG_UNBLOCK),
		uintptr(unsafe.Pointer(&unset[0])),
		0, 8, 0, 0,
	)
	require.Zero(t, errno, "failed to unblock SIGURG in cleanup")
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./cmd/agentsh-unixwrap/ -run TestBlockSIGURG -v
```

Expected: FAIL — `blockSIGURG` is undefined.

- [ ] **Step 3: Implement blockSIGURG**

In `cmd/agentsh-unixwrap/main.go`, add `"runtime"` and `"unsafe"` to the imports.

Add the `blockSIGURG` function after `waitForACK` (after line 258):

```go
// blockSIGURG blocks SIGURG on the current OS thread via rt_sigprocmask.
// Go's runtime sends SIGURG every ~10ms for goroutine preemption. When execve
// is trapped by seccomp user-notify, the kernel waits in
// wait_for_completion_interruptible(), which is woken by ANY signal. SIGURG
// causes ERESTARTSYS → stale notification ID → infinite retry loop.
//
// Must be called after runtime.LockOSThread() to ensure the mask change
// applies to the thread that will call syscall.Exec().
func blockSIGURG() {
	var set [1]uint64
	set[0] = 1 << (unix.SIGURG - 1)
	_, _, errno := unix.RawSyscall6(
		unix.SYS_RT_SIGPROCMASK,
		uintptr(unix.SIG_BLOCK),
		uintptr(unsafe.Pointer(&set[0])),
		0, // oldset = nil
		8, // sizeof(sigset_t)
		0, 0,
	)
	if errno != 0 {
		log.Printf("warning: blockSIGURG: rt_sigprocmask: %v", errno)
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./cmd/agentsh-unixwrap/ -run TestBlockSIGURG -v
```

Expected: PASS.

- [ ] **Step 5: Wire blockSIGURG into the exec path**

In `cmd/agentsh-unixwrap/main.go`, right before the `syscall.Exec` call (currently line 204), add:

```go
	// Block SIGURG on this OS thread to prevent Go's ~10ms async preemption
	// from interrupting seccomp_do_user_notification during execve.
	// Since syscall.Exec replaces the process image, this has no lasting effect.
	runtime.LockOSThread()
	blockSIGURG()
```

The full exec section becomes:

```go
	// Block SIGURG on this OS thread to prevent Go's ~10ms async preemption
	// from interrupting seccomp_do_user_notification during execve.
	// Since syscall.Exec replaces the process image, this has no lasting effect.
	runtime.LockOSThread()
	blockSIGURG()

	// Exec the real command.
	cmd := os.Args[2]
	// syscall.Exec requires an absolute path — resolve via PATH lookup.
	cmdPath, err := exec.LookPath(cmd)
	if err != nil {
		log.Fatalf("exec %s failed: %v", cmd, err)
	}
	args := os.Args[2:]
	if err := syscall.Exec(cmdPath, args, os.Environ()); err != nil {
		log.Fatalf("exec %s failed: %v", cmd, err)
	}
```

- [ ] **Step 6: Verify full build and tests**

```bash
go build ./... && go test ./... && GOOS=windows go build ./...
```

Expected: All builds and tests pass. The `//go:build linux && cgo` tags on both `main.go` and `sigurg_test.go` keep these out of the Windows cross-compile.

- [ ] **Step 7: Commit**

```bash
git add cmd/agentsh-unixwrap/main.go cmd/agentsh-unixwrap/sigurg_test.go
git commit -m "fix(seccomp): block SIGURG before exec to prevent ERESTARTSYS loop

Go's async preemption sends SIGURG every ~10ms, which interrupts
seccomp_do_user_notification's wait_for_completion_interruptible(),
causing ERESTARTSYS → stale notification → infinite retry loop.
Confirmed on Ubuntu Server ARM64 in a VM (0% → 98% with asyncpreemptoff=1).

Block SIGURG on the exec thread via rt_sigprocmask(SIG_BLOCK) right before
syscall.Exec(). Since exec replaces the process image, the mask change has
no lasting effect. runtime.LockOSThread() ensures the mask applies to the
same thread that calls exec.

This is Layer 2 of the fix — works on all kernels. Layer 1 (SetWaitKill /
WAIT_KILLABLE_RECV, previous commit) handles kernel 6.0+."
```
