# Fix SIGURG Preemption Interrupting Seccomp User Notifications

**Date:** 2026-04-13
**Status:** Approved

## Problem

Go's async preemption sends SIGURG to all threads every ~10ms (since Go 1.14). When the wrapper (`agentsh-unixwrap`) calls `syscall.Exec()` and the seccomp filter traps it, the kernel suspends the thread in `seccomp_do_user_notification()` using `wait_for_completion_interruptible()`. SIGURG interrupts this wait, causing ERESTARTSYS. The kernel restarts `execve`, creating a new notification — but the supervisor may already be processing the old one. This loops every ~10ms until timeout.

Confirmed on Ubuntu Server ARM64 in a VM. `GODEBUG=asyncpreemptoff=1` in the wrapper env raises success rate from 0% to 98%, confirming the root cause. ARM64 VMs are particularly affected because higher latency for cross-process operations (ProcessVMReadv, path resolution, ioctl) makes it impossible for the supervisor to respond within the 10ms SIGURG window.

**References:**
- [LWN: Seccomp user-space notification and signals](https://lwn.net/Articles/851813/)
- [Go issue #37942: SIGURG from async preemption](https://github.com/golang/go/issues/37942)
- [Kernel patches: Handle seccomp notification preemption](https://lwn.net/Articles/849747/)
- [Kernel docs: seccomp_filter](https://docs.kernel.org/userspace-api/seccomp_filter.html)

## Solution

Two layers of defense, both always active:

### Layer 1: `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` via `SetWaitKill`

At filter installation time in `InstallFilterWithConfig()`, call `filt.SetWaitKill(true)` before `filt.Load()`. This sets the `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` flag, which makes the kernel use `wait_for_completion_killable()` instead of `wait_for_completion_interruptible()`. Only fatal signals (SIGKILL) can interrupt the notification wait — SIGURG is ignored.

Requires kernel 6.0+ and libseccomp >= 2.6.0. On older kernels, `Load()` returns an error when the flag is unrecognized. Since the current `InstallFilterWithConfig` creates the filter via libseccomp, we handle this gracefully: try `SetWaitKill(true)`, log at debug level if it fails, continue without it.

> **Follow-up (2026-04-14):** The libseccomp version requirement is now enforced at
> build time via the `#error` guards in `internal/netmonitor/unix/seccomp_version_check.go`
> and `cmd/agentsh-unixwrap/seccomp_version_check.go`, and CI builds a static libseccomp
> 2.6 via `scripts/build-libseccomp.sh`. See
> `docs/superpowers/specs/2026-04-14-libseccomp-2.6-defense-in-depth-design.md`
> for the hardening rationale.

### Layer 2: Block SIGURG before exec

In the wrapper's `main()`, right before `syscall.Exec()`, block SIGURG on the current OS thread via raw `rt_sigprocmask(SIG_BLOCK, {SIGURG})` syscall. This prevents Go's runtime from delivering SIGURG to the thread that will be suspended in `seccomp_do_user_notification`.

`runtime.LockOSThread()` is required before the signal mask change to ensure the goroutine stays on the same OS thread through to the `syscall.Exec()` call. Since `exec` replaces the process image, the signal mask change has no lasting effect — the Go runtime ceases to exist after exec.

### Why both

- SetWaitKill is the proper kernel-level fix but requires kernel 6.0+.
- SIGURG block works on all kernels but is specific to the exec path in the wrapper.
- Together they provide defense in depth: SetWaitKill protects all seccomp notification waits (not just the wrapper's exec), and the SIGURG block covers older kernels.

## Changes

### 1. Dependency upgrade

Upgrade `libseccomp-golang` from v0.10.0 to v0.11.0 in `go.mod`. This brings in `SetWaitKill()` / `GetWaitKill()`. Requires C `libseccomp >= 2.6.0` on the build system.

### 2. `internal/netmonitor/unix/seccomp_linux.go`

In `InstallFilterWithConfig()`, after `seccomp.NewFilter(seccomp.ActAllow)` and before adding any rules:

```go
if err := filt.SetWaitKill(true); err != nil {
    slog.Debug("seccomp: SetWaitKill unavailable (kernel < 6.0)", "error", err)
}
```

Add `log/slog` import (already used by other files in the package).

### 3. `cmd/agentsh-unixwrap/main.go`

Before `syscall.Exec()` (currently line 204):

```go
runtime.LockOSThread()
blockSIGURG()
```

New function:

```go
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

New imports: `runtime`, `unsafe`.

### 4. `cmd/agentsh-unixwrap/sigurg_test.go` (new file)

Linux-only build tag. Unit test for `blockSIGURG`:

1. Call `runtime.LockOSThread()` to pin the test goroutine
2. Call `blockSIGURG()`
3. Read the current signal mask via `rt_sigprocmask(SIG_SETMASK, nil, &oldset, 8)`
4. Assert the SIGURG bit (bit 22, 0-indexed) is set in `oldset`

No integration test for the full ERESTARTSYS loop — it requires ARM64 + VM + timing sensitivity. The unit test plus kernel-side SetWaitKill gives confidence both defenses are wired up.

## Error handling

| Failure | Behavior |
|---------|----------|
| `SetWaitKill(true)` rejected by kernel | Debug log, continue. Layer 2 provides protection. |
| `rt_sigprocmask` fails | Warning log, exec proceeds. Rare — only on exotic kernels. |
| Both fail | Same behavior as before this fix. No regression. |

## Files touched

| File | Change |
|------|--------|
| `go.mod`, `go.sum` | Upgrade libseccomp-golang v0.10.0 -> v0.11.0 |
| `internal/netmonitor/unix/seccomp_linux.go` | Add `SetWaitKill(true)` + `slog` import |
| `cmd/agentsh-unixwrap/main.go` | Add `blockSIGURG()`, `runtime.LockOSThread()`, new imports |
| `cmd/agentsh-unixwrap/sigurg_test.go` | New: unit test for blockSIGURG |
