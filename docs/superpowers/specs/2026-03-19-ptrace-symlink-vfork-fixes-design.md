# Ptrace Tracer: Symlink Verification + vfork Fast-path

**Date:** 2026-03-19
**Status:** Design
**Context:** Vercel Sandbox testing (Firecracker VM, ptrace-only enforcement) found 2 gaps: symlink escape via openat and vfork+ptrace deadlock with Python subprocess.run.

---

## Gap 1: Symlink Resolution Bypass — Exit-time Verification

### Problem

When a tracee opens a file through a symlink (e.g., `cat /tmp/shadow_link` where the symlink points to `/etc/shadow`), the policy should evaluate against the resolved target (`/etc/shadow`), not the symlink path (`/tmp/shadow_link`).

The tracer already has entry-time symlink resolution via `resolveViaProc()` which walks components through `/proc/<tid>/root`. However, the bypass is still reproducible on `main`, suggesting an environmental or edge-case failure in the resolution pipeline. The exact root cause has not been isolated.

### Solution

Defense-in-depth: add exit-time path verification for openat/openat2. After the kernel completes the open, read what was actually opened and verify it against policy.

#### 1.1 Fix PTRACE_GET_SYSCALL_INFO Op check

**File:** `internal/ptrace/syscall_context.go`

`getSyscallEntryInfo` currently rejects any `Op != 1`. For PTRACE_EVENT_SECCOMP stops, the kernel returns `Op = 3` (PTRACE_SYSCALL_INFO_SECCOMP). The seccomp variant has the same struct layout as entry for `nr` and `args[6]`, so the data is valid. The strict check forces a fallback to full `getRegs()` on every seccomp stop.

Fix: accept `Op == 1` (entry) or `Op == 3` (seccomp). Both have identical `nr + args[6]` layout.

```go
// Before:
if info.Op != 1 {
    return nil, fmt.Errorf("unexpected op %d (want entry=1)", info.Op)
}

// After:
if info.Op != 1 && info.Op != 3 {
    return nil, fmt.Errorf("unexpected op %d (want entry=1 or seccomp=3)", info.Op)
}
```

#### 1.2 Always require exit stops for openat/openat2

**File:** `internal/ptrace/tracer.go`

Change `needsExitStop()` to always return true for `SYS_OPENAT` and `SYS_OPENAT2`:

```go
// Before:
case unix.SYS_OPENAT, unix.SYS_OPENAT2:
    return t.cfg.MaskTracerPid

// After:
case unix.SYS_OPENAT, unix.SYS_OPENAT2:
    return true
```

This ensures the tracer catches the exit stop so `handleOpenatExit` can verify the opened path.

#### 1.3 Exit-time path verification

**File:** `internal/ptrace/handle_file.go` (in `handleOpenatExit` or new function called from it)

After a successful openat (retVal >= 0):

1. Read the real path: `os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", tid, fd))`
2. If the path read fails, skip verification (the fd may have been closed already by another thread)
3. Evaluate policy against the real path using `t.cfg.FileHandler.HandleFile(ctx, FileContext{...})`
4. If denied:
   a. Inject `close(fd)` into the tracee using existing `injectSyscall` / register manipulation
   b. Override the return value to `-EACCES` using `setRegs` to modify the return register

The existing `handleOpenatExit` already reads `/proc/<tid>/fd/<fd>` for TracerPid masking. The verification piggybacks on this read.

**Implementation detail for fd cleanup:** The tracer needs to close the fd in the tracee's fd table before overriding the return. The simplest approach:

1. Read current regs
2. Save current regs
3. Set syscall nr to `SYS_CLOSE`, arg0 to `fd`
4. `PtraceSyscall` to execute the close
5. Wait for exit stop
6. Restore saved regs with return value set to `-EACCES`
7. Resume

This pattern is already used by `cleanupInjectedFD` for exec redirect cleanup.

**SessionID for policy evaluation:** The exit-time handler needs the session ID and TGID. These are already available via `t.tracees[tid]` (same as `handleOpenatExit` uses today).

### Performance impact

Adds one extra ptrace stop cycle per openat/openat2 (exit stop). For file-heavy workloads this is measurable but acceptable given the security criticality. The exit path is lightweight when the path is allowed (just a `Readlink` + policy check, no fd injection needed).

---

## Gap 2: vfork + ptrace Deadlock — Fast-path vfork Children

### Problem

Python's `subprocess.run()` with `capture_output=True` uses `vfork()` on Linux since Python 3.9. With vfork:

1. Parent is kernel-frozen until the child calls `execve()` or `_exit()`
2. Child makes setup syscalls (close, dup2, etc.) between vfork and exec
3. Each syscall generates a ptrace stop (seccomp or TRACESYSGOOD)
4. Each stop requires: read syscall info, read tracee memory, resolve paths, evaluate policy, resume
5. Accumulated latency keeps the parent frozen longer
6. External timeouts trigger, causing empty API responses

`os.system()` works because it uses `fork()` (not vfork) — the parent is not frozen.

### Solution

Fast-path all syscalls for vfork children except execve/execveat. Between vfork and exec, POSIX restricts the child to async-signal-safe operations only. These don't access controlled resources and are safe to allow without policy evaluation.

#### 2.1 Fast-path in handleSeccompStop

**File:** `internal/ptrace/tracer.go`

After reading state and before `dispatchSyscall`, check `IsVforkChild`:

```go
func (t *Tracer) handleSeccompStop(ctx context.Context, tid int) {
    sc, err := t.buildSyscallContext(tid)
    if err != nil {
        t.allowSyscall(tid)
        return
    }
    nr := sc.Info.Nr

    t.mu.Lock()
    state := t.tracees[tid]
    isVfork := state != nil && state.IsVforkChild
    if state != nil {
        state.InSyscall = true
        state.LastNr = nr
        state.NeedExitStop = t.needsExitStop(nr)
        // ... existing escalation logic ...
    }
    t.mu.Unlock()

    // Fast-path: vfork children only need policy evaluation at execve.
    // All other syscalls between vfork and exec are async-signal-safe
    // setup operations (close, dup2, sigaction, etc.) — safe to allow.
    if isVfork && !isExecveSyscall(nr) {
        t.allowSyscall(tid)
        return
    }

    t.dispatchSyscall(ctx, tid, nr, sc)
}
```

#### 2.2 Fast-path in handleSyscallStop (entry path)

**File:** `internal/ptrace/tracer.go`

In the `entering` branch of `handleSyscallStop`, add the same check after `buildSyscallContext`:

```go
if entering {
    sc, err := t.buildSyscallContext(tid)
    if err != nil {
        t.allowSyscall(tid)
        return
    }
    nr := sc.Info.Nr
    state.LastNr = nr
    state.NeedExitStop = t.needsExitStop(nr)

    // Fast-path vfork children (same logic as handleSeccompStop).
    if state.IsVforkChild && !isExecveSyscall(nr) {
        t.allowSyscall(tid)
        return
    }

    t.dispatchSyscall(ctx, tid, nr, sc)
}
```

#### 2.3 Existing lifecycle (no changes needed)

- `IsVforkChild = true`: set by `markVforkChild()` after PTRACE_EVENT_VFORK (line 1235)
- `IsVforkChild = false`: cleared by `handleExecEvent()` after PTRACE_EVENT_EXEC (line 1247)
- After exec, the process is no longer a vfork child and gets full policy enforcement for all subsequent syscalls

### Security analysis

**What's allowed without policy check:** close, dup2/dup3, sigaction, sigprocmask, setsid, setpgid, chdir, _exit. These are:
- fd management (close, dup2) — rearranging already-open fds
- Signal management — no security implications
- Process group management — no security implications
- _exit — terminates the child

**What still gets full policy check:** execve/execveat — the actual security boundary where the child starts a new program. This is where path resolution, argument inspection, and policy evaluation matter.

**Risk:** A malicious vfork child could call `openat()` between vfork and exec, which would be allowed without policy check. However, this is undefined behavior (POSIX only allows async-signal-safe functions after vfork), and the kernel may not support it reliably. Additionally, the exit-time verification from Gap 1 would catch any policy-violating opens.

### Performance impact

Eliminates all policy evaluation overhead between vfork and exec. The ptrace stop/resume cycle itself (kernel context switch) remains, but per-stop processing drops from ~50us (memory read + path resolution + policy eval) to ~1us (check flag + allow).

---

## Files changed

| File | Change |
|---|---|
| `internal/ptrace/syscall_context.go` | Accept Op=1 and Op=3 in `getSyscallEntryInfo` |
| `internal/ptrace/tracer.go` | `needsExitStop`: always true for openat/openat2. Fast-path vfork children in `handleSeccompStop` and `handleSyscallStop` |
| `internal/ptrace/handle_file.go` | `handleOpenatExit`: exit-time path verification with policy check, fd close + return override on deny |
| `internal/ptrace/handle_file_test.go` | Tests for exit-time symlink verification |
| `internal/ptrace/tracer_test.go` | Tests for vfork fast-path behavior |

## Test plan

### Gap 1 tests
- Symlink to denied path: create symlink `/tmp/link` → `/etc/shadow`, verify openat through symlink is denied
- Chained symlinks: `/tmp/link2` → `/tmp/link1` → `/etc/shadow`, verify denied
- Symlink to allowed path: `/tmp/link` → `/etc/os-release`, verify allowed
- O_NOFOLLOW: openat with O_NOFOLLOW on symlink, verify resolvePathNoFollow is used
- Exit-time verification unit test: mock a scenario where entry-time resolution returns wrong path, verify exit-time catch

### Gap 2 tests
- vfork child close/dup2: verify allowed without policy evaluation
- vfork child execve: verify full policy evaluation occurs
- IsVforkChild lifecycle: verify flag set at vfork, cleared at exec
- Non-vfork child: verify normal policy evaluation for all syscalls
