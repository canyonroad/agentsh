# Design: Seccomp Prefilter Injection for Server-Wired Ptrace Mode

**Date:** 2026-03-15
**Status:** Implemented

---

## 1. Problem

In server-wired ptrace mode, every syscall generates a ptrace-stop (`TRACESYSGOOD` mode) because the seccomp prefilter is not installed. Only ~30 syscall types need tracing, but the tracer traps all ~300+ syscall types, causing ~10-50x overhead compared to baseline.

### Goals

- Reduce ptrace overhead to <5% vs baseline (matching sidecar-mode performance)
- Zero behavioral regressions in exec, file, network, signal, DNS redirect, SNI rewrite, TracerPid masking
- Graceful fallback when seccomp injection is blocked by the container runtime

### Non-Goals

- Changing sidecar mode behavior
- x32 ABI support (not used by agentsh workloads)

## 2. Solution: Inject BPF via Ptrace Syscall Injection

After `PTRACE_SEIZE` + `PTRACE_INTERRUPT` stops the child, inject a `seccomp(SECCOMP_SET_MODE_FILTER)` syscall using the existing `injectSyscall` engine. The BPF program returns `SECCOMP_RET_TRACE` for traced syscalls and `SECCOMP_RET_ALLOW` for all others. The kernel then generates `PTRACE_EVENT_SECCOMP` stops only for traced syscalls.

## 3. BPF Program

The BPF syscall list is generated from the existing `tracedSyscallNumbers()` function in `syscalls.go` — the single source of truth for which syscalls the tracer handles. This includes:

- **Exec**: `execve`, `execveat`
- **File**: `openat`, `openat2`, `unlinkat`, `renameat2`, `mkdirat`, `linkat`, `symlinkat`, `fchmodat`, `fchmodat2`, `fchownat` (+ legacy amd64: `open`, `creat`, `mkdir`, `rmdir`, `unlink`, `rename`, `link`, `symlink`, `chmod`, `chown`)
- **Network**: `connect`, `bind`, `socket`, `sendto`, `listen`
- **Signal**: `kill`, `tkill`, `tgkill`, `rt_sigqueueinfo`, `rt_tgsigqueueinfo`
- **I/O tracking**: `write`, `read`, `pread64`, `close` (DNS redirect sendto rewrite, TracerPid masking, TLS SNI rewrite, fd tracking)

Structure: BPF validates `arch == AUDIT_ARCH_X86_64` (or `AUDIT_ARCH_AARCH64`), loads syscall number, compares against each traced number, returns `SECCOMP_RET_TRACE` on match, `SECCOMP_RET_ALLOW` on default. Architecture check prevents mismatches on compat/x32 syscalls.

Built once at tracer startup from `tracedSyscallNumbers()`, cached as `[]unix.SockFilter`. ~40-50 instructions depending on architecture.

## 4. Injection Point and Lifecycle

Injection happens in `attachThread()` after `PTRACE_SETOPTIONS` and before the tracee is resumed. The lifecycle is reordered to support injection:

```
attachThread(tid, opts):
  PTRACE_SEIZE(tid)
  PTRACE_INTERRUPT(tid)
  Wait4(tid) — stopped
  readTGID(tid)

  // Open MemFD early (needed for injection memory writes)
  memFD = open(/proc/tid/mem)

  // Create TraceeState early (needed for scratch page allocator)
  t.tracees[tid] = &TraceeState{..., MemFD: memFD}

  PTRACE_SETOPTIONS(tid, TRACESECCOMP | TRACESYSGOOD | ...)  ← always set BOTH

  // Inject seccomp prefilter (only for explicitly-attached processes)
  if t.cfg.SeccompPrefilter && opts.sessionID != "" {
      if err := t.injectSeccompFilter(tid); err != nil {
          slog.Warn("prefilter injection failed, falling back", ...)
          // TraceeState.HasPrefilter stays false — TRACESYSGOOD mode
      } else {
          t.tracees[tid].HasPrefilter = true
      }
  }

  // Resume
  if opts.keepStopped {
      // parked for cgroup hook
  } else if t.tracees[tid].HasPrefilter {
      PtraceCont(tid, 0)     ← prefilter mode
  } else {
      PtraceSyscall(tid, 0)  ← fallback: trap all syscalls
  }
```

Key changes from current `attachThread`:
- `MemFD` opened before `PTRACE_SETOPTIONS` (currently opened after resume). Needed for scratch page allocator used by `injectSyscall`, not for the BPF write itself.
- `TraceeState` created before injection (currently created after resume). Needed because `injectSyscall` looks up TraceeState for the scratch page.
- `PTRACE_SETOPTIONS` always sets both `TRACESECCOMP` and `TRACESYSGOOD` (currently one or the other). This is safe: `handleStop` already dispatches both `SIGTRAP|0x80` (TRACESYSGOOD) and `PTRACE_EVENT_SECCOMP` stops.

### Injection Steps

`injectSeccompFilter(tid)` uses `process_vm_writev` to write the BPF program bytes into the tracee's scratch page (allocated via `injectSyscall(mmap)` if not already present). Then injects two syscalls via the `injectSyscall` engine (which uses MemFD for register save/restore):

1. **Allocate scratch page** — `injectSyscall(mmap, ...)` if not already allocated for this TGID. Uses the existing scratch page allocator.
2. **Write BPF program + `sock_fprog` struct** — `process_vm_writev` writes the filter bytes to the scratch page. This does NOT use MemFD.
3. **Inject `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`** — via `injectSyscall`. Uses MemFD for register read/write.
4. **Inject `seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)`** — via `injectSyscall`. Uses MemFD for register read/write.

In summary: `process_vm_writev` for data writes, `MemFD` for register manipulation during syscall injection.

### Failure Handling

On injection failure:
- `TraceeState.HasPrefilter` stays `false`
- Tracee resumes with `PtraceSyscall` (TRACESYSGOOD mode — all syscalls trapped)
- No `PTRACE_SETOPTIONS` change needed (both flags already set)
- Warning logged with reason (EPERM, EINVAL, etc.)

### PR_SET_NO_NEW_PRIVS Impact

`PR_SET_NO_NEW_PRIVS` prevents setuid/setcap escalation. This is acceptable for agentsh workloads — sandboxed agent commands should not escalate privileges. The flag is already set by the seccomp wrapper in non-ptrace mode.

## 5. Per-Tracee Prefilter State

Replace the global `prefilterActive bool` on `Tracer` with per-tracee state.

Add `HasPrefilter bool` to `TraceeState`. Set on successful injection. In `handleNewChild`, inherit from parent: `child.HasPrefilter = parent.HasPrefilter` (kernel inherits the seccomp filter across fork/clone/exec).

Update all call sites that check `prefilterActive`:

- `allowSyscall(tid)` — lock, read `tracees[tid].HasPrefilter`, unlock, then `PtraceCont` or `PtraceSyscall`
- `resumeTracee(tid, sig)` — same pattern
- `denySyscall(tid, errno)` — deny fixup uses `PtraceSyscall` to catch syscall-exit for return value rewrite, regardless of prefilter mode. This is correct: even with `SECCOMP_RET_TRACE`, the deny path needs syscall-exit to apply the errno. After the fixup completes, resume switches back to `PtraceCont`.
- `attachThread` initial resume — `PtraceCont` if `HasPrefilter`, `PtraceSyscall` if not
- `ptraceOptions()` — always return `TRACESECCOMP | TRACESYSGOOD` (both flags). Remove the `prefilterActive` branch.
- `traceSysGood()` — remove (no longer needed as global). `handleStop` dispatches both stop types already.

Remove the global `prefilterActive` field from `Tracer`.

### Multi-Thread Attach

`SECCOMP_SET_MODE_FILTER` without `SECCOMP_FILTER_FLAG_TSYNC` is **thread-scoped** — it only applies to the calling thread (the thread we inject the syscall into).

**Exec path**: Processes are always single-threaded at attach time (freshly started by `cmd.Start()`). Single-thread injection works. Forked children inherit the filter via kernel seccomp inheritance.

**Wrap path**: The shell may be multi-threaded. Inject the filter on **every attached thread** individually in `attachThread`. Each thread that gets successfully injected has `HasPrefilter = true`; threads where injection fails fall back to `PtraceSyscall` (TRACESYSGOOD). This avoids TSYNC complexity entirely.

The per-thread approach is simpler and more robust than TSYNC:
- No TSYNC failure semantics to handle
- No TGID-level state tracking needed
- Mixed-mode (some threads with prefilter, some without) works because `handleStop` dispatches both stop types and `allowSyscall`/`resumeTracee` check per-tracee `HasPrefilter`
- Overhead of per-thread injection is negligible (3 injected syscalls per thread, done once at attach)

## 6. Scope

### Changes

| File | Change |
|------|--------|
| `internal/ptrace/seccomp_filter.go` | New. `buildPrefilterBPF()` generates BPF from `tracedSyscallNumbers()`. Architecture validation instruction. |
| `internal/ptrace/seccomp_filter_test.go` | New. Verify instruction count, architecture coverage, parity with `tracedSyscallNumbers()`. |
| `internal/ptrace/inject_seccomp.go` | New. `injectSeccompFilter(tid)` — scratch page alloc, write BPF via `process_vm_writev`, inject `prctl` + `seccomp`. |
| `internal/ptrace/tracer.go` | Remove `prefilterActive`. Add `HasPrefilter` to `TraceeState`. Update `allowSyscall`, `resumeTracee`, `denySyscall`, `ptraceOptions`, `handleNewChild`. Remove `traceSysGood`. |
| `internal/ptrace/attach.go` | Reorder: open MemFD and create TraceeState before injection. Call `injectSeccompFilter` for each explicitly-attached thread. Set `HasPrefilter` per-thread on success. |
| `internal/ptrace/inject.go` | Verify `waitForSyscallStop` handles `PTRACE_EVENT_SECCOMP` stops (already implemented at inject.go:232). May need no changes if existing handling is sufficient. |

### Unchanged

- `internal/api/` — prefilter is internal to the tracer
- Config — `seccomp_prefilter: true` already exists
- Wrap path — same attach flow, gets prefilter automatically

### Testing

- **Unit**: BPF instruction parity with `tracedSyscallNumbers()` — no syscall can be in one but not the other
- **Integration**: attach to child with prefilter, verify `PTRACE_EVENT_SECCOMP` events arrive
- **Integration**: DNS redirect (`sendto` rewrite) works with prefilter active
- **Integration**: TracerPid masking (`read` interception) works with prefilter active
- **Fallback**: mock seccomp injection failure, verify TRACESYSGOOD fallback works
- **Inheritance**: forked children inherit filter without re-injection
- **Mixed-mode**: coexisting prefilter and non-prefilter tracees (if injection fails for one)
- **Multi-thread target**: attach to already-multithreaded process, verify each thread gets its own filter injection and `HasPrefilter = true`
- **Partial injection failure**: simulate injection failure on some threads within a TGID, verify mixed-mode (some `PTRACE_EVENT_SECCOMP`, some `SIGTRAP|0x80`) works correctly with per-tracee resume logic
- **Benchmark**: `make bench` baseline vs ptrace — target <5% overhead

## 7. Benchmark Results (Pre-Optimization)

Measured after seccomp prefilter injection is in place but before per-syscall resume optimization. `PtraceSyscall` is used uniformly, negating the prefilter's entry-filtering benefit.

| Mode | Spawn (30) | File I/O (200) | Nested (10) | Deny (10) |
|------|-----------|---------------|------------|----------|
| baseline | 898ms | 138ms | 363ms | 132ms |
| full (seccomp+FUSE) | 942ms (+5%) | 137ms (-1%) | 331ms (-9%) | 132ms (0%) |
| ptrace + prefilter | 7136ms (+695%) | 3370ms (+2342%) | 15620ms (+4203%) | 120ms (-9%) |
| ptrace no prefilter | 7298ms (+713%) | 2736ms (+1882%) | 14726ms (+3956%) | 125ms (-5%) |

**Analysis**: Prefilter vs no-prefilter is nearly identical because `PtraceSyscall` traps all syscall exits regardless of BPF filter. The per-syscall `PtraceCont` optimization (Section 3 follow-up) is needed to realize the prefilter's benefit.
