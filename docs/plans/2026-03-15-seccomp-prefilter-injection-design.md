# Design: Seccomp Prefilter Injection for Server-Wired Ptrace Mode

**Date:** 2026-03-15
**Status:** Draft

---

## 1. Problem

In server-wired ptrace mode, every syscall generates a ptrace-stop (`TRACESYSGOOD` mode) because the seccomp prefilter is not installed. Only ~30 syscall types need tracing (exec, file, network, signal), but the tracer traps all ~300+ syscall types, causing ~10-50x overhead compared to baseline.

The seccomp prefilter (`SeccompPrefilter: true` in config) was designed for sidecar mode where the BPF could be installed before the workload starts. In server-wired mode, the child process is started by Go's `os/exec` and the tracer attaches afterward — there's no pre-exec hook to install the BPF.

## 2. Solution: Inject BPF via Ptrace Syscall Injection

After `PTRACE_SEIZE` + `PTRACE_INTERRUPT` stops the child, inject a `seccomp(SECCOMP_SET_MODE_FILTER)` syscall using the existing `injectSyscall` engine. The BPF program returns `SECCOMP_RET_TRACE` for traced syscalls and `SECCOMP_RET_ALLOW` for all others. The kernel then generates `PTRACE_EVENT_SECCOMP` stops only for traced syscalls.

## 3. BPF Program

A static seccomp-BPF filter (~30-40 instructions) that traces:

- **Exec**: `execve`, `execveat`
- **File**: `openat`, `openat2`, `unlinkat`, `renameat2`, `mkdirat`, `linkat`, `symlinkat`, `fchmodat`, `fchmodat2`, `fchownat` (+ legacy amd64: `open`, `creat`, `mkdir`, `rmdir`, `unlink`, `rename`, `link`, `symlink`, `chmod`, `chown`)
- **Network**: `connect`, `bind`
- **Signal**: `kill`, `tkill`, `tgkill`, `rt_sigqueueinfo`, `rt_tgsigqueueinfo`
- **Syscall-exit tracking**: `read`, `pread64`, `close` (TracerPid masking, fd tracking)

Structure: load syscall number → compare against each traced number → `SECCOMP_RET_TRACE` on match → `SECCOMP_RET_ALLOW` on default.

Architecture-specific (amd64 vs arm64 syscall numbers). Built once at tracer startup, reused for every child attach. Compiled in Go as `[]unix.SockFilter`, not loaded from a file.

## 4. Injection Point

Injection happens in `attachThread()` after `PTRACE_SETOPTIONS` and before the tracee is resumed:

```go
// In attachThread, after PTRACE_SETOPTIONS:
if t.cfg.SeccompPrefilter && opts.sessionID != "" {
    if err := t.injectSeccompFilter(tid); err != nil {
        slog.Warn("seccomp prefilter injection failed, falling back to TRACESYSGOOD",
            "tid", tid, "error", err)
        // Non-fatal: fall back to trapping all syscalls
    }
}
```

`injectSeccompFilter(tid)` performs three injected syscalls:

1. **Write BPF to tracee memory** — use the scratch page allocator (`tgidScratch`, already exists for exec redirect) to write the `sock_filter` array into the tracee's address space
2. **Inject `prctl(PR_SET_NO_NEW_PRIVS, 1)`** — required before `seccomp()`. Idempotent if already set.
3. **Inject `seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)`** — installs the BPF filter

Only explicitly-attached processes (from `ptraceExecAttach`, identified by `opts.sessionID != ""`) get injection. Auto-traced children from `handleNewChild` inherit the filter via the kernel's seccomp fork inheritance — no injection needed.

Injection failure is non-fatal — falls back to TRACESYSGOOD (current behavior, all syscalls trapped). This handles environments where `seccomp()` is blocked.

## 5. Per-Tracee Prefilter State

Replace the global `prefilterActive bool` on `Tracer` with per-tracee state:

Add `HasPrefilter bool` to `TraceeState`. Set it on successful injection. In `handleNewChild`, inherit from parent: `child.HasPrefilter = parent.HasPrefilter`.

Update all ~5 call sites that check `prefilterActive` to check per-tracee state:

- `allowSyscall(tid)` — `PtraceCont` if prefilter, `PtraceSyscall` if not
- `resumeTracee(tid, sig)` — same
- `denySyscall(tid, errno)` — resume after deny uses same logic
- `attachThread` initial resume — `PtraceCont` if prefilter, `PtraceSyscall` if not
- `traceSysGood()` — no longer needed as global; with prefilter, stops come as `PTRACE_EVENT_SECCOMP`, without they come as `SIGTRAP|0x80`. `handleStop` already dispatches both.

Remove the global `prefilterActive` field from `Tracer`.

## 6. Scope

### Changes

| File | Change |
|------|--------|
| `internal/ptrace/seccomp_filter.go` | New. BPF program builder (`buildPrefilterBPF`) returning `[]unix.SockFilter`. |
| `internal/ptrace/seccomp_filter_amd64.go` | amd64 traced syscall number list (includes legacy). |
| `internal/ptrace/seccomp_filter_arm64.go` | arm64 traced syscall number list. |
| `internal/ptrace/inject_seccomp.go` | New. `injectSeccompFilter(tid)` — writes BPF to tracee memory, injects `prctl` + `seccomp` syscalls. |
| `internal/ptrace/tracer.go` | Remove global `prefilterActive`. Add `HasPrefilter` to `TraceeState`. Update `allowSyscall`, `resumeTracee`, `denySyscall`, `traceSysGood` to check per-tracee state. Inherit `HasPrefilter` in `handleNewChild`. |
| `internal/ptrace/attach.go` | Call `injectSeccompFilter` after `PTRACE_SETOPTIONS` for explicitly-attached processes. Set `HasPrefilter` on `TraceeState`. |

### Unchanged

- `internal/api/` — prefilter is internal to the tracer
- Wrap path — same attach flow, gets prefilter automatically
- Config — `seccomp_prefilter: true` already exists, just wasn't functional in server mode

### Testing

- **Unit**: verify BPF program compiles and has correct instruction count per architecture
- **Integration**: attach to child, verify `PTRACE_EVENT_SECCOMP` events (not `SIGTRAP|0x80`)
- **Benchmark**: re-run bench comparing baseline vs ptrace with prefilter
- **Fallback**: verify injection failure falls back gracefully (non-fatal)
- **Inheritance**: verify forked children inherit the filter without re-injection
