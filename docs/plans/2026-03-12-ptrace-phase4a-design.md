# Ptrace Phase 4a: Core Steering Engine — Design

**Date:** 2026-03-12
**Author:** Eran / Canyon Road
**Status:** Design Complete

---

## Overview

Phase 4a adds syscall-level redirect/steering to the ptrace backend, bringing it to feature parity with seccomp+FUSE for the core enforcement behaviors: exec redirect, file path redirect, soft-delete, and connect redirect.

All steering builds on a new **syscall injection engine** — the ability to execute arbitrary syscalls inside a stopped tracee. This is the same technique used by CRIU, strace, and Datadog CWS.

## 1. Syscall Injection Engine

### Foundation

`injectSyscall(pid, nr, args)` executes an arbitrary syscall in a stopped tracee:

1. Save the tracee's current register state
2. Write new register values (syscall nr + args)
3. Set IP to a known `syscall` instruction in the tracee's address space
4. Resume with `PtraceSyscall` → wait for syscall-enter stop
5. Resume with `PtraceSyscall` → wait for syscall-exit stop
6. Read return value from registers
7. Restore original register state

Uses the two-phase PtraceSyscall approach (not PtraceSingleStep) — immune to seccomp prefilter interactions and signal delivery races.

### Syscall Gadget Discovery

**Primary (Option C): Reuse current IP.** When the tracee is stopped at a syscall-enter or PTRACE_EVENT_SECCOMP, IP points right after the `syscall` instruction. `IP - 2` on amd64 / `IP - 4` on arm64 is the instruction itself. Zero cost, no memory writes. Works for all injection that happens during syscall interception — which covers all our use cases.

**Fallback: VDSO scan.** For edge cases where the tracee isn't at a syscall stop (e.g., PTRACE_INTERRUPT), scan the VDSO for a `syscall; ret` gadget. Cache per-tracee, invalidate on exec (ASLR remaps the VDSO).

### Architecture Support

Add to `Regs` interface (amd64 + arm64):
- `Clone() Regs`
- `SetArg(index int, val uint64)`
- `SetInstructionPointer(addr uint64)`
- `InstructionPointer() uint64`
- `ReturnValue() int64`

## 2. Scratch Page Allocation

For file path redirect where the replacement path is longer than the original.

**Strategy: mmap injection (Strategy B from spec).**

1. First time a tracee needs scratch: inject `mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)`. Cache the address.
2. Bump-allocate within the page for each string write.
3. Reset `used = 0` at each new syscall-enter stop — the kernel has consumed the data.
4. Invalidate on exec (address space remapped).

**Per-TGID, not per-TID.** Threads in the same process share address space, so one mmap serves all threads. Avoids redundant mmap injection in multi-threaded tracees.

Only file redirect needs scratch regularly. Connect redirect uses fixed-size sockaddr (always fits in-place). Exec redirect writes short stub paths that typically fit in the original buffer.

## 3. Exec Redirect

When `ExecHandler.Handle()` returns `ActionRedirect`:

### Sequence

1. **Create socketpair** in the tracer process (for stub communication)
2. **Inject fd** into tracee at fd 100 via `pidfd_getfd` (kernel 5.6+, Fargate runs 5.10+):
   - Inject `pidfd_open(tracer_pid, 0)` → pidfd
   - Inject `pidfd_getfd(pidfd, src_fd, 0)` → copy socketpair fd into tracee
   - Inject `dup3(got_fd, 100, 0)` → place at fd 100
   - Inject `close(pidfd)` + `close(got_fd)` → clean up temporaries
3. **Write stub path** into tracee memory (overwrite original filename, or use scratch if longer)
4. **Update registers** so kernel executes `execve` with stub path
5. **Resume** — stub runs, finds fd 100, connects back to tracer

### Stub Binary Location

**Option A (recommended for now):** Bind-mount the stub from the sidecar container via shared volume, configured in the ECS task definition / K8s pod spec. Simple, matches the deployment model.

**Option B (future):** Write stub into tracee memory via `memfd_create` + `execveat(fd, "", AT_EMPTY_PATH)` — entirely ptrace-injected, no filesystem dependency.

### Error Handling

If any injection step fails mid-sequence: restore saved registers, close any fds already injected via `close` injection, fall back to `denySyscall(tid, EACCES)`. Never leave the tracee in a half-modified state.

## 4. File Path Redirect

When `FileHandler.Handle()` returns `ActionRedirect`:

1. Read path from tracee memory at the pointer in the path argument
2. If replacement fits in original buffer length → overwrite in-place via `writeString`
3. If longer → allocate from scratch page, write path there, update register to new pointer
4. Resume — kernel executes the syscall with the redirected path

Works for all file syscalls from Phase 2: `openat`, `openat2`, `unlinkat`, `renameat2`, `mkdirat`, `linkat`, `symlinkat`, `fchmodat`, `fchownat`. Path argument position varies by syscall but is already mapped in the Phase 2 handler dispatch.

## 5. Soft-Delete

When `FileHandler.Handle()` returns `ActionSoftDelete` on `unlinkat`:

1. **Deny** the original `unlinkat` (nr = -1, fake success with return value 0)
2. **Inject** `renameat2(dirfd, path, trashDirFD, trashPath, 0)` to move the file to trash
3. **Inject** `mkdirat` for the trash directory on first use if it doesn't exist
4. **Emit** audit event with trash path for operator recovery

**Limitations:**
- Cross-device rename fails — fall back to deny with audit log
- Trash directory must be on the same filesystem as the file being deleted

From the tracee's perspective, `unlink()` returns 0 (success). The file is moved to trash instead of deleted. Identical to FUSE soft-delete behavior.

## 6. Connect Redirect

When `NetworkHandler.Handle()` returns `ActionRedirect`:

1. Read `sockaddr` from tracee memory, parse family/address/port
2. Resolve redirect target hostname to IP in the tracer process
3. Encode new `sockaddr_in` (16 bytes) or `sockaddr_in6` (28 bytes)
4. Write back at the same pointer — always fits (fixed-size structs)
5. Resume — kernel connects to the redirect target

**IPv4 ↔ IPv6 mismatch:** Prefer resolving to matching address family. If original is IPv4 and redirect is IPv6-only, update `addrlen` register and use stack-relative scratch for the 12 extra bytes. Prefer `.To4()` results when available.

## 7. Handler Interface Changes

Extend result types to support steering actions:

```go
type ExecResult struct {
    Action    Action  // Allow | Deny | Redirect
    Errno     int32
    StubPath  string  // for Redirect
    // StubFD managed internally by tracer
}

type FileResult struct {
    Action       Action  // Allow | Deny | Redirect | SoftDelete
    Errno        int32
    RedirectPath string  // for Redirect
    TrashDir     string  // for SoftDelete
}

type NetworkResult struct {
    Action       Action  // Allow | Deny | Redirect
    Errno        int32
    RedirectAddr net.IP  // for Redirect
    RedirectPort int     // for Redirect
}
```

Syscall handler dispatch adds a third path:

```
handler.Handle() → result
  Allow      → allowSyscall(tid)
  Deny       → denySyscall(tid, errno)
  Redirect   → redirectExec/redirectFile/redirectConnect(tid, result)
  SoftDelete → softDelete(tid, result)
```

All redirect operations save registers upfront and restore + deny on any injection failure.

## 8. Testing Strategy

Integration tests behind `//go:build integration && linux`, using helper binaries compiled at test time.

| Test | What it validates |
|------|-------------------|
| `TestIntegration_SyscallInjection` | Inject `getpid()`, verify return matches tracee's PID |
| `TestIntegration_ExecRedirect` | Redirect `/bin/echo` → stub, verify stub runs |
| `TestIntegration_FileRedirect` | Redirect `openat` path, verify redirected file contents read |
| `TestIntegration_SoftDelete` | Soft-delete on `unlinkat`, verify file at trash path, helper saw success |
| `TestIntegration_ConnectRedirect` | Redirect connect to different port, verify connection to redirect target |
| `TestIntegration_ScratchPage` | Redirect to longer path, verify mmap injection + redirect works |

All runnable via `docker run --cap-add SYS_PTRACE`.

## 9. Files

| File | Action |
|------|--------|
| `internal/ptrace/inject.go` | Create — syscall injection engine |
| `internal/ptrace/inject_amd64.go` | Create — amd64 gadget address (IP-2) |
| `internal/ptrace/inject_arm64.go` | Create — arm64 gadget address (IP-4) |
| `internal/ptrace/scratch.go` | Create — scratch page allocation |
| `internal/ptrace/redirect_exec.go` | Create — exec redirect (fd injection + stub rewrite) |
| `internal/ptrace/redirect_file.go` | Create — file path redirect + soft-delete |
| `internal/ptrace/redirect_net.go` | Create — connect redirect (sockaddr rewrite) |
| `internal/ptrace/args_amd64.go` | Modify — add Clone, SetArg, SetInstructionPointer, ReturnValue |
| `internal/ptrace/args_arm64.go` | Modify — add Clone, SetArg, SetInstructionPointer, ReturnValue |
| `internal/ptrace/tracer.go` | Modify — wire redirect dispatch into syscall handlers |
| `internal/ptrace/integration_test.go` | Modify — add redirect integration tests |

## 10. What's NOT in Phase 4a

- DNS redirect (Phase 4b)
- SNI rewrite (Phase 4b)
- TracerPid masking (Phase 4b)
- Sidecar auto-discovery (Phase 4c)
- Fargate E2E tests (Phase 4c)
- EKS Fargate support (Phase 4c)
- Multi-thread tracer scaling (future, only if measurements show bottleneck)
