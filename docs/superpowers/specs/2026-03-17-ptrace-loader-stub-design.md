# Ptrace Loader Stub + Experimental SYSEMU Design

**Date**: 2026-03-17
**Status**: Draft
**Goal**: Reduce per-exec ptrace overhead by pre-installing the seccomp BPF filter via a loader binary, and experimentally reduce per-deny overhead via PTRACE_SYSEMU.

## Context

After the previous round of optimizations (PR #143), ptrace mode overhead is +394%. The benchmark shows per-exec attach cost as the dominant remaining overhead:

| Phase | Overhead | Root cause |
|---|---|---|
| Deep tree (20x4-lvl) | +1316% | 80 sequential attaches × ~15ms each |
| Process spawn (120) | +269% | 120 attaches × ~15ms each |
| Wide tree (10x10-fan) | +372% | 100 attaches × ~15ms each |
| Network (10 curl) | +2010% | Per-syscall stops (not attach-related) |

The current attach flow per exec:
1. `cmd.Start()` — Go forks and execs the child
2. `PTRACE_SEIZE` + `PTRACE_INTERRUPT` + `Wait4` polling (~2-3ms)
3. `PTRACE_SETOPTIONS` (fork/clone/exec tracing)
4. Resume with `PtraceSyscall`
5. **Deferred BPF injection** on first syscall EXIT: `prctl(PR_SET_NO_NEW_PRIVS)` + `seccomp(SET_MODE_FILTER)` — 2 injected syscalls, each requiring 1-2 ptrace cycles (~4-8ms total)
6. Resume — tracee now has the prefilter

Steps 1-4 are unavoidable (ptrace must attach for syscall interception). Step 5 is the target — if the child self-installs the BPF filter before the tracer attaches, the deferred injection path is eliminated entirely.

## Optimization 1: Loader Stub

### Design

A new binary `agentsh-loader` that wraps every exec in ptrace mode:

```
Before: fork → exec(cmd, args...) → tracer attaches → inject BPF → run
After:  fork → exec(agentsh-loader, cmd, args...) → loader installs BPF → exec(cmd) → tracer attaches (filter already present) → run
```

### Loader binary (`cmd/agentsh-loader/main.go`)

~60 lines. Linux-only (`//go:build linux`).

**Arguments**: `agentsh-loader --filter-fd=N -- cmd arg1 arg2 ...`

**Behavior**:
1. Parse `--filter-fd=N` from args, find `--` separator, remaining args are the real command
2. Read serialized BPF filter from fd N (binary format: `uint16 count` + `count * 8 bytes` of `sock_filter` instructions)
3. Call `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`
4. Build `sock_fprog` struct pointing to the filter array
5. Call `seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)`
6. Close fd N
7. `syscall.Exec(cmd, args, environ)` — replaces the loader with the real command

**Error handling**: If any step fails, write error to stderr and exit 126 (matching exec failure convention). The tracer will see the process exit and report the error. The fallback (deferred injection) handles the case where the loader binary is missing.

**Wire format** (pipe → loader): Simple binary encoding:
```
[2 bytes: uint16 little-endian instruction count]
[count * 8 bytes: sock_filter instructions, each 8 bytes]
```

No `sock_fprog` header — the loader builds that itself with the pointer to its local buffer.

### Server-side changes (`internal/api/exec.go`)

When ptrace is active and `SeccompPrefilter` is enabled:

1. Serialize the narrow BPF filter to a byte buffer (reuse `narrowTracedSyscallNumbers` + `buildBPFForSyscalls` or `buildBPFForActions`)
2. Create `os.Pipe()` — write end for server, read end inherited by child
3. Write serialized filter to write end, close write end
4. Wrap the command: instead of `exec.Command(cmd, args...)`, use `exec.Command("agentsh-loader", "--filter-fd=N", "--", cmd, args...)`
5. Set read end's fd to be inherited via `cmd.ExtraFiles`

The filter is compiled once per session (or per config change) and reused for every exec. The pipe write is ~200-500 bytes — negligible.

**Loader path resolution**: The loader binary path is resolved at server startup (check `/usr/bin/agentsh-loader`, then `$PATH`). If not found, fall back to existing deferred injection. Store the resolved path in a config field.

### Tracer-side changes (`internal/ptrace/attach.go`)

Add an `AttachOption`: `WithPrefilterInstalled()`. When set, `attachThread` skips setting `PendingPrefilter = true`. The tracee already has the filter, so `HasPrefilter` should be set to `true` immediately.

```go
// In attachThread, after creating TraceeState:
if opts.prefilterInstalled {
    s.HasPrefilter = true
    // Don't set PendingPrefilter — filter already installed by loader
} else if t.cfg.SeccompPrefilter && opts.sessionID != "" {
    s.PendingPrefilter = true
}
```

This means:
- `allowSyscall` will use `PtraceCont` (not `PtraceSyscall`) from the first syscall — no wasted exit stops for deferred injection
- The deferred injection path in `handleSyscallStop` is never triggered
- The first syscall stop is a `PTRACE_EVENT_SECCOMP` (filter is already active)

### Fallback behavior

If `agentsh-loader` is not found at startup:
- Log a warning: "agentsh-loader not found, falling back to deferred BPF injection"
- Set `loaderPath = ""` — exec path skips the wrapper
- All existing behavior preserved — zero regression risk

### Build and distribution

**Dockerfile.bench** — add build and copy:
```dockerfile
RUN go build -o /out/agentsh          ./cmd/agentsh && \
    go build -o /out/agentsh-shell-shim ./cmd/agentsh-shell-shim && \
    go build -o /out/agentsh-unixwrap  ./cmd/agentsh-unixwrap && \
    go build -o /out/agentsh-stub      ./cmd/agentsh-stub && \
    go build -o /out/agentsh-loader    ./cmd/agentsh-loader

COPY --from=builder /out/agentsh-loader    /usr/bin/agentsh-loader
```

**Makefile** — no changes needed (existing `go build ./...` covers all `cmd/` binaries).

**CI** — no changes needed (existing build matrix builds all `cmd/` binaries).

### Expected impact

Each exec saves ~4-8ms of BPF injection overhead (2 injected syscalls × 1-2 ptrace cycles × ~2ms each). For the benchmark:
- Process spawn (120 execs): saves ~480-960ms → estimated 5-10% improvement
- Deep tree (80 execs): saves ~320-640ms → estimated 4-8% improvement
- Wide tree (100 execs): saves ~400-800ms → estimated 5-10% improvement

The improvement is proportional to exec count. Deep tree's absolute overhead is dominated by the sequential attach latency (PTRACE_SEIZE + INTERRUPT + Wait4 polling), which the loader doesn't eliminate — only the BPF injection phase is removed.

## Optimization 2: Experimental PTRACE_SYSEMU for denies

### Design

Use `PTRACE_SYSEMU` to skip kernel syscall execution for denied syscalls, saving 1 context switch per deny (entry-only instead of entry+exit).

### Current deny flow (2 stops)

1. **Entry stop** (seccomp or TRACESYSGOOD): handler decides deny
2. Set `ORIG_RAX = -1` (invalidate syscall), set `PendingDenyErrno`, resume with `PtraceSyscall`
3. **Exit stop**: kernel set `RAX = -ENOSYS`, tracer overwrites with `-errno`, resume

### Proposed SYSEMU deny flow (1 stop)

1. **Entry stop**: handler decides deny
2. Set `RAX = -errno` directly (no ORIG_RAX modification needed)
3. Resume with `PTRACE_SYSEMU` — kernel skips syscall execution, tracee sees `RAX = -errno`
4. No exit stop

### Implementation

**Runtime probe** at tracer startup:
```go
func probePtraceSysemu() bool {
    // Test SYSEMU from a seccomp stop on a sacrificial child
    // Returns true if kernel handles SYSEMU correctly from SECCOMP_RET_TRACE stops
}
```

This is a non-trivial probe — it needs to:
1. Fork a child, attach via ptrace, install a seccomp filter
2. Child makes a syscall that triggers the filter
3. Tracer resumes with `PTRACE_SYSEMU`
4. Verify the child sees the correct return value and the next syscall works normally

**Tracer integration** — in `denySyscall` (`tracer.go:523`):
```go
if t.hasSysemu && state.HasPrefilter {
    // Fast path: set return value, resume with SYSEMU (1 stop)
    regs.SetReturnValue(int64(-errno))
    t.setRegs(tid, regs)
    unix.PtraceSyscall(tid, 0) // TODO: replace with SYSEMU once verified
} else {
    // Existing path: nullify + exit fixup (2 stops)
    regs.SetSyscallNr(-1)
    // ... existing code
}
```

### Risk and scope

**This is experimental.** The interaction between `PTRACE_SYSEMU` and `SECCOMP_RET_TRACE` stops is not well-documented in the kernel. The probe verifies it works at runtime. If the probe fails, the existing 2-stop path is used — zero regression.

**Impact is marginal.** Deny enforcement is already +0.9% in benchmarks. The savings apply to dynamic denies (static denies are already handled at BPF level via `SECCOMP_RET_ERRNO` from PR #143). Real-world impact depends on how many dynamic denies occur.

## Implementation order

1. **Loader stub** — high impact, well-understood mechanism
2. **SYSEMU** — experimental, low impact, can be deferred without loss

## Files affected

| File | Changes |
|---|---|
| `cmd/agentsh-loader/main.go` | New — loader binary |
| `internal/api/exec.go` | Wrap command with loader in ptrace mode |
| `internal/ptrace/attach.go` | `WithPrefilterInstalled` option, skip deferred injection |
| `internal/ptrace/tracer.go` | Add `hasSysemu` field, SYSEMU deny path |
| `internal/ptrace/seccomp_filter.go` | Export filter serialization for loader |
| `Dockerfile.bench` | Build and copy agentsh-loader |

## Testing

- Unit tests for loader binary (parse args, read filter, install seccomp)
- Unit tests for filter serialization/deserialization
- Integration test: exec with loader, verify seccomp filter is active
- Benchmark before/after: `make bench`
- Cross-compile: `GOOS=windows go build ./...`
- SYSEMU probe test: verify probe detects support/non-support correctly
