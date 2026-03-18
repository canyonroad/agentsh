# Ptrace Performance Optimizations Design

**Date**: 2026-03-17
**Status**: Draft
**Goal**: Reduce ptrace mode overhead from ~621% to substantially lower through four complementary optimizations.

## Context

Ptrace mode currently adds ~621% overhead compared to baseline (with seccomp prefilter enabled). Full mode (seccomp user-notify + FUSE + Landlock) adds only ~4%. The gap exists because ptrace requires userspace context switches on every intercepted syscall.

Benchmark data (MaskTracerPid=off, seccomp prefilter on):

| Phase | Baseline | Ptrace | Overhead |
|---|---|---|---|
| Process spawn (120) | 3505ms | 17742ms | +406% |
| File I/O (1000 ops) | 273ms | 841ms | +208% |
| Git workflow | 56ms | 608ms | +986% |
| Network (10 curl) | 357ms | 13286ms | +3622% |
| Deep tree (20x4-lvl) | 626ms | 13251ms | +2017% |
| Wide tree (10x10-fan) | 329ms | 2047ms | +522% |
| **Total** | **7509ms** | **54147ms** | **+621%** |

Four optimizations are implemented in priority order, each building on the previous.

## Optimization 1: Config-aware exit stop elimination

### Problem

`needsExitStop()` (`tracer.go:465`) unconditionally returns `true` for `openat`, `openat2`, `connect`, `read`, `pread64`, `execve`, and `execveat`. This causes `allowSyscall()` to use `PtraceSyscall` (generating an exit stop) even when the exit handler would immediately return due to config.

Specifically:
- `handleOpenatExit` returns immediately when `!t.cfg.MaskTracerPid` (`tracer.go:1006`)
- `handleConnectExit` only does TLS port tracking when `t.fds != nil` and a connection succeeds

With `MaskTracerPid=off`, every openat/connect generates a wasted exit stop + context switch.

### Solution

Convert `needsExitStop` from a standalone function to a method on `Tracer`:

```go
func (t *Tracer) needsExitStop(nr int) bool {
    switch nr {
    case unix.SYS_READ, unix.SYS_PREAD64:
        return true // only traced when escalated — always needs exit
    case unix.SYS_OPENAT, unix.SYS_OPENAT2:
        return t.cfg.MaskTracerPid // fd tracking for TracerPid masking
    case unix.SYS_CONNECT:
        return t.cfg.TraceNetwork && t.fds != nil // TLS port tracking
    case unix.SYS_EXECVE, unix.SYS_EXECVEAT:
        return true // exec failure cleanup
    }
    return false
}
```

### Call site changes

Two locations set `NeedExitStop`:
- `handleSyscallStop` (`tracer.go:900`): `state.NeedExitStop = needsExitStop(nr)` → `state.NeedExitStop = t.needsExitStop(nr)`
- `handleSeccompStop` (`tracer.go:956`): same change

No changes needed to `allowSyscall` — it already checks `mustCatchExit(s)` which reads `NeedExitStop`. When `NeedExitStop` is false and no pending fixups exist, `PtraceCont` is used automatically.

### Impact

With `MaskTracerPid=off`: saves 1 context switch per openat and connect syscall. Estimated 15-25% reduction in File I/O overhead, 5-10% in Network overhead.

With `MaskTracerPid=on`: no change — exit stops still fire.

### Risk

Low. The guard conditions exactly match the early-returns already in `handleOpenatExit` and `handleConnectExit`.

## Optimization 2: Config-driven BPF filter construction

### Problem

`narrowTracedSyscallNumbers()` (`syscalls.go:69`) returns a static list of 22+ syscalls. Several are always allowed by handlers and generate wasted entry stops:

- `socket`: always allowed at `handle_network.go:126` ("Only evaluate policy for connect and bind")
- `listen`: always allowed at `handle_network.go:126`
- `sendto`: only intercepted for DNS proxy redirect to port 53; all non-53 sendto is allowed
- `close`: only useful for fd tracker cleanup, which requires MaskTracerPid or TLS SNI

Each of these generates a seccomp stop → ptrace entry → handler immediately calls `allowSyscall`. The context switch is pure waste.

### Solution

Change `narrowTracedSyscallNumbers` to accept `TracerConfig` and build the list dynamically:

```go
func narrowTracedSyscallNumbers(cfg *TracerConfig) []int {
    var nums []int

    if cfg.TraceExecve {
        nums = append(nums, unix.SYS_EXECVE, unix.SYS_EXECVEAT)
    }
    if cfg.TraceFile {
        nums = append(nums,
            unix.SYS_OPENAT, unix.SYS_OPENAT2, unix.SYS_UNLINKAT,
            unix.SYS_MKDIRAT, unix.SYS_RENAMEAT2, unix.SYS_LINKAT,
            unix.SYS_SYMLINKAT, unix.SYS_FCHMODAT, unix.SYS_FCHMODAT2,
            unix.SYS_FCHOWNAT,
        )
        nums = append(nums, legacyFileSyscalls()...)
    }
    if cfg.TraceNetwork {
        nums = append(nums, unix.SYS_CONNECT, unix.SYS_BIND)
        if cfg.NetworkHandler != nil {
            nums = append(nums, unix.SYS_SENDTO) // DNS proxy redirect
        }
        // socket, listen: removed — always allowed
    }
    if cfg.TraceSignal {
        nums = append(nums,
            unix.SYS_KILL, unix.SYS_TGKILL, unix.SYS_TKILL,
            unix.SYS_RT_SIGQUEUEINFO, unix.SYS_RT_TGSIGQUEUEINFO,
        )
    }
    if cfg.MaskTracerPid || (cfg.TraceNetwork && cfg.NetworkHandler != nil) {
        nums = append(nums, unix.SYS_CLOSE) // fd tracker cleanup
    }

    return nums
}
```

Apply the same pattern to `tracedSyscallNumbers` (the full set including read/write).

### Call site changes

- `buildNarrowPrefilterBPF()` → `buildNarrowPrefilterBPF(cfg *TracerConfig)`, passes config through
- `buildPrefilterBPF()` → `buildPrefilterBPF(cfg *TracerConfig)`, same
- `injectSeccompFilter` (`inject_seccomp.go:31`): passes `t.cfg` to filter builder
- `buildEscalationBPF`: unchanged (takes explicit syscall lists)

### Syscalls removed from default filter

| Syscall | Reason traced | Why safe to remove |
|---|---|---|
| `socket` | Network category | Always allowed at `handle_network.go:126` |
| `listen` | Network category | Always allowed at `handle_network.go:126` |
| `sendto` | DNS redirect | Only needed when DNS proxy active |
| `close` | fd tracker | Only needed with MaskTracerPid or TLS SNI |

### Impact

Per `curl` invocation: saves ~15-25 wasted ptrace stops (socket, close, sendto). For 10 curls in the benchmark: ~150-250 fewer context switches. Estimated 10-20% reduction in Network overhead, 5-10% in process tree overhead.

### Risk

Low-medium. The removed syscalls have no policy logic. `close` is the only concern: if fd tracking is off at filter install time but somehow needed later, we'd miss close events. However, fd tracking state is determined at startup from config and doesn't change at runtime. Lazy escalation only adds read/write, not close.

## Optimization 3: BPF-level SECCOMP_RET_ERRNO for static denies

### Problem

When a policy always denies certain syscalls (e.g., all network connections), each denial still requires: seccomp stop → ptrace entry → read args → handler → deny → set errno → exit stop. This is 2 context switches for a decision that could be made entirely in kernel.

### Solution

#### New interface

```go
type StaticDenyChecker interface {
    StaticDenySyscalls() []StaticDeny
}

type StaticDeny struct {
    Nr    int
    Errno int
}
```

Handlers optionally implement `StaticDenyChecker` to declare syscalls that are always denied regardless of arguments for the lifetime of the session.

#### Extended BPF generation

Change `buildBPFForSyscalls` to support per-syscall return actions:

```go
type bpfSyscallAction struct {
    Nr     int
    Action uint32 // SECCOMP_RET_TRACE or SECCOMP_RET_ERRNO(errno)
}

func buildBPFForActions(actions []bpfSyscallAction) ([]unix.SockFilter, error)
```

The BPF program generates different return instructions per syscall:

```
LOAD nr
JEQ openat  → RET SECCOMP_RET_TRACE
JEQ connect → RET SECCOMP_RET_ERRNO|EACCES  (when deny-all)
...
RET SECCOMP_RET_ALLOW  (default)
```

#### Collection at filter install time

```go
func (t *Tracer) collectStaticDenies() []StaticDeny {
    var denies []StaticDeny

    // Category enabled but handler nil → deny all
    if t.cfg.TraceNetwork && t.cfg.NetworkHandler == nil {
        denies = append(denies,
            StaticDeny{unix.SYS_CONNECT, int(unix.EACCES)},
            StaticDeny{unix.SYS_BIND, int(unix.EACCES)},
        )
    }

    // Handler-declared denies
    if checker, ok := t.cfg.NetworkHandler.(StaticDenyChecker); ok {
        denies = append(denies, checker.StaticDenySyscalls()...)
    }
    if checker, ok := t.cfg.FileHandler.(StaticDenyChecker); ok {
        denies = append(denies, checker.StaticDenySyscalls()...)
    }

    return denies
}
```

#### Merge logic

In `injectSeccompFilter`, after building the narrow syscall list (from Optimization 2), merge with static denies:
- Syscalls in both the trace list and deny list → use `SECCOMP_RET_ERRNO`
- Syscalls in the trace list only → use `SECCOMP_RET_TRACE`
- Syscalls in the deny list but not trace list → add them with `SECCOMP_RET_ERRNO`

### Impact

Policy-dependent. For restrictive deployments (deny-all network, tight file policies): eliminates all ptrace stops for denied operations. For the benchmark (allow-heavy policies): minimal impact.

### Risk

Medium. The `StaticDenyChecker` interface must be conservative. A wrong declaration means silent denial with no ptrace override possible. Mitigations:
- Interface is opt-in (handlers don't have to implement it)
- Only for session-lifetime static decisions
- Log at filter install time which syscalls are BPF-denied

## Optimization 4: PTRACE_GET_SYSCALL_INFO for faster entry handling

### Problem

Every ptrace entry stop does a full `PTRACE_GETREGS` (reads 27 registers, 216 bytes on amd64) even though the entry handler typically only needs the syscall number and 2-3 arguments.

### Solution

#### New entry info retrieval

```go
type SyscallEntryInfo struct {
    Nr   int
    Args [6]uint64
}

func (t *Tracer) getSyscallEntryInfo(tid int) (*SyscallEntryInfo, error) {
    // Uses PTRACE_GET_SYSCALL_INFO (ptrace request 0x420e)
    // Returns ptrace_syscall_info struct with op, nr, args
    // ~80 bytes vs 216 bytes for full registers
}
```

#### Lazy register access via SyscallContext

```go
type SyscallContext struct {
    Info    SyscallEntryInfo
    tid     int
    tracer  *Tracer
    regs    Regs
    loaded  bool
}

func (sc *SyscallContext) Regs() (Regs, error) {
    if !sc.loaded {
        var err error
        sc.regs, err = sc.tracer.getRegs(sc.tid)
        if err != nil {
            return nil, err
        }
        sc.loaded = true
    }
    return sc.regs, nil
}
```

#### Handler refactoring

Handlers receive `*SyscallContext` instead of `Regs`. The allow path reads args from `sc.Info.Args[n]`. The deny/redirect path calls `sc.Regs()` for full register access.

#### Capability detection at startup

```go
func (t *Tracer) detectCapabilities() {
    t.hasSyscallInfo = probePtraceSyscallInfo()
}
```

Probe at startup, fall back to `getRegs` on older kernels. Linux 5.3+ supports `PTRACE_GET_SYSCALL_INFO`.

### Impact

Saves one full register read per allowed syscall entry. Estimated 5-10% reduction in per-stop latency. The context switch cost still dominates, so overall improvement is modest (~5% total).

### Risk

Low. Full fallback to existing `getRegs` path. `PTRACE_GET_SYSCALL_INFO` is well-supported on Linux 5.3+ (Fargate runs 6.x kernels). The `SyscallContext` refactor changes handler signatures but not logic.

### Dropped: cwd caching

Considered caching `/proc/<tid>/cwd` readlink results per-TGID. Dropped because:
- Correctness risk: stale cwd after `chdir` without re-tracing chdir
- Marginal gain: readlink is ~1-2μs, not the bottleneck
- Would require adding `chdir`/`fchdir` to the BPF filter for invalidation, partially defeating the purpose

## Combined impact estimate

| Optimization | MaskTracerPid=off | MaskTracerPid=on |
|---|---|---|
| 1. Config-aware exit stops | 15-25% of File I/O, 5-10% of Network | No change |
| 2. Smarter BPF filter | 10-20% of Network, 5-10% of trees | Same |
| 3. BPF-level deny | Policy-dependent | Policy-dependent |
| 4. PTRACE_GET_SYSCALL_INFO | ~5% overall | ~5% overall |

These are multiplicative — each reduces the number or cost of remaining stops. Conservative estimate: **30-50% total overhead reduction** for MaskTracerPid=off deployments (621% → ~310-430%). More with deny-heavy policies.

## Implementation order

1. **Optimization 1** (config-aware exit stops) — smallest change, immediate impact
2. **Optimization 2** (smarter BPF filter) — builds on Opt 1, removes more stops
3. **Optimization 1** (BPF-level deny) — extends BPF generation from Opt 2
4. **Optimization 4** (PTRACE_GET_SYSCALL_INFO) — independent, can be done in parallel

## Files affected

| File | Optimizations | Changes |
|---|---|---|
| `tracer.go` | 1, 4 | `needsExitStop` → method; `SyscallContext` dispatch |
| `syscalls.go` | 2 | Config-driven filter lists |
| `seccomp_filter.go` | 2, 3 | Config-aware builder; mixed TRACE/ERRNO BPF |
| `inject_seccomp.go` | 2, 3 | Pass config to builders; collect static denies |
| `handle_file.go` | 4 | Accept `SyscallContext` |
| `handle_network.go` | 4 | Accept `SyscallContext` |
| `handle_read.go` | 4 | Accept `SyscallContext` |
| `handle_write.go` | 4 | Accept `SyscallContext` |
| Handler interfaces | 3, 4 | `StaticDenyChecker`; `SyscallContext` |

## Testing

- Benchmark before/after each optimization with `make bench`
- Unit tests for BPF filter generation with mixed actions
- Unit tests for `needsExitStop` with different config combinations
- Integration tests for static deny (verify EPERM without ptrace stop)
- Cross-compile check: `GOOS=windows go build ./...`
