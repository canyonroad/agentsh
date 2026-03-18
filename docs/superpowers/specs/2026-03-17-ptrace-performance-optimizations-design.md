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
- `handleOpenatExit` returns immediately when `!t.cfg.MaskTracerPid` (`tracer.go:1006`). Note: `t.fds` is unconditionally initialized in `Run()` at `tracer.go:1578` so the `t.fds == nil` guard in `handleOpenatExit` is always false during the tracer's lifetime.
- `handleConnectExit` does TLS fd watching for SNI rewrite after successful connect to TLS ports

With `MaskTracerPid=off`, every openat generates a wasted exit stop + context switch.

Note: `handleNetwork` already performs inline exit stop skipping for connect to non-TLS ports at `handle_network.go:256-263` (`s.NeedExitStop = false` when `port != 443 && port != 853`). So the connect case in `needsExitStop` provides marginal additional benefit — only covering the initial default before the handler runs. The primary value of this optimization is for **openat**.

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
        return t.cfg.TraceNetwork // TLS port tracking; inline skip in handleNetwork
                                  // handles port-level granularity (443/853 only)
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

With `MaskTracerPid=off`: saves 1 context switch per openat syscall. The connect benefit is marginal since the inline skip in `handleNetwork` already handles most cases. Estimated 15-25% reduction in File I/O overhead.

With `MaskTracerPid=on`: no change — exit stops still fire for openat. Connect exit stops are unchanged (already inline-skipped for non-TLS ports).

### Risk

Low. The openat guard condition exactly matches the early-return in `handleOpenatExit`. The connect simplification from `t.cfg.TraceNetwork && t.fds != nil` to `t.cfg.TraceNetwork` is safe because `t.fds` is always non-nil.

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

Apply the same pattern to `tracedSyscallNumbers` (the full set used as fallback when seccomp prefilter is off, i.e., TRACESYSGOOD mode). That function should also be config-driven, adding the same category-based syscall selection plus `SYS_READ`/`SYS_PREAD64`/`SYS_WRITE` unconditionally (since without a prefilter, all traced syscalls need TRACESYSGOOD handling). The escalation BPF lists (`readEscalationSyscalls`, `writeEscalationSyscalls`) remain unchanged — they are explicit static lists used only when stacking additional filters.

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

Known limitation: if the DNS proxy fails to start (`tracer.go:1581`), `t.dnsProxy` will be nil even though `TraceNetwork && NetworkHandler != nil` are set. In this case, `sendto` would be in the BPF filter but the handler would just `allowSyscall` every sendto — wasted stops, not incorrect behavior.

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

Handlers optionally implement `StaticDenyChecker` to declare syscalls that are always denied regardless of arguments for the lifetime of the session. Errno must be > 0; zero or negative values are rejected at filter install time with a warning log.

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

**Seccomp stacking invariant**: Static deny syscalls must never overlap with escalation syscall lists (`readEscalationSyscalls`, `writeEscalationSyscalls`). In seccomp filter stacking, the kernel returns the action with the lowest value (most restrictive). `SECCOMP_RET_ERRNO` (0x00050000) is lower than `SECCOMP_RET_TRACE` (0x7FF00000), so a BPF-level ERRNO cannot be overridden by a later TRACE escalation filter. Currently the escalation lists only contain `read`/`pread64`/`write`, which would never be statically denied, so there is no conflict. This non-overlap must be maintained as an invariant — validate at filter install time.

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
    // ~96 bytes vs 216 bytes for full registers
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

**Exit handlers continue using `getRegs`**: `PTRACE_GET_SYSCALL_INFO` at exit time returns `ptrace_syscall_info.exit` (rval + is_error), NOT the entry args. Exit handlers like `handleConnectExit` and `handleOpenatExit` need entry-time arguments (sockaddr pointer, fd number). Two options:
- (Recommended) Exit handlers call `getRegs()` directly, since registers still contain argument values at exit time. This preserves current behavior with no refactoring.
- Store `SyscallEntryInfo` in `TraceeState` alongside `LastNr` and carry it to exit handlers. More complex, marginal benefit.

#### Capability detection at startup

```go
func (t *Tracer) detectCapabilities() {
    t.hasSyscallInfo = probePtraceSyscallInfo()
}
```

Probe at startup, fall back to `getRegs` on older kernels. Linux 5.3+ supports `PTRACE_GET_SYSCALL_INFO`.

### Impact

Saves one full register read per allowed syscall entry. Both `PTRACE_GETREGS` and `PTRACE_GET_SYSCALL_INFO` are single ptrace calls; the difference is ~120 bytes less `copy_to_user`. The context switch and ptrace framework overhead dominate. Estimated 1-3% reduction in per-stop latency. Overall improvement is modest (~2-3% total).

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
| 1. Config-aware exit stops | 15-25% of File I/O | No change (connect inline skip already exists) |
| 2. Smarter BPF filter | 10-20% of Network, 5-10% of trees | Same |
| 3. BPF-level deny | Policy-dependent | Policy-dependent |
| 4. PTRACE_GET_SYSCALL_INFO | ~2-3% overall | ~2-3% overall |
| 5. Static allow categories | **37% total** (permissive policies) | Same |

Optimizations 1-4 are multiplicative — each reduces the number or cost of remaining stops. Conservative estimate: **25-40% total overhead reduction** for MaskTracerPid=off deployments (621% → ~370-465%). More with deny-heavy policies.

Optimization 5 is additive on top of 1-4, measured at **+367% → +229%** (after opts 1-3 already applied). Only applies when handler categories are fully permissive.

## Implementation order

1. **Optimization 1** (config-aware exit stops) — smallest change, immediate impact
2. **Optimization 2** (smarter BPF filter) — builds on Opt 1, removes more stops
3. **Optimization 3** (BPF-level deny) — extends BPF generation from Opt 2
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
- Integration tests for static deny (verify configured errno returned without ptrace stop)
- Cross-compile check: `GOOS=windows go build ./...`

## Optimization 5: Static allow for syscall categories (implemented 2026-03-18)

### Problem

When a handler's policy is fully permissive (allows everything), every intercepted syscall still generates a ptrace stop only to immediately allow it. For file-heavy workloads (curl loading shared libraries, git operations), this produces hundreds of wasted ptrace stops per command.

### Solution

Mirror the existing `StaticDenyChecker` pattern with a `StaticAllowChecker` interface:

```go
type StaticAllowChecker interface {
    StaticAllowSyscalls() []int
}
```

Handlers implement this to declare syscalls that are always allowed. At filter injection time, these syscalls are removed from the BPF traced set — the default `SECCOMP_RET_ALLOW` handles them in-kernel with zero ptrace overhead.

Config knobs `performance.static_allow_file` and `performance.static_allow_network` control which categories are statically allowed.

### Files changed

| File | Change |
|---|---|
| `static_policy.go` | `StaticAllowChecker` interface, `collectStaticAllows()` |
| `inject_seccomp.go` | Filter allows from `narrowNums` before BPF generation |
| `syscalls.go` | Exported `AllFileSyscalls()`, `AllNetworkSyscalls()` |
| `config/ptrace.go` | `StaticAllowFile`, `StaticAllowNetwork` in `PtracePerformanceConfig` |
| `api/ptrace_handlers.go` | `ptraceHandlerRouter` implements `StaticAllowChecker` |
| `api/app_ptrace_linux.go` | Wires config to router |

### Bug found during implementation

The initial implementation filtered `narrowNums` but the else branch (no static denies) called `buildNarrowPrefilterBPF(&t.cfg)` which recomputed the syscall list from config, ignoring static allows entirely. Fixed to use `buildBPFForSyscalls(narrowNums)` instead.

### Benchmark results

| Phase | Ptrace | Ptrace-allow | Improvement |
|---|---|---|---|
| Process spawn (120) | +231% | +160% | 31% less overhead |
| File I/O (1000 ops) | +114% | +46% | 60% less overhead |
| Network (10 curl) | +2073% | +682% | 67% less overhead |
| Deep tree (20x4-lvl) | +1297% | +708% | 45% less overhead |
| **Total** | **+367%** | **+229%** | **37% less overhead** |

### Tradeoff

Static allows bypass both policy enforcement AND audit logging for the allowed categories. Only enable when the policy is fully permissive for that category (no deny rules) and audit events for those syscalls are not needed.
