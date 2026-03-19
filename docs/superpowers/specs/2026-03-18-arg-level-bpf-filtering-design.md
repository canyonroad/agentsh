# Argument-Level BPF Filtering for Ptrace Overhead Reduction

**Date:** 2026-03-18
**Status:** Implemented (sendto filter active; openat filter deferred pending StaticReadAllowChecker)

## Problem

The ptrace tracer adds ~350% overhead (realistic policy) with the dominant cost being kernel context switches (~50-100μs per ptrace stop). The seccomp BPF prefilter currently checks only syscall numbers — every `openat` triggers a ptrace stop even for read-only opens that the policy would always allow. In restricted environments (gVisor/Modal, AWS Fargate) where seccomp user notify, Landlock, and FUSE are unavailable, ptrace + basic seccomp BPF is the only interception mechanism.

## Solution

Extend the seccomp BPF prefilter to check syscall arguments (flags, pointer values) before deciding whether to trigger a ptrace stop. Syscalls that can be determined safe at the BPF level get `SECCOMP_RET_ALLOW` in-kernel with zero ptrace overhead.

## Patterns

### 1. openat read-only detection (openat only, NOT openat2)

**Condition:** `args[2] & (O_WRONLY|O_RDWR|O_CREAT|__O_TMPFILE) == 0`

**Flag values:** `O_WRONLY=0x1`, `O_RDWR=0x2`, `O_CREAT=0x40`, `__O_TMPFILE=0x400000`. Combined mask: `0x400043`.

**BPF logic:** Single `JSET 0x400043` instruction on the low 32 bits of `args[2]` (offset 32 in `seccomp_data`). If any bit is set → `SECCOMP_RET_TRACE` (write/create needs policy check). If no bits set → `SECCOMP_RET_ALLOW` (read-only, skip ptrace).

**Why not openat2?** `openat2(dirfd, pathname, *open_how, size)` passes a **pointer** to `struct open_how` in `args[2]`, not inline flags. Classic BPF cannot dereference pointers, so applying the bitmask to a pointer value is incorrect. `openat2` remains unconditionally traced. In practice, `openat2` is rare — the vast majority of file opens use `openat`.

**Impact:** Eliminates ptrace stops for the majority of `openat` calls in typical workloads (builds, package installs, most program execution). Expected to substantially reduce the +131% file I/O overhead.

**Trade-off:** No audit events for read-only opens. Accepted per design discussion.

**Edge case — O_RDONLY|O_TRUNC:** A process could call `openat(dirfd, path, O_RDONLY|O_TRUNC)`, which has undefined behavior per POSIX but may truncate on Linux. The mask `0x400043` would allow this through since neither O_WRONLY nor O_RDWR is set. This is consistent with the existing `openatOperation()` handler behavior, which also classifies this as "open" (read-only). Not a regression.

### 2. sendto with NULL dest_addr

**Condition:** `args[4] == 0` (dest_addr pointer is NULL)

**BPF logic:** Load low 32 bits of `args[4]` (offset 48), check `== 0`. If zero, load high 32 bits (offset 52), check `== 0`. Both zero → `SECCOMP_RET_ALLOW`. Otherwise → `SECCOMP_RET_TRACE`.

**Impact:** Connected-socket sends (no destination to evaluate) skip ptrace. Sendto with a destination address still gets traced for DNS redirect handling.

### Dropped: connect AF_UNSPEC

BPF cannot dereference the sockaddr pointer to verify the address family. Checking `addrlen == 2` alone is not reliable for a security boundary.

## BPF Program Structure

The existing BPF program is a linear scan of syscall numbers. The new structure adds arg-check blocks at the end:

```
Load arch → check → Load nr
  → JEQ SYS_OPENAT   → jump to openat_check
  → JEQ SYS_OPENAT2  → jump to trace_ret     (pointer arg, cannot filter)
  → JEQ SYS_SENDTO   → jump to sendto_check
  → JEQ SYS_CONNECT  → jump to trace_ret     (unchanged)
  → ...
  → default: RET ALLOW

openat_check:
  LD W ABS 32                    // Load low 32 bits of args[2] (flags)
  JSET 0x400043                  // O_WRONLY|O_RDWR|O_CREAT|__O_TMPFILE
    → true:  RET TRACE           // write/create — needs policy
    → false: RET ALLOW           // read-only — skip ptrace

sendto_check:
  LD W ABS 48                    // Load low 32 bits of args[4]
  JEQ 0 → check_high
    → RET TRACE                  // non-null dest — needs policy
  check_high:
  LD W ABS 52                    // Load high 32 bits of args[4]
  JEQ 0 → RET ALLOW             // NULL — connected socket, skip
    → RET TRACE

trace_ret: RET TRACE
```

Syscalls with arg filters jump to their check block instead of the shared `RET TRACE`. All other syscalls behave identically to today.

## Config

New field in `PtracePerformanceConfig`:

```go
ArgLevelFilter bool `yaml:"arg_level_filter"`
```

Default: `false` (opt-in). Enabling bypasses ptrace for filtered syscall patterns, which means no audit events and no policy evaluation for those calls. Enable only when policy confirms the bypassed patterns are unconditionally safe. Only takes effect when `SeccompPrefilter` is also enabled.

## API

New types in `seccomp_filter.go`:

```go
// bpfArgFilter describes a bitmask check on a syscall argument.
// If (arg & Mask) != 0 → TRACE, else → ALLOW.
// Only applicable to arguments that are scalar values (flags, sizes),
// NOT pointers. Classic BPF cannot dereference pointers.
type bpfArgFilter struct {
    Nr       int
    ArgIndex int    // 0-5
    Mask     uint32
}

// bpfNullPtrFilter describes a NULL-pointer check on a syscall argument.
// If arg == 0 → ALLOW, else → TRACE.
type bpfNullPtrFilter struct {
    Nr       int
    ArgIndex int // 0-5
}
```

New builder function:

```go
func buildBPFWithArgFilters(
    actions []bpfSyscallAction,
    argFilters []bpfArgFilter,
    nullFilters []bpfNullPtrFilter,
) ([]unix.SockFilter, error)
```

## Integration

### Filter injection pipeline

In `injectSeccompFilter`, after collecting static denies/allows and building the action list:

```
if argLevelFilter  → buildBPFWithArgFilters(actions, argFilters, nullFilters)
else if denies > 0 → buildBPFForActions(actions)
else               → buildBPFForSyscalls(narrowNums)
```

`buildBPFWithArgFilters` subsumes `buildBPFForActions` — it handles per-syscall actions (TRACE/ERRNO) and arg-level checks. If a syscall has both a static deny and an arg filter, the static deny wins (arg filter not applied).

### Interaction with existing features

- **Escalation filters:** Only apply to read/write syscalls. No overlap with arg-filtered syscalls. Seccomp stacking uses lowest-value-wins semantics (`SECCOMP_RET_ERRNO` < `SECCOMP_RET_TRACE` < `SECCOMP_RET_ALLOW`), so a stacked escalation filter returning TRACE for read/write would not conflict with the base filter's ALLOW for openat/sendto since they are different syscalls. No conflict.
- **StaticAllowChecker:** If a handler declares `openat` as statically allowed, it's removed from `narrowNums` before arg filter construction. The arg filter won't be emitted. No conflict.
- **StaticDenyChecker:** Deny actions (ERRNO) take priority. Arg filter skipped for denied syscalls.
- **MaskTracerPid:** When enabled, `needsExitStop` returns true for all openat calls so that `handleOpenatExit` can track fds pointing to `/proc/*/status` and trigger read escalation. If the arg-level filter allows read-only opens through without a ptrace stop, fd tracking would never run, breaking TracerPid masking. **Therefore: when `MaskTracerPid` is enabled, the openat arg filter must NOT be applied.** The openat `bpfArgFilter` should only be emitted when `MaskTracerPid` is false. Currently `MaskTracerPid` is disabled, so no conflict exists in practice.

### Handler behavioral change

When `ArgLevelFilter` is on, the file handler only receives `openat` stops for write/create operations. The `operation` field from `openatOperation()` will never be `"open"` (read-only). This is consistent with the "skip audit for read-only opens" decision.

## Testing

### Unit tests (`seccomp_filter_test.go`)

1. `TestBPFArgFilterOpenatReadOnly` — verify JSET instruction with mask `0x400043`, correct ALLOW/TRACE returns
2. `TestBPFArgFilterSendtoNull` — verify two JEQ 0 instructions for 64-bit null check
3. `TestBPFArgFilterWithStaticDeny` — arg filter not applied when syscall has ERRNO action
4. `TestBPFArgFilterWithStaticAllow` — arg filter not emitted for syscalls removed by StaticAllowChecker
5. `TestBPFArgFilterInstructionLimit` — total program under 4096 instructions

### Integration tests (`integration_test.go`)

6. `TestArgFilterOpenatReadOnly` — read-only open produces no audit event; write/create produces ptrace stop
7. `TestArgFilterSendtoConnected` — connected-socket sendto produces no ptrace stop

### Benchmarks (`benchmark_test.go`)

8. Compare file I/O overhead with and without `ArgLevelFilter` to measure the read-only open optimization impact.

## Files Modified

| File | Change |
|------|--------|
| `internal/ptrace/seccomp_filter.go` | New types, new `buildBPFWithArgFilters` function, new BPF constants (JSET) |
| `internal/ptrace/inject_seccomp.go` | Wire arg filters into `injectSeccompFilter` |
| `internal/ptrace/tracer.go` | Add `ArgLevelFilter` to `TracerConfig` |
| `internal/config/ptrace.go` | Add `ArgLevelFilter` to `PtracePerformanceConfig` with default |
| `internal/api/app_ptrace_linux.go` | Pass `ArgLevelFilter` config to `TracerConfig` |
| `internal/ptrace/seccomp_filter_test.go` | Unit tests for arg-level BPF generation |
| `internal/ptrace/integration_test.go` | Integration tests for filtered syscalls |
| `internal/ptrace/benchmark_test.go` | Benchmark with arg-level filtering |

## Implementation Notes

**What shipped:**
- `buildBPFWithArgFilters` function with full support for arg bitmask (JSET) and null-pointer (JEQ) checks
- sendto NULL dest_addr filter is wired and active when `arg_level_filter: true`
- 6 unit tests verifying BPF generation including combined jump-target verification
- 1 integration test for sendto bypass (TestArgFilterSendtoConnected)
- Config pre-seeding in `Load`/`LoadWithSource` ensures bool defaults survive YAML unmarshal

**What was deferred:**
- openat read-only arg filter is NOT wired in `injectSeccompFilter`. Allowing read-only opens in-kernel bypasses path-based deny rules for read operations. A future `StaticReadAllowChecker` interface will let handlers declare that read-only opens are safe, at which point the openat arg filter can be enabled. The BPF generator supports it — it just needs to be wired.
- TestArgFilterOpenatReadOnly is skipped pending the above.
- Benchmark test not yet added.
