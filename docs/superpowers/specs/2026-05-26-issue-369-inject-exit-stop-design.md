# Ptrace inject: read syscall return only at a confirmed EXIT stop — Design

Issue: #369 ("Gap C") — ptrace `seccomp_prefilter` injection intermittently
loses the tracee on exe.dev kernel `6.12.90`, surfacing as `exit_code=-1`
(~50–75% of execs).

## Summary

agentsh installs the ptrace `seccomp_prefilter` (and performs file/exec
redirects) by **injecting syscalls into a stopped tracee**: it rewrites the
tracee's registers (`PTRACE_SETREGS`), resumes with `PTRACE_SYSCALL`, and reads
the injected syscall's return value out of `rax` (`PTRACE_GETREGS`). The read
point assumes a fixed number of resume cycles lands the tracee at the
syscall-**exit** stop.

erans's strace on kernel `6.12.90` (agentsh `0.20.3-rc2`, no shim) pinned the
root cause: the readback happens at the syscall-**entry** stop instead of the
**exit** stop. `injected syscall 9 (mmap) returned -38` is decisive — `-38`
(`-ENOSYS`) is exactly the placeholder Linux parks in `rax` at the syscall-entry
ptrace stop. The same desync makes the injected `seccomp`/`prctl` readbacks
garbage and, when it runs the tracee off the end of the expected stops, leaves
the tracee to exit mid-injection (`tracee N exited during injection`).

The trigger is `PTRACE_EVENT_SECCOMP` stops interleaving with the
`PTRACE_SYSCALL` enter/exit pairs once a `RET_TRACE` filter is active. The
existing cycle-counting accounting in `waitForSyscallStop` does not distinguish
entry from exit, so when the kernel's stop delivery on this kernel inserts an
extra stop, the fixed-cycle readback lands one stop early.

This design makes the injected-syscall readback **authoritative**: when
`PTRACE_GET_SYSCALL_INFO` is available, the inject path confirms the tracee is at
a syscall-**exit** stop (`op == PTRACE_SYSCALL_INFO_EXIT`) before reading `rax`,
resuming past any non-exit (entry/seccomp) stops to reach it. `process_vm_*`
access, the user-notify path, `WAIT_KILLABLE`, and cgroups are **not** touched —
erans confirmed `process_vm_writev` works on this kernel and the EIO writes were
a downstream artifact of the same desync.

## Goals

- On a kernel that interleaves `PTRACE_EVENT_SECCOMP` stops with syscall
  enter/exit stops, `injectSyscall` reads the injected syscall's return value
  only at the genuine syscall-exit stop — never the `-ENOSYS` entry placeholder.
- The fix is correct-by-construction: it does not depend on *how many* extra
  stops the kernel inserts, only on identifying the exit stop authoritatively.
- Zero behavior change on the current happy path (normal kernels, where the
  readback already lands at the exit stop): no extra resumes, identical result.
- Pre-5.3 kernels (no `PTRACE_GET_SYSCALL_INFO`) keep today's behavior exactly.

## Non-Goals

- **No defensive "don't kill the command on inject failure" guard.** The only
  fallback paths (pure `TRACESYSGOOD`, or running without the prefilter) are
  themselves broken/unsafe on this kernel (TRACESYSGOOD hangs every exec, 8/8;
  prefilter-less exec silently drops execve interception). Deferred — kept in
  reserve only if rc3 shows the readback fix is incomplete.
- **No startup ptrace-inject honesty probe.** Moot if the readback fix repairs
  the inject. Deferred.
- No change to `process_vm_readv/writev`, `/proc/<pid>/mem` access, the
  user-notify (`netmonitor/unix`) path, `WAIT_KILLABLE`, or cgroups.
- No change to the gadget/`injectFromEntry`/`injectFromExit` resume *protocol*
  itself beyond where the return value is read.

## Background

Relevant code (all `//go:build linux`, package `internal/ptrace`):

- `inject.go`
  - `injectSyscall` → dispatches to `injectFromEntry` (tracee at syscall-enter,
    one resume cycle) or `injectFromExit` (between syscalls; gadget + two resume
    cycles).
  - `injectFromEntry` (`:45`): after one `PtraceSyscall` + `waitForSyscallStop`
    (`:78`), reads `retRegs.ReturnValue()` (`:88`).
  - `injectFromExit` (`:109`): phase-1 wait (`:142`, enter), phase-2
    `PtraceSyscall` + `waitForSyscallStop` (`:152`, exit), then
    `retRegs.ReturnValue()` (`:162`).
  - `waitForSyscallStop` (`:182`): returns at the *first* stop that is either a
    TRACESYSGOOD syscall stop (`SIGTRAP|0x80`) **or** a `PTRACE_EVENT_SECCOMP`
    stop, with no entry/exit distinction. Already handles tracee-exit
    (`:207–212`), bounded re-resume on other event/signal stops.
  - `advancePastEntry` (`:270`): nullifies the current syscall (`ORIG_RAX=-1`),
    resumes to the next stop (`:280`), restores; used to move from an entry stop
    to an exit stop so subsequent injections use the gadget protocol.
- `syscall_context.go`
  - `ptraceGetSyscallInfo = 0x420e`; `ptraceSyscallInfo` struct with `Op uint8`
    (kernel: `NONE=0, ENTRY=1, EXIT=2, SECCOMP=3, RSEQ=4`).
  - `getSyscallEntryInfo` (`:63`): reads syscall info but **rejects** `op != 1
    && op != 3` (entry/seccomp only) — cannot be reused as-is for exit detection.
  - `probePtraceSyscallInfo` (`:114`) sets `t.hasSyscallInfo` at tracer init
    (`tracer.go:1868`); true on Linux 5.3+ (so true on `6.12.90`).
- Inject consumers that go through `injectSyscall` (all fixed centrally by this
  change): `scratch.go:55` (mmap scratch page), `inject_seccomp.go:191,205,300`
  (prctl/seccomp prefilter + escalation), `redirect_file.go` (openat/mkdirat/
  renameat2), `redirect_exec.go:230,236,248,254,261` (pidfd_open/getfd/fcntl/dup3).

Why the existing seccomp-stop handling is not enough: treating
`PTRACE_EVENT_SECCOMP` as an enter-equivalent stop keeps the 2-cycle model
correct for a *single* filtered syscall (seccomp-stop → exit-stop). The bug
appears only when the kernel inserts an *additional* stop (e.g. a seccomp stop
**and** a separate enter stop, or an extra interleaved event), shifting the
fixed-cycle readback one stop early. That extra-stop choreography is what differs
on `6.12.90`.

## Design

### 1. Raw stop-op accessor (`syscall_context.go`)

Add a helper that returns the raw `Op` of the current syscall-stop without the
entry-only rejection in `getSyscallEntryInfo`:

```go
// ptrace_syscall_info op values (uapi/linux/ptrace.h).
const (
    ptraceSyscallInfoNone    uint8 = 0
    ptraceSyscallInfoEntry   uint8 = 1
    ptraceSyscallInfoExit    uint8 = 2
    ptraceSyscallInfoSeccomp uint8 = 3
)

// syscallStopOp returns the PTRACE_GET_SYSCALL_INFO op for the tracee's current
// stop (entry/exit/seccomp/none). Only valid at a ptrace syscall/seccomp stop.
func (t *Tracer) syscallStopOp(tid int) (uint8, error) {
    var info ptraceSyscallInfo
    _, _, errno := unix.Syscall6(unix.SYS_PTRACE, uintptr(ptraceGetSyscallInfo),
        uintptr(tid), uintptr(ptraceSyscallInfoSize), uintptr(unsafe.Pointer(&info)), 0, 0)
    if errno != 0 {
        return ptraceSyscallInfoNone, fmt.Errorf("PTRACE_GET_SYSCALL_INFO: %w", errno)
    }
    return info.Op, nil
}
```

(`getSyscallEntryInfo` is left unchanged. The named op constants may also replace
the magic `1`/`3` in its existing check, but that is optional cleanup.)

### 2. Exit-confirming wait (`inject.go`)

Add a wait that lands the tracee at a genuine syscall-**exit** stop when
`PTRACE_GET_SYSCALL_INFO` is available, and otherwise preserves today's behavior:

```go
// waitForSyscallExitStop drives the tracee to a syscall-EXIT stop and returns
// once there. When PTRACE_GET_SYSCALL_INFO is unavailable it degrades to
// waitForSyscallStop (legacy cycle-counting behavior, unchanged).
//
// Injected syscalls run in isolation (the tracer controls the registers, so no
// other syscall executes between resumes); therefore the first EXIT stop reached
// is the injected syscall's exit. Any intervening entry/seccomp stops are
// resumed past. Bounded by the same guards as waitForSyscallStop.
func (t *Tracer) waitForSyscallExitStop(tid int) error {
    if err := t.waitForSyscallStop(tid); err != nil {
        return err
    }
    if !t.hasSyscallInfo {
        return nil // pre-5.3: cannot distinguish; keep legacy behavior
    }
    for i := 0; i < maxStopEvents; i++ {
        op, err := t.syscallStopOp(tid)
        if err != nil {
            // Can't classify this stop; trust the legacy stop (no worse than today).
            return nil
        }
        if op == ptraceSyscallInfoExit {
            return nil
        }
        // Entry/seccomp/none stop — advance to the injected syscall's exit.
        if err := unix.PtraceSyscall(tid, 0); err != nil {
            return fmt.Errorf("inject advance-to-exit tid %d: %w", tid, err)
        }
        if err := t.waitForSyscallStop(tid); err != nil {
            return err // includes "tracee N exited during injection"
        }
    }
    return fmt.Errorf("waitForSyscallExitStop tid %d: no exit stop within %d events", tid, maxStopEvents)
}
```

`maxStopEvents`/`timeout`/`pollDelay` are reused from `waitForSyscallStop`
(promote the consts to package/function scope as needed).

### 3. Use the exit-confirming wait at every readback point (`inject.go`)

Replace only the waits that immediately precede a return-value read or that exist
to reach the exit stop:

- `injectFromEntry` `:78` → `waitForSyscallExitStop` (the single resume must land
  at exit before `ReturnValue()` at `:88`).
- `injectFromExit` `:152` (phase 2) → `waitForSyscallExitStop` (before
  `ReturnValue()` at `:162`). Phase-1 `:142` stays `waitForSyscallStop` (it is
  positioning at a pre-execution stop; reaching exit there would be wrong).
- `advancePastEntry` `:280` → `waitForSyscallExitStop` (its purpose is to reach
  the exit stop so `InSyscall=false` is accurate).

`redirect_exec.go:174`'s `waitForSyscallStop` is reviewed during implementation;
it is changed only if it precedes a return-value read (otherwise left as-is).

### Resulting behavior on the failing kernel

When an interleaved seccomp/entry stop lands where the old code read `rax`,
`waitForSyscallExitStop` sees `op != EXIT`, resumes once more, reaches the true
exit stop, and reads the real return value (e.g. the mmap scratch address instead
of `-38`). The prefilter installs, the command exits normally.

### Happy-path equivalence

On a normal kernel the phase that previously landed at the exit stop now calls
`syscallStopOp`, gets `EXIT` on the first check, and returns with **no** extra
`PtraceSyscall`. Identical resume count, identical register read, identical
result. The only added cost is one `PTRACE_GET_SYSCALL_INFO` per injected
syscall (microseconds), already used elsewhere in the hot path.

## Decisions

- **Trust `rax` via `getRegs` once at the confirmed exit stop**, rather than
  reading `rval` from the `PTRACE_GET_SYSCALL_INFO` exit-union variant. `getRegs`
  is already needed for the post-inject register restore and is the established
  read path; using the op only as a *gate* keeps the change minimal and reuses
  tested code. (The exit-variant `rval` read is a possible future simplification,
  not needed here.)
- **Gate on `t.hasSyscallInfo`.** Pre-5.3 kernels keep the legacy cycle-counting
  behavior verbatim — the bug does not manifest there, and there is no
  authoritative exit signal to use.
- **Fix centrally in `injectSyscall`'s waits**, not per-caller. The same machinery
  backs mmap, prctl/seccomp, and file/exec redirects; one fix covers all.
- **No graceful-degrade / honesty probe** (see Non-Goals): the fallbacks are
  unsafe on this kernel and the readback fix should make them unnecessary.

## Error handling

- Tracee exits during the extra resume(s): `waitForSyscallStop` already detects
  `Exited()/Signaled()`, runs `handleExit`, and returns
  `"tracee N exited during injection"`. The existing `defer` in
  `injectFromEntry`/`injectFromExit` restores `savedRegs` on error. No new
  failure surface; the lost-tracee case is *reduced*, not newly introduced.
- `syscallStopOp` errno: treated as "cannot classify" → fall back to the legacy
  stop (behavior no worse than today).
- Bounded loop (`maxStopEvents`) prevents an unbounded spin if the kernel never
  reports an exit stop; returns a descriptive error that the existing inject
  callers already wrap (`inject prctl: …`, `scratch page: …`).

## Testing

The exe.dev desync is stop-delivery-timing specific to `6.12.90` and **cannot be
reproduced deterministically on a normal CI kernel** (a single filtered syscall
yields seccomp→exit, which the legacy 2-cycle path already handles). Tests
therefore target the new primitive's correctness and the no-regression
guarantee; the end-to-end fix is verified by erans on `v0.20.3-rc3`.

`internal/ptrace` (integration-tagged where a live tracee is needed,
`//go:build integration && linux`, matching existing `integration_test.go`):

1. **`syscallStopOp` classification** — attach a child, stop it at a syscall
   entry: assert `syscallStopOp` returns `ENTRY`; `PtraceSyscall` to exit: assert
   `EXIT`. Install a `RET_TRACE` filter on a benign syscall, trigger it: assert
   `SECCOMP` at the seccomp stop. Deterministic on any 5.3+ kernel.
2. **`injectSyscall` returns the true result, not the entry placeholder** —
   inject a benign syscall (e.g. `getpid`/`getuid`) and assert the returned value
   equals the real result and is not `-ENOSYS`. Run with the tracee under a
   `RET_TRACE` prefilter (the prefilter mode) and without it; both must return the
   correct value. Guards against a regression where a readback lands at a non-exit
   stop.
3. **Prefilter inject still succeeds end-to-end** on the CI kernel
   (`injectSeccompFilter` → command runs and exits 0). No-regression check.
4. **`hasSyscallInfo=false` path** — a unit test (no live tracee) asserting
   `waitForSyscallExitStop` reduces to `waitForSyscallStop` when the capability
   flag is false (e.g. via a tracer with `hasSyscallInfo=false` and a fake/stubbed
   stop), so pre-5.3 behavior is preserved.

Also: full `internal/ptrace` suite stays green; `go test ./...`;
`GOOS=windows go build ./...` (changed files are `//go:build linux`, so the
Windows build must remain unaffected).

## Affected files

- `internal/ptrace/syscall_context.go` — add `syscallStopOp` + op constants.
- `internal/ptrace/inject.go` — add `waitForSyscallExitStop`; use it at the three
  readback/exit waits (`injectFromEntry`, `injectFromExit` phase 2,
  `advancePastEntry`).
- `internal/ptrace/redirect_exec.go` — only if a `waitForSyscallStop` there
  precedes a return-value read (verified during implementation).
- Tests in `internal/ptrace/` (new cases per above).
- Everything else — `process_vm_*`, user-notify, `WAIT_KILLABLE`, cgroups,
  darwin/windows — intentionally **unchanged**.
