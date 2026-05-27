# Ptrace inject: authoritative exit-stop trigger + gadget/exec verification — Design

Issue: #369 ("Gap C"). Supersedes the rc6 honest-degrade direction (#399) — the bug
is **fixable**, not a kernel incapability.

## Summary

erans's source review (verified against `48d49782`) found the true root cause of
Gap C, which rc2–rc6 all missed. The seccomp-prefilter inject decides "is this a
syscall-EXIT stop?" using a **hand-toggled `state.InSyscall` bit**
(`tracer.go:896`), not the authoritative `PTRACE_GET_SYSCALL_INFO` op. On exe.dev
`6.12.90`, the post-exec `ld.so` syscall storm (interleaved `PTRACE_EVENT`/group/
signal stops) **desyncs that toggle by one**, so the inject fires at a stop that
isn't really an exit. `injectFromExit` then uses a **blind `RIP−2` gadget**
(`inject_amd64.go`) with no verification it points at a `syscall` (`0F 05`)
instruction — at a non-exit stop it doesn't, so the injected `mmap` executes
against garbage, returns an address-like RAX, and maps **no VMA** (the `#398`
phantom `new_mappings=[]`). "Works under strace" is the tell: serialization
re-syncs the stop sequence (Heisenbug).

This fixes the mis-execution at its source:
1. **Classify the trigger authoritatively** — gate the inject on
   `syscallStopOp == EXIT`, not `state.InSyscall` (reusing the `#396` accessor).
2. **Verify the gadget** — require the bytes at `RIP−2` to be `0F 05` before use.
3. **Verify execution** — after the injected syscall, require `ORIG_RAX == nr`.
4. **Fail-closed scratch** — return an error when the injected `mmap` maps no VMA,
   instead of building a phantom `scratchPage`.

(1) is the core fix; (2)–(4) turn any residual misfire into a clean inject error
instead of a silent phantom that later `EIO`s and kills the command.

## Goals

- On 6.12.90 the prefilter inject fires only at a true syscall-EXIT stop, the
  gadget is a real `syscall`, the injected `mmap` actually maps, the prefilter
  installs, and commands run **with ptrace enforcing** (kill rate → 0).
- Zero behavior change on kernels where the toggle was already correct (the
  authoritative op agrees with `InSyscall` there; same stop chosen).
- Pre-5.3 kernels (no `PTRACE_GET_SYSCALL_INFO`) keep the legacy toggle behavior.
- A genuinely failed inject (wrong gadget, syscall didn't run, mmap mapped
  nothing) becomes a clean error, never a phantom address used downstream.

## Non-Goals

- **The `#399` self-probe / honest-degrade is NOT removed here.** Once the inject
  works, the probe (which already always passed, since it bypasses the trigger)
  stays passing → degrade never fires → dormant. Reworking/removing the
  non-representative probe is a follow-up, tracked separately. (Its
  `ProbePtraceInject` reuse of `ensureScratchPage` is fail-open, so fix (4)'s new
  error path just makes the probe fail-open as before — no behavior change.)
- **The `TRACESYSGOOD` fallback hang is not addressed.** On inject failure the
  code logs "falling back to TRACESYSGOOD", which hangs on 6.12.90 (pre-existing,
  separate). With fix (1) correct, the inject succeeds, so this fallback is not
  reached on this kernel. Fixes (2)/(3)/(4) aborting would reach it — acceptable
  as they should be dormant once (1) is right; not made worse here.
- No change to `process_vm_*`, user-notify, cgroups, the wait_killable probe, or
  darwin/windows.

## Background (verified on this branch base)

- Prefilter trigger: `tracer.go:892-925` — `if state.PendingPrefilter &&
  !state.InSyscall { wait } else if state.PendingPrefilter && state.InSyscall {
  inject }`. The escalation triggers (`tracer.go:935-975`) use the identical
  `state.InSyscall` enter/exit pattern (`HasPrefilter && InSyscall &&
  PendingReadEscalation`, etc.).
- `syscallStopOp(tid) (uint8, error)` + op consts (`ptraceSyscallInfoEntry/Exit/
  Seccomp/None`) exist in `syscall_context.go` (added in #396); `t.hasSyscallInfo`
  is probed at startup. `PTRACE_O_TRACESYSGOOD` is always set, so at a SIGTRAP|0x80
  stop the op is ENTRY or EXIT (authoritative).
- Gadget: `inject_amd64.go:syscallGadgetAddr(regs) = regs.InstructionPointer()-2`
  (arm64 has its own in `inject_arm64.go` — check and mirror the verification).
- Return/orig-rax accessors: `args_amd64.go` — `ReturnValue()`=RAX,
  `SyscallNr()`=`Orig_rax`. (arm64 equivalents in `args_arm64.go`.)
- `injectFromExit`/`injectFromEntry` (`inject.go`): compute gadget, set regs,
  resume, `waitForSyscallExitStop`, read `retRegs.ReturnValue()`, restore.
- Scratch: `scratch.go:ensureScratchPage` — after the mmap inject, `#398` logs a
  WARN when `!addrInMaps(tid, addr)` but **builds `sp = &scratchPage{addr: addr}`
  anyway**. `t.readBytes(tid, addr, buf)` (`memory.go`) reads tracee memory
  (process_vm_readv → /proc/mem); confirmed working on 6.12.90.

## Design

### Fix 1 — authoritative exit-stop classification (`tracer.go`)

Add a helper:
```go
// atSyscallExitStop reports whether the tracee is at a syscall-EXIT stop. It
// prefers the authoritative PTRACE_GET_SYSCALL_INFO op; the hand-maintained
// InSyscall toggle is only a pre-5.3 fallback because that toggle can desync
// from the real stop sequence on kernels whose post-exec stop storm interleaves
// PTRACE_EVENT/signal stops (#369). Must be called on the tracer thread at a
// ptrace stop.
func (t *Tracer) atSyscallExitStop(tid int, inSyscall bool) bool {
	if t.hasSyscallInfo {
		if op, err := t.syscallStopOp(tid); err == nil {
			return op == ptraceSyscallInfoExit
		}
	}
	return inSyscall
}
```
In `handleSyscallStop`, replace the three `state.InSyscall` enter/exit decisions
(prefilter trigger + read-escalation + write-escalation) so the "this is an exit
stop, inject now" branch is gated on `t.atSyscallExitStop(tid, state.InSyscall)`
rather than the raw `state.InSyscall`. Compute the op **outside** the `t.mu`
critical section (read `PendingPrefilter`/`InSyscall` under lock, drop the lock,
classify, re-lock to mutate + inject) to avoid holding `t.mu` across a ptrace
call. Preserve every existing side effect: `PendingPrefilter=false`,
`InSyscall=false` before inject, the post-inject `InSyscall=true`/`HasPrefilter`
restore, and the "fall through to normal exit handling" comment/behavior. The
`InSyscall` toggle itself is still maintained for the legacy fallback and for the
normal (non-inject) exit handling.

### Fix 2 — gadget verification (`inject.go`, `injectFromExit`)

After `gadget := syscallGadgetAddr(savedRegs)` and before `SetInstructionPointer`,
read 2 bytes at `gadget` and require the `syscall` opcode:
```go
var op [2]byte
if err := t.readBytes(tid, gadget, op[:]); err != nil {
	return 0, fmt.Errorf("inject gadget read @0x%x: %w", gadget, err)
}
if op[0] != 0x0f || op[1] != 0x05 { // amd64 `syscall`
	return 0, fmt.Errorf("inject gadget @0x%x is not a syscall instruction (0x%02x%02x); stop misclassified", gadget, op[1], op[0])
}
```
(arm64: the `svc #0` encoding is `0xD4000001`; mirror the check in the arm64
path/build if `injectFromExit` is shared — verify which file holds the arm64
gadget and add an equivalent 4-byte check, or guard the check behind amd64 if the
gadget helper is arch-split.)

### Fix 3 — injected-syscall execution verification (`inject.go`)

In both `injectFromEntry` and `injectFromExit`, after reaching the exit stop and
reading `retRegs`, before trusting `ReturnValue()`:
```go
if got := retRegs.SyscallNr(); got != nr {
	injectErr = fmt.Errorf("injected syscall %d did not execute (orig_rax=%d at exit); stop misclassified", nr, got)
	return 0, injectErr
}
```
(Place inside the existing `injectErr` defer-restore scope so registers are
restored on this error.)

### Fix 4 — fail-closed scratch page (`scratch.go`, `ensureScratchPage`)

Replace the `#398` WARN-only block so an unmapped return is a hard error:
```go
if !addrInMaps(tid, addr) {
	return nil, fmt.Errorf("scratch mmap returned 0x%x but mapped no VMA (#369); new_mappings=%v",
		addr, newMapRanges(tid, mapsBefore))
}
```
(Remove the now-redundant WARN; the error carries the same diagnostic. Keep the
`mapsBefore` snapshot for the error detail.) `ensureScratchPage`'s callers already
handle its error (the prefilter/escalation inject paths wrap and fall back).

### Why this fixes 6.12.90

With (1), the inject fires only at a real EXIT stop ⇒ `RIP` is just past a real
`syscall` ⇒ `RIP−2` is `0F 05` ((2) passes) ⇒ the injected `mmap` actually runs
((3) passes, `orig_rax==SYS_mmap`) ⇒ a VMA appears ((4) passes) ⇒ the prefilter
installs ⇒ commands run with ptrace enforcing. (2)–(4) are guards: if the stop is
ever still misclassified, they abort with a precise error instead of the phantom.

## Decisions

- **Authoritative op over the toggle**, with the toggle kept only as the pre-5.3
  fallback. This is the minimal, surgical fix to the misclassification.
- **Apply (1) at all three trigger points** (prefilter + read/write escalation) —
  they share the identical desync-prone pattern; fixing only the prefilter would
  leave the escalations latent once the prefilter starts installing.
- **(2)/(3)/(4) abort to a clean error** rather than masking. They are
  defense-in-depth and dormant once (1) is correct.
- **#399 left dormant** (see Non-Goals) — out of scope; it does no harm once
  injection works, and removing it is separate churn.

## Error handling

- Each guard returns a descriptive error through the existing inject error paths
  (`injectSeccompFilter` → "falling back to TRACESYSGOOD" WARN). With (1) correct
  these are not reached on a healthy or fixed kernel; on a truly-broken one they
  yield a clean failure instead of a phantom-address `EIO` kill.
- `readBytes` for the gadget uses the working `process_vm_readv`/`/proc/mem`
  ladder; a read error aborts the inject (fail-safe).

## Testing

The 6.12.90 desync is not CI-reproducible (CI stops don't desync), so:

- **No-regression (integration, `//go:build integration && linux`):** the existing
  `TestIntegration_*` prefilter-inject tests (e.g. file/exec/network redirect,
  `MultipleRapidExecs`) must stay green — on CI the authoritative op agrees with
  the old toggle, the gadget is a real syscall, `orig_rax==nr`, and the mmap maps,
  so nothing aborts. This is the primary guard against breaking healthy kernels.
- **Unit (`//go:build linux`):** gadget-opcode check is a pure predicate — test
  `0x0f,0x05 → ok`; anything else → error. `atSyscallExitStop` fallback when
  `hasSyscallInfo=false` returns the toggle value (construct a `Tracer{hasSyscallInfo:false}`).
- **Integration for the new primitive:** a live-tracee test (mirror
  `syscall_stop_op_test.go`) that drives a child to a real exit stop and asserts
  `atSyscallExitStop` is true there and false at an entry stop; and that
  `injectFromExit` of a benign syscall (e.g. `getpid`) succeeds with the gadget +
  orig_rax guards in place (proving they don't reject a valid inject).
- Full `internal/ptrace` (+ dependent) suites green; `GOOS=windows go build ./...`;
  gofmt/vet clean. arm64 cross-build if the gadget check is arch-specific.

End-to-end on exe.dev 6.12.90 (kill rate → 0, prefilter installs, ptrace
enforcing) verified by erans on v0.20.3-rc7.

## Affected files

- `internal/ptrace/tracer.go` — `atSyscallExitStop` helper + the 3 trigger
  decisions in `handleSyscallStop`.
- `internal/ptrace/inject.go` — gadget verification + `orig_rax==nr` check in
  `injectFromExit`/`injectFromEntry`.
- `internal/ptrace/scratch.go` — fail-closed `ensureScratchPage`.
- `internal/ptrace/inject_arm64.go`/`args_arm64.go` — mirror gadget check if the
  gadget helper is arch-split (verify during implementation).
- Tests across `internal/ptrace/`.
- `#399` probe/degrade, `process_vm_*`, user-notify, cgroups, darwin/windows —
  unchanged.
