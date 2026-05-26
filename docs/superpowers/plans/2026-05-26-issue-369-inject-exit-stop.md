# Ptrace inject EXIT-stop readback — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the ptrace inject path read an injected syscall's return value only at a confirmed syscall-EXIT stop (via `PTRACE_GET_SYSCALL_INFO`), so interleaved `PTRACE_EVENT_SECCOMP`/entry stops on kernels like exe.dev's `6.12.90` can no longer make it read the `-ENOSYS` entry placeholder (issue #369, Gap C).

**Architecture:** Add a raw stop-op accessor and an exit-confirming wait in `internal/ptrace`, then route the three return-value/exit waits in `inject.go` through it. Gated on `t.hasSyscallInfo` (Linux 5.3+); pre-5.3 keeps legacy behavior. No change to `process_vm_*`, user-notify, `WAIT_KILLABLE`, cgroups, or darwin/windows.

**Tech Stack:** Go, `golang.org/x/sys/unix`, raw `PTRACE_GET_SYSCALL_INFO` (`0x420e`), `//go:build linux` (+ `integration` for live-tracee tests).

**Spec:** `docs/superpowers/specs/2026-05-26-issue-369-inject-exit-stop-design.md`

**Testing reality (read first):** The exe.dev desync is stop-delivery-timing specific to `6.12.90` and is **not** reproducible deterministically on a normal CI kernel (a single filtered syscall yields seccomp→exit, which the legacy 2-cycle path already handles). So there is no failing end-to-end test to write for the bug itself. We TDD the load-bearing primitive (`syscallStopOp`) against a live tracee, keep the existing suites green, and rely on erans verifying the end-to-end fix on `v0.20.3-rc3`. This is a deliberate, documented exception to "write a failing test that reproduces the bug."

---

## Task 1: Raw stop-op accessor `syscallStopOp`

**Files:**
- Modify: `internal/ptrace/syscall_context.go`
- Test (new): `internal/ptrace/syscall_stop_op_test.go`

- [ ] **Step 1: Write the failing test (live tracee, deterministic on 5.3+)**

Create `internal/ptrace/syscall_stop_op_test.go`:

```go
//go:build integration && linux

package ptrace

import (
	"os/exec"
	"runtime"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestSyscallStopOp_EntryThenExit verifies syscallStopOp classifies a
// syscall-entry stop as ENTRY(1) and the matching exit stop as EXIT(2).
// This is the load-bearing primitive for the inject EXIT-stop fix (#369).
func TestSyscallStopOp_EntryThenExit(t *testing.T) {
	requirePtrace(t)
	// ptrace requires all calls for one tracee to come from the same OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	pid := cmd.Process.Pid
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()

	// Initial stop is the exec/TRACEME stop; reap it.
	var ws unix.WaitStatus
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
		t.Fatalf("initial wait4: %v", err)
	}

	tr := &Tracer{hasSyscallInfo: probePtraceSyscallInfo()}
	if !tr.hasSyscallInfo {
		t.Skip("PTRACE_GET_SYSCALL_INFO unsupported on this kernel")
	}

	// Advance to a syscall-entry stop.
	if err := unix.PtraceSyscall(pid, 0); err != nil {
		t.Fatalf("ptracesyscall to entry: %v", err)
	}
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
		t.Fatalf("wait4 entry: %v", err)
	}
	if !ws.Stopped() {
		t.Fatalf("expected stop at entry, status=%v", ws)
	}
	op, err := tr.syscallStopOp(pid)
	if err != nil {
		t.Fatalf("syscallStopOp entry: %v", err)
	}
	if op != ptraceSyscallInfoEntry {
		t.Fatalf("entry stop op = %d, want %d (ENTRY)", op, ptraceSyscallInfoEntry)
	}

	// Advance to the matching syscall-exit stop.
	if err := unix.PtraceSyscall(pid, 0); err != nil {
		t.Fatalf("ptracesyscall to exit: %v", err)
	}
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
		t.Fatalf("wait4 exit: %v", err)
	}
	if !ws.Stopped() {
		t.Fatalf("expected stop at exit, status=%v", ws)
	}
	op, err = tr.syscallStopOp(pid)
	if err != nil {
		t.Fatalf("syscallStopOp exit: %v", err)
	}
	if op != ptraceSyscallInfoExit {
		t.Fatalf("exit stop op = %d, want %d (EXIT)", op, ptraceSyscallInfoExit)
	}
}
```

- [ ] **Step 2: Run it to verify it fails to compile (symbols undefined)**

Run: `go test -tags 'integration linux' ./internal/ptrace/ -run TestSyscallStopOp_EntryThenExit`
Expected: build failure — `undefined: ptraceSyscallInfoEntry`, `undefined: ... syscallStopOp`.

- [ ] **Step 3: Implement the constants + accessor**

In `internal/ptrace/syscall_context.go`, add after the `ptraceGetSyscallInfo` const (`:13`):

```go
// ptrace_syscall_info op values (uapi/linux/ptrace.h, PTRACE_SYSCALL_INFO_*).
const (
	ptraceSyscallInfoNone    uint8 = 0
	ptraceSyscallInfoEntry   uint8 = 1
	ptraceSyscallInfoExit    uint8 = 2
	ptraceSyscallInfoSeccomp uint8 = 3
)
```

And add this method (place after `getSyscallEntryInfo`):

```go
// syscallStopOp returns the PTRACE_GET_SYSCALL_INFO op for the tracee's current
// stop (none/entry/exit/seccomp). Valid only at a ptrace syscall or seccomp
// stop. Unlike getSyscallEntryInfo it does not reject the exit op — the inject
// path uses it to confirm a syscall-EXIT stop before trusting the return reg.
func (t *Tracer) syscallStopOp(tid int) (uint8, error) {
	var info ptraceSyscallInfo
	_, _, errno := unix.Syscall6(
		unix.SYS_PTRACE,
		uintptr(ptraceGetSyscallInfo),
		uintptr(tid),
		uintptr(ptraceSyscallInfoSize),
		uintptr(unsafe.Pointer(&info)),
		0, 0,
	)
	if errno != 0 {
		return ptraceSyscallInfoNone, fmt.Errorf("PTRACE_GET_SYSCALL_INFO: %w", errno)
	}
	return info.Op, nil
}
```

(Optional cleanup, not required: replace the literal `1`/`3` in `getSyscallEntryInfo`'s check with `ptraceSyscallInfoEntry`/`ptraceSyscallInfoSeccomp`.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test -tags 'integration linux' ./internal/ptrace/ -run TestSyscallStopOp_EntryThenExit -v`
Expected: PASS (or SKIP only if the kernel lacks `PTRACE_GET_SYSCALL_INFO`, which CI kernels ≥5.3 do not). If it fails because the first post-exec syscall stop is a signal stop, insert a loop that re-`PtraceSyscall`s until `ws.StopSignal()` is a syscall stop before the first `syscallStopOp` — but on `/bin/true` the entry stop is reached directly.

- [ ] **Step 5: Confirm the non-integration build still compiles**

Run: `go build ./internal/ptrace/ && go vet ./internal/ptrace/`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add internal/ptrace/syscall_context.go internal/ptrace/syscall_stop_op_test.go
git commit -m "feat(ptrace,#369): add syscallStopOp raw PTRACE_GET_SYSCALL_INFO op accessor

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: `waitForSyscallExitStop` and route the readback waits through it

**Files:**
- Modify: `internal/ptrace/inject.go` (add func; promote `maxStopEvents`; edit 3 call sites)

- [ ] **Step 1: Promote the stop-event cap to a package const**

In `internal/ptrace/inject.go`, inside `waitForSyscallStop` the `const ( maxStopEvents = 100; timeout = ...; pollDelay = ... )` block currently lives in-function. Add a package-level const above `waitForSyscallStop`:

```go
// injectMaxStopEvents bounds how many non-progress stops the inject waits
// tolerate before giving up, guarding against an unexpected stop storm.
const injectMaxStopEvents = 100
```

Then change the in-function block to drop `maxStopEvents` and reference `injectMaxStopEvents` at its two existing use sites (`:233`, `:244`):

```go
const (
	timeout   = 5 * time.Second
	pollDelay = 200 * time.Microsecond
)
```
and replace `stopEvents >= maxStopEvents` (×2) with `stopEvents >= injectMaxStopEvents`, and the two error strings `exceeded %d ... , maxStopEvents` with `injectMaxStopEvents`.

- [ ] **Step 2: Add `waitForSyscallExitStop`**

Add immediately after `waitForSyscallStop` (after `:251`):

```go
// waitForSyscallExitStop drives the tracee to a genuine syscall-EXIT stop and
// returns once there. When PTRACE_GET_SYSCALL_INFO is unavailable it degrades
// to waitForSyscallStop (legacy cycle-counting; unchanged for pre-5.3 kernels).
//
// Background (#369): on kernels that interleave PTRACE_EVENT_SECCOMP / entry
// stops with the PTRACE_SYSCALL enter/exit pairs (e.g. exe.dev 6.12.90), the
// fixed-cycle accounting could land the return-value read on an entry/seccomp
// stop, where rax holds the -ENOSYS entry placeholder rather than the syscall
// result. Injected syscalls run in isolation (the tracer controls the
// registers, so no other syscall executes between resumes), so the first EXIT
// stop reached is the injected syscall's exit; intervening entry/seccomp stops
// are resumed past.
func (t *Tracer) waitForSyscallExitStop(tid int) error {
	if err := t.waitForSyscallStop(tid); err != nil {
		return err
	}
	if !t.hasSyscallInfo {
		return nil // pre-5.3: cannot distinguish entry vs exit; keep legacy behavior
	}
	for i := 0; i < injectMaxStopEvents; i++ {
		op, err := t.syscallStopOp(tid)
		if err != nil {
			// Can't classify this stop; trust the legacy stop (no worse than before).
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
	return fmt.Errorf("waitForSyscallExitStop tid %d: no exit stop within %d events", tid, injectMaxStopEvents)
}
```

- [ ] **Step 3: Route the three readback/exit waits through it**

In `injectFromEntry`, the wait-exit at `:78`:
```go
	if err := t.waitForSyscallStop(tid); err != nil {
		injectErr = fmt.Errorf("inject wait-exit: %w", err)
		return 0, injectErr
	}
```
becomes:
```go
	if err := t.waitForSyscallExitStop(tid); err != nil {
		injectErr = fmt.Errorf("inject wait-exit: %w", err)
		return 0, injectErr
	}
```

In `injectFromExit`, the **phase-2** wait-exit at `:152` (NOT the phase-1 wait-enter at `:142`):
```go
	if err := t.waitForSyscallStop(tid); err != nil {
		injectErr = fmt.Errorf("inject wait-exit: %w", err)
		return 0, injectErr
	}
```
becomes `t.waitForSyscallExitStop(tid)` (same error wrapping). Leave the phase-1 wait at `:142` (`inject wait-enter`) as `waitForSyscallStop` — it positions at a pre-execution stop.

In `advancePastEntry`, the wait at `:280`:
```go
	if err := t.waitForSyscallStop(tid); err != nil {
		return fmt.Errorf("advance wait: %w", err)
	}
```
becomes `t.waitForSyscallExitStop(tid)` (same error wrapping). Its purpose is to reach the exit stop so `InSyscall=false` is accurate.

- [ ] **Step 4: Review `redirect_exec.go:174`**

Read `internal/ptrace/redirect_exec.go` around `:174`. If that `waitForSyscallStop` immediately precedes a `ReturnValue()`/return-value read, change it to `waitForSyscallExitStop`. If it is positioning only (no return read), leave it. Note the decision in the commit message.

- [ ] **Step 5: Build + vet**

Run: `go build ./internal/ptrace/ && go vet ./internal/ptrace/`
Expected: clean (no unused `maxStopEvents`, no undefined symbols).

- [ ] **Step 6: Run the existing ptrace unit tests (non-integration)**

Run: `go test ./internal/ptrace/`
Expected: PASS (these are `//go:build linux` tests; they must be unaffected).

- [ ] **Step 7: Commit**

```bash
git add internal/ptrace/inject.go internal/ptrace/redirect_exec.go
git commit -m "fix(ptrace,#369): read injected syscall return only at confirmed EXIT stop

waitForSyscallExitStop drives the tracee past interleaved entry/seccomp stops
to a genuine syscall-EXIT stop (op==2 via PTRACE_GET_SYSCALL_INFO) before the
inject path reads rax, so it can no longer read the -ENOSYS entry placeholder
on kernels that interleave PTRACE_EVENT_SECCOMP with the syscall enter/exit
pairs (exe.dev 6.12.90). Gated on hasSyscallInfo; pre-5.3 keeps legacy behavior.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: No-regression verification (existing inject path on a normal kernel)

**Files:** none (verification only)

- [ ] **Step 1: Run the ptrace integration suite if a ptrace-capable kernel is available**

Run: `go test -tags 'integration linux' ./internal/ptrace/ 2>&1 | tail -40`
Expected: PASS (or individual SKIPs where `requirePtrace` can't seize). The injection-exercising tests (`TestIntegration_FileRedirect`, `TestIntegration_*` under prefilter, `TestSyscallStopOp_EntryThenExit`) must pass — confirming the EXIT-confirming wait returns immediately on the happy path (op==EXIT on first check) with no behavior change.

- [ ] **Step 2: Full module test**

Run: `go test ./...`
Expected: PASS (modulo the known pre-existing flakes noted in repo memory; rerun any flaky package to confirm it is not newly broken).

---

## Task 4: Cross-compile + final gate

**Files:** none (verification only)

- [ ] **Step 1: Windows cross-compile (changed files are linux-only)**

Run: `GOOS=windows go build ./...`
Expected: success — the changes are under `//go:build linux`, so the Windows build must be unaffected.

- [ ] **Step 2: gofmt check on changed files**

Run: `gofmt -l internal/ptrace/`
Expected: no output (all formatted).
