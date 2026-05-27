# Ptrace inject: authoritative exit-stop trigger + gadget/exec verification — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Fix Gap C (#369) at its source — make the prefilter inject fire only at a true syscall-EXIT stop (authoritative `PTRACE_GET_SYSCALL_INFO`, not the desync-prone `InSyscall` toggle), verify the `RIP−2` gadget is a real `syscall`, verify the injected syscall actually executed, and fail-closed when the scratch `mmap` maps no VMA. Result: on exe.dev 6.12.90 the inject succeeds and commands run **with ptrace enforcing** (kill rate → 0), instead of phantom-address kills.

**Spec:** `docs/superpowers/specs/2026-05-27-issue-369-inject-trigger-gadget-design.md`

**Testing reality:** the 6.12.90 stop-desync is NOT reproducible on CI (CI stops don't desync), so there is no failing test to write for the bug itself. The guards are correct-by-construction; tests assert (a) no regression — the prefilter inject still works on the CI kernel with all guards active, and (b) unit-level correctness of the new predicates. End-to-end verified by erans on v0.20.3-rc7.

---

## Task 1: Authoritative exit-stop trigger classification (`tracer.go`)  [capable model]

**Files:** Modify `internal/ptrace/tracer.go`. Test: `internal/ptrace/inject_trigger_test.go` (new) + `internal/ptrace/integration_test.go` (no-regression, existing).

This is the delicate core fix. The `InSyscall` enter/exit toggle in `handleSyscallStop` desyncs on 6.12.90's post-exec stop storm; replace the **trigger decision** (not the toggle maintenance) with the authoritative op.

- [ ] **Step 1: Add the helper** (near `syscallStopOp` consumers in `tracer.go`, or in `inject.go`):
```go
// atSyscallExitStop reports whether the tracee is at a syscall-EXIT stop. It
// prefers the authoritative PTRACE_GET_SYSCALL_INFO op; the hand-maintained
// InSyscall toggle is only a pre-5.3 fallback, because that toggle can desync
// from the real stop sequence on kernels whose post-exec stop storm interleaves
// PTRACE_EVENT/signal stops (#369). Call on the tracer thread at a ptrace stop.
func (t *Tracer) atSyscallExitStop(tid int, inSyscall bool) bool {
	if t.hasSyscallInfo {
		if op, err := t.syscallStopOp(tid); err == nil {
			return op == ptraceSyscallInfoExit
		}
	}
	return inSyscall
}
```

- [ ] **Step 2: Unit test the fallback** (`inject_trigger_test.go`, `//go:build linux`):
```go
func TestAtSyscallExitStop_FallbackToToggle(t *testing.T) {
	tr := &Tracer{hasSyscallInfo: false} // no PTRACE_GET_SYSCALL_INFO → use toggle
	if !tr.atSyscallExitStop(0, true) {
		t.Fatal("fallback: inSyscall=true must report exit")
	}
	if tr.atSyscallExitStop(0, false) {
		t.Fatal("fallback: inSyscall=false must report not-exit")
	}
}
```
Run: `go test ./internal/ptrace/ -run AtSyscallExitStop` → FAIL (undefined) then PASS after Step 1.

- [ ] **Step 3: Restructure the prefilter trigger** in `handleSyscallStop` (`tracer.go:~889-925`). Replace the `if PendingPrefilter && !InSyscall {…} else if PendingPrefilter && InSyscall {…}` block with the authoritative classification, computing the op OUTSIDE the `t.mu` critical section (don't hold `t.mu` across the ptrace call):
```go
		t.mu.Lock()
		state := t.tracees[tid]
		pendingPrefilter := state != nil && state.PendingPrefilter
		inSyscall := state != nil && state.InSyscall
		t.mu.Unlock()

		if pendingPrefilter && t.atSyscallExitStop(tid, inSyscall) {
			// Confirmed syscall-EXIT: inject now. (Entry/unconfirmable stops fall
			// through — the next exit stop will trigger injection.)
			t.mu.Lock()
			if s := t.tracees[tid]; s != nil {
				s.PendingPrefilter = false
				s.InSyscall = false // injectFromExit protocol
			}
			t.mu.Unlock()
			if err := t.injectSeccompFilter(tid); err != nil {
				slog.Warn("seccomp prefilter injection failed, falling back to TRACESYSGOOD", "tid", tid, "error", err)
				t.mu.Lock()
				if s := t.tracees[tid]; s != nil {
					s.InSyscall = true
				}
				t.mu.Unlock()
			} else {
				t.mu.Lock()
				if s := t.tracees[tid]; s != nil {
					s.HasPrefilter = true
					s.InSyscall = true
				}
				t.mu.Unlock()
			}
			// Fall through to normal exit handling (InSyscall=true restored).
		}
```
Preserve the surrounding comments' intent and the "fall through, do NOT return" behavior. The `InSyscall` toggle is still maintained elsewhere for the legacy fallback + normal exit handling — do not remove that.

- [ ] **Step 4: Apply the same classification to the escalation triggers** (`tracer.go:~935-980`). The read- and write-escalation blocks gate inject on `HasPrefilter && state.InSyscall && PendingXEscalation` and set pending on `HasPrefilter && !state.InSyscall`. Replace those `state.InSyscall` / `!state.InSyscall` enter/exit checks with `t.atSyscallExitStop(tid, state.InSyscall)` / `!t.atSyscallExitStop(...)`, computing the op outside the lock as in Step 3. Keep all flag side-effects identical.

- [ ] **Step 5: Build + vet + no-regression.**
Run: `go build ./internal/ptrace/ && go vet ./internal/ptrace/`
Run: `go test ./internal/ptrace/` (unit) → PASS.
Run (if kernel allows): `go test -tags 'integration linux' ./internal/ptrace/ 2>&1 | tail -30` → the prefilter-inject integration tests (`TestIntegration_*Allow/Deny/Redirect`, `MultipleRapidExecs`, etc.) must still PASS — on CI the authoritative op agrees with the old toggle, so the same stop is chosen. Report any that flip (those would reveal a behavior change).

- [ ] **Step 6: Commit** (`fix(ptrace,#369): classify prefilter/escalation inject trigger via syscallStopOp==EXIT`).

---

## Task 2: Gadget + execution verification in the inject path (`inject.go` + arch files)

**Files:** Modify `internal/ptrace/inject.go`, `internal/ptrace/inject_amd64.go`, `internal/ptrace/inject_arm64.go`. Test: `internal/ptrace/inject_guard_test.go` (new, arch-split or amd64-guarded).

- [ ] **Step 1: Add a per-arch syscall-instruction predicate.**
In `inject_amd64.go`:
```go
// isSyscallInsn reports whether b is the amd64 `syscall` instruction (0F 05).
func isSyscallInsn(b []byte) bool { return len(b) >= 2 && b[0] == 0x0f && b[1] == 0x05 }
```
In `inject_arm64.go` (verify the encoding against the file; `svc #0` = `0xD4000001`, little-endian bytes `01 00 00 D4`):
```go
// isSyscallInsn reports whether b is the arm64 `svc #0` instruction.
func isSyscallInsn(b []byte) bool {
	return len(b) >= 4 && b[0] == 0x01 && b[1] == 0x00 && b[2] == 0x00 && b[3] == 0xd4
}
```
(`syscallInsnSize` already exists per-arch: 2 on amd64, 4 on arm64 — use it for the read length.)

- [ ] **Step 2: Unit-test the predicate** (`inject_guard_test.go`, `//go:build linux`; gate arch-specific bytes with `runtime.GOARCH` or build tags):
```go
func TestIsSyscallInsn(t *testing.T) {
	// On amd64 the syscall insn is 0F 05; anything else must be rejected.
	if runtime.GOARCH == "amd64" {
		if !isSyscallInsn([]byte{0x0f, 0x05}) { t.Fatal("0f05 should be a syscall insn") }
		if isSyscallInsn([]byte{0x48, 0x89}) { t.Fatal("mov must not be a syscall insn") }
		if isSyscallInsn([]byte{0x0f}) { t.Fatal("short buf must be rejected") }
	}
}
```

- [ ] **Step 3: Fix (2) — verify the gadget** in `injectFromExit`, right after `gadget := syscallGadgetAddr(savedRegs)` and before `injRegs.SetInstructionPointer(gadget)`:
```go
	insn := make([]byte, syscallInsnSize)
	if err := t.readBytes(tid, gadget, insn); err != nil {
		return 0, fmt.Errorf("inject gadget read @0x%x: %w", gadget, err)
	}
	if !isSyscallInsn(insn) {
		return 0, fmt.Errorf("inject gadget @0x%x not a syscall instruction (% x); stop misclassified (#369)", gadget, insn)
	}
```

- [ ] **Step 4: Fix (3) — verify execution** in BOTH `injectFromEntry` and `injectFromExit`, immediately after `retRegs, err := t.getRegs(tid)` succeeds and BEFORE `ret := retRegs.ReturnValue()`:
```go
	if got := retRegs.SyscallNr(); got != nr {
		injectErr = fmt.Errorf("injected syscall %d did not execute (orig_rax=%d at exit); stop misclassified (#369)", nr, got)
		return 0, injectErr
	}
```
(Inside the existing `injectErr` defer scope so registers are restored on this error.)

- [ ] **Step 5: Build all arches + test.**
Run: `go build ./internal/ptrace/ && GOARCH=arm64 go build ./internal/ptrace/ && go vet ./internal/ptrace/`
Run: `go test ./internal/ptrace/ -run 'IsSyscallInsn'` → PASS.
Run (if kernel allows): `go test -tags 'integration linux' ./internal/ptrace/ 2>&1 | tail -30` → prefilter-inject + redirect tests still PASS (on CI the gadget is a real syscall and `orig_rax==nr`, so the guards never reject a valid inject). Report any flips.

- [ ] **Step 6: Commit** (`fix(ptrace,#369): verify inject gadget is a syscall insn + injected syscall executed`).

---

## Task 3: Fail-closed scratch page (`scratch.go`)

**Files:** Modify `internal/ptrace/scratch.go`.

- [ ] **Step 1: Replace the #398 WARN-only block** in `ensureScratchPage`. The current code logs a WARN when `!addrInMaps(tid, addr)` then builds `sp = &scratchPage{addr: addr, size: 4096}` regardless. Change to return an error so the phantom address is never used:
```go
	if !addrInMaps(tid, addr) {
		return nil, fmt.Errorf("scratch mmap returned 0x%x but mapped no VMA (#369); new_mappings=%v",
			addr, newMapRanges(tid, mapsBefore))
	}
```
(Remove the `slog.Warn` it replaces; keep the `mapsBefore` snapshot for the error detail. The `slog` import may become unused in scratch.go — drop it if so.)

- [ ] **Step 2: Build + vet + test.**
Run: `go build ./internal/ptrace/ && go vet ./internal/ptrace/`
Run: `go test ./internal/ptrace/` and (if kernel allows) `go test -tags 'integration linux' ./internal/ptrace/ 2>&1 | tail -20` → on CI the mmap maps, so `ensureScratchPage` returns success and prefilter-inject tests stay green.
Note: `ptrace.ProbePtraceInject` (the #399 probe) calls `ensureScratchPage` and is fail-open on its error — so this new error path keeps the probe fail-open (no behavior change there). Confirm `go test ./internal/ptrace/ -tags 'integration linux' -run InjectProbe` still PASSes (Injectable=true on CI).

- [ ] **Step 3: Commit** (`fix(ptrace,#369): fail-closed when injected scratch mmap maps no VMA`).

---

## Task 4: Full gates

- [ ] **Step 1:** `go test ./...` — green except the known pre-existing `internal/fsmonitor` FUSE-mount env failure (rerun to confirm unrelated).
- [ ] **Step 2:** `GOOS=windows go build ./...` and `GOARCH=arm64 go build ./...` — clean (the arch-split `isSyscallInsn`/`syscallInsnSize` keep both building).
- [ ] **Step 3:** `gofmt -l` clean on all changed files; `go vet ./internal/ptrace/` clean.
