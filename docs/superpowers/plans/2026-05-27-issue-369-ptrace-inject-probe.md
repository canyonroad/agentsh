# Ptrace inject self-probe + honest degrade — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Stop the ~60% `exit -1` kills on kernels where ptrace syscall injection is unreliable (#369 Gap C) by probing injectability at startup and **degrading honestly** — don't start the ptrace tracer, warn, report it in detect, fail-fast under strict.

**Architecture:** A `sync.Once` behavioral probe (`ptrace.ProbePtraceInject`) injects a test `mmap` via the production gadget path into a controlled child and checks `/proc/<pid>/maps` for a real VMA (8 iterations; fail-open on probe error). A new `SecurityCapabilities.PtraceInjectable` feeds detect + strict validation; a **runtime gate** in `initPtraceTracer` (the piece that actually stops the kills) skips the tracer when unreliable. Default = degrade-and-continue; `Security.Strict`/ptrace = fail-fast.

**Spec:** `docs/superpowers/specs/2026-05-27-issue-369-ptrace-inject-probe-design.md`

**Tasks are ordered so the wiring (capabilities, gate, strict) is built and unit-tested via a probe SEAM before the real fork-and-inject probe is written.** The probe's broken-kernel result is not reproducible on CI; final verification is erans on v0.20.3-rc6.

---

## Task 1: Capability field + detect honesty + strict `ModePtrace`

**Files:** Modify `internal/capabilities/security_caps.go`, `internal/capabilities/detect_linux.go`, `internal/capabilities/validate.go`. Test: `internal/capabilities/detect_linux_test.go`, `internal/capabilities/validate_test.go`.

- [ ] **Step 1: Failing tests.**

In `detect_linux_test.go` add:
```go
func TestPtraceBackendDetail_InjectUnreliable(t *testing.T) {
	caps := &SecurityCapabilities{Ptrace: true, PtraceEnabled: true, PtraceInjectable: false}
	if got := ptraceBackendDetail(caps); got != "syscall injection unreliable on this kernel (disabled)" {
		t.Fatalf("detail = %q", got)
	}
}

func TestPtraceBackend_Available_RequiresInjectable(t *testing.T) {
	// Available only when Ptrace && PtraceEnabled && PtraceInjectable.
	domains := buildLinuxDomains(&SecurityCapabilities{Ptrace: true, PtraceEnabled: true, PtraceInjectable: false})
	if b := findBackend(domains, "Command Control", "ptrace"); b == nil || b.Available {
		t.Fatalf("ptrace backend should be unavailable when not injectable; got %+v", b)
	}
	domains = buildLinuxDomains(&SecurityCapabilities{Ptrace: true, PtraceEnabled: true, PtraceInjectable: true})
	if b := findBackend(domains, "Command Control", "ptrace"); b == nil || !b.Available {
		t.Fatalf("ptrace backend should be available when injectable; got %+v", b)
	}
}
```
Add a `findBackend(domains, domainName, backendName) *Backend` test helper if one does not already exist (search domains for the named backend). In `validate_test.go`:
```go
func TestValidateStrictMode_PtraceRequiresInjectable(t *testing.T) {
	err := ValidateStrictMode(ModePtrace, &SecurityCapabilities{Ptrace: true, PtraceInjectable: false})
	if err == nil {
		t.Fatal("strict ptrace mode must fail when injection is unreliable")
	}
	if err := ValidateStrictMode(ModePtrace, &SecurityCapabilities{Ptrace: true, PtraceInjectable: true}); err != nil {
		t.Fatalf("strict ptrace mode should pass when injectable: %v", err)
	}
}
```

- [ ] **Step 2: Run — expect FAIL/compile error** (`PtraceInjectable` undefined, detail mismatch, no `ModePtrace` strict case). Run: `go test ./internal/capabilities/ -run 'Ptrace'`.

- [ ] **Step 3: Add the fields** in `security_caps.go` `SecurityCapabilities` (after `PtraceEnabled`):
```go
	PtraceInjectable  bool   // injected syscalls (mmap) reliably take effect here (issue #369)
	PtraceInjectDetail string // why injection is unreliable, when PtraceInjectable is false
```

- [ ] **Step 4: Detect honesty** in `detect_linux.go`. Replace `ptraceBackendDetail`'s first branch group so an injectable failure is explained, and add the injectable term to the backend `Available`:
```go
func ptraceBackendDetail(caps *SecurityCapabilities) string {
	if caps.Ptrace && !caps.PtraceInjectable {
		return "syscall injection unreliable on this kernel (disabled)"
	}
	if caps.Ptrace && caps.PtraceEnabled {
		return ""
	}
	if caps.Ptrace {
		return "available, not active (enable ptrace mode)"
	}
	return ""
}
```
And at the ptrace backend (line ~130):
```go
{Name: "ptrace", Available: caps.Ptrace && caps.PtraceEnabled && caps.PtraceInjectable, Detail: ptraceBackendDetail(caps), Description: "syscall tracing", CheckMethod: "probe"},
```

- [ ] **Step 5: Strict `ModePtrace` case** in `validate.go` `ValidateStrictMode` (add before `default:`):
```go
	case ModePtrace:
		if !caps.Ptrace {
			return fmt.Errorf("strict mode %q requires the ptrace capability", mode)
		}
		if !caps.PtraceInjectable {
			return fmt.Errorf("strict mode %q requires reliable ptrace syscall injection (unavailable on this kernel)", mode)
		}
```

- [ ] **Step 6: Run tests — expect PASS.** `go test ./internal/capabilities/`. Then `go build ./... && go vet ./internal/capabilities/`.

- [ ] **Step 7: Commit** (`feat(capabilities,#369): PtraceInjectable capability + detect/strict honesty`).

---

## Task 2: Runtime gate in `initPtraceTracer` (via a probe seam)

**Files:** Modify `internal/api/app.go` (add `ptraceDegraded atomic.Bool`), `internal/api/app_ptrace_linux.go`. Test: `internal/api/app_ptrace_probe_test.go` (new, `//go:build linux`).

- [ ] **Step 1: Failing test** (`app_ptrace_probe_test.go`) using a seam:
```go
//go:build linux

package api

import "testing"

func TestInitPtraceTracer_DegradesWhenNotInjectable(t *testing.T) {
	orig := ptraceInjectProbe
	t.Cleanup(func() { ptraceInjectProbe = orig })
	ptraceInjectProbe = func() bool { return false } // injection unreliable

	a := newTestAppWithPtraceEnabled(t) // helper: minimal App, cfg.Sandbox.Ptrace.Enabled=true
	a.initPtraceTracer()

	if a.ptraceTracer != nil {
		t.Fatal("tracer must NOT start when injection is unreliable")
	}
	if !a.ptraceDegraded.Load() {
		t.Fatal("ptraceDegraded must be set")
	}
	if a.ptraceFailed.Load() {
		t.Fatal("must NOT fail-closed on degrade")
	}
}
```
If a minimal-App test helper doesn't exist, add `newTestAppWithPtraceEnabled` building the smallest `*App` that lets `initPtraceTracer` run (mirror existing api tests' App construction). Keep the helper minimal; the assertions only touch `ptraceTracer`, `ptraceDegraded`, `ptraceFailed`.

- [ ] **Step 2: Run — expect FAIL** (`ptraceInjectProbe`, `ptraceDegraded` undefined). `go test ./internal/api/ -run DegradesWhenNotInjectable`.

- [ ] **Step 3: Add `ptraceDegraded`** to the `App` struct in `app.go` near `ptraceFailed` (same `atomic.Bool` type).

- [ ] **Step 4: Add the seam + gate** in `app_ptrace_linux.go`. Near the top of the file:
```go
// ptraceInjectProbe reports whether ptrace syscall injection is reliable here.
// Seam for tests; defaults to the real one-time behavioral probe (#369).
var ptraceInjectProbe = func() bool { return ptrace.ProbePtraceInject().Injectable }
```
In `initPtraceTracer`, immediately after the `if !cfg.Enabled { … return }` block:
```go
	if !ptraceInjectProbe() {
		slog.Warn("ptrace syscall injection is unreliable on this kernel; not starting the "+
			"ptrace tracer (degraded). Commands run WITHOUT ptrace enforcement. Run on a kernel "+
			"with working ptrace injection, or set sandbox.ptrace.enabled:false to silence. (#369)")
		a.ptraceDegraded.Store(true)
		a.warnIfFamiliesOrphan()
		a.warnIfSocketRulesOrphan()
		return // do NOT start the tracer; do NOT set ptraceFailed (not fail-closed)
	}
```

- [ ] **Step 5: Run test — expect PASS.** `go test ./internal/api/ -run DegradesWhenNotInjectable`. Then `go build ./... && go vet ./internal/api/`.

- [ ] **Step 6: Commit** (`feat(api,#369): runtime gate — skip ptrace tracer when injection unreliable`).

---

## Task 3: Strict fail-fast already covered by Task 1 — wire-through check only

**Files:** none new (Task 1 added the `ModePtrace` strict case; `server/security.go` already calls `ValidateStrictMode`). Test: `internal/server/security_test.go`.

- [ ] **Step 1: Failing test** asserting `DetectAndValidateSecurityMode` errors when `Security.Mode:"ptrace"` + `Strict:true` on a not-injectable host. Since `DetectSecurityCapabilities` runs the real probe, inject a seam: confirm whether `security_test.go` can construct caps; if `DetectAndValidateSecurityMode` can't be unit-tested without real detection, instead add a direct `ValidateStrictMode(ModePtrace, …)` test (already in Task 1) and a `security_test.go` test that calls `ValidateStrictMode` through the same path. If a seam is needed for `DetectSecurityCapabilities`, defer to Task 4's wiring and keep this as the Task 1 unit test only.
- [ ] **Step 2-3: Verify** `go test ./internal/server/ ./internal/capabilities/` green. (No new production code expected; this task confirms the strict path is wired.)
- [ ] **Step 4: Commit if any test added** (`test(server,#369): strict ptrace mode fails fast when not injectable`).

---

## Task 4: The real behavioral probe `ProbePtraceInject` (capable model)

**Files:** Create `internal/ptrace/inject_probe_linux.go`. Child sentinel hook: `cmd/agentsh/main.go` (or wherever `ProbeSeccompInstall`'s child sentinel is detected — mirror it). Test: `internal/ptrace/inject_probe_test.go` (`//go:build integration && linux`).

**This is the hard, fidelity-critical task — use a capable model.** Follow these precedents exactly:
- Re-exec/sentinel/`sync.Once` structure: `internal/netmonitor/unix/seccomp_install_probe_linux.go` (`ProbeSeccompInstall`, `installProbeOnce`, two-factor child detection: sentinel argv + ≥16-char env token).
- Child attach + thread pinning: `internal/ptrace/syscall_stop_op_test.go` (`exec.Command` + `SysProcAttr{Ptrace:true}` + `runtime.LockOSThread`).
- **Production inject to reuse for fidelity:** `internal/ptrace/scratch.go:ensureScratchPage` → `injectSyscallRet(SYS_MMAP,…)` → `injectFromExit` (gadget). The `addrInMaps`/`mapStarts`/`newMapRanges` helpers (`memory.go`) verify mapping.

- [ ] **Step 1: Define the API + result.**
```go
type InjectProbeResult struct {
	Injectable bool
	Detail     string
}
func ProbePtraceInject() InjectProbeResult // sync.Once cached
```

- [ ] **Step 2: Child sentinel.** Add an init-time check (mirroring the seccomp probe's `isInstallProbeChildInvocation`): when invoked with the inject-probe sentinel argv + valid env token, the child blocks forever (`select{}` / `unix.Pause()`) so the parent can inject then kill it. Wire it where the seccomp probe child is dispatched.

- [ ] **Step 3: Probe loop (parent).** `runtime.LockOSThread`. For `injectProbeIterations` (=8):
  1. `cmd := exec.Command(self, injectProbeSentinel)`, `SysProcAttr{Ptrace:true, Setpgid:true}`, env token; `Start()`.
  2. `Wait4` initial stop; `PtraceSetOptions(PTRACE_O_TRACESYSGOOD)`.
  3. Construct a minimal `Tracer` (`NewTracer(TracerConfig{SeccompPrefilter:true})`, set `hasSyscallInfo = probePtraceSyscallInfo()`), register tracee state (`t.tracees[pid] = &TraceeState{TGID: pid, InSyscall:false, MemFD:-1}`), drive the child to a between-syscalls EXIT stop (PtraceSyscall to an enter, then `advancePastEntry`), capture `savedRegs`, then call `t.ensureScratchPage(pid, pid, savedRegs)` — **the production gadget mmap inject**.
  4. `mapped := addrInMaps(pid, sp.addr)`; on the first failure capture `mmap_ret`/`newMapRanges` for `Detail`.
  5. `unix.Kill(-pgid, SIGKILL)`; `cmd.Wait()`.
  6. If `!mapped` → return `{false, detail}` immediately.
  - Per-iteration timeout (~1s). Any setup/attach error → treat as probe-error.
- All 8 mapped → `{true, "8/8 injected mmap mapped"}`.

- [ ] **Step 4: Fail-open on probe error.** If the probe can't run (fork/attach/timeout) → `{true, "probe inconclusive: <err>"}` (assume healthy; do not degrade). Only a clean `mapped==false` degrades.

- [ ] **Step 5: Cache** with `sync.Once` (`probeInjectOnce`); concurrent callers share one result.

- [ ] **Step 6: Integration test** (`//go:build integration && linux`): `ProbePtraceInject().Injectable == true` on the CI kernel (injection works there); assert no leaked children (`pgrep`-style check or that `cmd.Wait` returned). `requirePtrace(t)` skip guard.

- [ ] **Step 7: Verify** `go build ./internal/ptrace/`, `go vet`, `go test -tags 'integration linux' ./internal/ptrace/ -run InjectProbe`, and `go test ./internal/ptrace/` (unit). Confirm the child sentinel path doesn't interfere with normal `agentsh` startup (no sentinel ⇒ no-op).

- [ ] **Step 8: Commit** (`feat(ptrace,#369): ProbePtraceInject — behavioral mmap-inject reliability probe`).

---

## Task 5: Wire the real probe into capability detection

**Files:** Create `internal/capabilities/check_ptrace_linux.go`; modify `internal/capabilities/security_caps.go` (call it in `DetectSecurityCapabilities`, gated on `caps.Ptrace`). Non-linux: a `check_ptrace_other.go` stub returning injectable=false/not-applicable.

- [ ] **Step 1:** `check_ptrace_linux.go`:
```go
//go:build linux
package capabilities
import "github.com/agentsh/agentsh/internal/ptrace"
func checkPtraceInject() (bool, string) {
	r := ptrace.ProbePtraceInject()
	return r.Injectable, r.Detail
}
```
Non-linux stub: `func checkPtraceInject() (bool, string) { return false, "" }`.

- [ ] **Step 2:** In `DetectSecurityCapabilities`, after `caps.Ptrace = checkPtraceCapability()`:
```go
	if caps.Ptrace {
		caps.PtraceInjectable, caps.PtraceInjectDetail = checkPtraceInject()
	}
```
(Only probe when the ptrace capability exists — avoids the fork cost otherwise.)

- [ ] **Step 3: Verify** `go build ./...`, `go test ./internal/capabilities/ ./internal/server/`, and confirm `agentsh detect` compiles. Check there is no import cycle (`capabilities` → `ptrace`); if one exists, move `ProbePtraceInject` behind an interface or have `api` set `PtraceInjectable` instead. **If import cycle: STOP and report** — fall back to having `initPtraceTracer` (api) own the probe and pass the result to detect via config/state rather than capabilities importing ptrace.

- [ ] **Step 4: Commit** (`feat(capabilities,#369): wire ProbePtraceInject into DetectSecurityCapabilities`).

---

## Task 6: Full gates

- [ ] **Step 1:** `go test ./...` — green except the known pre-existing `internal/fsmonitor` FUSE-mount env failure (rerun to confirm it's unrelated).
- [ ] **Step 2:** `GOOS=windows go build ./...` (all new linux files are `//go:build linux`; verify the non-linux `checkPtraceInject` stub keeps Windows/darwin building).
- [ ] **Step 3:** `gofmt -l` clean on all changed files; `go vet ./...` clean for changed packages.
