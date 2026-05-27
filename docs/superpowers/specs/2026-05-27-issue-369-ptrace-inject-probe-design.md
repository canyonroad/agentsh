# Ptrace inject self-probe + honest degrade — Design

Issue: #369 ("Gap C"), Path 1. Follow-up to the diagnosis in #396/#397/#398.

## Summary

On exe.dev kernel `6.12.90`, agentsh's ptrace syscall injection is fundamentally
unreliable: an injected `mmap` returns a plausible address but creates no VMA
(rc5/#398 proved `new_mappings=[]`), so the seccomp-prefilter scratch-page write
`EIO`s and the command is lost (`exit -1`, ~60%). No inject-side fix worked
across rc1–rc5, and `seccomp_prefilter: false` (pure `TRACESYSGOOD`) hangs every
exec — so **ptrace mode as a whole is unusable on this kernel**.

This design stops the kills by making agentsh **honest**: a one-time startup
behavioral probe injects a test `mmap` (via the **production** inject path) into a
controlled child and verifies a real VMA appears. If injection is unreliable,
agentsh **degrades** — it does not start the ptrace tracer, warns loudly, and
reports ptrace as not-enforcing in `agentsh detect`; commands run under the
remaining backends instead of dying. Under `Security.Strict` (or a required
minimum mode) that needs ptrace, it **fails fast at startup** instead. This
mirrors the #388/#390 `SeccompInstallable` precedent, extended with the one piece
#390 didn't need: a **runtime gate** so the tracer doesn't start when the probe
fails.

## Goals

- On a kernel where injected `mmap` doesn't reliably map, agentsh does **not**
  start the ptrace tracer (default), logs a clear degraded-mode `WARN`, and
  commands succeed under the remaining backends — no `exit -1` kills.
- `agentsh detect` reports the ptrace Command Control backend as not-enforcing
  with an actionable detail ("syscall injection unreliable on this kernel").
- `Security.Strict` / required-minimum-mode that depends on ptrace **fails fast**
  at startup (reusing #390's validation path), not per-command later.
- Zero behavior change on healthy kernels: the probe passes, the tracer starts
  exactly as today.
- The probe is **faithful** (reuses the production scratch-`mmap` inject) and
  **robust to the ~60% intermittency** (multiple iterations; any failure ⇒
  unreliable).

## Non-Goals

- **Not fixing the inject.** The inject is unfixable on this kernel; we gate it.
- **No auto-fallback to a specific backend.** Degrade means "don't run ptrace";
  the already-configured remaining backends (seccomp-user-notify / landlock) run
  as configured. We do not auto-enable anything new.
- **No wiring of `SecurityCapabilities.PtraceEnabled` into `SelectMode`.** That
  flag is currently unset in production (a pre-existing gap); the ptrace-mode
  *reporting* path is out of scope here. We touch the ptrace **backend
  availability** (detect) and the **runtime start gate**, not `SelectMode`'s
  `ModePtrace` selection.
- **No change to the inject/stop machinery, `process_vm_*`, user-notify, cgroups.**
- The probe runs **once per process** (cached); it is not re-run per command.

## Background (integration points, verified)

- Tracer start: `internal/api/app_ptrace_linux.go:initPtraceTracer()` gates on
  `cfg.Sandbox.Ptrace.Enabled` (`:41`), constructs the tracer (`:97`), and runs
  it in a goroutine; a tracer `Run` error sets `a.ptraceFailed` (fail-closed,
  `:121-123`). Called from `app.go:NewApp` (`:207`).
- Existing startup ptrace probe precedent: `probePtraceSyscallInfo()` →
  `t.hasSyscallInfo` (`tracer.go:1868`).
- Seccomp behavioral-probe precedent: `internal/netmonitor/unix/seccomp_install_probe_linux.go`
  (`ProbeSeccompInstall`, `sync.Once`, re-exec child w/ sentinel argv + env
  token); surfaced via `internal/capabilities/check_seccomp_linux.go:realCheckSeccompInstall`
  into `SecurityCapabilities.SeccompInstallable` (`security_caps.go:72-75`).
- Detect: `buildLinuxDomains` ptrace backend `Available: caps.Ptrace && caps.PtraceEnabled`,
  `Detail: ptraceBackendDetail(caps)` (`detect_linux.go:130, :47-60`).
- Strict/degraded validation: `internal/server/security.go` —
  `DetectAndValidateSecurityMode`, `ValidateStrictMode`, `WarnDegraded` (`:13-54`).
- Inject path to reuse: `internal/ptrace/scratch.go:ensureScratchPage` →
  `injectSyscallRet(SYS_MMAP)` → `injectFromExit`; the #398 diagnostic helpers
  `addrInMaps`/`mapStarts`/`newMapRanges` are in `memory.go`.
- Child-attach harness pattern: `exec.Command` + `SysProcAttr{Ptrace: true}` +
  `runtime.LockOSThread` (see `internal/ptrace/syscall_stop_op_test.go`).

## Design

### 1. Behavioral probe `ProbePtraceInject` (`internal/ptrace`, new file)

A `sync.Once`-cached probe that returns whether injected `mmap` reliably maps:

```go
type InjectProbeResult struct {
    Injectable bool
    Detail     string // human-readable: iterations, a sample mmap_ret, mapped?
}

func ProbePtraceInject() InjectProbeResult // cached via sync.Once
```

Algorithm (parent runs on a `runtime.LockOSThread`-pinned goroutine):

For each of `injectProbeIterations` (= 8) iterations:
1. Start a controlled child: `exec.Command(self, injectProbeSentinel)` with
   `SysProcAttr{Ptrace: true, Setpgid: true}` and the env token (mirror
   `ProbeSeccompInstall`'s two-factor child detection; the child blocks, e.g.
   `select{}` / `unix.Pause`, so it is a stable tracee).
2. `Wait4` the initial exec/trace stop; `PtraceSetOptions(PTRACE_O_TRACESYSGOOD)`.
3. Drive to a between-syscalls (exit) stop and **reuse the production inject**:
   construct a minimal `Tracer` (or call the inject helper directly) and invoke
   the **same `ensureScratchPage` / `injectSyscallRet(SYS_MMAP, …)` gadget path**
   used in production, capturing the returned address.
4. `mapped := addrInMaps(childPid, addr)`; record a sample `mmap_ret` + the
   `newMapRanges` diff for the detail string.
5. `Kill` + `Wait` the child (and its pgid).
- If **any** iteration yields `mapped == false` ⇒ `Injectable = false`
  (unreliable). Only if **all** iterations map ⇒ `Injectable = true`.
- Each iteration bounded by a timeout (e.g. 1s); the whole probe bounded overall.

**Fidelity is the critical requirement.** The probe MUST exercise the production
gadget inject (`injectFromExit` via `ensureScratchPage`/`injectSyscallRet`), not a
hand-rolled `injectFromEntry`, so it reproduces the defect erans observed. If
reusing `ensureScratchPage` against a probe child proves impractical, the
fallback is to call the exact same `injectSyscall(SYS_MMAP, …)` sequence with the
gadget protocol — but it must be the gadget path.

**Robustness to intermittency.** The mmap fails ~60% on the affected kernel, so a
single attempt could pass by luck. 8 iterations make a false-pass on a broken
kernel ~`0.4^8 ≈ 0.07%`; a healthy kernel passes all 8 deterministically.

**Probe-error semantics (fail-OPEN).** If the probe itself cannot run (fork
fails, attach denied, timeout with no clear result), default to
`Injectable = true` (assume healthy; do not disable enforcement). A genuinely
broken kernel produces a clean, repeatable `mapped == false` (per rc5), not a
probe error — so fail-open does not mask the real case while avoiding spurious
degradation on healthy hosts where the probe merely had trouble.

Child sentinel handling: add an init-time check (in the same place the seccomp
probe child is handled, or `main`) — if invoked with the inject-probe sentinel +
valid env token, block forever (`select{}`), so the parent can inject and then
kill it.

### 2. Capability field (`internal/capabilities`)

- Add `SecurityCapabilities.PtraceInjectable bool` and `PtraceInjectDetail string`.
- In `DetectSecurityCapabilities()`, **only when `caps.Ptrace` is true**, call a
  `checkPtraceInject()` (linux) that invokes `ptrace.ProbePtraceInject()` and sets
  the fields. On non-linux / no ptrace cap, `PtraceInjectable = false`,
  `PtraceInjectDetail = ""` (and it is not consulted — see gating).

### 3. Detect honesty (`internal/capabilities/detect_linux.go`)

- `ptraceBackendDetail`: when `caps.Ptrace && !caps.PtraceInjectable`, return
  `"syscall injection unreliable on this kernel (disabled)"`.
- ptrace Command Control backend `Available`: `caps.Ptrace && caps.PtraceEnabled
  && caps.PtraceInjectable` (keeps the existing `PtraceEnabled` term; adds the
  injectable term so detect never shows ptrace enforcing when it can't inject).

### 4. Runtime gate — the piece that stops the kills (`internal/api/app_ptrace_linux.go`)

In `initPtraceTracer`, after the `cfg.Enabled` gate and before constructing/
starting the tracer:

```go
if probe := ptrace.ProbePtraceInject(); !probe.Injectable {
    slog.Warn("ptrace syscall injection unreliable on this kernel; "+
        "NOT starting ptrace tracer (degraded). Commands run without ptrace "+
        "enforcement. Set sandbox.ptrace.enabled:false to silence, or run on a "+
        "kernel with working ptrace injection.",
        "detail", probe.Detail)
    a.warnIfFamiliesOrphan() // file/network/signal families lose their backend
    a.ptraceDegraded.Store(true)
    return // do NOT start the tracer, do NOT set ptraceFailed (NOT fail-closed)
}
```

- `a.ptraceDegraded` is a new flag (distinct from `ptraceFailed`): commands run
  normally; ptrace simply isn't active. It is surfaced in startup logging.
- This deliberately does **not** take the fail-closed path — the chosen behavior
  (Option A) is degrade-and-continue.

### 5. Strict fail-fast (`internal/server/security.go`)

In `DetectAndValidateSecurityMode` / `ValidateStrictMode`: when the
required/strict mode depends on ptrace enforcement and
`!caps.PtraceInjectable` (with `caps.Ptrace` present, i.e. ptrace was the
intended backend), fail startup with a clear error
("ptrace syscall injection is unreliable on this kernel; required mode <m> cannot
be enforced"). This reuses the existing strict-validation seam so an operator who
*requires* the enforcement gets a hard stop rather than a silent downgrade.

### Resulting behavior

- exe.dev 6.12.90, `ptrace.enabled:true`, non-strict: probe fails → tracer not
  started → `WARN` degraded → `/bin/echo` and the shim suite **run** (no kills);
  `agentsh detect` shows `ptrace - syscall injection unreliable on this kernel`.
- Same host, `Security.Strict` requiring full/ptrace: **fail-fast** at startup.
- Healthy kernel: probe passes (all 8 iterations map) → tracer starts as today.

## Decisions

- **Degrade-and-continue by default + fail-fast on strict** (Option A): killing
  ~60% of commands is the worst outcome; reduced-but-logged enforcement on a
  broken kernel is the lesser evil, and operators who *require* the level get the
  strict fail-fast. Matches #390's philosophy.
- **Runtime gate is mandatory** (unlike #390's reporting-only): the tracer start
  is config-driven, so only gating `initPtraceTracer` actually stops the kills.
- **Probe reuses the production gadget inject** for fidelity, and runs **8
  iterations** for robustness against the ~60% intermittency.
- **Fail-open on probe error**; the real broken case is a clean repeatable
  `mapped=false`, so fail-open won't mask it.

## Error handling

- Probe child leak/zombie: each iteration `Kill`+`Wait`s the child (pgid) under a
  per-iteration timeout; the probe never blocks startup unbounded.
- Probe runs once (`sync.Once`); concurrent callers (detect + initPtraceTracer +
  server validation) share one result.
- Degrade path never fail-closes; strict path fails fast with a descriptive error.

## Testing

The broken-kernel result is not reproducible on CI (injection works there), so:

- **Probe wiring / result plumbing** (unit, no live tracee): `InjectProbeResult`
  threading into `SecurityCapabilities.PtraceInjectable`; `ptraceBackendDetail`
  and backend `Available` for `{Ptrace:true, PtraceInjectable:false}` vs `true`;
  `SelectMode`/detect parity (table tests in `capabilities`).
- **Runtime gate** (unit): with a faked/injected probe result `Injectable:false`,
  `initPtraceTracer` does not start the tracer and sets `ptraceDegraded` (inject a
  probe func/seam so the test doesn't fork); `Injectable:true` starts as today.
- **Strict fail-fast** (unit): `ValidateStrictMode` errors when strict requires
  ptrace and `PtraceInjectable:false`.
- **Probe happy path** (integration, `//go:build integration && linux`):
  `ProbePtraceInject()` returns `Injectable:true` on the CI kernel (injection
  works), and children are reaped (no leaks).
- Full `internal/ptrace`, `internal/capabilities`, `internal/server`,
  `internal/api` suites stay green; `GOOS=windows go build ./...`.

End-to-end on exe.dev 6.12.90 (probe trips → degrade → shim suite runs) is
verified by erans on v0.20.3-rc6.

## Affected files

- `internal/ptrace/inject_probe_linux.go` (new) — `ProbePtraceInject`, child
  sentinel, iteration loop reusing the gadget inject.
- `internal/ptrace/` — child-sentinel init hook (or in `cmd/agentsh`/`main`).
- `internal/capabilities/security_caps.go` — `PtraceInjectable`/`PtraceInjectDetail`
  + set in `DetectSecurityCapabilities` (gated on `caps.Ptrace`).
- `internal/capabilities/check_ptrace_linux.go` (new) — `checkPtraceInject`.
- `internal/capabilities/detect_linux.go` — `ptraceBackendDetail` + backend
  `Available`.
- `internal/api/app_ptrace_linux.go` — runtime gate + `ptraceDegraded`.
- `internal/server/security.go` — strict fail-fast.
- Tests across the above packages.
- Inject machinery, `process_vm_*`, user-notify, cgroups, darwin/windows —
  unchanged.
