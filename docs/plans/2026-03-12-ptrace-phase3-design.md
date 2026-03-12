# Ptrace Phase 3: Production Hardening (Code-Only)

**Date:** 2026-03-12
**Scope:** max_hold_ms timeout, ptrace-specific metrics, graceful degradation, overhead benchmarks
**Deferred:** Sidecar auto-discovery, Fargate E2E tests, seccomp prefilter injection (need AWS infra)

---

## 1. max_hold_ms Timeout Enforcement

The tracer can "park" a tracee when policy evaluation is async (e.g., waiting for human/LLM approval). Currently, a parked tracee waits forever — if the approval callback never fires, the workload thread is permanently blocked.

### Design

- Add `ParkedAt time.Time` to `TraceeState`.
- In the main event loop's idle `select` (the `time.After(5ms)` branch), sweep `parkedTracees` and check elapsed time against `cfg.MaxHoldMs`.
- On timeout: deny with EACCES (fail-closed), emit `slog.Warn` with tid/elapsed/syscall, increment `ptrace_timeouts_total` counter.
- The sweep is cheap — `parkedTracees` is typically empty or has 1-2 entries.

### Why deny, not allow

The `on_attach_failure` setting controls what happens when *attachment* fails (process runs untraced). Timeout is different — we had time to evaluate and couldn't decide. Fail-closed (deny) is safer. A separate config knob for fail-open timeouts can be added later if needed.

---

## 2. Graceful Degradation

Three failure modes to handle:

### A. Tracee exits while parked

A parked tracee is waiting for an async approval. If it gets killed or exits before the approval arrives, the resume request will try to `allowSyscall`/`denySyscall` on a dead TID, which fails with ESRCH.

- In `handleResumeRequest()`, after unparking, check if the TID still exists in `t.tracees`. If not (already cleaned up by `handleExit()`), skip the ptrace call and log it.
- In `handleExit()`, if the exiting TID is in `parkedTracees`, remove it and log a warning.

### B. ptrace operation fails with ESRCH mid-handling

The tracee can die between reading its registers and writing back the deny.

- Treat ESRCH from any ptrace op as "tracee gone" — call `handleExit()` to clean up memFD and tracee map. No crash, no tracer degradation.

### C. Unexpected mass tracee loss

If the workload container crashes, all tracees disappear at once. The tracer hits ECHILD from `wait4` and blocks on the attach/resume channels.

- Already works correctly — the ECHILD path blocks on `ctx.Done()` or new attach requests. No change needed.

No new config knobs — these are all internal robustness fixes.

---

## 3. Ptrace-Specific Metrics

Wire three metrics into the existing `pkg/observability/PrometheusCollector`:

### New metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `agentsh_ptrace_tracees_active` | gauge | — | Current tracee count |
| `agentsh_ptrace_attach_failures_total` | counter | `reason` | PTRACE_SEIZE failures (esrch, eperm, other) |
| `agentsh_ptrace_timeouts_total` | counter | — | max_hold_ms timeout firings |

### Wiring

- Add a `Metrics` interface to the ptrace package: `IncAttachFailure(reason string)`, `IncTimeout()`, `SetTraceeCount(n int)`. Keeps ptrace decoupled from prometheus.
- `PrometheusCollector` implements this interface.
- `TracerConfig` gets an optional `Metrics` field (nil-safe — if nil, no metrics emitted).
- The tracer calls `SetTraceeCount` after every attach/detach/exit, `IncAttachFailure` on SEIZE errors, `IncTimeout` on max_hold_ms expiry.

### What we don't add

Per-syscall counters or latency histograms for ptrace specifically. The existing `agentsh_operations_total` and `agentsh_operation_latency_seconds` already capture decision outcomes from the handler layer — ptrace vs seccomp is transparent at that level.

---

## 4. Overhead Benchmarks

Go benchmark tests in the ptrace package, behind `//go:build integration && linux`.

### BenchmarkExecOverhead

Fork a child that does `execve(/bin/true)` in a loop. Measure wall-clock time per exec with tracing (allow-all handler) vs without tracing (baseline). Run with prefilter on and off.

### BenchmarkFileIOOverhead

Fork a child that does rapid `openat`/`close` cycles on a temp file. Measure throughput with file tracing enabled (allow-all) vs disabled. Isolates the cost of high-frequency syscall interception.

### What we report

Each benchmark prints ns/op. Compare prefilter-on vs prefilter-off via `go test -bench`.

### What we don't add

No Fargate-specific benchmarks (need real infra). No CI enforcement of perf thresholds (noisy in shared runners). These are diagnostic tools, not regression gates.
