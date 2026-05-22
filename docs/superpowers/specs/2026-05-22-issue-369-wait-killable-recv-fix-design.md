# Issue #369 — WAIT_KILLABLE_RECV regression fix (behavioral probe)

**Date:** 2026-05-22
**Status:** Design — pending implementation
**Tracking issue:** [#369](https://github.com/agentsh/agentsh/issues/369)

## Problem

Since #316 (v0.20.x), `agentsh-unixwrap` sets `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` on the raw `seccomp(2)` syscall whenever the kernel reports a major version ≥6. On exe.dev VMs (kernel `6.12.67`, with `ProcessVMReadv` returning `ENOSYS`), every wrapped command launched with both `unix_socket` notify rules and file/metadata notify rules in the same filter is killed by signal within ~80 ms of filter install — before any policy events fire. The same configuration on the same VM worked under v0.19.2 because the libseccomp 2.5.3 path used by v0.19.2 had `SetWaitKill` as a silent no-op (the API arrived in libseccomp 2.6), so the flag was never actually on the kernel ABI mask. The intent of #316 is correct; this design addresses the latent kernel quirk it exposed.

The current detection function, `ProbeWaitKillable` (`internal/netmonitor/unix/addfd_linux.go:117`), is a uname-based version check. It is a guess, not a probe. On `6.12.67` it returns `true` while the kernel's WAIT_KILLABLE_RECV implementation, when combined with the production filter composition, kills wrapped processes.

The existing EINVAL-retry path (`seccomp_load_linux.go:185`) only catches kernels that reject the flag at filter-load time. This kernel accepts the flag and misbehaves at runtime; the retry never fires.

## Goals

- Replace the version-based probe with a behavioral check that reflects actual kernel behavior under the filter composition we'll install.
- Provide an operator-visible override (force on / force off) for cases the probe gets wrong.
- Surface enough log signal that an operator triaging an incident on a future broken kernel can self-diagnose.
- Fail-safe in both directions: if uncertain, prefer the degradation cost (SIGURG-induced ERESTARTSYS noise) over the catastrophic cost (every wrapped command dies).

## Non-goals

- Diagnosing the kernel-side root cause. The interaction is opaque from userspace; we treat the kernel as a black box.
- Persisting probe results across server restarts. Kernels change between boots; re-probe each time.
- Reproducing the bad kernel in CI. We test the probe's logic and the decision flow; the bad-kernel path is the field safety net.
- Changing how `WAIT_KILLABLE_RECV` interacts with libseccomp. The raw-syscall path from #316 stays.

## Architecture overview

Two-layer decision: server-process makes the call once at startup; wrapper-process consumes the decision via the existing `AGENTSH_SECCOMP_CONFIG` env var.

```
Server startup (once per process)
  cfg.Sandbox.Seccomp.WaitKillable *bool
       │
       ├── non-nil ─────────────► use as-is              (source: config)
       │
       └── nil ─► kernel <6 ────► false                  (source: kernel_unsupported)
              ─► composition safe► true                  (source: filter_composition_safe)
              ─► probe success ──► true                  (source: behavioral_probe)
              ─► probe killed ───► false                 (source: behavioral_probe)
              ─► probe errored ──► false (fail-safe)     (source: behavioral_probe_error)

  Result + source memoized on App; passed to every wrapper via JSON.
```

`ProbeWaitKillable` (uname check) is retained as a fast pre-filter — kernels <6 don't have the flag and need no behavioral check. Kernels ≥6 enter the behavioral path.

## Detailed design

### 1. Behavioral probe (`internal/netmonitor/unix/wait_killable_probe_linux.go`)

Signature:

```go
func ProbeWaitKillableBehavior(ctx context.Context, iterations int) (bool, error)
```

Per iteration:

1. `socketpair(AF_UNIX, SOCK_STREAM, …)` for notify-fd handoff.
2. `fork()`.
3. **Child:**
   - `prctl(PR_SET_NO_NEW_PRIVS, 1, …)`.
   - `seccomp(SET_MODE_FILTER, NEW_LISTENER|WAIT_KILLABLE_RECV, …)` with a hardcoded filter containing notify rules for both the socket family (`socket`, `connect`, `bind`, `listen`, `sendto`) and the file/metadata family (the union of `installFileMonitorRules`' syscalls plus `statx`, `newfstatat`, `faccessat2`, `readlinkat`).
   - Send notify fd to parent via `SCM_RIGHTS`.
   - `execve("/bin/true", …)`. Fall back to `/bin/echo` if `/bin/true` is missing; if neither exists, the probe returns `(false, ErrNoProbeBinary)` and the decision goes to `behavioral_probe_error`.
4. **Parent:**
   - Receive notify fd from child.
   - Goroutine: read notifications from the fd, respond with `SECCOMP_USER_NOTIF_FLAG_CONTINUE` to each, until child exits.
   - `waitpid(child, …)` with a 1-second deadline; on timeout `kill(child, SIGKILL)` and treat as fail.
   - Close notify fd and socketpair.
   - Classify:
     - `WIFEXITED && exit_status == 0` → iteration pass.
     - `WIFSIGNALED` with any signal → iteration fail (the bug).
     - Timeout → iteration fail.
     - System errors during fork/socketpair/recv → return error to caller.
5. Short-circuit: first failed iteration returns `(false, nil)` immediately.
6. All iterations pass → returns `(true, nil)`.

Constants:
- Default iterations: 5. Rationale: with the issue's ~50% kill rate, P(all-5-pass on broken kernel) ≈ 3%; doubling to 10 reduces to ~0.1% at 2× boot cost. The operator override is the final guarantee.
- Per-iteration timeout: 1 s. Worst-case boot ≤ `iterations × timeout` = 5 s.

Non-Linux stub: `wait_killable_probe_stub.go` returns `(false, nil)` on `!linux`.

### 2. Filter-composition heuristic (`filterCompositionCouldTriggerBug`)

```go
func filterCompositionCouldTriggerBug(cfg SandboxSeccompConfig) bool {
    socketFamily := cfg.UnixSocket.Enabled
    fmDefault := FileMonitorBoolWithDefault(cfg.FileMonitor.EnforceWithoutFUSE, false)
    fileFamily := FileMonitorBoolWithDefault(cfg.FileMonitor.Enabled, false) ||
                  FileMonitorBoolWithDefault(cfg.FileMonitor.InterceptMetadata, fmDefault)
    return socketFamily && fileFamily
}
```

The function operates on the *effective* config after defaults are resolved (matching the logic in `seccomp_wrapper_config.go`), not on the raw YAML toggles. This catches the gotcha that produced the issue's misleading bisection row: `file_monitor.enabled=false` with `enforce_without_fuse=true` *still* installs metadata notify rules, so the composition is still risky.

When this returns `false`, no behavioral probe is needed — `WAIT_KILLABLE_RECV` is safe by current kernel evidence. When it returns `true`, the probe runs.

### 3. Config plumbing

Four files; all add a `WaitKillable *bool` (tri-state: nil = auto, true = force on, false = force off):

| File | Field | Surface |
|---|---|---|
| `internal/config/config.go` | `SandboxSeccompConfig.WaitKillable *bool` | YAML: `sandbox.seccomp.wait_killable` |
| `internal/api/seccomp_wrapper_config.go` | `seccompWrapperConfig.WaitKillable *bool` | JSON tag `wait_killable` |
| `cmd/agentsh-unixwrap/config.go` | `WrapperConfig.WaitKillable *bool` | JSON tag `wait_killable` |
| `internal/netmonitor/unix/seccomp_linux.go` | `FilterConfig.WaitKillable *bool` | in-process struct |

Server side, in `App` (or the equivalent startup context): decide once, memoize on `a.waitKillableDecision bool` and `a.waitKillableSource string`. `buildSeccompWrapperConfig` sets `seccompCfg.WaitKillable = &a.waitKillableDecision` on every session.

Wrapper side: `cmd/agentsh-unixwrap/main.go` already wires `WrapperConfig` → `FilterConfig`; add the new field to that mapping.

`InstallFilterWithConfig` (`seccomp_linux.go:303`):

```go
var wantWaitKill bool
if cfg.WaitKillable != nil {
    wantWaitKill = *cfg.WaitKillable
} else {
    wantWaitKill = ProbeWaitKillable() // legacy fallback for direct/test invocations
}
```

When `AGENTSH_SECCOMP_CONFIG` is unset (defaults path in `loadConfig`, used by some tests), `cfg.WaitKillable` is nil and the legacy uname-based probe is used. The new behavioral probe runs in the server process only; the wrapper never probes.

### 4. Diagnosability

Five log lines, all named consistently:

**Boot, behavioral-probe path:**

```
seccomp: wait_killable behavioral probe starting iterations=5 timeout_per_iter_ms=1000
seccomp: wait_killable iteration iteration=1 result=pass duration_ms=42
seccomp: wait_killable iteration iteration=2 result=killed signal=9 duration_ms=83
seccomp: wait_killable decision value=false source=behavioral_probe reason="iteration 2 killed by signal" total_duration_ms=125
```

**Boot, probe-skipped path** (one line, no iterations):

```
seccomp: wait_killable decision value=true  source=config
seccomp: wait_killable decision value=false source=kernel_unsupported
seccomp: wait_killable decision value=true  source=filter_composition_safe
```

**Per-exec, in the existing `seccomp: filter loaded` line** (`seccomp_linux.go:500`), add `wait_killable_source`:

```
seccomp: filter loaded fd=4 wait_killable=true wait_killable_source=behavioral_probe kernel_probe_supports=true libseccomp_runtime=2.5.3
```

An operator triaging a kill incident greps one line to see the *source* of the decision on that exec.

## Performance

| Phase | Cost |
|---|---|
| Server boot, `WaitKillable` set in config | 0 (probe skipped) |
| Server boot, filter composition safe | 0 (probe skipped) |
| Server boot, kernel <6 | 0 (probe skipped, ProbeWaitKillable is a fast uname call) |
| Server boot, probe runs (5 iters, healthy kernel) | ~100–350 ms one-time |
| Server boot, probe runs (5 iters, broken kernel, short-circuit on iter 1–2) | ~20–150 ms one-time |
| Per wrapped exec | Faster than today: removes the per-exec `unix.Uname()` call in the wrapper |

Worst-case bound: `iterations × per-iteration timeout` = 5 s on a pathologically hung kernel.

## Testing

Six test surfaces, all gated correctly for platform:

1. **Decision-logic unit test** (`internal/api/wait_killable_decision_test.go`): table-driven over the seven branches of the startup switch. Pure logic; runs on all platforms. Inject `ProbeWaitKillable`, `filterCompositionCouldTriggerBug`, and the behavioral probe via a small interface.
2. **Composition-heuristic unit test**: matrix covering `unix_socket.enabled`, `file_monitor.enabled`, `enforce_without_fuse`, explicit `intercept_metadata`. Catches the bisection-misleading row from the issue.
3. **JSON plumbing round-trip tests**: extend `internal/api/seccomp_wrapper_test.go` and `cmd/agentsh-unixwrap/config_test.go` to assert `*bool` survives marshal/unmarshal for `nil` / `&true` / `&false`.
4. **`InstallFilterWithConfig` override test** (`internal/netmonitor/unix/seccomp_linux_test.go`): reuse the existing `loadFilterSyscall` injection seam to verify the `WAIT_KILLABLE_RECV` bit on the syscall flags arg for each combination of `cfg.WaitKillable` and host `ProbeWaitKillable()`.
5. **Probe tests** (`internal/netmonitor/unix/wait_killable_probe_linux_test.go`):
   - **5a (mocked iteration runner):** inject the per-iteration runner as a function; verify all-pass → true, first-fail → false (short-circuit), all-error → error.
   - **5b (real iteration, Linux only):** run probe with iterations=2 on stock CI kernel; assert `(true, nil)` and duration < 2 s. Second test: force the iteration child to `kill(getpid(), SIGKILL)` right after notify-fd handoff to verify the "saw a death" path returns `(false, nil)`. Skip when `/bin/true` missing.
6. **Sigurg-probe test extension** (`internal/netmonitor/unix/sigurg_probe_test.go`): add an assertion that when `AGENTSH_SECCOMP_CONFIG` carries `"wait_killable": false`, the loaded-filter log line emits `wait_killable=false` and `wait_killable_source=config`. Proves the operator override flows end-to-end.

**Out of scope**: simulating the exe.dev-style broken kernel in CI. We don't have it; the probe is the production safety net. If we ever obtain a reproducible image, we add a CI lane in a follow-up.

## Operator UX

| Situation | Operator action |
|---|---|
| Stock kernel, no quirk | None. Probe runs ~300 ms at boot, decides `true`. |
| exe.dev-style broken kernel | None. Probe catches it, decides `false`, logs reason. |
| Operator knows their kernel is fine, wants faster boot | `sandbox.seccomp.wait_killable: true` → probe skipped. |
| Operator on a new broken kernel where probe got fooled | Greps log for `wait_killable_source`, sets `sandbox.seccomp.wait_killable: false`. |
| Test environment with synthetic kernel | Set explicitly either way; never relies on the probe. |

## Open questions / follow-ups

- **Disk-cached probe result**: rejected for v1. Re-probe each boot to handle kernel upgrades, container image swaps, live patches. If boot latency becomes a hot issue, the explicit `wait_killable: true` knob is the operator's escape hatch.
- **Per-invocation adaptive retry** (option B from brainstorming): not in v1. Added later only if we discover a kernel where the boot probe is insufficient — e.g., where the bug is so non-deterministic that 10 iterations still get fooled. Not over-engineered preemptively.
- **CI lane on a reproducer image**: separate follow-up issue if we obtain one (Docker, AMI, etc.).
- **Telemetry on decision source**: today only logged. If we later add server-emitted metrics, `wait_killable_source` is a useful label for tracking how many fleets land in each branch.
