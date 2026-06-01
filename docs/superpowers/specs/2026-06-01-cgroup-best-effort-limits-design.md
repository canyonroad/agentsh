# Design: Graceful degradation for unenforceable per-command cgroup limits (#411)

**Date:** 2026-06-01
**Issue:** #411
**Status:** Proposed

## Problem

On hosts where agentsh's cgroup is nested under another service's slice and
`cgroup.subtree_control` is not writable (e.g. Freestyle Firecracker VMs),
**every command through the shell shim aborts with `exit 126`** /
`server rejected wrap setup`.

Root cause chain:

1. **The startup probe is over-optimistic.** `tryTopLevel`
   (`internal/limits/cgroupv2_probe.go:333`) uses `memory.max` *existence*
   (`fs.Stat`) as its canary. The slice dir exists with controller files
   present, so the probe returns `ModeTopLevel` — even though the file is not
   actually **writable**.
2. **The per-command write EPERMs and the error is unclassified.**
   `CgroupManager.Apply` (`internal/limits/cgroupv2_manager.go:97`) does
   `mkdir` (succeeds) then `WriteFile(memory.max)` → EPERM, returning a plain
   `fmt.Errorf("write memory.max…")`. In `applyCgroupV2`
   (`internal/api/cgroups.go:112`) that plain error falls through the
   `default:` arm (not the deliberate typed fail-closed paths) and returns
   `nil, err`.
3. **It is on the before-ACK critical path.** `wrapNeedsCgroupBeforeAck`
   returns true (`cgroups.enabled`), so `wrapCgroupSetupForNotifyHook` runs
   before the notify-fd ACK (`internal/api/wrap.go:840`). Any error there
   aborts the handshake → notify-status `false` → shim fail-closes → `exit
   126` on *every* command.

The limits were never enforceable on such a host anyway — this is a documented
nested-cgroup gap that `agentsh detect` already warns about. The current
failure is therefore neither a useful security refusal nor a graceful skip; it
is an unhandled error that happens to abort the command with a cryptic code.

### Design tension

agentsh has a **deliberate fail-closed stance**: if a command requests a
resource limit that cannot be enforced, refuse rather than run pretending to be
sandboxed (the typed `CgroupUnavailableError` /
`CgroupResourceLimitsUnavailableError`). The issue asks for the opposite —
degrade and run. eBPF already models this graduation with `Enabled` /
`Enforce` / `Required`.

Critically, cgroup **resource limits (mem/cpu/pids) are QoS / DoS-protection,
not a confinement boundary** — exceeding a memory cap does not *escape* the
sandbox. The confinement boundaries are seccomp and eBPF egress, the latter of
which rides on the same cgroup and must keep failing closed.

## Approach

Two robustness fixes ship unconditionally (they are simply *correct*); one
opt-in policy knob enables degradation; one independent fix addresses the
stderr-pollution side observation.

### 1. Probe writability test (unconditional correctness fix)

`internal/limits/cgroupv2_probe.go`

After confirming `memory.max` exists in `tryTopLevel`, actually **test that a
child cgroup's limit file is writable**: `mkdir` a throwaway probe child under
the slice, attempt `WriteFile(memory.max, "max")` (a safe no-op value the
kernel always accepts), then remove the child.

- If the probe child `mkdir` fails → `ModeUnavailable` (cannot create children
  at all).
- If the limit write fails with EPERM/EACCES → reuse the existing
  attach-feasibility logic (`maybeUpgradeToAttachOnly` /
  `probeAttachOnlyFeasibility`) to land on `ModeAttachOnly` when pid-attach is
  feasible, otherwise `ModeUnavailable`. The reason string records "memory.max
  not writable in child cgroup".
- If the write succeeds → `ModeTopLevel` as today (remove the probe child).

Effect: `agentsh detect` now reports the truth on Freestyle-style hosts, and
the per-command path naturally routes through the *typed*
`CgroupResourceLimitsUnavailableError` (the `ModeAttachOnly` arm in `Apply`)
instead of the over-optimistic `ModeTopLevel` write-and-fail path.

### 2. Classify runtime `.max` write EPERM as typed error (unconditional, defense-in-depth)

`internal/limits/cgroupv2_manager.go`

The probe is a point-in-time snapshot; a host can change after startup. As a
backstop, when a `.max` write in `Apply` fails with EPERM/EACCES, wrap it in
`CgroupResourceLimitsUnavailableError` rather than a plain `fmt.Errorf`. This
guarantees the failure is *legible* (a refusal/degrade event) regardless of
whether the probe caught it, and never again falls through the generic
`default:` abort arm. Because the `ModeTopLevel` arm `mkdir`s the child cgroup
*before* attempting the write, this path must also `Remove` the just-created
(empty) child dir before returning, so a degraded host does not accumulate
orphan cgroups between the per-command failure and the next startup reap.

### 3. Opt-in best-effort policy knob (the behavior change)

`internal/config/config.go` — add to `SandboxCgroupsConfig`:

```go
type SandboxCgroupsConfig struct {
    Enabled    bool   `yaml:"enabled"`
    BasePath   string `yaml:"base_path"`
    BestEffort bool   `yaml:"best_effort"` // NEW: degrade unenforceable resource limits instead of failing closed
}
```

`BestEffort` defaults to `false` → **current fail-closed behavior is
preserved** (zero-value additive). Chosen over a `Required *bool` pointer for
self-documenting additivity; the eBPF graduated model is the conceptual
precedent.

In `applyCgroupV2` (`internal/api/cgroups.go`), when `Apply` returns
`CgroupResourceLimitsUnavailableError` **or** `CgroupUnavailableError`:

- **If** `cfg.Sandbox.Cgroups.BestEffort` is true **and** no eBPF enforcement
  is in play (`!ebpfEnabled && !ebpfEnforce && !ebpfRequired`): log a warning,
  emit a new `cgroup_limits_degraded` event (carrying the reason + requested
  limits), and **return a no-op cleanup with nil error** so the wrap handshake
  proceeds and the command runs *without* the limit.
- **Else**: behave exactly as today (emit the refusal event, return the error,
  fail closed).

The eBPF gate is essential: eBPF egress enforcement depends on the cgroup
existing with the process attached, so when any eBPF flag is set the cgroup
path must still succeed (mkdir + attach do succeed on Freestyle; only the
*limit writes* EPERM — but we keep the strict path here to avoid silently
weakening an egress boundary).

### 4. Sequencing

No structural change to `wrap.go`. The degrade happens inside `applyCgroupV2`,
which now returns a nil error in the best-effort case, so the before-ACK
handshake proceeds naturally. Cgroup **create + attach** stay before the ACK
(eBPF depends on them); only the **resource-limit unenforceability** is
degradable. This satisfies the issue's "ideally don't fail the handshake"
without a risky re-architecture of the critical path.

### 5. Side observation: stderr pollution (independent fix)

`internal/netmonitor/unix/seccomp_linux.go:518`

The per-exec `slog.Info("seccomp: filter loaded", …)` is emitted by the
wrapper process, whose slog output lands on the **wrapped command's stderr**,
corrupting machine-readable stderr streams (notably `agentsh detect --output
json`). Fix: route the wrapper's diagnostic logging off the user-visible
stderr — preferred is to send it through the server-log channel; if no such
channel is reachable from the wrapper, downgrade this line to `slog.Debug`.
Tracked as a separate, lower-priority workstream from the cgroup fix.

## Components & boundaries

| Unit | Change | Depends on |
|------|--------|-----------|
| `cgroupv2_probe.go` | write-test child `memory.max`; honest mode | existing `maybeUpgradeToAttachOnly` |
| `cgroupv2_manager.go` | classify EPERM `.max` write as typed error | error types in `cgroupv2_errors.go` |
| `config.go` | add `BestEffort bool` | — |
| `cgroups.go::applyCgroupV2` | degrade-on-typed-error when `BestEffort && !ebpf*` | config field, typed errors |
| `seccomp_linux.go` | route filter-loaded line off command stderr | — (independent) |

## Error handling

- Unenforceable limits, `BestEffort=false` (default): fail closed, refusal
  event — unchanged guarantee.
- Unenforceable limits, `BestEffort=true`, no eBPF: warn + `cgroup_limits_degraded`
  event + run without limit.
- Unenforceable limits, `BestEffort=true`, eBPF enabled/enforce/required: fail
  closed (egress boundary preserved).
- Unexpected (non-permission) write errors: still fail closed regardless of
  `BestEffort` (only EPERM/EACCES are classified as "unavailable"; other
  errors remain hard failures).

## Testing

- **Probe** (`cgroupv2_probe_test.go`): fake FS where slice `memory.max`
  exists but child `memory.max` write returns EPERM → assert `ModeAttachOnly`
  (or `ModeUnavailable` when attach also fails), not `ModeTopLevel`.
- **Manager** (`cgroupv2_manager_test.go`): EPERM on `.max` write →
  `CgroupResourceLimitsUnavailableError`, not plain error.
- **applyCgroupV2** (api tests): typed error + `BestEffort=true` + no eBPF →
  nil error, no-op cleanup, `cgroup_limits_degraded` emitted; same +
  `BestEffort=false` → error propagated; same + eBPF required → error
  propagated even with `BestEffort=true`.
- **Wrap** (`wrap_linux_test.go`): best-effort degrade path → handshake ACKs
  successfully (no `exit 126`).
- **Cross-compile:** `GOOS=windows go build ./...` (the limits package is
  `//go:build linux`; ensure no Windows breakage).

## Out of scope

- Making nested-cgroup limits actually enforceable (kernel/host limitation).
- Changing the default fail-closed posture for any other sandbox subsystem.
- Reworking the before-ACK handshake architecture.
