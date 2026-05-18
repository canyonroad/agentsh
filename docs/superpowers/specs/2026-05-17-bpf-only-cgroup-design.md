# BPF-only cgroup attach mode

**Status:** Approved, ready for implementation plan.
**Tracking:** [#347](https://github.com/canyonroad/agentsh/issues/347).
**Builds on:** [#346](https://github.com/canyonroad/agentsh/pull/346) (startup WARN + cgroups prerequisite docs), [#344](https://github.com/canyonroad/agentsh/pull/344) (wrap eBPF hardening).

## Problem

eBPF network enforcement is silently unreachable on hosts where `sandbox.cgroups.enabled=true` can't be honored — most importantly, stock Docker containers, where the scope cgroup ships with empty `cgroup.subtree_control` and writes to enable the `memory` controller return ENOTSUP without a host-side `docker.service` `Delegate=memory pids cpu` drop-in.

Today the eBPF cgroup_connect attach is gated behind the full cgroup-v2 resource-limit machinery: the probe (`internal/limits/cgroupv2_probe.go`) tries to enable required controllers in `subtree_control`, and the call sites (`internal/api/wrap.go::wrapNeedsCgroupBeforeAck`, `internal/api/cgroups.go::applyCgroupV2`) only proceed when `cgroups.enabled=true`. PR #346 added a WARN when `ebpf.enabled=true` and `cgroups.enabled=false`, which closed the silent-skip path discovered in #343 but did not actually enable BPF enforcement on such hosts.

The kernel BPF program doesn't need any cgroup controllers enabled. It only needs *a* cgroup with a known ID and the BPF attach capabilities (`CAP_BPF`, `/sys/fs/bpf`, kernel `CONFIG_CGROUP_BPF`). Decoupling the BPF attach path from `cgroups.enabled` makes eBPF enforcement reachable on the Docker hosts that are the dominant agentsh deployment shape, without requiring operators to do host-side systemd surgery.

## Goals

- BPF cgroup_connect attach works on stock Docker without `Delegate=` drop-ins, when the kernel and capabilities permit BPF attach.
- Existing strict `cgroups.enabled=true` semantics are preserved — operators who explicitly assert that cgroups work continue to get hard-fail at startup if the assertion is false.
- Failures in the new path are loud (`WARN` with specific cause) by default and convertible to startup-fatal via the existing `ebpf.required=true` knob.
- `agentsh detect` reports the new partial state explicitly so operators can see what's available without parsing log Detail strings.

## Non-goals

- No change to the kernel BPF program, its embedded `.o` files, or `internal/netmonitor/ebpf/program.go`.
- No new config flags. The activation path is derived from the existing `cgroups.enabled` / `ebpf.{enabled,enforce,required}` settings.
- No real-kernel integration tests for the new mode beyond what the existing `internal/netmonitor/ebpf/integration_test.go` already covers. Probe-level and wrap-path tests with mocked FS prove the wiring.
- No revisit of the `cgroups.enabled=true` + AttachOnly-feasible case — that explicitly remains a hard fail at startup. The operator asked for full cgroups; partial-honor would be a behavior change in the strict direction.

## Architecture

A fourth cgroup mode `ModeAttachOnly` is added to `internal/limits/cgroupv2_probe.go`. The probe gains one outcome: when controller writes to `subtree_control` fail but `mkdir` + writing to `cgroup.procs` succeed under a writable parent, the probe lands on `ModeAttachOnly` instead of `ModeUnavailable`. `CgroupManager.Apply()` learns this mode and returns a path-only handle (mkdir + attach pid, no `.max` writes).

The cgroup manager is constructed whenever `cgroups.enabled=true` **or** any of `ebpf.{enabled,enforce,required}=true`. The gates in `internal/api/wrap.go::wrapNeedsCgroupBeforeAck`, `internal/api/cgroups.go::applyCgroupV2`, and `internal/api/app.go::NewApp` are widened to that predicate.

Strict `cgroups.enabled=true` semantics are preserved by a `permitAttachOnly` input to `ProbeCgroupsV2`. When `cgroups.enabled=true`, the call passes `permitAttachOnly=false` and the probe collapses an AttachOnly-feasible-but-controllers-unenableable host to `ModeUnavailable` (today's behavior). When `cgroups.enabled=false && ebpf.*` is set, the call passes `permitAttachOnly=true` and the probe is allowed to return `ModeAttachOnly`.

`agentsh detect` splits the existing binary `cgroups-v2` check: it keeps its meaning ("resource limits work") and gains a sibling `ebpf_cgroup_attach` ("BPF attach to a session cgroup is reachable"). Each has its own tip ladder.

## Components

### `internal/limits/cgroupv2_probe.go`

Add `ModeAttachOnly` to the `CgroupMode` enum, between `ModeTopLevel` and `ModeUnavailable`.

Extend `ProbeCgroupsV2(ctx, fs, ownHint)` with a `permitAttachOnly bool` parameter. (Or pass a struct of options to avoid signature churn for future inputs; either is fine — the impl plan can decide.) When the existing decision tree would land on `ModeUnavailable`, and `permitAttachOnly` is true, run a new feasibility check:

1. mkdir a probe-test cgroup under own cgroup (or DefaultSliceDir if top-level mkdir-only is reachable but controller-enable failed there too).
2. Write the probe process's pid into `<test>/cgroup.procs`.
3. Write the pid back into the parent's `cgroup.procs` to release the probe-test cgroup.
4. rmdir the probe-test cgroup.

On full success, return `Mode: ModeAttachOnly` with a `Reason` that names the controller-enable failure (e.g., `controllers cpu,memory,pids cannot be enabled in subtree_control: ENOTSUP`). On any step failure (mkdir, attach, rmdir), fall through to `ModeUnavailable` with a reason that names the attach feasibility failure.

`CgroupProbeResult.OwnCgroup` and `CgroupProbeResult.SliceDir` semantics carry forward to `ModeAttachOnly`: child cgroups are created under `OwnCgroup` (or `SliceDir` if the top-level fallback is what made attach-only feasible).

`ProbeCgroupsV2Default(ctx)` (the no-options variant used by capability detection) keeps `permitAttachOnly=true`. The detect output should reflect attach-only availability regardless of operator config — operators may run detect to *decide* whether to set `cgroups.enabled=true` or not.

### `internal/limits/cgroupv2_manager.go`

Extend `Apply(name, pid, lim)` with one branch for `ModeAttachOnly`:

- If `lim.IsEmpty()`: mkdir + attach pid + return `*CgroupV2` handle. Skip all `.max` writes.
- If `!lim.IsEmpty()`: return `*CgroupResourceLimitsUnavailableError` (new error type, structured fields `Reason string, Limits CgroupV2Limits`). Do not create a cgroup.

`CgroupV2.Close()` works identically for AttachOnly cgroups — rmdir the cgroup directory.

New error type `CgroupResourceLimitsUnavailableError` in `internal/limits/cgroupv2_errors.go` parallels the existing `CgroupUnavailableError`. The distinction matters at call sites: `CgroupUnavailableError` means "nothing works"; `CgroupResourceLimitsUnavailableError` means "BPF attach works but you can't set limits."

### `internal/api/app.go`

`NewApp` constructs the cgroup manager when:

```go
needsCgroup := cfg.Sandbox.Cgroups.Enabled ||
    cfg.Sandbox.Network.EBPF.Enabled ||
    cfg.Sandbox.Network.EBPF.Enforce ||
    cfg.Sandbox.Network.EBPF.Required
```

The existing #346 WARN block (currently `(EBPF.Enabled || EBPF.Enforce) && !Cgroups.Enabled` → "ebpf inactive — requires sandbox.cgroups.enabled=true") is removed. It is replaced by a mode-aware log line emitted after the probe completes:

- `Mode in {Nested, TopLevel}` + ebpf configured: no log (success is silent).
- `Mode == ModeAttachOnly` + ebpf configured: `INFO ebpf: attach-only mode active (resource limits unavailable: <controllers>)`.
- `Mode == ModeUnavailable` + ebpf configured + `!ebpf.required`: `WARN ebpf: enforcement configured but unavailable (<cause>; check CAP_BPF and /sys/fs/bpf) ebpf.enabled=<v> ebpf.enforce=<v> cgroups.enabled=<v>`.
- `Mode == ModeUnavailable` + ebpf configured + `ebpf.required`: server startup must abort. `NewApp` today returns only `*App` (no error), so the implementation plan will either change the signature to `(*App, error)` or do startup validation in a sibling function called before `NewApp`. The spec leaves the mechanism open; the contract is that the server must not begin serving requests in this state.

Wording for the WARN follows the structure proposed in Eran's #343 follow-up: the message string carries the action/cause, the structured kv pairs carry observed state.

### `internal/api/wrap.go`

`wrapNeedsCgroupBeforeAck` uses the widened predicate:

```go
if cfg.Sandbox.Cgroups.Enabled ||
   cfg.Sandbox.Network.EBPF.Enabled ||
   cfg.Sandbox.Network.EBPF.Enforce ||
   cfg.Sandbox.Network.EBPF.Required {
    return true
}
// existing per-policy resource-limits check stays
```

`defaultWrapCgroupSetupForNotify` continues to call `applyCgroupV2`. Apply()'s return value is dispatched as follows:

- `*CgroupV2{Path}` (success): proceed with BPF attach.
- `*CgroupResourceLimitsUnavailableError` (AttachOnly + non-empty limits): return the error to abort wrap setup. This is an operator contradiction — they asked for resource limits without `cgroups.enabled=true`. Emitting `EventCgroupUnavailableRefusal` here matches today's behavior for the analogous `*CgroupUnavailableError` path. Note that in the BPF-only common case (no policy resource limits configured), `applyCgroupV2` builds an empty `cgLimits` and the AttachOnly branch returns a path-only handle directly, so this error path is only reached when the operator actually requested limits.
- `*CgroupUnavailableError`: same dispatch as today — emit the refusal event, log per the matrix, return error.

If the BPF attach itself fails post-Apply (e.g., `AttachConnectToCgroup` returns non-nil), the call site consults `cfg.Sandbox.Network.EBPF.Required`: WARN-and-continue if false, return error if true.

### `internal/api/cgroups.go`

`applyCgroupV2` accepts the same widened activation predicate. When `cgroupMgr.Apply()` returns `*CgroupV2` under `ModeAttachOnly`, the existing BPF allowlist population path runs against that cgroup just like today. Resource limit emission events (`EventCgroupUnavailableRefusal`, etc.) keep their semantics: they fire only when the operator requested limits and the manager refused.

### `internal/capabilities/check.go` + `tips.go`

The `cgroups-v2` `realCheckCgroupsV2` is renamed to `cgroups_v2_resource_limits`. `Available = (Mode in {Nested, TopLevel})`. Detail string carries the mode + reason.

A new check `realCheckEBPFCgroupAttach` is added. `Available = (ebpf.CheckSupport().Supported && Mode in {Nested, TopLevel, ModeAttachOnly})`. Detail names which of (a) eBPF kernel support, (b) cgroup attach feasibility is the blocker when not available.

Tips ladder in `tips.go` gains entries for `cgroups_v2_resource_limits` (point operators at the `docker.service` `Delegate=` drop-in) and `ebpf_cgroup_attach` (point operators at `CAP_BPF`, `/sys/fs/bpf`, kernel `CONFIG_CGROUP_BPF`).

Backward-compat shim: the flat capabilities map exposed via `LastCgroupProbe()` continues to carry the probe result. Old consumers reading `cgroups-v2` would not find it — release notes document the key rename.

### `docs/ebpf.md`

The Configuration callout for `sandbox.cgroups.enabled=true` is reworded: "Setting `sandbox.cgroups.enabled=true` enables resource limits (memory, cpu, pids) in addition to BPF attach. Set it only if you also want resource limits — BPF network enforcement works on its own when the cgroup_connect program can attach to a session cgroup."

The "Stock Docker host-side prerequisite" subsection from #346 stays. Its framing changes: the `Delegate=memory pids cpu` drop-in is presented as an opt-in for resource limits, not a prerequisite for BPF enforcement.

## Data flow

### Startup (server boot)

1. `NewApp(cfg, ...)` evaluates `needsCgroup`. If false (no cgroups, no ebpf): skip construction; existing no-cgroup behavior.
2. `NewCgroupManager(ctx, basePath)` is called. The constructor calls `ProbeCgroupsV2(ctx, fs, basePath, permitAttachOnly=!cfg.Sandbox.Cgroups.Enabled)`.
3. Probe runs the decision tree. Returns a `CgroupProbeResult` with `Mode`, `Reason`, and the chosen `OwnCgroup`/`SliceDir`.
4. `NewApp` emits one log line per the matrix in `internal/api/app.go` section. If `Mode == ModeUnavailable && ebpf.required=true`, `NewApp` returns a startup error and the server exits.

### Wrap setup (per `agentsh wrap`)

1. Caller invokes `defaultWrapCgroupSetupForNotify(ctx, app, session, sessionID, wrapperPID)`.
2. Setup calls `applyCgroupV2(ctx, ..., pid=wrapperPID, lim=policyLimits)`.
3. Inside, `cgroupMgr.Apply(name, pid, lim)` runs.
   - In `ModeAttachOnly` with empty `lim`: mkdir + attach pid succeeds; handle returned.
   - In `ModeAttachOnly` with non-empty `lim`: `CgroupResourceLimitsUnavailableError`. Setup checks if limits are zero (BPF-only intent), retries with zero `lim` (or short-circuits the Apply call entirely); the path-only handle is created. Otherwise return error.
   - In `ModeUnavailable`: `CgroupUnavailableError`. Setup logs WARN (soft fail) or returns error (hard fail under `ebpf.required`).
4. With a `CgroupV2` handle in hand, `ebpfAttachConnectToCgroup(handle.Path)` runs.
5. On BPF attach failure: same soft/hard split as probe failure. Setup logs WARN or returns error.
6. On success: `ebpfPopulateAllowlist` + `ebpfStartCollector` run. The wrap-init ACK proceeds; `agentsh-unixwrap` is told it's allowed to exec.

### Per-command exec

Same as today's `applyCgroupV2` call path from `exec_stream.go`. The new mode is transparent to that caller — Apply returns a handle, BPF attach runs against it, allowlist is populated.

## Failure handling matrix

| `cgroups.enabled` | `ebpf.{enabled,enforce}` | `ebpf.required` | Probe Mode | Result |
|---|---|---|---|---|
| true | any | any | Nested / TopLevel | Full cgroups; attach BPF if ebpf set. Unchanged. |
| true | any | any | AttachOnly (filtered out — `permitAttachOnly=false`) | N/A; probe returns Unavailable instead. |
| true | any | any | Unavailable | Hard fail at startup. Unchanged. |
| false | true | false | Nested / TopLevel | BPF attach proceeds; INFO log. |
| false | true | false | AttachOnly | BPF-only mode active; INFO log. |
| false | true | false | Unavailable | WARN; server starts; no enforcement. Soft fail. |
| false | true | true | AttachOnly | BPF-only mode active. |
| false | true | true | Unavailable | Hard fail at startup. |
| false | false | any | any | No cgroups, no BPF. Unchanged. |

Attach-time failures (post-probe — BPF verifier rejects, `CAP_BPF` detected missing at attach, `AttachConnectToCgroup` returns non-nil err) follow the same soft/hard split as probe-time failures. The implementation lives at the call sites (`wrap.go::defaultWrapCgroupSetupForNotify`, `cgroups.go::applyCgroupV2`); both consult `cfg.Sandbox.Network.EBPF.Required` to decide whether to return an error or log and continue.

## Testing

**Probe tests** (`internal/limits/cgroupv2_probe_test.go`).
- AttachOnly is reached when controller-enable fails but mkdir/attach work, given `permitAttachOnly=true`. Assert the probe-test cgroup is created and removed cleanly.
- AttachOnly is filtered to Unavailable when `permitAttachOnly=false`. Same fake FS, different gate.
- Existing Nested / TopLevel / Unavailable tests continue to assert today's behavior.

**Apply tests** (`internal/limits/cgroupv2_manager_test.go`).
- AttachOnly + empty limits: success, handle returned, no `.max` writes.
- AttachOnly + non-empty memory/pids/cpu limits: `CgroupResourceLimitsUnavailableError`, no cgroup created.
- AttachOnly + Close(): cgroup directory removed.

**Wrap-path tests**.
- `cgroups.enabled=false, ebpf.enabled=true, required=false` + AttachOnly: wrap setup succeeds, `ebpfAttachConnectToCgroup` called with the AttachOnly handle's path.
- Same config + Unavailable: wrap setup succeeds (no attach), WARN logged.
- Same config but `required=true` + AttachOnly: setup succeeds.
- Same with `required=true` + Unavailable: setup returns an error.
- `cgroups.enabled=true` + AttachOnly-feasible: unchanged (probe returns Unavailable per `permitAttachOnly=false`); existing hard-fail test stays.

**Exec-path tests** (`internal/api/cgroups_linux_test.go`).
- AttachOnly with `cgroups.enabled=false, ebpf.enabled=true`, policy resource limits zero: `applyCgroupV2` returns a path; `ebpfPopulateAllowlist` runs; cleanup removes the cgroup at command end.

**Capability/detect tests** (`internal/capabilities/check_test.go`).
- `cgroups_v2_resource_limits` ✓ when Mode in {Nested, TopLevel}, ✗ when AttachOnly or Unavailable.
- `ebpf_cgroup_attach` ✓ when eBPF support OK and Mode in {Nested, TopLevel, AttachOnly}, ✗ otherwise.

**TDD discipline.** All new tests are written first (RED), then probe/manager/call-site code added until they pass (GREEN). Existing tests continue to pass throughout — the probe and Apply changes are additive, not modifications of existing modes.

## Migration & compatibility

| Pre-this config | Pre-this behavior | Post-this behavior |
|---|---|---|
| `cgroups.enabled=true, ebpf.enabled=true`, host supports controllers | Full cgroups + BPF | Unchanged |
| `cgroups.enabled=true`, host can't enable controllers | Hard fail at startup | Unchanged — strict assertion honored |
| `cgroups.enabled=false, ebpf.enabled=true`, BPF prereqs met | WARN ("ebpf inactive"), no enforcement | **Behavior change**: BPF-only mode activates, enforcement works. WARN becomes INFO ("attach-only mode active"). |
| `cgroups.enabled=false, ebpf.enabled=true`, BPF prereqs not met | WARN ("ebpf inactive"), no enforcement | Reworded WARN ("ebpf enforcement unavailable: <cause>"), no enforcement |
| `cgroups.enabled=false, ebpf.required=true`, BPF prereqs met | Hard fail at wrap-init time | Succeeds at server startup; wrap-init proceeds. **Failure location moves from wrap-init to startup**. |
| `cgroups.enabled=false, ebpf.required=true`, BPF prereqs not met | Hard fail at wrap-init time | Hard fail at server startup. **Failure location moves from wrap-init to startup**. Earlier failure is preferable: the server refuses to come up rather than starting and breaking the first wrap call. |
| `cgroups.enabled=false, ebpf.enabled=false` | No cgroups, no BPF | Unchanged |

No config schema changes. No new fields, no removed fields, no semantic flips. The detect output's capability key set changes (`cgroups-v2` → `cgroups_v2_resource_limits` + `ebpf_cgroup_attach`); release notes will call this out. `agentsh detect` is a diagnostic tool, not a stable API.

## Open work post-implementation

- Real-kernel integration test for AttachOnly mode (out of scope for this spec; the probe-level and wrap-path mocked tests prove the wiring).
- Operator documentation page collecting Docker prerequisites in one place — partly handled by `docs/ebpf.md` updates; a dedicated "agentsh on Docker" page would be a natural follow-up.
