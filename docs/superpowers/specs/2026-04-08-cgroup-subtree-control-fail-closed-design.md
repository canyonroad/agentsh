# Cgroup v2 Resource Limits — Probe, Fallback, and Fail-Closed

**Date:** 2026-04-08
**Status:** Draft
**Issue:** [#197](https://github.com/erans/agentsh/issues/197) — Resource limits silently unenforced when parent cgroup's `subtree_control` is empty
**Scope:** Linux native platform only. Lima and WSL2 share the same silent-failure pattern but are out of scope (follow-up issue).

## Problem

Per-command resource limits (`memory.max`, `pids.max`, `cpu.max`) configured in policy are silently not enforced when agentsh runs inside a cgroup whose parent has an empty `cgroup.subtree_control`. On Freestyle VMs this is the default — systemd places the agentsh server under `/system.slice/freestyle-supervisor.service/`, which delegates no controllers to children. Sub-cgroups `mkdir` successfully but contain no controller files, so subsequent writes to `memory.max` and friends fail because the target file does not exist; the kernel surfaces this as `permission denied` to the writer. agentsh currently reports the failure verbatim even though the process has root and the real cause is that the parent never delegated controllers to its children.

Two independent defects combine to produce the silent-failure behaviour:

1. **`enableControllers()` in `internal/limits/cgroupv2_linux.go:171-185` silently swallows per-controller write errors** (`continue` on error) and returns `nil`. The caller believes controllers were enabled; they weren't.
2. **The capability probe at `internal/capabilities/check_cgroups_linux.go:13-27` only tests read access** to `/sys/fs/cgroup`, never write access to `subtree_control` or the ability to create a functional sub-cgroup. `agentsh detect` therefore reports cgroup v2 as "present" on hosts where enforcement is impossible.

The result: commands run with limits set in policy but no kernel-level enforcement, and the operator has no signal that anything is wrong. Only the VM-level safety net (OOM kill, timeout) remains.

## Goals

1. Replace silent failure with a deterministic probe → mode → fail-closed flow.
2. Detect the three real operating states on a Linux host: nested enforcement works, top-level fallback is needed, enforcement is unavailable.
3. Refuse per-command exec when policy configures limits that can't be enforced. No per-command work continues under the false assumption that limits are in place.
4. Emit structured events and `agentsh detect` output that name the actual cause (`subtree_control` delegation, missing root controller) so operators can diagnose and fix it.
5. Remain a good citizen of systemd's cgroup tree on correctly configured hosts (`Delegate=yes`).

## Non-Goals

- Fixing Lima and WSL2. They have the same silent-swallow pattern in `internal/platform/lima/resources.go:100-103` and `internal/platform/wsl2/resources.go:100-103`. A follow-up issue will track the port of this design to those platforms.
- Supporting cgroup v1. agentsh already requires cgroup v2 (`DetectCgroupV2()` at `internal/limits/cgroupv2_linux.go:28-31`).
- Supporting the `io` controller as a required controller. Many kernels omit `io` from the root cgroup by default; requiring it would break clean installs. `io` is probed separately and treated as best-effort (see § Probe Algorithm).

## Design

### Three operating modes

The probe runs once at startup and picks one of three modes:

- **`nested`** — agentsh's own cgroup has `cpu memory pids` in its `subtree_control`, either because the init system delegated them (systemd `Delegate=yes`) or because the probe successfully wrote them. Per-command sub-cgroups are created under agentsh's own cgroup as today. This is the well-behaved systemd path.

- **`top-level`** — the nested path could not be reached (parent `subtree_control` is empty and the probe's enable write failed — typically `EBUSY` from cgroup v2's "no internal processes" rule, or `EACCES` from a restricted mount). Per-command sub-cgroups are created under a stable `/sys/fs/cgroup/agentsh.slice/` parent. This is the Freestyle path.

- **`unavailable`** — neither path is reachable (root `cgroup.controllers` lacks a required controller, or root `subtree_control` is not writable, or `agentsh.slice` can't be created with controller files). The mode carries a structured reason. Commands whose policy specifies any limit are refused per-exec.

The mode is stored immutably on a new `CgroupManager` for the lifetime of the process. No re-probing per command; if something changes mid-run, the operator restarts agentsh.

### Why "nested first"

On a well-configured systemd host with `Delegate=yes`, agentsh's own cgroup already has controllers enabled and the nested path works at zero cost (one `subtree_control` read). On a host without delegation (Freestyle, bare systemd services without `Delegate=yes`), the nested path's enable-write typically fails with `EBUSY` because cgroup v2 forbids enabling domain controllers in a cgroup that holds internal processes. One failed write is negligible; the fallback to top-level follows immediately.

Writing `/sys/fs/cgroup/agentsh.slice/` directly (skipping the nested path) would be simpler, but on a systemd host it bypasses the init system's cgroup tree and risks conflicting with unit lifecycle management. Preferring nested when it works keeps us inside the delegated subtree on hosts that set up delegation correctly.

### Probe algorithm

Required controllers: `cpu`, `memory`, `pids`. The `io` controller is probed separately and tracked as a best-effort flag.

```
probe():
  1. Discover agentsh's own cgroup dir via /proc/self/cgroup → own

  2. Read own/cgroup.controllers → availableInOwn
     If {cpu, memory, pids} ⊄ availableInOwn → jump to step 5 (try top-level)

  3. Read own/cgroup.subtree_control → delegatedByOwn
     If {cpu, memory, pids} ⊆ delegatedByOwn
        → return (nested, reason="already delegated",
                  io_available=io ∈ delegatedByOwn)

  4. Attempt enable: write "+cpu +memory +pids" to own/cgroup.subtree_control
     - success → re-read subtree_control to confirm;
                 return (nested, reason="enabled by probe",
                         io_available=<probe io separately>)
     - EBUSY  → jump to step 5, record reason prefix
                "parent cgroup has internal processes (EBUSY)"
     - EACCES → jump to step 5, record reason prefix
                "parent cgroup subtree_control not writable (EACCES)"
     - other  → jump to step 5, record reason prefix "enable failed: <err>"

  5. Try top-level:
     a. Read /sys/fs/cgroup/cgroup.controllers → availableInRoot
        If {cpu, memory, pids} ⊄ availableInRoot
           → return (unavailable,
                     reason="root cgroup missing controller <X>")

     b. Read /sys/fs/cgroup/cgroup.subtree_control → delegatedByRoot
        If {cpu, memory, pids} ⊄ delegatedByRoot
           - write "+cpu +memory +pids" to root subtree_control
           - on failure: return (unavailable,
                                  reason="root subtree_control not writable: <err>")

     c. Mkdir /sys/fs/cgroup/agentsh.slice/ (idempotent: ignore EEXIST)

     d. Verify /sys/fs/cgroup/agentsh.slice/memory.max exists
        (confirms controller files were populated after mkdir)
        If missing → return (unavailable,
                             reason="agentsh.slice missing controller files after mkdir")

     e. Reap orphans: list children of agentsh.slice; for each child,
        read cgroup.events → if "populated 0", rmdir child.
        Errors on individual reap attempts are logged but do not fail the probe.
        Emit cgroup_orphans_reaped event if count > 0.

     f. return (top-level, reason="using /sys/fs/cgroup/agentsh.slice",
                io_available=io ∈ delegatedByRoot)
```

All filesystem operations go through a narrow `cgroupFS` interface (see § Boundaries) so the probe is unit-testable with an in-memory fake.

### Behaviour per mode at exec time

| Mode | Policy has limits | Behaviour |
|---|---|---|
| `nested` | any | Create sub-cgroup under agentsh's own cgroup, write non-zero limits, attach PID. Same per-write logic as today. |
| `top-level` | any | Create sub-cgroup under `/sys/fs/cgroup/agentsh.slice/`, write non-zero limits, attach PID. |
| `unavailable` | no limits | Allow the command. No cgroup is created. |
| `unavailable` | any limit > 0 | **Refuse** the command. Return `CgroupUnavailableError`; emit `cgroup_unavailable_refusal` event. |

The refusal is per-exec rather than per-startup. Startup always succeeds (modulo unrelated failures). This allows policies that mix limit-bearing and limit-free commands to continue running the latter even on hosts where enforcement is unavailable.

### Boundaries and file layout

- **`internal/limits/cgroupv2_linux.go`**
  - New `CgroupMode` enum: `ModeNested`, `ModeTopLevel`, `ModeUnavailable`.
  - New `CgroupManager` struct holding mode, reason, own-cgroup dir, slice dir (if top-level), io-available flag, and a `cgroupFS` handle. Construct via `NewCgroupManager(ctx, fs cgroupFS) (*CgroupManager, error)`.
  - `CgroupManager.Apply(name, pid, lim)` — the primary entry point. Routes to nested or top-level parent internally based on mode; returns `CgroupUnavailableError` when mode is unavailable and `lim` is non-empty. Callers no longer pass a parent directory; the manager owns that decision.
  - New `cgroupFS` interface (unexported): `ReadFile`, `WriteFile`, `Mkdir`, `Remove`, `Stat`, `ReadDir`, `OpenFile`. Real implementation `osCgroupFS` hits `/sys/fs/cgroup`; test implementation `fakeCgroupFS` is in-memory.
  - `enableControllers()` (line 171) is rewritten to return a structured `EnableControllersError{ParentDir, Controller, Err}` wrapping the underlying errno. No more `continue` on error.
  - The package-level `ApplyCgroupV2` function (line 55) is removed. Its single caller in `internal/api/cgroups.go` migrates to `CgroupManager.Apply`. The existing `TestApplyCgroupV2_CreatesAndCleansUp` test migrates alongside it (renamed to `TestManagerApply_CreatesAndCleansUp`).

- **`internal/api/cgroups.go`**
  - `applyCgroupV2()` (lines 21-61) is changed to consult a `*CgroupManager` held on the server instead of calling the package-level function directly. When the manager returns `CgroupUnavailableError`, the handler emits `cgroup_unavailable_refusal` and returns an error to the exec caller.
  - The server's initialization (wherever `api.Server` is constructed) builds and stores the manager. A single probe per process.

- **`internal/capabilities/check_cgroups_linux.go`**
  - `probeCgroupsV2()` (lines 13-27) is extended to call the same `CgroupManager` probe (or an equivalent thin wrapper) and populates a new `CgroupMode`, `CgroupReason`, `CgroupSliceDir`, and `IOAvailable` field in the capability report.
  - `agentsh detect` output gains the new structured block (see § Observability).

- **`internal/limits/cgroupv2_linux_test.go`**
  - Extended with the unit tests listed in § Testing. Uses `fakeCgroupFS`.

- **`internal/limits/cgroupv2_integration_test.go`** (new file, build tag `//go:build linux && cgroup_integration`)
  - Three integration tests that hit the real kernel; invoked via `go test -tags cgroup_integration ./internal/limits/...` on a privileged host. Not part of default `go test ./...`.

### Error handling

**`enableControllers()` fix** — the core silent-failure bug:

```go
// Before
for _, c := range ctrls {
    if _, err := f.WriteString("+" + c); err != nil {
        continue
    }
}
return nil

// After
for _, c := range ctrls {
    if _, err := f.WriteString("+" + c); err != nil {
        return &EnableControllersError{
            ParentDir:  parentDir,
            Controller: c,
            Err:        err,
        }
    }
}
return nil
```

The probe inspects the wrapped error with `errors.Is(err, syscall.EBUSY)` etc. to record a specific reason string in the mode.

**New structured error types:**

```go
// EnableControllersError is returned when writing to subtree_control fails.
// Wraps the underlying errno so callers can discriminate EBUSY from EACCES.
type EnableControllersError struct {
    ParentDir  string
    Controller string
    Err        error
}

func (e *EnableControllersError) Error() string {
    return fmt.Sprintf("enable controller %q in %s: %v",
        e.Controller, e.ParentDir, e.Err)
}

func (e *EnableControllersError) Unwrap() error { return e.Err }

// CgroupUnavailableError is returned by CgroupManager.Apply when the manager's
// mode is ModeUnavailable and the caller's policy requires non-empty limits.
type CgroupUnavailableError struct {
    Reason string          // human-readable probe reason
    Limits CgroupV2Limits  // what the caller requested
}

func (e *CgroupUnavailableError) Error() string {
    return fmt.Sprintf(
        "cgroup enforcement unavailable (%s); policy requires %s — refusing command",
        e.Reason, e.Limits.Summary())
}
```

**Error message hygiene:**
- `"set memory.max: <err>"` (line 84) and the `pids.max`/`cpu.max` siblings become `"write memory.max (mode=%s, dir=%s): %w"` — naming the mode and directory makes the actual cause diagnosable from logs.
- `applyCgroupV2()` in `internal/api/cgroups.go` distinguishes two failure classes: `cgroup_apply_failed` for unexpected post-probe kernel errors (belt and braces; shouldn't happen), and `cgroup_unavailable_refusal` for the fail-closed path (not an error, a policy decision).

### Observability

**New and changed audit events:**

| Event | When | Fields |
|---|---|---|
| `cgroup_mode` | Startup, once | `mode`, `reason`, `own_cgroup`, `slice_dir` (if top-level), `io_available` |
| `cgroup_orphans_reaped` | Startup, top-level mode, if any orphans removed | `count`, `names[]` |
| `cgroup_unavailable_refusal` | Per-exec when mode is unavailable and limits are set | `session_id`, `command`, `reason`, `limits` |
| `cgroup_apply_failed` | Per-exec, unexpected kernel error post-probe | `session_id`, `err` (kept as today for defence in depth) |

**`agentsh detect` output** — the capability probe currently reports a simple `cgroupsV2: present/absent` line. It gains a structured block:

```
cgroup v2:
  mode:           top-level
  reason:         parent cgroup has internal processes (EBUSY); using agentsh.slice
  own_cgroup:     /system.slice/freestyle-supervisor.service
  slice_dir:      /sys/fs/cgroup/agentsh.slice
  controllers:    cpu memory pids (io: unavailable)
```

On a healthy systemd host with `Delegate=yes`:

```
cgroup v2:
  mode:           nested
  reason:         already delegated
  own_cgroup:     /system.slice/agentsh.service
  controllers:    cpu memory pids io
```

On a host where enforcement is impossible:

```
cgroup v2:
  mode:           unavailable
  reason:         root cgroup missing memory controller
  own_cgroup:     /
  controllers:    cpu pids
```

### Lifecycle of `/sys/fs/cgroup/agentsh.slice/`

In top-level mode, the slice directory is treated as a **stable shared parent** that survives across agentsh restarts:

- **Creation:** eager at startup, during the probe (step 5c). Idempotent `mkdir` — ignore `EEXIST`.
- **Orphan reaping:** at startup, before any commands run, list children of the slice and `rmdir` any whose `cgroup.events` reports `populated 0`. A populated orphan (stuck process) is left in place; reap failures on individual children do not fail the probe.
- **Per-command children:** created lazily under the slice as commands exec. Existing `CgroupV2.Close()` logic (lines 106-126) handles per-command cleanup unchanged — it waits for unpopulation then `rmdir`s the child.
- **Clean shutdown:** agentsh makes a best-effort pass over unpopulated children at shutdown, but the slice directory itself is **not** removed. Keeping the directory stable means the next restart finds it and can reap orphans without racing a re-creation.
- **Crash recovery:** orphans from a crashed agentsh linger under `agentsh.slice/` until the next startup's reap pass removes them. This is the motivation for the startup reap: without it, crashed commands would leak directories indefinitely.

### Policy behaviour

No changes to the policy schema. The `ResourceLimits` struct at `internal/policy/model.go:184-195` and the runtime `Limits` struct at `internal/policy/engine.go:56-64` remain as-is. The fail-closed decision is made at enforcement time by `CgroupManager.Apply`, not at policy evaluation time.

No opt-out flag for "run without enforcement". An operator who wants to run in an environment where enforcement is impossible should remove the limit fields from the policy explicitly. A silent "best effort" mode is exactly the footgun this change is fixing.

## Behaviour Change and Release Notes

**This is a breaking change for any host currently hitting silent-failure.** Before: commands with limits in policy ran with no kernel enforcement; the operator had no signal. After: those same commands now either (a) run under the top-level `agentsh.slice` fallback (Freestyle and similar — the common case), or (b) are refused at exec time with a clear error (hosts where no fallback is reachable).

Release notes must include:
- A summary of the change and the security rationale.
- The list of new events (`cgroup_mode`, `cgroup_orphans_reaped`, `cgroup_unavailable_refusal`).
- Guidance for operators: run `agentsh detect` after upgrade to see the active mode; if `mode: unavailable`, check the reason field and either fix the host's cgroup configuration or remove limits from policy.
- A pointer to the follow-up issue for Lima and WSL2.

## Testing

### Unit tests — `internal/limits/cgroupv2_linux_test.go`

Fast, hermetic, backed by `fakeCgroupFS`. Covers the probe decision tree:

- `TestProbe_NestedAlreadyDelegated` — `own/subtree_control` already has `cpu memory pids` → mode `nested`, reason `"already delegated"`.
- `TestProbe_NestedEnableSucceeds` — `own/subtree_control` is empty, write succeeds → mode `nested`, reason `"enabled by probe"`.
- `TestProbe_EnableEBUSY_FallbackToTopLevel` — enable write returns `EBUSY`, root cgroup has required controllers → mode `top-level`, reason names EBUSY.
- `TestProbe_EnableEACCES_FallbackToTopLevel` — same shape but `EACCES`.
- `TestProbe_TopLevelMissingMemory` — root `cgroup.controllers` lacks `memory` → mode `unavailable`, reason names the missing controller.
- `TestProbe_TopLevelSubtreeControlNotWritable` — root `subtree_control` needs writing and the write fails → mode `unavailable`, reason is the wrapped error.
- `TestProbe_TopLevelMkdirMissingControllerFiles` — `mkdir` succeeds but `agentsh.slice/memory.max` is missing → mode `unavailable`.
- `TestProbe_TopLevelOrphanReap` — pre-seed `agentsh.slice` with unpopulated children → orphans are removed; `cgroup_orphans_reaped` event recorded.
- `TestProbe_TopLevelStuckOrphan` — one child reports `populated 1` → probe leaves it in place, does not fail.
- `TestProbe_IOControllerUnavailable` — required controllers present, `io` absent → probe succeeds, `io_available=false`.
- `TestApply_ModeNested_WritesLimits` — mode nested, limits set → writes to correct parent.
- `TestApply_ModeTopLevel_WritesLimits` — mode top-level, limits set → writes under `agentsh.slice`.
- `TestApply_ModeUnavailable_NoLimits_Allows` — mode unavailable, empty limits → no error, no cgroup created.
- `TestApply_ModeUnavailable_WithLimits_Refuses` — mode unavailable, non-empty limits → returns `CgroupUnavailableError`.
- `TestEnableControllers_EBUSYReturned` — confirms the bug fix: `enableControllers` no longer swallows `EBUSY`, returns a wrapped `EnableControllersError`.

### Integration tests — `internal/limits/cgroupv2_integration_test.go` (new)

Build tag `//go:build linux && cgroup_integration`. Not part of default `go test ./...`; run on a privileged Linux host via `go test -tags cgroup_integration ./internal/limits/...`.

- `TestIntegration_ProbeReal` — runs the probe against the real `/sys/fs/cgroup` and asserts it returns a non-error result in one of the three modes. Does not assert which mode — depends on the CI host configuration.
- `TestIntegration_TopLevelApplyAndEnforce` — if probe returns top-level, create a child cgroup with `memory.max=8MB`, attach the test process, verify `memory.max` reads back as `8388608`, then clean up.
- `TestIntegration_OrphanReap` — pre-create a stale unpopulated child under `agentsh.slice`, run the probe, verify the orphan is gone.

### Manual verification on Freestyle

Out of band, using the reporter's probe script at <https://github.com/canyonroad/agentsh-freestyle> (`src/diag-kernel.sh`, sections 08-10, and `npm run diag:kernel`). Documented as a release checklist item, not automated in this repo's CI.

### Explicitly not tested

- **Lima and WSL2 platform behaviour** — out of scope; tracked in follow-up.
- **Race between probe result and actual apply** — impossible under this design because the probe's enable-write is the same write that would have failed at apply time. If the probe selects nested mode, apply time will not re-fail on `subtree_control`.

## Open Questions

None at design time. All four brainstorming questions were resolved:
1. Fix strategy → auto-detect with populate-first (nested → top-level → unavailable).
2. Fail-closed policy → per-command refusal; no opt-out flag.
3. Platform scope → Linux native only; Lima/WSL2 follow-up.
4. Slice lifecycle → stable `agentsh.slice`, reap orphans at startup.

## Follow-Ups (not in this change)

1. **Lima and WSL2 parity.** Port the probe / fail-closed contract to `internal/platform/lima/resources.go` and `internal/platform/wsl2/resources.go`. The current code at lines 100-103 in both files silently swallows `subtree_control` errors with `2>/dev/null || true`. Same class of bug; different execution model (shell scripts inside the guest). File as a new issue referencing this design.
2. **Shared probe across CLI and daemon.** Currently the daemon probes at server startup and `agentsh detect` probes separately. If these diverge in the future (e.g. daemon caches mode on disk for faster `detect`), reconcile them behind a single entry point.
