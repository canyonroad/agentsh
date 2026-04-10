# Cgroup Auto-Leaf-Move and Legacy Cleanup

**Date:** 2026-04-10
**Status:** Draft
**Motivation:** User feedback that cgroup setup doesn't work out-of-the-box under systemd. The process's own cgroup contains internal processes, causing EBUSY when enabling subtree_control. Additionally, deprecated cgroup code paths create confusion about which path honors config.

## Problem

Under systemd, agentsh's own cgroup (e.g. `/sys/fs/cgroup/system.slice/agentsh.service`) contains the agentsh process. The cgroup v2 no-internal-processes rule prevents enabling `subtree_control` when a cgroup has both processes and child cgroups that need controllers. The current probe detects EBUSY and falls through to top-level mode (`/sys/fs/cgroup/agentsh.slice`), which requires root-level cgroup access and prompted users to create workarounds (`base_path` + `ExecStartPre`).

Separately, deprecated cgroup code paths (`ApplyCgroupV2`, `LinuxLimiter`, `platform/linux/ResourceLimiter`) ignore the config's `BasePath` and silently discard `enableControllers` errors, creating confusion.

## Solution

Two changes:

1. **Auto-leaf-move** — when the probe detects EBUSY on the own cgroup, move the agentsh process into a `leaf` child cgroup, then retry enabling controllers on the parent. This is the standard systemd pattern for processes that need to manage child cgroups.

2. **Legacy cleanup** — remove all deprecated cgroup code paths so `CgroupManager` is the single source of truth.

## Design

### 1. Auto-Leaf-Move in the Probe

Modify `ProbeCgroupsV2` in `internal/limits/cgroupv2_probe.go`. Insert a new step between the current step 4 (enable fails) and step 5 (try top-level). The step triggers only on EBUSY, not on EACCES/EPERM (permission issues that leaf-move won't fix).

**New probe flow:**

```
1. Resolve own cgroup (ownHint or /proc/self/cgroup)
2. Check own cgroup has required controllers → if not, try top-level
3. Check subtree_control already delegates → if yes, return ModeNested
4. Try enableControllersFS on own → if success, return ModeNested
4b. If EBUSY specifically:
    a. mkdir own/leaf (0755)
    b. Write own PID to own/leaf/cgroup.procs (moves process out of own)
    c. Retry enableControllersFS on own
    d. If success → return ModeNested (Reason: "leaf-moved; enabled by probe", LeafMoved: true)
    e. If retry fails → fall through to tryTopLevel (leaf stays, harmless)
5. On other failures (EACCES, EPERM, etc) → fall through to tryTopLevel as before
```

**Implementation details:**

- The child cgroup is named `leaf` — fixed name, predictable, easy to detect on restart.
- Created via the `cgroupFS` interface so it's fully testable with `fakeCgroupFS`.
- If `own/leaf` already exists (restart scenario), `mkdir` with EEXIST is tolerated.
- Writing to `cgroup.procs` moves all threads of the calling process atomically (kernel guarantee).
- The PID written is `os.Getpid()` — the process writing the file.
- `OwnCgroup` stays pointing to `own` (not `own/leaf`) since that's where child command cgroups are created.

### 2. Probe Result Changes

`CgroupProbeResult` gains one field:

```go
type CgroupProbeResult struct {
    Mode          CgroupMode
    Reason        string
    OwnCgroup     string
    SliceDir      string
    IOAvailable   bool
    OrphansReaped []string
    LeafMoved     bool     // true if the probe moved the process to own/leaf
}
```

The server's event publishing at `server.go:422-435` adds `LeafMoved` to the `cgroup_mode` event fields map.

No changes to `CgroupManager.Apply()` — it uses `probe.OwnCgroup` which still points to the parent where children are created.

### 3. Legacy Code Removal

**Delete entirely:**

- `internal/limits/limiter_linux.go` — `LinuxLimiter` type and all methods. Zero production callers.
- `internal/platform/linux/resources.go` — `ResourceLimiter`, `ResourceHandle`, and all methods. Only called from the `Resources()` accessor and tests.
- `internal/platform/linux/resources_test.go` — tests for the deleted code.

**Delete from existing files:**

- `internal/limits/cgroupv2_linux.go` — remove the deprecated `ApplyCgroupV2` function (lines 55-107). Keep `CurrentCgroupDir`, `DetectCgroupV2`, `CgroupV2`, `CgroupV2Limits`, `sanitizeCgroupName`, `cpuMaxFromPct`, `cgroupUnpopulated`, `enableControllers`, `enableControllersFS`.
- `internal/platform/linux/platform.go` — remove the `resources` field from `Platform` struct. Keep `Resources()` method (required by the `platform.Platform` interface) but change it to return `nil`.

**Retain:**

- `enableControllers` / `enableControllersFS` — used by the probe.
- `CurrentCgroupDir` — used by the probe when `ownHint` is empty.
- All other non-deprecated functions in `cgroupv2_linux.go`.

### 4. Test Changes

**Migrate tests off `ApplyCgroupV2`:**

- `internal/limits/cgroupv2_linux_test.go` — migrate to `CgroupManager` via `NewCgroupManager(ctx, "")` then `mgr.Apply(...)`.
- `internal/netmonitor/ebpf/integration_test.go` and `pnacl_integration_test.go` — these use explicit parent paths for eBPF cgroup attachment. Migrate to `CgroupManager` or inline mkdir+write-cgroup.procs since they only need a cgroup directory, not full limit enforcement.

**New probe tests in `cgroupv2_probe_test.go`** using `fakeCgroupFS`:

1. EBUSY on own cgroup → leaf-move succeeds → `ModeNested` with `LeafMoved: true`
2. EBUSY on own cgroup → leaf mkdir fails → falls through to top-level
3. EBUSY on own cgroup → leaf-move succeeds but enable retry fails → falls through to top-level
4. Non-EBUSY error (EACCES) → no leaf-move attempt, straight to top-level

## Scope Boundary

This design does NOT change:

- The `CgroupManager.Apply()` path — it already works correctly.
- The config schema (`SandboxCgroupsConfig`) — `BasePath` continues to work as documented.
- The top-level fallback logic in `tryTopLevel()` — it remains as the fallback if leaf-move fails.
- The `cgroupv2_other.go` stub for non-Linux platforms.
