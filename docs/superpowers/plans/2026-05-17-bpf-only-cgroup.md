# BPF-only cgroup attach mode — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make eBPF cgroup_connect attach reachable on hosts where `sandbox.cgroups.enabled=true` can't be honored (notably stock Docker), so domain-based `network_rules` enforce against subprocesses that strip `HTTP_PROXY` without operators needing host-side systemd surgery.

**Architecture:** Add a fourth cgroup mode `ModeAttachOnly` to the existing probe in `internal/limits/`. When the probe lands on it, `CgroupManager.Apply()` returns a path-only handle (mkdir + attach pid, no controller writes) suitable for `AttachConnectToCgroup`. Widen the cgroup-manager construction predicate in `internal/api/app.go` to include `ebpf.{enabled,enforce,required}=true`, and update `wrap.go` / `cgroups.go` to dispatch on the new mode and new error type. Split the `cgroups-v2` capability check into `cgroups_v2_resource_limits` + a new `ebpf_cgroup_attach`.

**Tech Stack:** Go (Linux-only for the new code paths), existing `fakeCgroupFS` test infrastructure, slog for structured logging, cilium/ebpf-go for attach.

**Spec:** `docs/superpowers/specs/2026-05-17-bpf-only-cgroup-design.md`.

---

## File map

- `internal/limits/cgroupv2_probe.go` — add `ModeAttachOnly` constant, extend `ProbeCgroupsV2` signature with a `permitAttachOnly` input, add the new feasibility check.
- `internal/limits/cgroupv2_errors.go` — add `CgroupResourceLimitsUnavailableError` type.
- `internal/limits/cgroupv2_manager.go` — extend `Apply` with the `ModeAttachOnly` branch; thread `permitAttachOnly` through `newCgroupManagerFS`/`NewCgroupManager` from the caller.
- `internal/limits/cgroupv2_probe_test.go` — new probe tests.
- `internal/limits/cgroupv2_manager_test.go` — new Apply tests.
- `internal/api/app.go` — widen `cgroupMgr` construction predicate; replace the #346 WARN block with mode-aware log lines; signal startup failure when `ebpf.required=true` and mode is `Unavailable`.
- `internal/api/wrap.go` — widen `wrapNeedsCgroupBeforeAck`; dispatch on `CgroupResourceLimitsUnavailableError` in `defaultWrapCgroupSetupForNotify`.
- `internal/api/cgroups.go` — widen the activation gate in `applyCgroupV2`; dispatch on the new error.
- `internal/capabilities/check.go` — rename `realCheckCgroupsV2` → `realCheckCgroupsV2ResourceLimits`, add `realCheckEBPFCgroupAttach`.
- `internal/capabilities/check_cgroups_linux.go` — narrow `probeCgroupsV2`'s "Available" mapping; add attach-feasibility helper.
- `internal/capabilities/tips.go` — new tip entries for the two new capability keys.
- `internal/capabilities/check_test.go` (or `check_linux_test.go` if Linux-specific) — capability check tests.
- `docs/ebpf.md` — rewording in the Configuration callout; reframe the Stock Docker subsection.

---

## Task 1: Add `ModeAttachOnly` constant

**Files:**
- Modify: `internal/limits/cgroupv2_probe.go:17-24`

- [ ] **Step 1: Add the new constant**

Edit `internal/limits/cgroupv2_probe.go` to add `ModeAttachOnly` between `ModeTopLevel` and `ModeUnavailable`:

```go
const (
	ModeNested      CgroupMode = "nested"
	ModeTopLevel    CgroupMode = "top-level"
	ModeAttachOnly  CgroupMode = "attach-only"
	ModeUnavailable CgroupMode = "unavailable"
)
```

- [ ] **Step 2: Verify build**

Run: `go build ./internal/limits/`
Expected: builds cleanly.

- [ ] **Step 3: Commit**

```bash
git add internal/limits/cgroupv2_probe.go
git commit -m "limits: add ModeAttachOnly cgroup mode constant"
```

---

## Task 2: Add `CgroupResourceLimitsUnavailableError` error type

**Files:**
- Modify: `internal/limits/cgroupv2_errors.go`
- Test: `internal/limits/cgroupv2_errors_test.go` (new)

- [ ] **Step 1: Write the failing test**

Create `internal/limits/cgroupv2_errors_test.go`:

```go
//go:build linux

package limits

import (
	"strings"
	"testing"
)

func TestCgroupResourceLimitsUnavailableError_Message(t *testing.T) {
	e := &CgroupResourceLimitsUnavailableError{
		Reason: "controllers cpu,memory,pids cannot be enabled in subtree_control: ENOTSUP",
		Limits: CgroupV2Limits{MaxMemoryBytes: 16 << 20, PidsMax: 64},
	}
	msg := e.Error()
	if !strings.Contains(msg, "resource limits unavailable") {
		t.Errorf("missing prefix: %q", msg)
	}
	if !strings.Contains(msg, "ENOTSUP") {
		t.Errorf("missing reason: %q", msg)
	}
	if !strings.Contains(msg, "memory.max=16777216") {
		t.Errorf("missing memory summary: %q", msg)
	}
	if !strings.Contains(msg, "pids.max=64") {
		t.Errorf("missing pids summary: %q", msg)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/limits/ -run TestCgroupResourceLimitsUnavailableError_Message -v`
Expected: FAIL with `undefined: CgroupResourceLimitsUnavailableError`.

- [ ] **Step 3: Add the type**

Append to `internal/limits/cgroupv2_errors.go`:

```go
// CgroupResourceLimitsUnavailableError is returned by CgroupManager.Apply when
// the probe landed on ModeAttachOnly (cgroup mkdir + attach work, but
// controllers cannot be enabled in subtree_control) and the caller's policy
// requires one or more non-zero resource limits. BPF attach is still reachable
// against the cgroup path; only the .max writes have nowhere to bind. Callers
// surface this differently from CgroupUnavailableError so the operator-facing
// message can be specific.
type CgroupResourceLimitsUnavailableError struct {
	Reason string
	Limits CgroupV2Limits
}

func (e *CgroupResourceLimitsUnavailableError) Error() string {
	return fmt.Sprintf(
		"cgroup resource limits unavailable (%s); policy requires %s — refusing command",
		e.Reason, e.Limits.Summary())
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/limits/ -run TestCgroupResourceLimitsUnavailableError_Message -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/limits/cgroupv2_errors.go internal/limits/cgroupv2_errors_test.go
git commit -m "limits: add CgroupResourceLimitsUnavailableError type"
```

---

## Task 3: Extend probe with `permitAttachOnly` + new feasibility check

**Files:**
- Modify: `internal/limits/cgroupv2_probe.go`
- Test: `internal/limits/cgroupv2_probe_test.go` (extend)

This task changes the `ProbeCgroupsV2` signature. Callers in `cgroupv2_manager.go` and elsewhere update in Task 4; for this task the manager call site temporarily passes `false` (preserving today's behavior) so the build stays green.

- [ ] **Step 1: Write the failing test — AttachOnly reached with permitAttachOnly=true**

Add to `internal/limits/cgroupv2_probe_test.go` (after the existing tests):

```go
func TestProbe_AttachOnly_ReachedWhenPermitted(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	// Own cgroup advertises controllers but rejects subtree_control writes
	// for memory — mirrors the stock-Docker scope-cgroup symptom.
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "")
	f.failSubtreeWrite(own+"/cgroup.subtree_control", "+memory", syscall.ENOTSUP)
	// Top-level slice also refuses controller enable so the probe doesn't
	// fall back to that path.
	f.failSubtreeWrite("/sys/fs/cgroup/cgroup.subtree_control", "+memory", syscall.ENOTSUP)

	res, err := ProbeCgroupsV2(context.Background(), f, own, true /*permitAttachOnly*/)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Mode != ModeAttachOnly {
		t.Fatalf("mode: got %q, want %q (reason=%q)", res.Mode, ModeAttachOnly, res.Reason)
	}
	if !strings.Contains(res.Reason, "memory") {
		t.Errorf("reason should name the failed controller: %q", res.Reason)
	}
}

func TestProbe_AttachOnly_FilteredWhenNotPermitted(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "")
	f.failSubtreeWrite(own+"/cgroup.subtree_control", "+memory", syscall.ENOTSUP)
	f.failSubtreeWrite("/sys/fs/cgroup/cgroup.subtree_control", "+memory", syscall.ENOTSUP)

	res, err := ProbeCgroupsV2(context.Background(), f, own, false /*permitAttachOnly*/)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Mode != ModeUnavailable {
		t.Fatalf("mode: got %q, want %q (reason=%q)", res.Mode, ModeUnavailable, res.Reason)
	}
}
```

If `fakeCgroupFS` doesn't have a `failSubtreeWrite` helper yet, add it (a tiny extension to the existing test FS that records which subtree_control writes should ENOTSUP). Look at the existing fake to confirm the helper name and pattern; if a similar helper exists by a different name, use that.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/limits/ -run TestProbe_AttachOnly -v`
Expected: FAIL — `too many arguments in call to ProbeCgroupsV2` (the new bool parameter doesn't exist yet) or `undefined: failSubtreeWrite`.

- [ ] **Step 3: Extend `ProbeCgroupsV2` signature**

Modify the signature in `internal/limits/cgroupv2_probe.go`:

```go
func ProbeCgroupsV2(ctx context.Context, fs cgroupFS, ownHint string, permitAttachOnly bool) (*CgroupProbeResult, error) {
```

Also extend `ProbeCgroupsV2Default`:

```go
func ProbeCgroupsV2Default(ctx context.Context) (*CgroupProbeResult, error) {
	return ProbeCgroupsV2(context.Background(), osCgroupFS{}, "", true /*permitAttachOnly*/)
}
```

`ProbeCgroupsV2Default` is the no-options variant used by `agentsh detect`. Detect should reflect AttachOnly availability regardless of operator config (operators may run detect to *decide* whether to set `cgroups.enabled=true`), so it always permits attach-only.

Update the existing `newCgroupManagerFS` caller of `ProbeCgroupsV2` to pass `false` (placeholder — Task 4 makes this configurable):

```go
func newCgroupManagerFS(ctx context.Context, fs cgroupFS, ownHint string) (*CgroupManager, error) {
	probe, err := ProbeCgroupsV2(ctx, fs, ownHint, false /*permitAttachOnly*/)
```

- [ ] **Step 4: Add the feasibility check**

Inside `ProbeCgroupsV2`, after the existing path falls through to what would be `ModeUnavailable` (look for the existing `return &CgroupProbeResult{Mode: ModeUnavailable, ...}` return at the bottom of the decision tree), insert the new branch:

```go
// At the point where the existing code would return ModeUnavailable
// with a "controllers cannot be enabled" reason, check if attach-only
// is permitted AND feasible. If so, return ModeAttachOnly instead.

if permitAttachOnly {
	parentDir := own
	// If top-level was attempted and the slice dir is available, prefer
	// that as the parent (matches ModeTopLevel placement). Otherwise
	// stick with own.
	if topLevelSliceDir != "" {
		parentDir = topLevelSliceDir
	}
	feasible, feasibleErr := probeAttachOnlyFeasibility(fs, parentDir)
	if feasible {
		return &CgroupProbeResult{
			Mode:      ModeAttachOnly,
			Reason:    unavailableReason, // re-use the controller-enable failure description
			OwnCgroup: own,
			SliceDir:  topLevelSliceDir,
		}, nil
	}
	// Attach-only also infeasible — extend the reason for the
	// Unavailable return below.
	unavailableReason = unavailableReason + "; attach-only also infeasible: " + feasibleErr.Error()
}

return &CgroupProbeResult{Mode: ModeUnavailable, Reason: unavailableReason}, nil
```

Note: the variable names (`unavailableReason`, `topLevelSliceDir`) above are illustrative; match them to what the existing decision tree already uses for the same concepts. The impl will need to capture the controller-enable failure description as a string before the final return.

Then add the new helper at the bottom of the file:

```go
// probeAttachOnlyFeasibility verifies that mkdir under parentDir and writes
// to cgroup.procs work — the two operations the BPF-only path needs. Returns
// (true, nil) on full success.
//
// To avoid leaking probe-test cgroups, the helper writes the probe process's
// PID into the test cgroup, then writes it back into the parent's cgroup.procs
// to release the test cgroup, then rmdirs the test directory.
func probeAttachOnlyFeasibility(fs cgroupFS, parentDir string) (bool, error) {
	testDir := filepath.Join(parentDir, "agentsh.probe")
	if err := fs.Mkdir(testDir, 0o755); err != nil && !errors.Is(err, syscall.EEXIST) {
		return false, fmt.Errorf("mkdir %s: %w", testDir, err)
	}
	pid := strconv.Itoa(os.Getpid())
	if err := fs.WriteFile(filepath.Join(testDir, "cgroup.procs"), []byte(pid), 0o644); err != nil {
		_ = fs.Remove(testDir)
		return false, fmt.Errorf("write cgroup.procs in test dir: %w", err)
	}
	// Move the probe process back into the parent so the test cgroup is empty.
	if err := fs.WriteFile(filepath.Join(parentDir, "cgroup.procs"), []byte(pid), 0o644); err != nil {
		// We couldn't move back out. Best-effort rmdir will likely fail.
		_ = fs.Remove(testDir)
		return false, fmt.Errorf("release pid back to parent: %w", err)
	}
	if err := fs.Remove(testDir); err != nil {
		return false, fmt.Errorf("rmdir test cgroup: %w", err)
	}
	return true, nil
}
```

`fs.Remove` is the cgroupFS abstraction's rmdir. If the existing interface uses a different name (e.g., `Rmdir`), match it. If `os.Getpid()` is the wrong way to get the probe PID in the fake-fs context, look at how the existing probe steps handle PIDs — most likely they read `/proc/self/cgroup` via `CurrentCgroupDir()` and don't write PIDs at all.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/limits/ -run TestProbe -v`
Expected: all probe tests PASS, including the two new ones.

- [ ] **Step 6: Run the full limits package tests**

Run: `go test ./internal/limits/`
Expected: PASS. No existing tests broken — the new probe outcome is additive.

- [ ] **Step 7: Commit**

```bash
git add internal/limits/cgroupv2_probe.go internal/limits/cgroupv2_probe_test.go
git commit -m "limits: probe ModeAttachOnly when controllers can't be enabled

Extends ProbeCgroupsV2 with a permitAttachOnly input. When the existing
decision tree would return ModeUnavailable because controllers can't be
enabled in subtree_control, and permitAttachOnly is true, the probe now
runs an attach-only feasibility check (mkdir + cgroup.procs write + cleanup)
and returns ModeAttachOnly on success.

ProbeCgroupsV2Default (used by agentsh detect) passes permitAttachOnly=true
unconditionally so the detect output reflects host capability honestly.
newCgroupManagerFS passes false for now — Task 4 makes this caller-driven."
```

---

## Task 4: Thread `permitAttachOnly` through `NewCgroupManager`

**Files:**
- Modify: `internal/limits/cgroupv2_manager.go`
- Modify: `internal/api/app.go` (caller site)

This is a small wiring task that lets the caller (app.go in Task 5) signal whether attach-only is allowed for the per-app probe.

- [ ] **Step 1: Extend `NewCgroupManager` and `newCgroupManagerFS` signatures**

Modify `internal/limits/cgroupv2_manager.go`:

```go
func NewCgroupManager(ctx context.Context, ownHint string, permitAttachOnly bool) (*CgroupManager, error) {
	return newCgroupManagerFS(ctx, osCgroupFS{}, ownHint, permitAttachOnly)
}

func newCgroupManagerFS(ctx context.Context, fs cgroupFS, ownHint string, permitAttachOnly bool) (*CgroupManager, error) {
	probe, err := ProbeCgroupsV2(ctx, fs, ownHint, permitAttachOnly)
	if err != nil {
		return nil, fmt.Errorf("probe cgroups v2: %w", err)
	}
	return &CgroupManager{fs: fs, probe: probe}, nil
}
```

- [ ] **Step 2: Update the existing test call sites**

Run: `go build ./... 2>&1 | head -20`

Find every callsite that currently calls `newCgroupManagerFS(ctx, fs, own)` or `NewCgroupManager(ctx, ownHint)`. Update each to pass the matching `permitAttachOnly` value:
- Existing manager-construction tests that don't exercise AttachOnly: pass `false` (preserves today's strict behavior — they should keep getting ModeUnavailable when controllers can't be enabled, not the new mode).
- The caller in `internal/api/app.go` will get its real value in Task 5; for now, change the call to `NewCgroupManager(ctx, basePath, false)` so the build stays green.

- [ ] **Step 3: Verify build + tests still pass**

Run: `go build ./... && go test ./internal/limits/ ./internal/api/`
Expected: build clean, all existing tests pass.

- [ ] **Step 4: Commit**

```bash
git add internal/limits/cgroupv2_manager.go internal/api/app.go
git commit -m "limits: thread permitAttachOnly through CgroupManager constructor

NewCgroupManager and newCgroupManagerFS gain a permitAttachOnly bool that
forwards to ProbeCgroupsV2. Existing call sites pass false to preserve
today's strict-cgroup behavior; app.go gets its real value in the next
commit."
```

---

## Task 5: Extend `Apply` with `ModeAttachOnly` branch

**Files:**
- Modify: `internal/limits/cgroupv2_manager.go:54-98`
- Modify: `internal/limits/cgroupv2_manager_test.go`

- [ ] **Step 1: Write failing tests**

Add to `internal/limits/cgroupv2_manager_test.go`:

```go
func TestManagerApply_AttachOnly_EmptyLimits_Succeeds(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "")
	f.failSubtreeWrite(own+"/cgroup.subtree_control", "+memory", syscall.ENOTSUP)
	f.failSubtreeWrite("/sys/fs/cgroup/cgroup.subtree_control", "+memory", syscall.ENOTSUP)

	m, err := newCgroupManagerFS(context.Background(), f, own, true /*permitAttachOnly*/)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if m.Probe().Mode != ModeAttachOnly {
		t.Fatalf("mode: %q", m.Probe().Mode)
	}

	cg, err := m.Apply("agentsh-sess-cmd", 4242, CgroupV2Limits{})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if cg == nil {
		t.Fatalf("expected handle, got nil")
	}
	if !strings.HasPrefix(cg.Path, own+"/") {
		t.Fatalf("attach-only cgroup path: %q (want prefix %q)", cg.Path, own)
	}
	// PID was written.
	data, _ := f.ReadFile(cg.Path + "/cgroup.procs")
	if string(data) != "4242" {
		t.Errorf("cgroup.procs: got %q, want 4242", data)
	}
	// No .max files written.
	if _, err := f.ReadFile(cg.Path + "/memory.max"); err == nil {
		t.Errorf("memory.max should not be written in AttachOnly mode")
	}
	if _, err := f.ReadFile(cg.Path + "/pids.max"); err == nil {
		t.Errorf("pids.max should not be written in AttachOnly mode")
	}
}

func TestManagerApply_AttachOnly_WithLimits_Refuses(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "")
	f.failSubtreeWrite(own+"/cgroup.subtree_control", "+memory", syscall.ENOTSUP)
	f.failSubtreeWrite("/sys/fs/cgroup/cgroup.subtree_control", "+memory", syscall.ENOTSUP)

	m, err := newCgroupManagerFS(context.Background(), f, own, true)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	cg, err := m.Apply("agentsh-sess-cmd", 4242, CgroupV2Limits{MaxMemoryBytes: 16 << 20})
	if err == nil {
		t.Fatalf("expected error, got cg=%v", cg)
	}
	var rlErr *CgroupResourceLimitsUnavailableError
	if !errors.As(err, &rlErr) {
		t.Fatalf("error type: got %T, want *CgroupResourceLimitsUnavailableError", err)
	}
	if rlErr.Limits.MaxMemoryBytes != 16<<20 {
		t.Errorf("error carries limits: got %+v", rlErr.Limits)
	}
	// No cgroup directory was created.
	if _, err := f.ReadFile(own + "/agentsh-sess-cmd/cgroup.procs"); err == nil {
		t.Errorf("AttachOnly+limits refusal should not create the cgroup")
	}
}

func TestManagerApply_AttachOnly_CloseRemovesCgroup(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "")
	f.failSubtreeWrite(own+"/cgroup.subtree_control", "+memory", syscall.ENOTSUP)
	f.failSubtreeWrite("/sys/fs/cgroup/cgroup.subtree_control", "+memory", syscall.ENOTSUP)

	m, _ := newCgroupManagerFS(context.Background(), f, own, true)
	cg, err := m.Apply("agentsh-sess-cmd", 4242, CgroupV2Limits{})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := cg.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	if exists, _ := f.DirExists(cg.Path); exists {
		t.Errorf("attach-only cgroup not removed by Close: %s", cg.Path)
	}
}
```

`f.DirExists` is the convention for the fake FS; if the actual helper is named differently (e.g., the test reads the absence of any seeded file under the path), match the existing convention.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/limits/ -run TestManagerApply_AttachOnly -v`
Expected: FAIL — `Apply()` doesn't yet know about ModeAttachOnly, so it'll either succeed-with-writes (wrong behavior) or fall through unexpected paths.

- [ ] **Step 3: Add the `ModeAttachOnly` branch in `Apply`**

Modify `internal/limits/cgroupv2_manager.go::Apply`. The existing function has the structure:

```go
func (m *CgroupManager) Apply(name string, pid int, lim CgroupV2Limits) (*CgroupV2, error) {
	if pid <= 0 { ... }
	if m.probe.Mode == ModeUnavailable { ... }
	// mkdir + .max writes + cgroup.procs write
}
```

Insert the new branch between the `ModeUnavailable` check and the existing mkdir/writes:

```go
if m.probe.Mode == ModeAttachOnly {
	if !lim.IsEmpty() {
		return nil, &CgroupResourceLimitsUnavailableError{
			Reason: m.probe.Reason,
			Limits: lim,
		}
	}
	// Empty limits: mkdir + attach pid only. Same parent resolution as
	// the success path below.
	parent := m.parentDir()
	safe := sanitizeCgroupName(name)
	dir := filepath.Join(parent, safe)

	if err := m.fs.Mkdir(dir, 0o755); err != nil && !errors.Is(err, syscall.EEXIST) {
		return nil, fmt.Errorf("mkdir cgroup (mode=%s, dir=%s): %w", m.probe.Mode, dir, err)
	}
	if err := m.fs.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644); err != nil {
		return nil, fmt.Errorf("attach pid (mode=%s, dir=%s): %w", m.probe.Mode, dir, err)
	}
	return &CgroupV2{Path: dir}, nil
}
```

The existing nested/top-level success path stays unchanged below this block.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/limits/ -run TestManagerApply -v`
Expected: all manager Apply tests PASS, including the three new AttachOnly ones.

- [ ] **Step 5: Run the full limits package tests**

Run: `go test ./internal/limits/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/limits/cgroupv2_manager.go internal/limits/cgroupv2_manager_test.go
git commit -m "limits: Apply handles ModeAttachOnly (mkdir + attach pid only)

In ModeAttachOnly:
- empty limits: mkdir + attach pid + return path handle; no .max writes
- non-empty limits: return *CgroupResourceLimitsUnavailableError, no cgroup created

Existing ModeNested / ModeTopLevel / ModeUnavailable paths unchanged."
```

---

## Task 6: Widen `needsCgroup` predicate + startup logging in `app.go`

**Files:**
- Modify: `internal/api/app.go:104-145`

- [ ] **Step 1: Identify the `needsCgroup` decision and rewrite**

Find the current cgroupMgr construction logic (around line 125-130, where `appCgroupMgr` is set from the constructor's `cgroupMgr` parameter). The construction itself happens upstream (in cmd/agentsh/main.go or similar) — the predicate that *decides* whether to construct lives at that upstream call site.

Find the upstream caller. Search:

```bash
grep -rn "NewCgroupManager(" --include="*.go" cmd/ internal/
```

The single non-test caller is the place to change. Today that caller probably has a check like:

```go
var cgroupMgr *limits.CgroupManager
if cfg.Sandbox.Cgroups.Enabled {
	cgroupMgr, err = limits.NewCgroupManager(ctx, cfg.Sandbox.Cgroups.BasePath, false)
	...
}
```

Rewrite it as:

```go
var cgroupMgr *limits.CgroupManager
needsCgroup := cfg.Sandbox.Cgroups.Enabled ||
	cfg.Sandbox.Network.EBPF.Enabled ||
	cfg.Sandbox.Network.EBPF.Enforce ||
	cfg.Sandbox.Network.EBPF.Required
if needsCgroup {
	permitAttachOnly := !cfg.Sandbox.Cgroups.Enabled
	cgroupMgr, err = limits.NewCgroupManager(ctx, cfg.Sandbox.Cgroups.BasePath, permitAttachOnly)
	if err != nil {
		return nil, fmt.Errorf("cgroup probe: %w", err)
	}
}
```

`permitAttachOnly = !cgroups.Enabled` is the key correctness invariant: when the operator explicitly asserts `cgroups.enabled=true`, the strict path (probe collapses to Unavailable when controllers fail) is preserved.

- [ ] **Step 2: Replace the #346 WARN block in `NewApp` with mode-aware logging**

Inside `NewApp`, find the existing block from #346:

```go
if (cfg.Sandbox.Network.EBPF.Enabled || cfg.Sandbox.Network.EBPF.Enforce) && !cfg.Sandbox.Cgroups.Enabled {
	slog.Warn("ebpf: enforcement configured but inactive — requires sandbox.cgroups.enabled=true",
		"ebpf.enabled", cfg.Sandbox.Network.EBPF.Enabled,
		"ebpf.enforce", cfg.Sandbox.Network.EBPF.Enforce,
		"cgroups.enabled", cfg.Sandbox.Cgroups.Enabled,
	)
}
```

Replace with a mode-aware dispatch. `cgroupMgr` may be nil (when `needsCgroup` was false); in that case the block is a no-op.

```go
if cgroupMgr != nil && (cfg.Sandbox.Network.EBPF.Enabled || cfg.Sandbox.Network.EBPF.Enforce || cfg.Sandbox.Network.EBPF.Required) {
	mode := cgroupMgr.Probe().Mode
	reason := cgroupMgr.Probe().Reason
	switch mode {
	case limits.ModeAttachOnly:
		slog.Info("ebpf: attach-only mode active (resource limits unavailable)",
			"reason", reason,
			"ebpf.enabled", cfg.Sandbox.Network.EBPF.Enabled,
			"ebpf.enforce", cfg.Sandbox.Network.EBPF.Enforce,
		)
	case limits.ModeUnavailable:
		slog.Warn("ebpf: enforcement configured but unavailable (check CAP_BPF and /sys/fs/bpf)",
			"reason", reason,
			"ebpf.enabled", cfg.Sandbox.Network.EBPF.Enabled,
			"ebpf.enforce", cfg.Sandbox.Network.EBPF.Enforce,
			"cgroups.enabled", cfg.Sandbox.Cgroups.Enabled,
		)
	}
	// ModeNested / ModeTopLevel: success path, no log (silent success).
}
```

- [ ] **Step 3: Handle `ebpf.required=true` + `ModeUnavailable` as startup failure**

The spec defers the exact mechanism to the impl plan. The simplest workable choice is to return an error from the upstream cgroup-manager constructor call site (the same place modified in Step 1), before `NewApp` is called:

In the upstream caller (most likely `cmd/agentsh/main.go` or `cmd/agentsh/server.go` — the command's run function), immediately after `NewCgroupManager` succeeds, check:

```go
if cgroupMgr != nil && cfg.Sandbox.Network.EBPF.Required {
	if cgroupMgr.Probe().Mode == limits.ModeUnavailable {
		return fmt.Errorf("ebpf.required=true but cgroup probe is unavailable: %s", cgroupMgr.Probe().Reason)
	}
}
```

This is a startup-time validation step — fails the server boot before any session can start. If the upstream caller's structure doesn't allow this cleanly (e.g., the call is buried inside a constructor chain), introduce a small helper `limits.ValidateForEBPFRequired(probe *CgroupProbeResult) error` and call it at the upstream site.

- [ ] **Step 4: Build and run app tests**

Run: `go build ./... && go test ./internal/api/`
Expected: build clean, existing api tests pass.

- [ ] **Step 5: Add an integration-style smoke test for the new log lines**

A full slog capture test is heavier than needed here, but verify by inspection: run a manual mental walkthrough of the four config combinations and convince yourself each yields the expected log line. Note this in the commit message.

If the codebase has a slog-capture test helper already, use it. Otherwise skip the automated test — the per-component tests in subsequent tasks will catch wiring breakage.

- [ ] **Step 6: Commit**

```bash
git add internal/api/app.go cmd/  # plus whichever upstream file actually owns the construction
git commit -m "api: widen cgroupMgr construction predicate; mode-aware startup logs

The cgroup manager is now constructed whenever any of:
- sandbox.cgroups.enabled=true
- sandbox.network.ebpf.enabled=true
- sandbox.network.ebpf.enforce=true
- sandbox.network.ebpf.required=true

permitAttachOnly=true is passed only when cgroups.enabled=false, preserving
the existing strict path (cgroups.enabled=true still hard-fails when
controllers can't be enabled).

The #346 WARN block is replaced by:
- ModeAttachOnly + ebpf set: INFO 'attach-only mode active'
- ModeUnavailable + ebpf set: WARN 'enforcement unavailable: <cause>'
- ModeNested/TopLevel + ebpf set: silent success

ebpf.required=true + ModeUnavailable is enforced at server-startup time
as a hard fail (operator's invariant is violated)."
```

---

## Task 7: Widen `wrap.go` predicate

**Files:**
- Modify: `internal/api/wrap.go:815-829`

- [ ] **Step 1: Update `wrapNeedsCgroupBeforeAck`**

Replace the existing predicate. Current shape (from spec Section C):

```go
func wrapNeedsCgroupBeforeAck(a *App, s *session.Session) bool {
	if a.cfg.Sandbox.Network.EBPF.Required {
		return true
	}
	if !a.cfg.Sandbox.Cgroups.Enabled {
		return false
	}
	if a.cfg.Sandbox.Network.EBPF.Enabled || a.cfg.Sandbox.Network.EBPF.Enforce {
		return true
	}
	// existing per-policy resource-limits check
	engine := a.policyEngineFor(s)
	if engine == nil {
		return false
	}
	lim := engine.Limits()
	return lim.MaxMemoryMB > 0 || lim.CPUQuotaPercent > 0 || lim.PidsMax > 0
}
```

Becomes:

```go
func wrapNeedsCgroupBeforeAck(a *App, s *session.Session) bool {
	if a.cfg.Sandbox.Cgroups.Enabled ||
		a.cfg.Sandbox.Network.EBPF.Enabled ||
		a.cfg.Sandbox.Network.EBPF.Enforce ||
		a.cfg.Sandbox.Network.EBPF.Required {
		return true
	}
	// Per-policy resource-limits check unchanged.
	engine := a.policyEngineFor(s)
	if engine == nil {
		return false
	}
	lim := engine.Limits()
	return lim.MaxMemoryMB > 0 || lim.CPUQuotaPercent > 0 || lim.PidsMax > 0
}
```

Note the existing `if !cfg.Sandbox.Cgroups.Enabled { return false }` short-circuit is removed — that's the change that lets the BPF-only path run.

- [ ] **Step 2: Remove the obsolete required-vs-cgroups hard-fail in `defaultWrapCgroupSetupForNotify`**

Find the block (around `wrap.go:839-841` per the design doc):

```go
if a.cfg.Sandbox.Network.EBPF.Required && !a.cfg.Sandbox.Cgroups.Enabled {
	return nil, fmt.Errorf("ebpf required but sandbox.cgroups.enabled=false")
}
```

This becomes redundant — startup validation (Task 6, Step 3) catches the `required + Unavailable` case earlier. Delete this block. The `required + AttachOnly` case now legitimately proceeds.

- [ ] **Step 3: Build**

Run: `go build ./internal/api/`
Expected: builds clean.

- [ ] **Step 4: Run existing wrap tests**

Run: `go test ./internal/api/ -run TestWrap`
Expected: existing wrap tests PASS. Some may have asserted the deleted hard-fail message; those need updating in Task 8 along with the new error-dispatch tests.

If a test fails because it asserted the old hard-fail behavior, mark the failure and continue — Task 8 covers it.

- [ ] **Step 5: Commit**

```bash
git add internal/api/wrap.go
git commit -m "api: widen wrap predicate to include ebpf.* triggers

wrapNeedsCgroupBeforeAck now returns true whenever any cgroup or ebpf
setting is enabled, not just when cgroups.enabled=true. The redundant
hard-fail for required + !cgroups.enabled in defaultWrapCgroupSetupForNotify
is removed; that case is now handled at server startup (see prior commit)
and the required + AttachOnly case proceeds normally."
```

---

## Task 8: Dispatch new error type in wrap.go

**Files:**
- Modify: `internal/api/wrap.go::defaultWrapCgroupSetupForNotify`
- Test: extend the wrap test file (find current location via `grep -rn "TestWrap" internal/api/`)

- [ ] **Step 1: Write failing tests**

The existing test infrastructure in `internal/api/cgroups_linux_test.go` provides `fakeCgroupManagerForAPITest` (apply path + probe) and `newAppWithFakeCgroupManager`. Extend the fake to be mode-aware, then add the new tests.

Edit `internal/api/cgroups_linux_test.go`:

```go
// fakeCgroupManagerForAPITest already exists. Extend it with mode + applyErr
// fields so the AttachOnly tests can drive both probe outcomes and Apply
// error returns from a single fixture.

type fakeCgroupManagerForAPITest struct {
	path     string
	mode     limits.CgroupMode // defaults to ModeNested when zero
	applyErr error             // when set, Apply returns this instead of a CgroupV2
}

func (m *fakeCgroupManagerForAPITest) Apply(name string, pid int, lim limits.CgroupV2Limits) (*limits.CgroupV2, error) {
	if m.applyErr != nil {
		return nil, m.applyErr
	}
	if err := os.MkdirAll(m.path, 0o755); err != nil {
		return nil, err
	}
	return &limits.CgroupV2{Path: m.path}, nil
}

func (m *fakeCgroupManagerForAPITest) Probe() *limits.CgroupProbeResult {
	mode := m.mode
	if mode == "" {
		mode = limits.ModeNested
	}
	return &limits.CgroupProbeResult{Mode: mode}
}
```

Add the new tests at the end of the file:

```go
func TestDefaultWrapCgroupSetup_AttachOnly_NoLimits_Succeeds(t *testing.T) {
	withEBPFHooks(t)
	cgPath := t.TempDir()
	attachCalled := ""
	ebpfAttachConnectToCgroup = func(path string) (*ebpf.Collection, func() error, error) {
		attachCalled = path
		return &ebpf.Collection{}, func() error { return nil }, nil
	}
	// Other ebpf hooks default to no-op via withEBPFHooks; if your existing
	// helper doesn't already pre-stub them, set them here so the setup
	// reaches the attach call.

	enabled := false
	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = false
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.Network.EBPF.Enabled = true

	app := newAppWithFakeCgroupManager(t, cfg, cgPath)
	app.cgroupMgr.(*fakeCgroupManagerForAPITest).mode = limits.ModeAttachOnly

	cleanup, err := defaultWrapCgroupSetupForNotify(context.Background(), app, &session.Session{}, "sess-1", 4242)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if cleanup == nil {
		t.Fatalf("expected cleanup closure")
	}
	if attachCalled == "" {
		t.Errorf("ebpfAttachConnectToCgroup should have been called")
	}
	_ = cleanup()
}

func TestDefaultWrapCgroupSetup_AttachOnly_LimitsRequested_Errors(t *testing.T) {
	withEBPFHooks(t)
	cgPath := t.TempDir()
	enabled := false
	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = false
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.Network.EBPF.Enabled = true

	app := newAppWithFakeCgroupManager(t, cfg, cgPath)
	fake := app.cgroupMgr.(*fakeCgroupManagerForAPITest)
	fake.mode = limits.ModeAttachOnly
	fake.applyErr = &limits.CgroupResourceLimitsUnavailableError{
		Reason: "controllers cannot be enabled: ENOTSUP",
		Limits: limits.CgroupV2Limits{MaxMemoryBytes: 16 << 20},
	}

	// Construct a session whose policy demands memory limits.
	pol, _ := policy.NewEngine(&policy.Policy{
		Version: 1,
		Name:    "limits-test",
		Limits:  policy.Limits{MaxMemoryMB: 16},
	}, false, true)
	sess := &session.Session{} // attach pol via whatever existing helper exists

	_, err := defaultWrapCgroupSetupForNotify(context.Background(), app, sess, "sess-1", 4242)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	var rlErr *limits.CgroupResourceLimitsUnavailableError
	if !errors.As(err, &rlErr) {
		t.Errorf("error type: got %T, want *CgroupResourceLimitsUnavailableError", err)
	}
	_ = pol
}

func TestDefaultWrapCgroupSetup_Unavailable_NotRequired_WarnContinues(t *testing.T) {
	withEBPFHooks(t)
	cgPath := t.TempDir()
	enabled := false
	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = false
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.Network.EBPF.Enabled = true
	// ebpf.required defaults false.

	app := newAppWithFakeCgroupManager(t, cfg, cgPath)
	fake := app.cgroupMgr.(*fakeCgroupManagerForAPITest)
	fake.mode = limits.ModeUnavailable
	fake.applyErr = &limits.CgroupUnavailableError{
		Reason: "probe unavailable: capability gap",
	}

	cleanup, err := defaultWrapCgroupSetupForNotify(context.Background(), app, &session.Session{}, "sess-1", 4242)
	if err != nil {
		t.Fatalf("expected nil error (soft fail), got %v", err)
	}
	if cleanup == nil {
		t.Errorf("expected a non-nil noop cleanup closure")
	}
	_ = cleanup()
}

func TestDefaultWrapCgroupSetup_Unavailable_Required_HardFails(t *testing.T) {
	withEBPFHooks(t)
	cgPath := t.TempDir()
	enabled := false
	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = false
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.Network.EBPF.Enabled = true
	cfg.Sandbox.Network.EBPF.Required = true

	app := newAppWithFakeCgroupManager(t, cfg, cgPath)
	fake := app.cgroupMgr.(*fakeCgroupManagerForAPITest)
	fake.mode = limits.ModeUnavailable
	fake.applyErr = &limits.CgroupUnavailableError{Reason: "probe unavailable"}

	_, err := defaultWrapCgroupSetupForNotify(context.Background(), app, &session.Session{}, "sess-1", 4242)
	if err == nil {
		t.Fatalf("expected error under ebpf.required=true, got nil")
	}
}
```

If `session.Session` doesn't accept a policy engine in this construction shape, look at how other tests in the file attach policy engines to sessions and match that pattern.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/api/ -run TestDefaultWrapCgroupSetup_AttachOnly -v`
Expected: tests fail because either the dispatch is missing or the test fixtures don't exist yet.

- [ ] **Step 3: Update `defaultWrapCgroupSetupForNotify` to dispatch on the new error**

Find the existing call to `applyCgroupV2` inside `defaultWrapCgroupSetupForNotify` (around `wrap.go:846-853`). The current code returns whatever applyCgroupV2 returns. Update it to interpret the error:

```go
cleanup, err := applyCgroupV2(ctx, em, a, sessionID, cmdID, wrapperPID, lim, a.metrics, engine)
if err != nil {
	var unavail *limits.CgroupUnavailableError
	var limUnavail *limits.CgroupResourceLimitsUnavailableError
	switch {
	case errors.As(err, &limUnavail):
		// Operator asked for limits in a host that can only do attach.
		// EventCgroupUnavailableRefusal is emitted by applyCgroupV2 itself;
		// just propagate the error.
		return nil, err
	case errors.As(err, &unavail):
		// Probe Unavailable — soft fail unless required.
		if a.cfg.Sandbox.Network.EBPF.Required {
			return nil, err
		}
		slog.Warn("ebpf: wrap cgroup setup unavailable, continuing without enforcement",
			"reason", unavail.Reason,
			"session_id", sessionID,
		)
		return func() error { return nil }, nil
	default:
		return nil, err
	}
}
return cleanup, nil
```

`applyCgroupV2` is the function returning `(func() error, error)`. Match the actual return shape.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/api/ -run TestDefaultWrapCgroupSetup -v`
Expected: PASS.

- [ ] **Step 5: Run all api tests**

Run: `go test ./internal/api/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/api/wrap.go internal/api/wrap_cgroup_test.go
git commit -m "api: dispatch CgroupResourceLimitsUnavailableError in wrap setup

defaultWrapCgroupSetupForNotify now distinguishes three error returns
from applyCgroupV2:
- CgroupResourceLimitsUnavailableError: propagate (operator wants
  resource limits without cgroups.enabled — contradiction to surface)
- CgroupUnavailableError + !ebpf.required: WARN, continue without
  enforcement
- CgroupUnavailableError + ebpf.required: propagate (hard fail)"
```

---

## Task 9: Widen `cgroups.go` predicate and handle the new error

**Files:**
- Modify: `internal/api/cgroups.go:36-220`

- [ ] **Step 1: Update the activation gate in `applyCgroupV2`**

Find the early-return at the top of `applyCgroupV2` (around line 38):

```go
if cfg == nil || !cfg.Sandbox.Cgroups.Enabled {
	return nil, nil
}
```

Replace with the widened predicate:

```go
needsCgroup := cfg != nil && (cfg.Sandbox.Cgroups.Enabled ||
	cfg.Sandbox.Network.EBPF.Enabled ||
	cfg.Sandbox.Network.EBPF.Enforce ||
	cfg.Sandbox.Network.EBPF.Required)
if !needsCgroup {
	return nil, nil
}
```

- [ ] **Step 2: Adjust the `cgLimits` build so AttachOnly doesn't trip the error path with stale policy limits**

The existing code builds `cgLimits` from `policy.Limits()`. Find the spot (around line 47-54). The behavior we want:

- If `cgroupMgr.Probe().Mode == ModeAttachOnly`: pass `CgroupV2Limits{}` (empty) when policy limits are also empty (the BPF-only common case). When policy limits are non-empty, leave them in `cgLimits` so Apply returns `CgroupResourceLimitsUnavailableError` and the operator sees the contradiction.

The simplest read is: don't filter cgLimits based on mode at all. Apply does the right thing: empty limits in AttachOnly → success; non-empty limits in AttachOnly → CgroupResourceLimitsUnavailableError. Just let the existing build proceed. No change needed beyond Step 1.

- [ ] **Step 3: Add error dispatch around the Apply call**

Find the existing call to `app.cgroupMgr.Apply(...)` in `applyCgroupV2` (around line 68). Today the error handling looks like:

```go
cg, err := app.cgroupMgr.Apply("agentsh-"+sanitizeCgroupTag(sessionID)+"-"+sanitizeCgroupTag(cmdID), pid, cgLimits)
if err != nil {
	var ue *limits.CgroupUnavailableError
	if errors.As(err, &ue) {
		// emit EventCgroupUnavailableRefusal
		// return nil cleanup, err
	}
	return nil, err
}
```

Extend the error-type switch to also recognize `*limits.CgroupResourceLimitsUnavailableError`. The new error gets a distinct refusal event (or reuses `EventCgroupUnavailableRefusal` with a different `reason` field — whichever matches the existing event taxonomy).

```go
cg, err := app.cgroupMgr.Apply(name, pid, cgLimits)
if err != nil {
	var ue *limits.CgroupUnavailableError
	var rlue *limits.CgroupResourceLimitsUnavailableError
	switch {
	case errors.As(err, &rlue):
		ev := types.Event{
			ID:        uuid.NewString(),
			Timestamp: time.Now().UTC(),
			Type:      string(events.EventCgroupUnavailableRefusal),
			SessionID: sessionID,
			CommandID: cmdID,
			Fields: map[string]any{
				"reason":             rlue.Reason,
				"resource_limits_unavailable": true,
				"max_memory_mb":      lim.MaxMemoryMB,
				"cpu_quota_pct":      lim.CPUQuotaPercent,
				"pids_max":           lim.PidsMax,
			},
		}
		_ = app.store.AppendEvent(ctx, ev)
		app.broker.Publish(ev)
		return nil, err
	case errors.As(err, &ue):
		// existing handling unchanged
		...
	default:
		return nil, err
	}
}
```

Match the exact structure of the existing `CgroupUnavailableError` event emission (the field names and event constants).

- [ ] **Step 4: Build and run tests**

Run: `go test ./internal/api/`
Expected: existing tests still pass; tests added in Task 8 still pass.

- [ ] **Step 5: Add a per-exec test for the AttachOnly success path**

If `internal/api/cgroups_linux_test.go` doesn't already test `applyCgroupV2` end-to-end with a mocked manager, add one:

```go
func TestApplyCgroupV2_AttachOnly_NoLimits_Succeeds(t *testing.T) {
	// Configure App with cgroups.enabled=false, ebpf.enabled=true.
	// Mock cgroupMgr to return a CgroupV2 with ModeAttachOnly.
	// Call applyCgroupV2 with empty policy.Limits.
	// Assert: cleanup is non-nil; ebpfAttachConnectToCgroup was called.
}
```

Reuse the existing mock pattern (`ebpfAttachConnectToCgroup` is already a var for substitution per `cgroups.go:29`).

- [ ] **Step 6: Run all api tests**

Run: `go test ./internal/api/`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/api/cgroups.go internal/api/cgroups_linux_test.go
git commit -m "api: applyCgroupV2 dispatches CgroupResourceLimitsUnavailableError

The activation gate widens to include ebpf.* triggers (same predicate as
wrap.go). When Apply returns *CgroupResourceLimitsUnavailableError,
applyCgroupV2 emits an EventCgroupUnavailableRefusal event tagged with
resource_limits_unavailable=true and returns the error to the caller."
```

---

## Task 10: Split the `cgroups-v2` capability check

**Files:**
- Modify: `internal/capabilities/check.go`
- Modify: `internal/capabilities/check_cgroups_linux.go`
- Test: extend or add `internal/capabilities/check_cgroups_test.go`

- [ ] **Step 1: Write failing test**

Create or extend `internal/capabilities/check_cgroups_test.go`:

```go
//go:build linux

package capabilities

import (
	"testing"

	"github.com/agentsh/agentsh/internal/limits"
)

func TestCheckCgroupsV2ResourceLimits_NestedAvailable(t *testing.T) {
	cacheCgroupProbe(&limits.CgroupProbeResult{
		Mode:   limits.ModeNested,
		Reason: "test fixture",
	})
	r := realCheckCgroupsV2ResourceLimits()
	if !r.Available {
		t.Errorf("Nested should be Available=true; got %+v", r)
	}
	if r.Feature != "cgroups_v2_resource_limits" {
		t.Errorf("Feature: got %q, want %q", r.Feature, "cgroups_v2_resource_limits")
	}
}

func TestCheckCgroupsV2ResourceLimits_AttachOnly_NotAvailable(t *testing.T) {
	cacheCgroupProbe(&limits.CgroupProbeResult{
		Mode:   limits.ModeAttachOnly,
		Reason: "attach-only test fixture",
	})
	r := realCheckCgroupsV2ResourceLimits()
	if r.Available {
		t.Errorf("AttachOnly should NOT report resource_limits Available; got %+v", r)
	}
}

func TestCheckCgroupsV2ResourceLimits_Unavailable(t *testing.T) {
	cacheCgroupProbe(&limits.CgroupProbeResult{
		Mode:   limits.ModeUnavailable,
		Reason: "test fixture",
	})
	r := realCheckCgroupsV2ResourceLimits()
	if r.Available {
		t.Errorf("Unavailable should NOT report Available; got %+v", r)
	}
}
```

- [ ] **Step 2: Run test to verify failures**

Run: `go test ./internal/capabilities/ -run TestCheckCgroupsV2ResourceLimits -v`
Expected: FAIL — `undefined: realCheckCgroupsV2ResourceLimits`.

- [ ] **Step 3: Rename the check**

In `internal/capabilities/check.go`:

- Rename `realCheckCgroupsV2` → `realCheckCgroupsV2ResourceLimits`.
- Rename the `checkCgroupsV2` var (line 31) → `checkCgroupsV2ResourceLimits`.
- Update `CheckAll`'s usage (line 104) accordingly.

In the renamed function, change the Available mapping to require `Mode in {Nested, TopLevel}` explicitly:

```go
func realCheckCgroupsV2ResourceLimits() CheckResult {
	probe := probeCgroupsV2()
	// Available iff the host can actually enforce resource limits, not
	// merely "cgroup v2 is mounted." ModeAttachOnly is reported as
	// not-available here; the new ebpf_cgroup_attach check tracks attach
	// feasibility separately.
	available := false
	if last := LastCgroupProbe(); last != nil {
		available = last.Mode == limits.ModeNested || last.Mode == limits.ModeTopLevel
	}
	return CheckResult{
		Feature:   "cgroups_v2_resource_limits",
		Available: available,
		Error:     probeAsError(probe, available),
	}
}
```

`probeAsError` is a small helper that returns a structured error when Available=false and the probe carries a reason. Inline its logic if the existing patterns don't have a similar helper.

Also adjust `internal/capabilities/check_cgroups_linux.go::probeCgroupsV2`: the `Available` field there determines whether the wrapper indicates "anything at all about cgroups works." It can keep its current meaning (`!= ModeUnavailable`) because two different consumers want different views.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/capabilities/ -run TestCheckCgroupsV2ResourceLimits -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/capabilities/check.go internal/capabilities/check_cgroups_linux.go internal/capabilities/check_cgroups_test.go
git commit -m "capabilities: split cgroups-v2 check into resource_limits-only

realCheckCgroupsV2 → realCheckCgroupsV2ResourceLimits. Reports
Available=true only when the probe lands on Nested or TopLevel mode.
ModeAttachOnly reports Available=false here — operators querying for
'can I set resource limits' get an accurate negative. Attach feasibility
moves to a new check in the next commit."
```

---

## Task 11: Add `ebpf_cgroup_attach` capability check

**Files:**
- Modify: `internal/capabilities/check.go`
- Modify: `internal/capabilities/check_ebpf_linux.go`
- Test: extend `internal/capabilities/check_cgroups_test.go` or new `check_ebpf_attach_test.go`

- [ ] **Step 1: Write failing test**

```go
func TestCheckEBPFCgroupAttach_AttachOnlyAvailable(t *testing.T) {
	cacheCgroupProbe(&limits.CgroupProbeResult{
		Mode:   limits.ModeAttachOnly,
		Reason: "test fixture",
	})
	// Stub the eBPF kernel-support probe to "supported".
	checkeBPF = func() CheckResult { return CheckResult{Feature: "ebpf", Available: true} }
	t.Cleanup(func() { checkeBPF = realCheckeBPF })

	r := realCheckEBPFCgroupAttach()
	if !r.Available {
		t.Errorf("AttachOnly + ebpf-supported should be Available=true; got %+v", r)
	}
	if r.Feature != "ebpf_cgroup_attach" {
		t.Errorf("Feature: got %q, want %q", r.Feature, "ebpf_cgroup_attach")
	}
}

func TestCheckEBPFCgroupAttach_UnavailableMode(t *testing.T) {
	cacheCgroupProbe(&limits.CgroupProbeResult{
		Mode:   limits.ModeUnavailable,
		Reason: "test fixture",
	})
	checkeBPF = func() CheckResult { return CheckResult{Feature: "ebpf", Available: true} }
	t.Cleanup(func() { checkeBPF = realCheckeBPF })

	r := realCheckEBPFCgroupAttach()
	if r.Available {
		t.Errorf("Mode=Unavailable should be Available=false; got %+v", r)
	}
}

func TestCheckEBPFCgroupAttach_KernelUnsupported(t *testing.T) {
	cacheCgroupProbe(&limits.CgroupProbeResult{Mode: limits.ModeNested})
	checkeBPF = func() CheckResult { return CheckResult{Feature: "ebpf", Available: false} }
	t.Cleanup(func() { checkeBPF = realCheckeBPF })

	r := realCheckEBPFCgroupAttach()
	if r.Available {
		t.Errorf("ebpf unsupported should be Available=false; got %+v", r)
	}
}
```

- [ ] **Step 2: Add the new check function**

In `internal/capabilities/check.go`:

```go
var checkEBPFCgroupAttach = realCheckEBPFCgroupAttach

func realCheckEBPFCgroupAttach() CheckResult {
	ebpfResult := checkeBPF()
	var mode limits.CgroupMode = limits.ModeUnavailable
	if last := LastCgroupProbe(); last != nil {
		mode = last.Mode
	}
	available := ebpfResult.Available &&
		(mode == limits.ModeNested || mode == limits.ModeTopLevel || mode == limits.ModeAttachOnly)
	r := CheckResult{
		Feature:   "ebpf_cgroup_attach",
		Available: available,
	}
	if !available {
		switch {
		case !ebpfResult.Available:
			r.Error = fmt.Errorf("eBPF kernel support unavailable: %v", ebpfResult.Error)
		default:
			r.Error = fmt.Errorf("cgroup attach feasibility unavailable: probe mode is %q", mode)
		}
	}
	return r
}
```

- [ ] **Step 3: Wire it into `CheckAll`**

In `CheckAll(cfg)`, add a clause after the existing eBPF check:

```go
if cfg.Sandbox.Network.EBPF.Enabled || cfg.Sandbox.Network.EBPF.Enforce || cfg.Sandbox.Network.EBPF.Required {
	result := checkEBPFCgroupAttach()
	result.ConfigKey = "sandbox.network.ebpf.enabled"
	result.Suggestion = "See docs/ebpf.md for capability requirements (CAP_BPF, /sys/fs/bpf, CONFIG_CGROUP_BPF)"
	if !result.Available && cfg.Sandbox.Network.EBPF.Required {
		failures = append(failures, result)
	}
}
```

Note: only `required=true` causes `CheckAll` to record this as a failure. `enabled=true` alone is best-effort, matching the soft-fail design.

- [ ] **Step 4: Verify**

Run: `go test ./internal/capabilities/ -run TestCheckEBPFCgroupAttach -v`
Expected: PASS.

Run: `go test ./internal/capabilities/`
Expected: PASS (existing tests still green).

- [ ] **Step 5: Commit**

```bash
git add internal/capabilities/check.go internal/capabilities/check_ebpf_linux.go internal/capabilities/check_cgroups_test.go
git commit -m "capabilities: add ebpf_cgroup_attach check

New CheckResult key ebpf_cgroup_attach reports Available=true iff
- eBPF kernel support is present (probeEBPF passes), AND
- the cgroup probe lands on a mode where attach is feasible
  (Nested, TopLevel, or AttachOnly).

CheckAll treats ebpf_cgroup_attach failures as fatal only when
ebpf.required=true (matches the runtime soft-fail design)."
```

---

## Task 12: Add tips entries for the new capability keys

**Files:**
- Modify: `internal/capabilities/tips.go`
- Test: existing tips test file (find via `grep -rn "TestTips" internal/capabilities/`)

- [ ] **Step 1: Add tip entries**

In `internal/capabilities/tips.go`, find the existing tip definitions block (the map keyed by `CheckKey`). Add:

```go
"cgroups_v2_resource_limits": {
	{Tip: Tip{
		Feature: "cgroups_v2_resource_limits",
		Impact:  "Resource limits (memory/cpu/pids) cannot be enforced for sessions",
		Action:  "Required only if you want resource limits. On stock Docker, add a docker.service drop-in:\n  # /etc/systemd/system/docker.service.d/cgroup-delegate.conf\n  [Service]\n  Delegate=memory pids cpu\nThen `systemctl daemon-reload && systemctl restart docker`. eBPF network enforcement does NOT require this.",
	}},
},

"ebpf_cgroup_attach": {
	{Tip: Tip{
		Feature: "ebpf_cgroup_attach",
		Impact:  "Network rules (domain-based denies) won't enforce against subprocesses",
		Action:  "eBPF cgroup_connect requires CAP_BPF (or CAP_SYS_ADMIN), /sys/fs/bpf mounted, and kernel CONFIG_CGROUP_BPF. Check `agentsh detect` output for the specific blocker.",
	}},
},
```

Also rename the existing `cgroups_v2` tip key entries to `cgroups_v2_resource_limits` (search the file for `"cgroups_v2"` usages and update). The tip lines themselves stay accurate but should now point operators at the Delegate= drop-in as the resource-limits fix, not the eBPF fix.

- [ ] **Step 2: Update tip-mapping tests**

Find `internal/capabilities/tips_test.go` and verify tests assert against the new keys. Update any test that referenced `cgroups_v2` to `cgroups_v2_resource_limits`.

- [ ] **Step 3: Run**

Run: `go test ./internal/capabilities/`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/capabilities/tips.go internal/capabilities/tips_test.go
git commit -m "capabilities: tips for cgroups_v2_resource_limits + ebpf_cgroup_attach

cgroups_v2_resource_limits tips point operators at the systemd
docker.service Delegate= drop-in needed for stock Docker.

ebpf_cgroup_attach tips list CAP_BPF, /sys/fs/bpf, and CONFIG_CGROUP_BPF
as the requirements specific to the attach path."
```

---

## Task 13: Update `docs/ebpf.md`

**Files:**
- Modify: `docs/ebpf.md`

- [ ] **Step 1: Rewrite the Configuration callout**

Replace the existing `> **Prerequisite:** the eBPF runtime is attached inside the cgroup-setup path, so sandbox.cgroups.enabled: true is required...` callout (from #346) with:

```markdown
> **`sandbox.cgroups.enabled: true` is optional for eBPF enforcement.**
> The eBPF cgroup_connect program attaches to a per-session cgroup created
> by agentsh. When `cgroups.enabled: false` and `ebpf.{enabled,enforce}: true`,
> agentsh probes the host for "attach-only" cgroup feasibility (mkdir +
> attach pid without enabling resource controllers) and uses that path
> if available. Set `cgroups.enabled: true` only if you also want resource
> limits (memory, cpu, pids). If the operator wants strict enforcement
> guarantees, set `sandbox.network.ebpf.required: true` — startup fails
> closed if neither path works.
```

Remove the now-incorrect `cgroups.enabled: true # REQUIRED for eBPF activation` from the example YAML and adjust the comment.

- [ ] **Step 2: Reframe the "Stock Docker host-side prerequisite" section**

The existing section reads as a hard requirement. Rewrite it as a resource-limits-specific guide:

```markdown
### Stock Docker host-side prerequisite for resource limits (optional)

If you set `sandbox.cgroups.enabled: true` to get memory/cpu/pids
resource limits, stock Docker has an extra step: container scopes
ship with empty `cgroup.subtree_control`, and writing `+memory` from
inside the container returns `ENOTSUP` even with `CAP_SYS_ADMIN`. The
agentsh cgroup manager will fail to enable the `memory` controller
and refuse commands that request resource limits. `agentsh detect`
surfaces this as:

  RESOURCE LIMITS
    cgroups_v2_resource_limits  ✗  unavailable: enable controller "memory" failed: ENOTSUP

Fix on the host:

  # /etc/systemd/system/docker.service.d/cgroup-delegate.conf
  [Service]
  Delegate=memory pids cpu

Then `systemctl daemon-reload && systemctl restart docker` and rerun
the container.

**Not required for eBPF network enforcement.** With `cgroups.enabled:
false, ebpf.enabled: true`, agentsh activates attach-only mode and
the BPF cgroup_connect program runs without any controllers enabled.
`--cap-add SYS_ADMIN --cap-add BPF -v /sys/fs/bpf:/sys/fs/bpf:rw` on
`docker run` are still required for the attach itself.
```

- [ ] **Step 3: Verify markdown renders cleanly**

Run: `git diff docs/ebpf.md | head -100`
Expected: changes look sensible. No accidental link or code-block damage.

- [ ] **Step 4: Commit**

```bash
git add docs/ebpf.md
git commit -m "docs(ebpf): cgroups.enabled is optional for BPF enforcement

The Configuration callout from #346 is reworded: sandbox.cgroups.enabled
is now optional for eBPF enforcement (set it only if you want resource
limits). The Stock Docker subsection is reframed as a resource-limits
guide, with an explicit note that BPF enforcement does NOT require the
docker.service Delegate= drop-in."
```

---

## Final verification

- [ ] **Step 1: Full test suite**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 2: Cross-compile checks (per `CLAUDE.md`)**

Run: `GOOS=windows go build ./... && GOOS=darwin go build ./...`
Expected: clean.

- [ ] **Step 3: vet**

Run: `go vet ./internal/limits/ ./internal/api/ ./internal/capabilities/`
Expected: clean.

- [ ] **Step 4: Open PR**

Open a PR titled `feat(ebpf): attach-only cgroup mode (#347)`. PR body references the spec at `docs/superpowers/specs/2026-05-17-bpf-only-cgroup-design.md` and itemizes the user-facing changes (capability key split, behavior change for `cgroups.enabled=false + ebpf.enabled=true`, hard-fail location move for `ebpf.required + Unavailable`).

---

## Spec coverage check

Spec sections traced to tasks:

- Section A (Architecture overview) → all tasks.
- Section B (Probe & ModeAttachOnly) → Tasks 1, 3.
- Section C (Apply branching) → Task 5.
- Section C (Call-site predicate widening) → Tasks 4, 6, 7, 9.
- Section D (Failure & required matrix) → Task 6 (startup hard-fail), Task 8 (wrap-time dispatch).
- Section E (Logs) → Task 6.
- Section E (`agentsh detect` output split) → Tasks 10, 11.
- Section E (Tips ladder) → Task 12.
- Section F (Testing) → tests across Tasks 3, 5, 8, 9, 10, 11.
- Section G (Migration & compatibility) → docs in Task 13; behavior changes called out in commit messages.
