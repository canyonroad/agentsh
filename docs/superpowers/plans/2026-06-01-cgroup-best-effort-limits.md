# Graceful Degradation for Unenforceable cgroup Limits (#411) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the shell shim from fail-closing every command (`exit 126`) on hosts where the nested cgroup's `memory.max` is not writable, by making the probe honest, classifying the EPERM write error, and adding an opt-in best-effort degrade policy.

**Architecture:** Three layers. (1) The startup probe write-tests a child `memory.max` so it downgrades out of `ModeTopLevel` honestly. (2) `CgroupManager.Apply` classifies an EPERM `.max` write as the typed `CgroupResourceLimitsUnavailableError` (backstop). (3) `applyCgroupV2` degrades that typed error to a warning + no-op when `sandbox.cgroups.best_effort: true` **and** no eBPF enforcement is configured; otherwise the deliberate fail-closed behavior is unchanged. A separate, independent fix downgrades a per-exec wrapper log line that pollutes command stderr.

**Tech Stack:** Go, cgroup v2, `internal/limits` (build-tagged `//go:build linux`), `internal/api`, `internal/config`, `internal/events`.

**Reference spec:** `docs/superpowers/specs/2026-06-01-cgroup-best-effort-limits-design.md`

---

## File Structure

| File | Responsibility | Change |
|------|----------------|--------|
| `internal/config/config.go` | config schema | add `BestEffort bool` to `SandboxCgroupsConfig` |
| `internal/config/config_test.go` | config parse test | assert `best_effort` parses |
| `internal/events/types.go` | event taxonomy | add `EventCgroupLimitsDegraded` |
| `internal/limits/cgroupv2_probe.go` | startup probe | write-test child `memory.max` in `tryTopLevel` |
| `internal/limits/cgroup_fs_fake_test.go` | test fake | add `writeErrUnder` (ancestor-keyed write failure) |
| `internal/limits/cgroupv2_probe_test.go` | probe tests | non-writable child → not `ModeTopLevel` |
| `internal/limits/cgroupv2_manager.go` | per-command apply | classify EPERM `.max` write; remove orphan dir |
| `internal/limits/cgroupv2_manager_test.go` | manager tests | EPERM write → typed error + dir removed |
| `internal/api/cgroups.go` | wrap-time cgroup setup | best-effort degrade branch |
| `internal/api/cgroups_linux_test.go` | api tests | degrade succeeds; eBPF keeps strict |
| `internal/netmonitor/unix/seccomp_linux.go` | filter install | downgrade per-exec "filter loaded" to Debug |

---

## Task 1: Add `best_effort` config field

**Files:**
- Modify: `internal/config/config.go:485-491`
- Test: `internal/config/config_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/config/config_test.go` (near the existing cgroups assertions around line 93):

```go
func TestConfig_CgroupsBestEffortParses(t *testing.T) {
	yaml := `
sandbox:
  cgroups:
    enabled: true
    best_effort: true
`
	cfg, err := Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.Sandbox.Cgroups.BestEffort {
		t.Fatalf("sandbox.cgroups.best_effort: got false, want true")
	}
}
```

> Note: confirm the package's loader entrypoint. If `Load([]byte)` does not exist, mirror the helper used by the adjacent test at `config_test.go:93` (it already loads a config and reads `cfg.Sandbox.Cgroups.Enabled`). Use the same loader.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestConfig_CgroupsBestEffortParses -v`
Expected: FAIL — `cfg.Sandbox.Cgroups.BestEffort` undefined (compile error).

- [ ] **Step 3: Add the field**

In `internal/config/config.go`, modify `SandboxCgroupsConfig`:

```go
type SandboxCgroupsConfig struct {
	Enabled bool `yaml:"enabled"`
	// BasePath is a cgroupfs directory under which per-command cgroups will be created.
	// If empty, agentsh will default to the current process cgroup.
	// Note: this should be a path under /sys/fs/cgroup (or relative to the current process cgroup dir).
	BasePath string `yaml:"base_path"`
	// BestEffort, when true, degrades unenforceable per-command resource limits
	// (e.g. memory.max EPERM on a non-writable nested cgroup) to a logged warning
	// and runs the command WITHOUT the limit, instead of fail-closing the wrap.
	// Defaults to false (fail-closed) to preserve the resource-limit guarantee.
	// Ignored when eBPF enforcement is configured: the cgroup egress path stays strict.
	// See issue #411.
	BestEffort bool `yaml:"best_effort"`
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/config/ -run TestConfig_CgroupsBestEffortParses -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(#411): add sandbox.cgroups.best_effort config field"
```

---

## Task 2: Add `cgroup_limits_degraded` event type

**Files:**
- Modify: `internal/events/types.go:150-154`, `:273-277`, and the `AllEventTypes` list (around `:279`)

- [ ] **Step 1: Add the constant**

In `internal/events/types.go`, extend the cgroup event block:

```go
// Cgroup v2 probe and enforcement events (see issue #197).
const (
	EventCgroupMode               EventType = "cgroup_mode"
	EventCgroupOrphansReaped      EventType = "cgroup_orphans_reaped"
	EventCgroupUnavailableRefusal EventType = "cgroup_unavailable_refusal"
	// EventCgroupLimitsDegraded is emitted when sandbox.cgroups.best_effort is on
	// and a per-command resource limit could not be enforced; the command runs
	// without the limit. See issue #411.
	EventCgroupLimitsDegraded EventType = "cgroup_limits_degraded"
)
```

- [ ] **Step 2: Register its category**

In the category map (around line 273-277), add:

```go
	EventCgroupUnavailableRefusal: "cgroup",
	EventCgroupLimitsDegraded:     "cgroup",
```

- [ ] **Step 3: Add to `AllEventTypes`**

Find the line in `AllEventTypes` (around line 318) listing `EventCgroupMode, EventCgroupOrphansReaped, EventCgroupUnavailableRefusal,` and append `EventCgroupLimitsDegraded`:

```go
	EventCgroupMode, EventCgroupOrphansReaped, EventCgroupUnavailableRefusal,
	EventCgroupLimitsDegraded,
```

- [ ] **Step 4: Build to verify**

Run: `go build ./internal/events/`
Expected: builds clean.

> If the events package has a test asserting `len(AllEventTypes)` or round-tripping every type's category, run `go test ./internal/events/` and update the expected count/coverage to include the new type.

- [ ] **Step 5: Commit**

```bash
git add internal/events/types.go
git commit -m "feat(#411): add cgroup_limits_degraded event type"
```

---

## Task 3: Probe write-tests child `memory.max` (honest mode)

**Files:**
- Modify: `internal/limits/cgroupv2_probe.go` (`tryTopLevel`, around `:333-342`; add helper near `probeNestedWritability` at `:253`)
- Modify: `internal/limits/cgroup_fs_fake_test.go` (add `writeErrUnder`)
- Test: `internal/limits/cgroupv2_probe_test.go`

**Context:** `tryTopLevel` currently only `Stat`s `memory.max` as a canary (it confirms the file exists, never that it is writable). On Freestyle the file exists but writes EPERM. All callers of `tryTopLevel` already wrap the result in `maybeUpgradeToAttachOnly` (`cgroupv2_probe.go:118,127,144,167`), so returning `ModeUnavailable` from `tryTopLevel` will be auto-upgraded to `ModeAttachOnly` when pid-attach is feasible — which routes per-command applies through the typed `CgroupResourceLimitsUnavailableError`.

- [ ] **Step 1: Add `writeErrUnder` to the test fake**

In `internal/limits/cgroup_fs_fake_test.go`, add a field to `fakeCgroupFS` (after `mkdirErrUnder`):

```go
	// writeErrUnder injects an error returned by WriteFile for any path whose
	// ancestor directory equals a key. Used to simulate hosts where a child
	// cgroup can be created but its memory.max is not writable (#411).
	writeErrUnder map[string]error
```

Initialize it in `newFakeCgroupFS()`:

```go
		mkdirErrUnder:        map[string]error{},
		writeErrUnder:        map[string]error{},
```

In `WriteFile` (the method at `:91`), add the ancestor check at the top of the function, before the existing `writeErrs` lookup:

```go
func (f *fakeCgroupFS) WriteFile(p string, data []byte, perm os.FileMode) error {
	p = path.Clean(p)
	for anc := path.Dir(p); anc != "/" && anc != "."; anc = path.Dir(anc) {
		if err, ok := f.writeErrUnder[anc]; ok {
			return &fs.PathError{Op: "write", Path: p, Err: err}
		}
	}
	// ... existing body (writeErrs lookup, etc.) unchanged ...
```

> Confirm `path` and `io/fs` are already imported in this file (they are — `path.Clean` and `fs.PathError` are used elsewhere in the fake).

- [ ] **Step 2: Write the failing probe test**

Add to `internal/limits/cgroupv2_probe_test.go`. Mirror the existing top-level setup (see the test seeding `agentsh.slice/memory.max` around line 64-95):

```go
func TestProbe_TopLevelMemoryMaxNotWritable_DowngradesFromTopLevel(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "")
	f.openErrs[own+"/cgroup.subtree_control:write"] = syscall.EBUSY // force fallback to top-level
	f.seedFile(DefaultSliceDir+"/memory.max", "max")                // canary exists
	f.writeErrUnder[DefaultSliceDir] = syscall.EPERM                // but child writes EPERM

	// permitAttachOnly=false so the result is not upgraded; we assert the raw downgrade.
	res, err := ProbeCgroupsV2(context.Background(), f, own, false)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Mode == ModeTopLevel {
		t.Fatalf("mode: got ModeTopLevel, want a downgraded mode (memory.max not writable)")
	}
}

func TestProbe_TopLevelMemoryMaxNotWritable_UpgradesToAttachOnly(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "")
	f.openErrs[own+"/cgroup.subtree_control:write"] = syscall.EBUSY
	f.seedFile(DefaultSliceDir+"/memory.max", "max")
	f.writeErrUnder[DefaultSliceDir] = syscall.EPERM

	// permitAttachOnly=true: attach feasibility is checked against `own`, which
	// allows mkdir + cgroup.procs writes, so the result upgrades to attach-only.
	res, err := ProbeCgroupsV2(context.Background(), f, own, true)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Mode != ModeAttachOnly {
		t.Fatalf("mode: got %q, want ModeAttachOnly", res.Mode)
	}
}
```

> Confirm the probe entrypoint name/signature. From `cgroupv2_manager.go:37` it is `ProbeCgroupsV2(ctx, fs, ownHint, permitAttachOnly)`. If `seedHealthyRoot`/`DefaultSliceDir`/`openErrs` usage differs, copy the exact setup from the passing test `TestManagerApply_TopLevelWritesUnderSlice` in `cgroupv2_manager_test.go:49`.

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/limits/ -run 'TestProbe_TopLevelMemoryMaxNotWritable' -v`
Expected: FAIL — both currently return `ModeTopLevel` because the probe never tests writability.

- [ ] **Step 4: Add the write-test helper**

In `internal/limits/cgroupv2_probe.go`, add near `probeNestedWritability` (`:253`):

```go
// probeTopLevelLimitWritability verifies that a child cgroup created under
// sliceDir accepts a write to its memory.max. On hosts where the slice exists
// with controller files present but the nested cgroup is not writable (e.g.
// Freestyle Firecracker), mkdir of the child succeeds yet writing memory.max
// returns EPERM. Stat'ing memory.max (the old canary) does not catch this.
// Writing the value "max" is a safe no-op the kernel always accepts when the
// file is writable. The probe child is removed before returning. See #411.
func probeTopLevelLimitWritability(fs cgroupFS, sliceDir string) error {
	name := fmt.Sprintf("agentsh.limit-probe-%d-%d", os.Getpid(), time.Now().UnixNano())
	probeDir := filepath.Join(sliceDir, name)
	if err := fs.Mkdir(probeDir, 0o755); err != nil {
		return fmt.Errorf("mkdir probe child: %w", err)
	}
	writeErr := fs.WriteFile(filepath.Join(probeDir, "memory.max"), []byte("max"), 0o644)
	_ = fs.Remove(probeDir)
	if writeErr != nil {
		return fmt.Errorf("write child memory.max: %w", writeErr)
	}
	return nil
}
```

- [ ] **Step 5: Wire it into `tryTopLevel`**

In `internal/limits/cgroupv2_probe.go`, replace the canary block at `:333-342` so that after confirming `memory.max` exists, it also checks writability. The new code:

```go
	if _, err := fs.Stat(filepath.Join(DefaultSliceDir, "memory.max")); err != nil {
		// memory.max is the canary: if it's missing, controller files weren't created
		// even though mkdir succeeded — enforcement is not possible here.
		return &CgroupProbeResult{
			Mode:      ModeUnavailable,
			Reason:    fmt.Sprintf("%s; %s missing controller files after mkdir", nestedFailureReason, DefaultSliceDir),
			OwnCgroup: own,
			SliceDir:  DefaultSliceDir,
		}, nil
	}
	// The canary file exists, but on nested cgroups it may not be writable
	// (mkdir of a child succeeds, memory.max write EPERMs). Verify before
	// claiming ModeTopLevel; callers upgrade ModeUnavailable to ModeAttachOnly
	// when pid-attach is still feasible. See #411.
	if werr := probeTopLevelLimitWritability(fs, DefaultSliceDir); werr != nil {
		return &CgroupProbeResult{
			Mode:      ModeUnavailable,
			Reason:    fmt.Sprintf("%s; %s child memory.max not writable: %v", nestedFailureReason, DefaultSliceDir, werr),
			OwnCgroup: own,
			SliceDir:  DefaultSliceDir,
		}, nil
	}
```

- [ ] **Step 6: Run the new tests to verify they pass**

Run: `go test ./internal/limits/ -run 'TestProbe_TopLevelMemoryMaxNotWritable' -v`
Expected: PASS — downgrade test gets a non-top-level mode; upgrade test gets `ModeAttachOnly`.

- [ ] **Step 7: Run the full limits suite to catch regressions**

Run: `go test ./internal/limits/ -v`
Expected: PASS. The existing `ModeTopLevel` tests (e.g. `TestManagerApply_TopLevelWritesUnderSlice`) still pass because the probe's random child write succeeds in the fake (no `writeErrUnder` set).

- [ ] **Step 8: Commit**

```bash
git add internal/limits/cgroupv2_probe.go internal/limits/cgroupv2_probe_test.go internal/limits/cgroup_fs_fake_test.go
git commit -m "fix(#411): probe write-tests child memory.max so top-level mode is honest"
```

---

## Task 4: Classify EPERM `.max` write as typed error + clean orphan dir

**Files:**
- Modify: `internal/limits/cgroupv2_manager.go:96-100` (and the pids/cpu writes for consistency)
- Test: `internal/limits/cgroupv2_manager_test.go`

**Context:** Backstop for hosts that change after the probe snapshot. Currently an EPERM `memory.max` write returns a plain `fmt.Errorf`, which downstream falls through the generic abort path. We classify EPERM/EACCES as `CgroupResourceLimitsUnavailableError` and remove the just-created (empty) child dir to avoid orphan accumulation.

- [ ] **Step 1: Write the failing test**

Add to `internal/limits/cgroupv2_manager_test.go` (mirror `TestManagerApply_TopLevelWritesUnderSlice` at `:49`):

```go
func TestManagerApply_TopLevelMemoryMaxWriteEPERM_ReturnsTypedErrorAndCleansUp(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "")
	f.openErrs[own+"/cgroup.subtree_control:write"] = syscall.EBUSY
	f.seedFile(DefaultSliceDir+"/memory.max", "max")

	m, err := newCgroupManagerFS(context.Background(), f, own, false)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if m.Probe().Mode != ModeTopLevel {
		t.Fatalf("precondition: mode %q, want ModeTopLevel", m.Probe().Mode)
	}

	// Now make the per-command child memory.max write fail (deterministic path).
	childMemMax := DefaultSliceDir + "/agentsh-sess-cmd/memory.max"
	f.writeErrs[childMemMax] = syscall.EPERM

	_, err = m.Apply("agentsh-sess-cmd", 1234, CgroupV2Limits{MaxMemoryBytes: 8 << 20})
	var rlErr *CgroupResourceLimitsUnavailableError
	if !errors.As(err, &rlErr) {
		t.Fatalf("error type: got %T (%v), want *CgroupResourceLimitsUnavailableError", err, err)
	}
	// The empty child dir must have been removed.
	if _, statErr := f.Stat(DefaultSliceDir + "/agentsh-sess-cmd"); statErr == nil {
		t.Errorf("orphan child cgroup dir left behind after EPERM write")
	}
}
```

> The Probe in `newCgroupManagerFS` runs the Task 3 write-test against a *random* child and succeeds (no `writeErrUnder` set), so the mode is `ModeTopLevel`. We then set `writeErrs` on the *deterministic* per-command path used by `Apply` (the `name` arg, sanitized), so only the real apply write fails.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/limits/ -run TestManagerApply_TopLevelMemoryMaxWriteEPERM -v`
Expected: FAIL — error is a plain `fmt.Errorf`, not the typed error; and the dir is left behind.

- [ ] **Step 3: Classify the error and clean up**

In `internal/limits/cgroupv2_manager.go`, replace the three `.max` write blocks (`:96-111`) so a permission failure returns the typed error after removing the empty dir. Add `"io/fs"` to imports if not present (for `fs.PathError` matching via `errors.Is` with `syscall.EPERM`/`EACCES`). Implementation:

```go
	writeLimit := func(file string, val []byte) error {
		if err := m.fs.WriteFile(filepath.Join(dir, file), val, 0o644); err != nil {
			if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
				// Host won't permit the limit write even though mkdir succeeded
				// (non-writable nested cgroup). Remove the empty child so we don't
				// accumulate orphans, and surface the deliberate typed error so
				// callers can apply best-effort policy instead of a generic abort.
				_ = m.fs.Remove(dir)
				return &CgroupResourceLimitsUnavailableError{
					Reason: fmt.Sprintf("write %s (mode=%s, dir=%s): %v", file, m.probe.Mode, dir, err),
					Limits: lim,
				}
			}
			return fmt.Errorf("write %s (mode=%s, dir=%s): %w", file, m.probe.Mode, dir, err)
		}
		return nil
	}

	if lim.MaxMemoryBytes > 0 {
		if err := writeLimit("memory.max", []byte(strconv.FormatInt(lim.MaxMemoryBytes, 10))); err != nil {
			return nil, err
		}
	}
	if lim.PidsMax > 0 {
		if err := writeLimit("pids.max", []byte(strconv.Itoa(lim.PidsMax))); err != nil {
			return nil, err
		}
	}
	if lim.CPUQuotaPct > 0 {
		q, p := cpuMaxFromPct(lim.CPUQuotaPct)
		if err := writeLimit("cpu.max", []byte(fmt.Sprintf("%d %d", q, p))); err != nil {
			return nil, err
		}
	}
```

> `errors` and `syscall` are already imported in this file (see `:6-11`). `os/io fs` is not needed — `errors.Is(err, syscall.EPERM)` unwraps the `*fs.PathError` returned by both the real `osCgroupFS.WriteFile` and the fake.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/limits/ -run TestManagerApply_TopLevelMemoryMaxWriteEPERM -v`
Expected: PASS

- [ ] **Step 5: Run the full limits suite**

Run: `go test ./internal/limits/`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/limits/cgroupv2_manager.go internal/limits/cgroupv2_manager_test.go
git commit -m "fix(#411): classify EPERM cgroup limit write as typed error, clean orphan dir"
```

---

## Task 5: Best-effort degrade in `applyCgroupV2`

**Files:**
- Modify: `internal/api/cgroups.go:73-127` (the error switch)
- Test: `internal/api/cgroups_linux_test.go`

**Context:** When `Apply` returns `CgroupResourceLimitsUnavailableError` or `CgroupUnavailableError`, degrade to a no-op when `best_effort` is set AND no eBPF flag is on. eBPF egress depends on the cgroup, so any eBPF flag keeps the strict path. Test harness `newAppWithFakeCgroupManager` + `fakeCgroupManagerForAPITest{mode, applyErr}` already exists (see `cgroups_linux_test.go:477`).

- [ ] **Step 1: Write the failing tests**

Add to `internal/api/cgroups_linux_test.go`:

```go
// best_effort + no eBPF + limits-unavailable → degrade (nil err, no-op cleanup, event emitted)
func TestApplyCgroupV2_BestEffort_LimitsUnavailable_Degrades(t *testing.T) {
	withEBPFHooks(t)
	cgPath := t.TempDir()

	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = true
	cfg.Sandbox.Cgroups.BestEffort = true
	// eBPF off — pure resource-limit case.

	app := newAppWithFakeCgroupManager(t, cfg, cgPath)
	fake := app.cgroupMgr.(*fakeCgroupManagerForAPITest)
	fake.mode = limits.ModeAttachOnly
	fake.applyErr = &limits.CgroupResourceLimitsUnavailableError{
		Reason: "child memory.max not writable: EPERM",
		Limits: limits.CgroupV2Limits{MaxMemoryBytes: 16 << 20},
	}

	cleanup, err := applyCgroupV2(context.Background(),
		storeEmitter{store: app.store, broker: app.broker}, app,
		"sess", "cmd", 1234, policy.Limits{MaxMemoryMB: 16}, nil, nil)
	if err != nil {
		t.Fatalf("expected degrade (nil err), got %v", err)
	}
	if cleanup == nil {
		t.Fatal("expected non-nil no-op cleanup")
	}
	_ = cleanup()
}

// best_effort=false → still fail closed
func TestApplyCgroupV2_BestEffortDisabled_LimitsUnavailable_FailsClosed(t *testing.T) {
	withEBPFHooks(t)
	cgPath := t.TempDir()

	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = true
	cfg.Sandbox.Cgroups.BestEffort = false

	app := newAppWithFakeCgroupManager(t, cfg, cgPath)
	fake := app.cgroupMgr.(*fakeCgroupManagerForAPITest)
	fake.mode = limits.ModeAttachOnly
	fake.applyErr = &limits.CgroupResourceLimitsUnavailableError{
		Reason: "child memory.max not writable: EPERM",
		Limits: limits.CgroupV2Limits{MaxMemoryBytes: 16 << 20},
	}

	_, err := applyCgroupV2(context.Background(),
		storeEmitter{store: app.store, broker: app.broker}, app,
		"sess", "cmd", 1234, policy.Limits{MaxMemoryMB: 16}, nil, nil)
	var rlErr *limits.CgroupResourceLimitsUnavailableError
	if !errors.As(err, &rlErr) {
		t.Fatalf("expected typed error, got %T (%v)", err, err)
	}
}

// best_effort=true BUT eBPF enabled → egress boundary preserved, still fail closed
func TestApplyCgroupV2_BestEffort_WithEBPF_FailsClosed(t *testing.T) {
	withEBPFHooks(t)
	cgPath := t.TempDir()

	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = true
	cfg.Sandbox.Cgroups.BestEffort = true
	cfg.Sandbox.Network.EBPF.Enabled = true // egress boundary present

	app := newAppWithFakeCgroupManager(t, cfg, cgPath)
	fake := app.cgroupMgr.(*fakeCgroupManagerForAPITest)
	fake.mode = limits.ModeAttachOnly
	fake.applyErr = &limits.CgroupResourceLimitsUnavailableError{
		Reason: "child memory.max not writable: EPERM",
		Limits: limits.CgroupV2Limits{MaxMemoryBytes: 16 << 20},
	}

	_, err := applyCgroupV2(context.Background(),
		storeEmitter{store: app.store, broker: app.broker}, app,
		"sess", "cmd", 1234, policy.Limits{MaxMemoryMB: 16}, nil, nil)
	if err == nil {
		t.Fatal("expected fail-closed with eBPF enabled, got nil")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/api/ -run 'TestApplyCgroupV2_BestEffort' -v`
Expected: the `_Degrades` test FAILs (error currently propagates); the other two may already pass — that's fine, they lock in behavior.

- [ ] **Step 3: Implement the degrade branch**

In `internal/api/cgroups.go`, add a helper above `applyCgroupV2`:

```go
// cgroupBestEffortDegradable reports whether an unenforceable resource-limit
// error should degrade to a no-op (run without the limit) rather than fail
// closed. Degradation requires sandbox.cgroups.best_effort AND the absence of
// any eBPF flag — eBPF egress enforcement rides on the cgroup and must stay
// strict. See issue #411.
func cgroupBestEffortDegradable(cfg *config.Config) bool {
	if cfg == nil || !cfg.Sandbox.Cgroups.BestEffort {
		return false
	}
	e := cfg.Sandbox.Network.EBPF
	return !e.Enabled && !e.Enforce && !e.Required
}
```

Then, inside `applyCgroupV2`'s error switch (`:76-127`), add a degrade check at the top of **both** the `rlue` and `ue` cases, before emitting the refusal event and returning the error. For the `rlue` case:

```go
		case errors.As(err, &rlue):
			if cgroupBestEffortDegradable(cfg) {
				slog.Warn("cgroup: resource limits unenforceable; running without them (best_effort)",
					"session_id", sessionID, "command_id", cmdID, "reason", rlue.Reason,
					"max_memory_mb", lim.MaxMemoryMB, "cpu_quota_pct", lim.CPUQuotaPercent, "pids_max", lim.PidsMax)
				ev := types.Event{
					ID:        uuid.NewString(),
					Timestamp: time.Now().UTC(),
					Type:      string(events.EventCgroupLimitsDegraded),
					SessionID: sessionID,
					CommandID: cmdID,
					Fields: map[string]any{
						"reason":        rlue.Reason,
						"max_memory_mb": lim.MaxMemoryMB,
						"cpu_quota_pct": lim.CPUQuotaPercent,
						"pids_max":      lim.PidsMax,
					},
				}
				_ = emit.AppendEvent(ctx, ev)
				emit.Publish(ev)
				return func() error { return nil }, nil
			}
			ev := types.Event{
				// ... existing refusal event unchanged ...
```

Apply the identical degrade prelude to the `ue` (`CgroupUnavailableError`) case, referencing `ue.Reason` instead of `rlue.Reason`.

> `cfg` is already in scope (`cfg := app.cfg` at `:37`). `slog`, `events`, `types`, `uuid`, `time` are already imported.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/api/ -run 'TestApplyCgroupV2_BestEffort' -v`
Expected: PASS (all three).

- [ ] **Step 5: Run the api suite**

Run: `go test ./internal/api/`
Expected: PASS — existing `TestDefaultWrapCgroupSetup_*` tests unaffected (they set `best_effort=false` implicitly via zero value, or enable eBPF).

- [ ] **Step 6: Commit**

```bash
git add internal/api/cgroups.go internal/api/cgroups_linux_test.go
git commit -m "fix(#411): best-effort degrade for unenforceable cgroup limits (no eBPF)"
```

---

## Task 6: Stop the per-exec "seccomp: filter loaded" line polluting command stderr

**Files:**
- Modify: `internal/netmonitor/unix/seccomp_linux.go:518-523`

**Context (independent of the cgroup fix):** This `slog.Info` is emitted by the `agentsh-unixwrap` wrapper process, whose slog default handler writes to **the wrapped command's stderr** (the wrapper uses stdlib `log`→stderr; slog default → stderr at Info). The wrapper has no log-forwarding channel to the server (server.log lines come from the server process), so per the spec's fallback we downgrade this single per-exec line to `Debug`. Operators who need the #369 `wait_killable` diagnostic can raise the wrapper's slog level.

- [ ] **Step 1: Downgrade the line**

In `internal/netmonitor/unix/seccomp_linux.go`, change the `slog.Info` at `:518` to `slog.Debug`:

```go
	// Per-exec diagnostic. Emitted from the unixwrap wrapper whose slog lands on
	// the wrapped command's stderr; keep at Debug so machine-readable command
	// output (e.g. `agentsh detect --output json`) is not corrupted. #369/#411.
	slog.Debug("seccomp: filter loaded",
		"fd", rawFd,
		"wait_killable", gotWaitKill,
		"wait_killable_source", cfg.WaitKillableSource,
		"kernel_probe_supports", ProbeWaitKillable(),
		"libseccomp_runtime", libVer)
```

- [ ] **Step 2: Verify no test asserts this line at Info**

Run: `grep -rn "filter loaded" internal/ cmd/ --include=*_test.go`
Expected: no test asserts the level/presence of this line. (If one does, update it to expect Debug.)

- [ ] **Step 3: Build the package**

Run: `go build ./internal/netmonitor/unix/`
Expected: builds clean.

- [ ] **Step 4: Commit**

```bash
git add internal/netmonitor/unix/seccomp_linux.go
git commit -m "fix(#411): downgrade per-exec 'seccomp: filter loaded' to Debug (stderr pollution)"
```

---

## Task 7: Full verification

- [ ] **Step 1: Build everything**

Run: `go build ./...`
Expected: clean.

- [ ] **Step 2: Cross-compile for Windows (per CLAUDE.md)**

Run: `GOOS=windows go build ./...`
Expected: clean. (The `internal/limits` cgroup code is `//go:build linux`; ensure nothing leaked into a cross-platform file.)

- [ ] **Step 3: Run the full test suite**

Run: `go test ./...`
Expected: PASS. Known pre-existing flakes unrelated to this change (per project memory): `TestFlushLoop_PeriodicSync` (Windows timer), `TestStore_*EmitsTransportLossOnWire` (load-sensitive), DB-proxy spine `-race` tests, and 3 local-env-only failures. Do not chase those.

- [ ] **Step 4: Run targeted suites once more**

Run: `go test ./internal/limits/ ./internal/api/ ./internal/config/ ./internal/events/ ./internal/netmonitor/unix/`
Expected: PASS.

- [ ] **Step 5: roborev the branch (per project workflow)**

Per project memory (`feedback_roborev_between_tasks`): run roborev on the branch and fix all issues above low before proceeding to PR.

Use the `roborev-review-branch` skill. Address findings, re-review until clean.

- [ ] **Step 6: Final commit / ready for PR**

Ensure the working tree is clean and all commits are present:

```bash
git log --oneline -8
git status
```

---

## Self-Review Notes (addressed)

- **Spec §1 (probe write-test):** Task 3. Reuses `maybeUpgradeToAttachOnly` via existing `tryTopLevel` callers — no new wiring of the upgrade path needed.
- **Spec §2 (classify EPERM + orphan cleanup):** Task 4, including the explicit `Remove(dir)` the spec self-review added.
- **Spec §3 (best_effort knob, eBPF gate):** Tasks 1 + 5. eBPF gate verified by `TestApplyCgroupV2_BestEffort_WithEBPF_FailsClosed`.
- **Spec §4 (sequencing):** No `wrap.go` change — degrade returns nil from `applyCgroupV2`, handshake proceeds. Confirmed via `defaultWrapCgroupSetupForNotify` → `applyCgroupV2` call chain.
- **Spec §5 (stderr):** Task 6.
- **Spec "non-permission errors still fail closed":** Task 4's `writeLimit` only classifies EPERM/EACCES; other errors keep the `%w` plain-error path → generic failure (unchanged).
- **Event type name consistency:** `EventCgroupLimitsDegraded` / string `"cgroup_limits_degraded"` used identically in Tasks 2 and 5.
- **Config field name consistency:** `BestEffort` / yaml `best_effort` used identically in Tasks 1 and 5.
