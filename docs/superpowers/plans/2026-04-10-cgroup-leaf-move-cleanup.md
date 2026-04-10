# Cgroup Auto-Leaf-Move and Legacy Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make cgroup enforcement work out-of-the-box under systemd by auto-moving agentsh into a leaf cgroup when EBUSY is detected, and remove all deprecated cgroup code paths.

**Architecture:** Insert a leaf-move step into the existing `ProbeCgroupsV2` decision tree (between "enable fails" and "try top-level"). Remove `ApplyCgroupV2`, `LinuxLimiter`, and `platform/linux/ResourceLimiter` — all unused in production. `CgroupManager` becomes the single cgroup code path.

**Tech Stack:** Go, cgroup v2, Linux kernel APIs

**Spec:** `docs/superpowers/specs/2026-04-10-cgroup-leaf-move-cleanup-design.md`

---

## File Map

**Create:** none

**Modify:**
- `internal/limits/cgroupv2_probe.go` — add `LeafMoved` field to `CgroupProbeResult`, add `tryLeafMove` function, call it from `ProbeCgroupsV2` on EBUSY
- `internal/limits/cgroupv2_other.go` — add `LeafMoved` field to non-Linux stub struct
- `internal/limits/cgroup_fs_fake_test.go` — add `openErrsOnce` map for "fail once then succeed" test pattern
- `internal/limits/cgroupv2_probe_test.go` — add 4 leaf-move test cases
- `internal/limits/cgroupv2_linux.go` — remove deprecated `ApplyCgroupV2` function (lines 55-107)
- `internal/limits/cgroupv2_linux_test.go` — remove `TestApplyCgroupV2_CreatesAndCleansUp`
- `internal/server/server.go` — add `leaf_moved` to cgroup_mode event fields
- `internal/platform/linux/platform.go` — remove `resources` field, make `Resources()` return nil
- `internal/netmonitor/ebpf/integration_test.go` — replace `ApplyCgroupV2` with inline cgroup creation
- `internal/netmonitor/ebpf/pnacl_integration_test.go` — replace `ApplyCgroupV2` with inline cgroup creation

**Delete:**
- `internal/limits/limiter_linux.go`
- `internal/platform/linux/resources.go`
- `internal/platform/linux/resources_test.go`

---

### Task 1: Add LeafMoved field to CgroupProbeResult

**Files:**
- Modify: `internal/limits/cgroupv2_probe.go:30-39`
- Modify: `internal/limits/cgroupv2_other.go:39-47`

- [ ] **Step 1: Add LeafMoved to the Linux CgroupProbeResult**

In `internal/limits/cgroupv2_probe.go`, add the `LeafMoved` field to the struct:

```go
type CgroupProbeResult struct {
	Mode        CgroupMode
	Reason      string
	OwnCgroup   string // absolute path to the process's own cgroup dir
	SliceDir    string // absolute path to /sys/fs/cgroup/agentsh.slice (top-level mode only; empty otherwise)
	IOAvailable bool   // true if the io controller is usable in the chosen mode
	// OrphansReaped is populated in top-level mode when the probe removed
	// leftover unpopulated child cgroups from a prior agentsh run.
	OrphansReaped []string
	LeafMoved     bool // true if the probe moved the process to OwnCgroup/leaf to resolve EBUSY
}
```

- [ ] **Step 2: Add LeafMoved to the non-Linux stub**

In `internal/limits/cgroupv2_other.go`, add the same field to the stub struct:

```go
// CgroupProbeResult is the output of ProbeCgroupsV2.
type CgroupProbeResult struct {
	Mode          CgroupMode
	Reason        string
	OwnCgroup     string
	SliceDir      string
	IOAvailable   bool
	OrphansReaped []string
	LeafMoved     bool
}
```

- [ ] **Step 3: Verify build**

Run: `go build ./internal/limits/...`
Expected: compiles cleanly — no code references `LeafMoved` yet.

- [ ] **Step 4: Verify cross-compile**

Run: `GOOS=windows go build ./internal/limits/...`
Expected: compiles (the non-Linux stub is used).

- [ ] **Step 5: Commit**

```bash
git add internal/limits/cgroupv2_probe.go internal/limits/cgroupv2_other.go
git commit -m "limits: add LeafMoved field to CgroupProbeResult"
```

---

### Task 2: Add openErrsOnce to fakeCgroupFS

The leaf-move tests need "fail first time, succeed on retry" behavior. The existing `openErrs` map is permanent — once an error is injected, every call fails. Add an `openErrsOnce` map that auto-clears after first use.

**Files:**
- Modify: `internal/limits/cgroup_fs_fake_test.go`

- [ ] **Step 1: Add the openErrsOnce field**

In `internal/limits/cgroup_fs_fake_test.go`, add the field to the struct and initialize it in the constructor:

```go
type fakeCgroupFS struct {
	// files maps absolute path -> entry. An entry with isDir=true represents a directory.
	files map[string]*fakeEntry
	// writeErrs optionally returns a specific error for WriteFile(path) or OpenFile(path) calls.
	writeErrs map[string]error
	// openErrs mirrors writeErrs but for OpenFile (subtree_control writes).
	openErrs map[string]error
	// openErrsOnce is like openErrs but the entry is deleted after the first hit,
	// allowing subsequent calls to the same path to succeed. Used for leaf-move
	// tests where the first enableControllers call fails with EBUSY and the
	// retry after leaf-move succeeds.
	openErrsOnce map[string]error
}
```

Update `newFakeCgroupFS`:

```go
func newFakeCgroupFS() *fakeCgroupFS {
	return &fakeCgroupFS{
		files:        map[string]*fakeEntry{"/sys/fs/cgroup": {isDir: true}},
		writeErrs:    map[string]error{},
		openErrs:     map[string]error{},
		openErrsOnce: map[string]error{},
	}
}
```

- [ ] **Step 2: Check openErrsOnce in fakeWriter.WriteString**

In `fakeWriter.WriteString`, check `openErrsOnce` before `openErrs`. If found, use the error and delete the entry:

```go
func (w *fakeWriter) WriteString(s string) (int, error) {
	key := w.path + ":write"
	if err, ok := w.fs.openErrsOnce[key]; ok {
		delete(w.fs.openErrsOnce, key)
		return 0, &fs.PathError{Op: "write", Path: w.path, Err: err}
	}
	if err, ok := w.fs.openErrs[key]; ok {
		return 0, &fs.PathError{Op: "write", Path: w.path, Err: err}
	}
	w.buf.WriteString(s)
	// Append to the underlying file content on every write, mimicking
	// cgroup subtree_control semantics: the kernel stores the controller
	// name without the leading "+"/"-" prefix.
	e := w.fs.files[w.path]
	if e == nil {
		return 0, &fs.PathError{Op: "write", Path: w.path, Err: syscall.ENOENT}
	}
	token := strings.TrimPrefix(s, "+")
	token = strings.TrimPrefix(token, "-")
	sep := ""
	if len(e.content) > 0 && !bytes.HasSuffix(e.content, []byte(" ")) {
		sep = " "
	}
	e.content = append(e.content, []byte(sep+token)...)
	return len(s), nil
}
```

- [ ] **Step 3: Run existing tests to verify no regression**

Run: `go test ./internal/limits/ -run 'TestFakeCgroupFS|TestProbe|TestManager' -v`
Expected: all existing tests pass unchanged.

- [ ] **Step 4: Commit**

```bash
git add internal/limits/cgroup_fs_fake_test.go
git commit -m "limits: add openErrsOnce to fakeCgroupFS for leaf-move tests"
```

---

### Task 3: Write leaf-move probe tests (TDD — tests first)

**Files:**
- Modify: `internal/limits/cgroupv2_probe_test.go`

- [ ] **Step 1: Write test — EBUSY triggers leaf-move, succeeds, returns ModeNested**

Add to `internal/limits/cgroupv2_probe_test.go`:

```go
func TestProbe_LeafMove_EBUSYSucceeds(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "")
	// First enableControllers call fails with EBUSY (process in cgroup);
	// after leaf-move, the retry succeeds.
	f.openErrsOnce[own+"/cgroup.subtree_control:write"] = syscall.EBUSY
	// Seed cgroup.procs so the leaf-move write (WriteFile) succeeds.
	f.seedFile(own+"/cgroup.procs", "1234")

	res, err := ProbeCgroupsV2(context.Background(), f, own)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Mode != ModeNested {
		t.Fatalf("mode: got %q, want nested", res.Mode)
	}
	if !res.LeafMoved {
		t.Fatalf("expected LeafMoved=true")
	}
	if !strings.Contains(res.Reason, "leaf-moved") {
		t.Fatalf("reason should contain 'leaf-moved': %q", res.Reason)
	}
	if res.OwnCgroup != own {
		t.Fatalf("OwnCgroup should be %q, got %q", own, res.OwnCgroup)
	}
	// Verify the leaf directory was created.
	if _, err := f.Stat(own + "/leaf"); err != nil {
		t.Fatalf("leaf dir should exist: %v", err)
	}
}
```

- [ ] **Step 2: Write test — EBUSY, leaf mkdir fails, falls through to top-level**

```go
func TestProbe_LeafMove_MkdirFails_FallbackTopLevel(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "")
	f.openErrsOnce[own+"/cgroup.subtree_control:write"] = syscall.EBUSY
	// Make the own dir not exist as a parent for leaf mkdir — leaf mkdir
	// will fail because the parent entry isn't a dir in our fake.
	// Actually: own exists as a dir, so we need to inject a mkdir error.
	// Remove the own dir entry so mkdir of own/leaf fails with ENOENT.
	// But we need own to stay for controller reads... Instead, pre-create
	// own/leaf so mkdir returns EEXIST, then block the cgroup.procs write.
	f.seedDir(own + "/leaf")
	f.writeErrs[own+"/leaf/cgroup.procs"] = syscall.EACCES
	f.seedFile("/sys/fs/cgroup/agentsh.slice/memory.max", "max")

	res, err := ProbeCgroupsV2(context.Background(), f, own)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Mode != ModeTopLevel {
		t.Fatalf("mode: got %q, want top-level", res.Mode)
	}
	if res.LeafMoved {
		t.Fatalf("expected LeafMoved=false")
	}
}
```

- [ ] **Step 3: Write test — EBUSY, leaf-move succeeds but enable retry fails, falls through to top-level**

```go
func TestProbe_LeafMove_RetryEnableFails_FallbackTopLevel(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "")
	// Use permanent openErrs — both the first and retry calls fail.
	f.openErrs[own+"/cgroup.subtree_control:write"] = syscall.EBUSY
	f.seedFile(own+"/cgroup.procs", "1234")
	f.seedFile("/sys/fs/cgroup/agentsh.slice/memory.max", "max")

	res, err := ProbeCgroupsV2(context.Background(), f, own)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Mode != ModeTopLevel {
		t.Fatalf("mode: got %q, want top-level", res.Mode)
	}
	if !strings.Contains(res.Reason, "EBUSY") {
		t.Fatalf("reason should contain EBUSY: %q", res.Reason)
	}
}
```

- [ ] **Step 4: Write test — EACCES skips leaf-move entirely, goes to top-level**

```go
func TestProbe_EACCES_NoLeafMove(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "")
	f.openErrs[own+"/cgroup.subtree_control:write"] = syscall.EACCES
	f.seedFile("/sys/fs/cgroup/agentsh.slice/memory.max", "max")

	res, err := ProbeCgroupsV2(context.Background(), f, own)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Mode != ModeTopLevel {
		t.Fatalf("mode: got %q, want top-level", res.Mode)
	}
	// Verify no leaf directory was created.
	if _, err := f.Stat(own + "/leaf"); err == nil {
		t.Fatalf("leaf dir should NOT exist for EACCES — leaf-move is EBUSY-only")
	}
	if res.LeafMoved {
		t.Fatalf("expected LeafMoved=false for EACCES")
	}
}
```

- [ ] **Step 5: Run tests to verify they fail (TDD red phase)**

Run: `go test ./internal/limits/ -run 'TestProbe_LeafMove|TestProbe_EACCES_NoLeafMove' -v`
Expected: all 4 new tests FAIL — `tryLeafMove` doesn't exist yet.

Note: `TestProbe_LeafMove_RetryEnableFails_FallbackTopLevel` and `TestProbe_EACCES_NoLeafMove` may pass since they test existing fallback behavior (EBUSY → top-level). That's fine — they're guard tests that verify leaf-move doesn't break existing behavior. `TestProbe_LeafMove_EBUSYSucceeds` will definitely fail since it expects `LeafMoved=true`.

- [ ] **Step 6: Commit**

```bash
git add internal/limits/cgroupv2_probe_test.go
git commit -m "limits: add leaf-move probe tests (red phase)"
```

---

### Task 4: Implement leaf-move in ProbeCgroupsV2

**Files:**
- Modify: `internal/limits/cgroupv2_probe.go:59-116`

- [ ] **Step 1: Add the tryLeafMove function**

Add the following function to `internal/limits/cgroupv2_probe.go`, after the `ProbeCgroupsV2` function:

```go
// tryLeafMove handles the EBUSY case: the own cgroup has internal processes
// (including agentsh itself), preventing subtree_control writes. We create a
// "leaf" child cgroup, move the current process into it, and retry enabling
// controllers on the parent. This is the standard pattern for systemd services
// that need to manage child cgroups.
//
// Returns true if the move succeeded and controllers were enabled. On any
// failure, returns false and leaves the caller to try top-level fallback.
func tryLeafMove(fs cgroupFS, own string) bool {
	leafDir := filepath.Join(own, "leaf")
	if err := fs.Mkdir(leafDir, 0o755); err != nil {
		if !errors.Is(err, syscall.EEXIST) {
			return false
		}
	}

	// Move the current process into the leaf cgroup.
	pid := []byte(strconv.Itoa(os.Getpid()))
	if err := fs.WriteFile(filepath.Join(leafDir, "cgroup.procs"), pid, 0o644); err != nil {
		return false
	}

	// Retry enabling controllers now that the parent has no internal processes.
	if err := enableControllersFS(fs, own, requiredControllers); err != nil {
		return false
	}
	return true
}
```

- [ ] **Step 2: Add os and strconv imports**

Add `"os"` and `"strconv"` to the import block at the top of `cgroupv2_probe.go` (if not already present). The current imports are:

```go
import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)
```

- [ ] **Step 3: Insert leaf-move step into ProbeCgroupsV2**

Replace the current step 4–5 block (lines 100–115) in `ProbeCgroupsV2`:

**Before (current code):**
```go
	// Step 4: try to enable the required set.
	enableErr := enableControllersFS(fs, own, requiredControllers)
	if enableErr == nil {
		// Re-read to confirm and to pick up the io flag.
		delegatedNow, _ := readControllerSet(fs, filepath.Join(own, "cgroup.subtree_control"))
		return &CgroupProbeResult{
			Mode:        ModeNested,
			Reason:      "enabled by probe",
			OwnCgroup:   own,
			IOAvailable: contains(delegatedNow, "io"),
		}, nil
	}

	// Step 5: classify the enable failure and fall through to top-level.
	reason := classifyEnableError(enableErr)
	return tryTopLevel(ctx, fs, own, reason)
```

**After (new code):**
```go
	// Step 4: try to enable the required set.
	enableErr := enableControllersFS(fs, own, requiredControllers)
	if enableErr == nil {
		// Re-read to confirm and to pick up the io flag.
		delegatedNow, _ := readControllerSet(fs, filepath.Join(own, "cgroup.subtree_control"))
		return &CgroupProbeResult{
			Mode:        ModeNested,
			Reason:      "enabled by probe",
			OwnCgroup:   own,
			IOAvailable: contains(delegatedNow, "io"),
		}, nil
	}

	// Step 4b: if EBUSY, try leaf-move — create own/leaf, move self there,
	// retry enabling controllers on the now-empty parent.
	if errors.Is(enableErr, syscall.EBUSY) {
		if tryLeafMove(fs, own) {
			delegatedNow, _ := readControllerSet(fs, filepath.Join(own, "cgroup.subtree_control"))
			return &CgroupProbeResult{
				Mode:        ModeNested,
				Reason:      "leaf-moved; enabled by probe",
				OwnCgroup:   own,
				IOAvailable: contains(delegatedNow, "io"),
				LeafMoved:   true,
			}, nil
		}
	}

	// Step 5: classify the enable failure and fall through to top-level.
	reason := classifyEnableError(enableErr)
	return tryTopLevel(ctx, fs, own, reason)
```

- [ ] **Step 4: Run the leaf-move tests**

Run: `go test ./internal/limits/ -run 'TestProbe_LeafMove|TestProbe_EACCES_NoLeafMove' -v`
Expected: all 4 tests PASS.

- [ ] **Step 5: Run all probe and manager tests**

Run: `go test ./internal/limits/ -run 'TestProbe|TestManager' -v`
Expected: all pass — existing tests unaffected.

- [ ] **Step 6: Commit**

```bash
git add internal/limits/cgroupv2_probe.go
git commit -m "limits: add auto-leaf-move on EBUSY in ProbeCgroupsV2"
```

---

### Task 5: Add LeafMoved to server event

**Files:**
- Modify: `internal/server/server.go:426-432`

- [ ] **Step 1: Add leaf_moved to the cgroup_mode event fields**

In `internal/server/server.go`, find the `Fields` map in the cgroup mode event (around line 426) and add the `leaf_moved` field:

```go
				Fields: map[string]any{
					"mode":         string(mgr.Probe().Mode),
					"reason":       mgr.Probe().Reason,
					"own_cgroup":   mgr.Probe().OwnCgroup,
					"slice_dir":    mgr.Probe().SliceDir,
					"io_available": mgr.Probe().IOAvailable,
					"leaf_moved":   mgr.Probe().LeafMoved,
				},
```

- [ ] **Step 2: Verify build**

Run: `go build ./internal/server/...`
Expected: compiles cleanly.

- [ ] **Step 3: Commit**

```bash
git add internal/server/server.go
git commit -m "server: include leaf_moved in cgroup_mode event"
```

---

### Task 6: Delete LinuxLimiter

**Files:**
- Delete: `internal/limits/limiter_linux.go`

- [ ] **Step 1: Delete the file**

```bash
rm internal/limits/limiter_linux.go
```

- [ ] **Step 2: Verify build**

Run: `go build ./internal/limits/...`
Expected: compiles — `LinuxLimiter` had no callers outside its own file. If there are compilation errors, check for imports of `ResourceLimiter`, `ResourceLimits`, `ResourceUsage`, `LimitViolation`, or `LimiterCapabilities` from this file. If these types are defined here and used elsewhere, they'll need to be kept in a separate file. (Based on analysis, they are not — these types are only used within the file itself.)

- [ ] **Step 3: Commit**

```bash
git add -u internal/limits/limiter_linux.go
git commit -m "limits: remove deprecated LinuxLimiter"
```

---

### Task 7: Delete platform/linux ResourceLimiter

**Files:**
- Delete: `internal/platform/linux/resources.go`
- Delete: `internal/platform/linux/resources_test.go`
- Modify: `internal/platform/linux/platform.go:26-34,192-196`

- [ ] **Step 1: Delete resources.go and resources_test.go**

```bash
rm internal/platform/linux/resources.go internal/platform/linux/resources_test.go
```

- [ ] **Step 2: Remove the resources field from Platform struct**

In `internal/platform/linux/platform.go`, remove the `resources` field from the struct:

```go
// Platform implements platform.Platform for Linux.
type Platform struct {
	config      platform.Config
	fs          *Filesystem
	net         *Network
	sandbox     *SandboxManager
	caps        platform.Capabilities
	initialized bool
}
```

- [ ] **Step 3: Simplify Resources() to return nil**

In `internal/platform/linux/platform.go`, replace the `Resources()` method:

```go
// Resources returns nil — cgroup enforcement is handled by CgroupManager in
// the server, not the platform ResourceLimiter interface.
func (p *Platform) Resources() platform.ResourceLimiter {
	return nil
}
```

- [ ] **Step 4: Verify build**

Run: `go build ./internal/platform/linux/...`
Expected: compiles. The `platform.Platform` interface still satisfied since `Resources()` returns `platform.ResourceLimiter` (nil satisfies interface return).

- [ ] **Step 5: Run platform tests**

Run: `go test ./internal/platform/linux/... -v`
Expected: pass (resource-specific tests are deleted; remaining platform tests should pass).

- [ ] **Step 6: Commit**

```bash
git add -u internal/platform/linux/
git commit -m "platform/linux: remove ResourceLimiter, cgroups handled by CgroupManager"
```

---

### Task 8: Remove deprecated ApplyCgroupV2

**Files:**
- Modify: `internal/limits/cgroupv2_linux.go:55-107`
- Modify: `internal/limits/cgroupv2_other.go:24-26`

- [ ] **Step 1: Remove ApplyCgroupV2 from cgroupv2_linux.go**

In `internal/limits/cgroupv2_linux.go`, delete the `ApplyCgroupV2` function (the block from the `// Deprecated:` comment through the closing brace, lines 55-107):

```go
// Deprecated: Use CgroupManager.Apply instead. ApplyCgroupV2 does not probe the
// cgroup hierarchy and silently discards enableControllers errors. It is retained
// only for callers that have not yet migrated (limiter_linux.go, platform/linux).
func ApplyCgroupV2(parentDir string, name string, pid int, lim CgroupV2Limits) (*CgroupV2, error) {
	...
}
```

Delete the entire function including the deprecation comment.

- [ ] **Step 2: Remove ApplyCgroupV2 from cgroupv2_other.go**

In `internal/limits/cgroupv2_other.go`, delete the `ApplyCgroupV2` function (lines 24-26):

```go
func ApplyCgroupV2(parentDir string, name string, pid int, lim CgroupV2Limits) (*CgroupV2, error) {
	return nil, fmt.Errorf("cgroups not supported")
}
```

- [ ] **Step 3: Verify build (expect failures from test files)**

Run: `go build ./internal/limits/...`
Expected: compiles (test files not compiled by `go build`). If compilation fails, check if any non-test production code still references `ApplyCgroupV2`.

- [ ] **Step 4: Commit**

```bash
git add internal/limits/cgroupv2_linux.go internal/limits/cgroupv2_other.go
git commit -m "limits: remove deprecated ApplyCgroupV2"
```

---

### Task 9: Migrate tests off ApplyCgroupV2

**Files:**
- Modify: `internal/limits/cgroupv2_linux_test.go:16-51`
- Modify: `internal/netmonitor/ebpf/integration_test.go:28,69`
- Modify: `internal/netmonitor/ebpf/pnacl_integration_test.go:68,142,240`

- [ ] **Step 1: Remove TestApplyCgroupV2_CreatesAndCleansUp from cgroupv2_linux_test.go**

In `internal/limits/cgroupv2_linux_test.go`, delete the `TestApplyCgroupV2_CreatesAndCleansUp` function (lines 16-51). The equivalent test already exists as `TestManagerApply_CreatesAndCleansUp_Integration` (lines 98-140) which uses `CgroupManager`.

- [ ] **Step 2: Replace ApplyCgroupV2 in integration_test.go**

In `internal/netmonitor/ebpf/integration_test.go`, replace the two `limits.ApplyCgroupV2` calls with inline cgroup creation. These tests only need a cgroup directory — they don't need limit enforcement.

Replace the import of `"github.com/agentsh/agentsh/internal/limits"` with just using `limits.DetectCgroupV2()` for the skip check, and use `os` + `strconv` for the inline cgroup creation.

Add `"strconv"` to the imports.

For the first occurrence (around line 28), replace:

```go
	if _, err := limits.ApplyCgroupV2("/sys/fs/cgroup", filepath.Base(tmp), os.Getpid(), limits.CgroupV2Limits{}); err != nil {
		t.Skipf("cgroup create failed: %v", err)
	}
```

with:

```go
	cgDir := filepath.Join("/sys/fs/cgroup", filepath.Base(tmp))
	if err := os.Mkdir(cgDir, 0o755); err != nil {
		t.Skipf("cgroup mkdir failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cgDir, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		_ = os.Remove(cgDir)
		t.Skipf("cgroup attach failed: %v", err)
	}
```

Apply the same replacement for the second occurrence (around line 69), adjusting the `tmp` variable name as appropriate (it uses `"agentsh-ebpf-deny-test"` instead of `"agentsh-ebpf-test"`).

- [ ] **Step 3: Replace ApplyCgroupV2 in pnacl_integration_test.go**

In `internal/netmonitor/ebpf/pnacl_integration_test.go`, apply the same replacement at all three call sites (around lines 68, 142, 240). Each follows the same pattern. Add `"strconv"` to the imports.

Replace each:

```go
	if _, err := limits.ApplyCgroupV2("/sys/fs/cgroup", filepath.Base(tmp), os.Getpid(), limits.CgroupV2Limits{}); err != nil {
		t.Skipf("cgroup create failed: %v", err)
	}
```

with:

```go
	cgDir := filepath.Join("/sys/fs/cgroup", filepath.Base(tmp))
	if err := os.Mkdir(cgDir, 0o755); err != nil {
		t.Skipf("cgroup mkdir failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cgDir, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		_ = os.Remove(cgDir)
		t.Skipf("cgroup attach failed: %v", err)
	}
```

Note: If `pnacl_integration_test.go` is an internal test (package `ebpf` not `ebpf_test`), it may already import `os` and `strconv`. Check the imports and only add what's missing. Also check if `limits` is still needed — if only `DetectCgroupV2()` is used, keep that import.

- [ ] **Step 4: Verify test compilation**

Run: `go test -run '^$' ./internal/limits/... ./internal/netmonitor/ebpf/...`
Expected: compiles and runs zero tests (the `-run '^$'` matches nothing, but compilation is verified).

- [ ] **Step 5: Run limits unit tests**

Run: `go test ./internal/limits/ -v`
Expected: all pass — the deleted test was redundant with `TestManagerApply_CreatesAndCleansUp_Integration`.

- [ ] **Step 6: Commit**

```bash
git add internal/limits/cgroupv2_linux_test.go internal/netmonitor/ebpf/integration_test.go internal/netmonitor/ebpf/pnacl_integration_test.go
git commit -m "tests: migrate off deprecated ApplyCgroupV2"
```

---

### Task 10: Final verification

- [ ] **Step 1: Full build**

Run: `go build ./...`
Expected: compiles cleanly.

- [ ] **Step 2: Cross-compile verification**

Run: `GOOS=windows go build ./...`
Expected: compiles cleanly (non-Linux stubs used).

- [ ] **Step 3: Full test suite**

Run: `go test ./...`
Expected: all pass.

- [ ] **Step 4: Verify no remaining references to deleted code**

Run: `grep -rn 'ApplyCgroupV2\|LinuxLimiter\|NewLinuxLimiter\|NewResourceLimiter' --include='*.go' . | grep -v '_test.go' | grep -v 'docs/' | grep -v vendor/`
Expected: no matches. (Test files in ebpf may still reference `limits.DetectCgroupV2` which is fine — that function is retained.)

- [ ] **Step 5: Commit (if any fixups needed)**

Only if previous steps revealed issues that required fixes.
