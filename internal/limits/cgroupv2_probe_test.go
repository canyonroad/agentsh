//go:build linux

package limits

import (
	"context"
	"strings"
	"syscall"
	"testing"
)

// seedHealthyRoot seeds the root cgroup with all needed controllers already
// delegated. Used as a starting point for tests that then adjust own-cgroup state.
func seedHealthyRoot(f *fakeCgroupFS) {
	f.seedFile("/sys/fs/cgroup/cgroup.controllers", "cpuset cpu io memory pids")
	f.seedFile("/sys/fs/cgroup/cgroup.subtree_control", "cpuset cpu io memory pids")
}

func TestProbe_NestedAlreadyDelegated(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu io memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "cpu io memory pids")

	res, err := ProbeCgroupsV2(context.Background(), f, own)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Mode != ModeNested {
		t.Fatalf("mode: got %q, want nested", res.Mode)
	}
	if res.Reason != "already delegated" {
		t.Fatalf("reason: got %q, want 'already delegated'", res.Reason)
	}
	if !res.IOAvailable {
		t.Fatalf("expected io_available=true")
	}
}

func TestProbe_NestedEnableSucceeds(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "")

	res, err := ProbeCgroupsV2(context.Background(), f, own)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Mode != ModeNested || res.Reason != "enabled by probe" {
		t.Fatalf("mode/reason: got %q/%q, want nested/enabled by probe", res.Mode, res.Reason)
	}
	if err := f.assertSubtreeControl(own+"/cgroup.subtree_control", "cpu", "memory", "pids"); err != nil {
		t.Fatalf("expected subtree_control populated: %v", err)
	}
}

func TestProbe_EnableEBUSY_FallbackToTopLevel(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "")
	// Injected: the enable write fails with EBUSY.
	f.openErrs[own+"/cgroup.subtree_control:write"] = syscall.EBUSY
	// Top-level needs to be ready: slice dir will be created by probe, but we
	// must seed memory.max to appear after mkdir (our fake doesn't auto-create
	// controller files, so we prepopulate the file at the expected path).
	f.seedFile("/sys/fs/cgroup/agentsh.slice/memory.max", "max")

	res, err := ProbeCgroupsV2(context.Background(), f, own)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Mode != ModeTopLevel {
		t.Fatalf("mode: got %q, want top-level", res.Mode)
	}
	if !strings.Contains(res.Reason, "EBUSY") {
		t.Fatalf("reason missing EBUSY: %q", res.Reason)
	}
	if res.SliceDir != DefaultSliceDir {
		t.Fatalf("slice dir: got %q", res.SliceDir)
	}
}

func TestProbe_EnableEACCES_FallbackToTopLevel(t *testing.T) {
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
	if !strings.Contains(res.Reason, "EACCES") {
		t.Fatalf("reason missing EACCES: %q", res.Reason)
	}
}

func TestProbe_TopLevelMissingMemoryController(t *testing.T) {
	f := newFakeCgroupFS()
	// Root is missing memory.
	f.seedFile("/sys/fs/cgroup/cgroup.controllers", "cpu pids")
	f.seedFile("/sys/fs/cgroup/cgroup.subtree_control", "")
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu pids")
	f.seedFile(own+"/cgroup.subtree_control", "")

	res, err := ProbeCgroupsV2(context.Background(), f, own)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Mode != ModeUnavailable {
		t.Fatalf("mode: got %q, want unavailable", res.Mode)
	}
	if !strings.Contains(res.Reason, "memory") {
		t.Fatalf("reason should name missing memory: %q", res.Reason)
	}
}

func TestProbe_TopLevelSliceMissingControllerFiles(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "")
	f.openErrs[own+"/cgroup.subtree_control:write"] = syscall.EBUSY
	// Do NOT seed agentsh.slice/memory.max — our fake mkdir won't auto-create it.

	res, err := ProbeCgroupsV2(context.Background(), f, own)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Mode != ModeUnavailable {
		t.Fatalf("mode: got %q, want unavailable", res.Mode)
	}
	if !strings.Contains(res.Reason, "missing controller files") {
		t.Fatalf("reason should name missing controller files: %q", res.Reason)
	}
}

func TestProbe_TopLevelOrphanReap(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "")
	f.openErrs[own+"/cgroup.subtree_control:write"] = syscall.EBUSY
	f.seedFile("/sys/fs/cgroup/agentsh.slice/memory.max", "max")
	// Orphan A is unpopulated -> should be reaped.
	f.seedFile("/sys/fs/cgroup/agentsh.slice/orphan-A/cgroup.events", "populated 0\nfrozen 0\n")
	// Orphan B is populated -> should be left alone.
	f.seedFile("/sys/fs/cgroup/agentsh.slice/orphan-B/cgroup.events", "populated 1\nfrozen 0\n")

	res, err := ProbeCgroupsV2(context.Background(), f, own)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Mode != ModeTopLevel {
		t.Fatalf("mode: got %q, want top-level", res.Mode)
	}
	if len(res.OrphansReaped) != 1 || res.OrphansReaped[0] != "orphan-A" {
		t.Fatalf("expected orphan-A reaped, got %v", res.OrphansReaped)
	}
	if _, err := f.Stat("/sys/fs/cgroup/agentsh.slice/orphan-A"); err == nil {
		t.Fatalf("orphan-A should have been removed")
	}
	if _, err := f.Stat("/sys/fs/cgroup/agentsh.slice/orphan-B"); err != nil {
		t.Fatalf("orphan-B should still exist: %v", err)
	}
}

func TestProbe_IOControllerOptional(t *testing.T) {
	f := newFakeCgroupFS()
	// Root has everything except io.
	f.seedFile("/sys/fs/cgroup/cgroup.controllers", "cpu memory pids")
	f.seedFile("/sys/fs/cgroup/cgroup.subtree_control", "cpu memory pids")
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "cpu memory pids")

	res, err := ProbeCgroupsV2(context.Background(), f, own)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Mode != ModeNested {
		t.Fatalf("mode: got %q, want nested", res.Mode)
	}
	if res.IOAvailable {
		t.Fatalf("expected io_available=false")
	}
}

func TestProbe_AllOrphansPopulated(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "")
	f.openErrs[own+"/cgroup.subtree_control:write"] = syscall.EBUSY
	f.seedFile("/sys/fs/cgroup/agentsh.slice/memory.max", "max")
	// All orphans are populated (active) — none should be reaped.
	f.seedFile("/sys/fs/cgroup/agentsh.slice/child-A/cgroup.events", "populated 1\nfrozen 0\n")
	f.seedFile("/sys/fs/cgroup/agentsh.slice/child-B/cgroup.events", "populated 1\nfrozen 0\n")

	res, err := ProbeCgroupsV2(context.Background(), f, own)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Mode != ModeTopLevel {
		t.Fatalf("mode: got %q, want top-level", res.Mode)
	}
	if len(res.OrphansReaped) != 0 {
		t.Fatalf("expected no orphans reaped, got %v", res.OrphansReaped)
	}
	// Both children should still exist.
	if _, err := f.Stat("/sys/fs/cgroup/agentsh.slice/child-A"); err != nil {
		t.Fatalf("child-A should still exist: %v", err)
	}
	if _, err := f.Stat("/sys/fs/cgroup/agentsh.slice/child-B"); err != nil {
		t.Fatalf("child-B should still exist: %v", err)
	}
}

func TestProbe_LeafMove_EBUSYSucceeds(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "")
	// First enableControllers call fails with EBUSY (process in cgroup);
	// after leaf-move, the retry succeeds.
	f.openWriteErrsOnce[own+"/cgroup.subtree_control:write"] = syscall.EBUSY
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
	if _, err := f.Stat(own + "/agentsh.leaf"); err != nil {
		t.Fatalf("leaf dir should exist: %v", err)
	}
}

func TestProbe_LeafMove_MkdirFails_FallbackTopLevel(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "")
	f.openWriteErrsOnce[own+"/cgroup.subtree_control:write"] = syscall.EBUSY
	// Pre-create own/leaf so mkdir returns EEXIST (tolerated),
	// then block the cgroup.procs write to simulate permission failure.
	f.seedDir(own + "/agentsh.leaf")
	f.writeErrs[own+"/agentsh.leaf/cgroup.procs"] = syscall.EACCES
	f.seedFile("/sys/fs/cgroup/agentsh.slice/memory.max", "max")

	res, err := ProbeCgroupsV2(context.Background(), f, own)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Mode != ModeTopLevel {
		t.Fatalf("mode: got %q, want top-level", res.Mode)
	}
	if !strings.Contains(res.Reason, "leaf-move failed") {
		t.Fatalf("reason should contain leaf-move failure: %q", res.Reason)
	}
	if res.LeafMoved {
		t.Fatalf("expected LeafMoved=false")
	}
}

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
	// Process was moved to own/leaf even though enable retry failed —
	// LeafMoved should reflect the side-effect.
	if !res.LeafMoved {
		t.Fatalf("expected LeafMoved=true (process was moved even though enable retry failed)")
	}
}

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
	if _, err := f.Stat(own + "/agentsh.leaf"); err == nil {
		t.Fatalf("leaf dir should NOT exist for EACCES — leaf-move is EBUSY-only")
	}
	if res.LeafMoved {
		t.Fatalf("expected LeafMoved=false for EACCES")
	}
}

func TestProbe_LeafMove_IdempotentSecondProbe(t *testing.T) {
	// Regression: after a successful leaf-move, a second probe with the same
	// ownHint (e.g. NewCgroupManager after CheckAll both using the service
	// cgroup path) should find subtree_control already delegated and NOT
	// attempt another leaf-move.
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "")
	f.openWriteErrsOnce[own+"/cgroup.subtree_control:write"] = syscall.EBUSY
	f.seedFile(own+"/cgroup.procs", "1234")

	// First probe: triggers leaf-move.
	res1, err := ProbeCgroupsV2(context.Background(), f, own)
	if err != nil {
		t.Fatalf("probe 1: %v", err)
	}
	if !res1.LeafMoved || res1.Mode != ModeNested {
		t.Fatalf("probe 1: expected leaf-moved nested, got mode=%q leaf=%v", res1.Mode, res1.LeafMoved)
	}

	// Second probe: same ownHint (parent). Subtree_control was enabled by
	// probe 1, so this should see "already delegated" immediately.
	res2, err := ProbeCgroupsV2(context.Background(), f, own)
	if err != nil {
		t.Fatalf("probe 2: %v", err)
	}
	if res2.Mode != ModeNested {
		t.Fatalf("probe 2: expected nested, got %q", res2.Mode)
	}
	if res2.OwnCgroup != own {
		t.Fatalf("probe 2: OwnCgroup should be %q, got %q", own, res2.OwnCgroup)
	}
	if res2.Reason != "already delegated" {
		t.Fatalf("probe 2: expected 'already delegated', got %q", res2.Reason)
	}
	// Verify no leaf/leaf was created.
	if _, err := f.Stat(own + "/agentsh.leaf/agentsh.leaf"); err == nil {
		t.Fatalf("leaf/leaf should NOT exist — probe should be idempotent")
	}
}

// TestProbe_AlreadyDelegated_EEXISTTreatedAsFailure ensures the writability
// probe does NOT treat EEXIST as success. A stale probe directory is no
// proof of current writability — the kernel's permission state may have
// changed since the prior run. Failing closed here is what prevents the
// false-positive availability the probe is designed to catch (roborev #7691
// finding on the original PR).
func TestProbe_AlreadyDelegated_EEXISTTreatedAsFailure(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "cpu memory pids")
	// Every mkdir under own returns EEXIST (simulates a host where probe
	// dirs collide with leftovers — or, more realistically, where the
	// kernel returns EEXIST as a misleading proxy for some other state).
	f.mkdirErrUnder[own] = syscall.EEXIST
	f.seedFile("/sys/fs/cgroup/agentsh.slice/memory.max", "max")

	res, err := ProbeCgroupsV2(context.Background(), f, own)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Mode == ModeNested {
		t.Fatalf("EEXIST under own must NOT be treated as proof of writability; got mode=%q", res.Mode)
	}
	if res.Mode != ModeTopLevel {
		t.Fatalf("expected fallback to top-level, got mode=%q reason=%q", res.Mode, res.Reason)
	}
}

func TestProbe_ExplicitLeafHintNotStripped(t *testing.T) {
	// Verify that an explicit absolute ownHint ending in "leaf" is NOT
	// rewritten — normalization only applies to auto-discovered paths.
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	leafPath := "/sys/fs/cgroup/system.slice/agentsh.service/agentsh.leaf"
	f.seedFile(leafPath+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(leafPath+"/cgroup.subtree_control", "cpu memory pids")

	res, err := ProbeCgroupsV2(context.Background(), f, leafPath)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.OwnCgroup != leafPath {
		t.Fatalf("explicit leaf hint should NOT be stripped: got %q, want %q", res.OwnCgroup, leafPath)
	}
}

// TestProbe_AlreadyDelegated_MkdirDeniedFallsBack covers the OpenComputer
// case: cgroup.subtree_control reports cpu/memory/pids delegated, but
// mkdir within the subtree is denied. Without the writability probe, this
// silently produces per-command cgroup_apply_failed at runtime while
// detect over-reports cgroups_v2 ✓ (canyonroad/agentsh#272).
func TestProbe_AlreadyDelegated_MkdirDeniedFallsBack(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu io memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "cpu io memory pids")
	f.mkdirErrUnder[own] = syscall.EACCES
	// Top-level slice mkdir should also fail (mirrors OC posture).
	f.mkdirErrUnder["/sys/fs/cgroup"] = syscall.EACCES

	res, err := ProbeCgroupsV2(context.Background(), f, own)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Mode != ModeUnavailable {
		t.Fatalf("mode: got %q, want unavailable (subtree mkdir denied + top-level mkdir denied)", res.Mode)
	}
	if !strings.Contains(res.Reason, "subtree delegated but child cgroup mkdir denied") {
		t.Fatalf("reason should explain delegated-but-not-writable: %q", res.Reason)
	}
}

// TestProbe_AlreadyDelegated_MkdirDeniedFallsToTopLevel is the case where
// the nested subtree is read-only-delegated but the top-level slice mkdir
// works — we should land in top-level mode, not unavailable.
func TestProbe_AlreadyDelegated_MkdirDeniedFallsToTopLevel(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "cpu memory pids")
	f.mkdirErrUnder[own] = syscall.EACCES
	// Top-level slice mkdir works; pre-seed memory.max so the slice probe passes.
	f.seedFile("/sys/fs/cgroup/agentsh.slice/memory.max", "max")

	res, err := ProbeCgroupsV2(context.Background(), f, own)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Mode != ModeTopLevel {
		t.Fatalf("mode: got %q, want top-level", res.Mode)
	}
	if !strings.Contains(res.Reason, "subtree delegated but child cgroup mkdir denied") {
		t.Fatalf("reason should explain why nested was rejected: %q", res.Reason)
	}
}

// TestProbe_AlreadyDelegated_MkdirSucceeds_ProbeCleanedUp verifies the
// writability probe leaves no stray directories on the happy path.
func TestProbe_AlreadyDelegated_MkdirSucceeds_ProbeCleanedUp(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu io memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "cpu io memory pids")

	res, err := ProbeCgroupsV2(context.Background(), f, own)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Mode != ModeNested || res.Reason != "already delegated" {
		t.Fatalf("mode/reason: got %q/%q, want nested/already delegated", res.Mode, res.Reason)
	}
	// No agentsh.write-probe-* directories should remain under own.
	entries, err := f.ReadDir(own)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "agentsh.write-probe-") {
			t.Fatalf("probe directory leaked: %s", e.Name())
		}
	}
}

// TestProbe_EnabledByProbe_MkdirDeniedFallsBack covers the case where
// enableControllersFS succeeds (subtree_control is writable) but mkdir
// within the subtree is still denied — same OC failure mode reached
// through a different path.
func TestProbe_EnabledByProbe_MkdirDeniedFallsBack(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "")
	f.mkdirErrUnder[own] = syscall.EACCES
	f.seedFile("/sys/fs/cgroup/agentsh.slice/memory.max", "max")

	res, err := ProbeCgroupsV2(context.Background(), f, own)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Mode != ModeTopLevel {
		t.Fatalf("mode: got %q, want top-level", res.Mode)
	}
	if !strings.Contains(res.Reason, "controllers enabled but child cgroup mkdir denied") {
		t.Fatalf("reason should explain enable-but-not-writable: %q", res.Reason)
	}
}

// TestProbe_LeafMove_MkdirDeniedFallsBack covers the leaf-move path: parent
// hits EBUSY, leaf-move + retry-enable succeeds, but child cgroup mkdir is
// still denied. The probe should also catch this case so the leaf-move
// branch can't over-report nested availability either.
func TestProbe_LeafMove_MkdirDeniedFallsBack(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "")
	// First write to subtree_control fails with EBUSY; retry after leaf-move succeeds.
	f.openWriteErrsOnce[own+"/cgroup.subtree_control:write"] = syscall.EBUSY
	// Block child cgroup mkdir specifically (but allow the leaf cgroup itself,
	// since agentsh.leaf creation happens before the writability probe).
	// We can't easily distinguish the two with mkdirErrUnder, so we accept
	// that the leaf is created first and then block subsequent probes by
	// switching the predicate after leaf creation. The fake doesn't support
	// that natively; instead, verify behavior via top-level fallback path.
	f.mkdirErrUnder[own] = syscall.EACCES
	f.seedFile("/sys/fs/cgroup/agentsh.slice/memory.max", "max")

	// Pre-create the leaf so the EBUSY+leaf-move retry doesn't need to mkdir
	// it (which would also be blocked by mkdirErrUnder[own]).
	f.seedDir(own + "/agentsh.leaf")

	res, err := ProbeCgroupsV2(context.Background(), f, own)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Mode != ModeTopLevel {
		t.Fatalf("mode: got %q, want top-level (probe should reject nested when child mkdir denied)", res.Mode)
	}
	if !strings.Contains(res.Reason, "child cgroup mkdir denied") {
		t.Fatalf("reason should mention the writability failure: %q", res.Reason)
	}
}
