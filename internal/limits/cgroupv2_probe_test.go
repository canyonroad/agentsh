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

func TestProbe_LeafMove_MkdirFails_FallbackTopLevel(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "")
	f.openErrsOnce[own+"/cgroup.subtree_control:write"] = syscall.EBUSY
	// Pre-create own/leaf so mkdir returns EEXIST (tolerated),
	// then block the cgroup.procs write to simulate permission failure.
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
