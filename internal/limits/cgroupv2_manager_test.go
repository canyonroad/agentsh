//go:build linux

package limits

import (
	"context"
	"errors"
	"strings"
	"syscall"
	"testing"
)

func TestManagerApply_NestedWritesLimits(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "cpu memory pids")

	m, err := newCgroupManagerFS(context.Background(), f, own, false)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if m.Probe().Mode != ModeNested {
		t.Fatalf("mode: %q", m.Probe().Mode)
	}

	cg, err := m.Apply("agentsh-sess-cmd", 4242, CgroupV2Limits{MaxMemoryBytes: 16 << 20, PidsMax: 64})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if cg == nil || !strings.HasPrefix(cg.Path, own+"/") {
		t.Fatalf("nested cgroup path: %q (want prefix %q)", cg.Path, own)
	}
	data, _ := f.ReadFile(cg.Path + "/memory.max")
	if string(data) != "16777216" {
		t.Fatalf("memory.max: got %q, want 16777216", data)
	}
	data, _ = f.ReadFile(cg.Path + "/pids.max")
	if string(data) != "64" {
		t.Fatalf("pids.max: got %q, want 64", data)
	}
	data, _ = f.ReadFile(cg.Path + "/cgroup.procs")
	if string(data) != "4242" {
		t.Fatalf("cgroup.procs: got %q, want 4242", data)
	}
}

func TestManagerApply_TopLevelWritesUnderSlice(t *testing.T) {
	f := newFakeCgroupFS()
	seedHealthyRoot(f)
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu memory pids")
	f.seedFile(own+"/cgroup.subtree_control", "")
	f.openErrs[own+"/cgroup.subtree_control:write"] = syscall.EBUSY
	f.seedFile("/sys/fs/cgroup/agentsh.slice/memory.max", "max")

	m, err := newCgroupManagerFS(context.Background(), f, own, false)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if m.Probe().Mode != ModeTopLevel {
		t.Fatalf("mode: %q", m.Probe().Mode)
	}

	cg, err := m.Apply("agentsh-sess-cmd", 1234, CgroupV2Limits{MaxMemoryBytes: 8 << 20})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !strings.HasPrefix(cg.Path, DefaultSliceDir+"/") {
		t.Fatalf("top-level cgroup path: %q (want prefix %q)", cg.Path, DefaultSliceDir)
	}
}

func TestManagerApply_UnavailableNoLimitsAllows(t *testing.T) {
	f := newFakeCgroupFS()
	f.seedFile("/sys/fs/cgroup/cgroup.controllers", "cpu pids") // no memory
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu pids")

	m, err := newCgroupManagerFS(context.Background(), f, own, false)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if m.Probe().Mode != ModeUnavailable {
		t.Fatalf("mode: %q", m.Probe().Mode)
	}

	cg, err := m.Apply("agentsh-sess-cmd", 1234, CgroupV2Limits{})
	if err != nil {
		t.Fatalf("apply with empty limits should succeed, got %v", err)
	}
	if cg != nil {
		t.Fatalf("expected nil cgroup in unavailable mode with no limits, got %+v", cg)
	}
}

func TestManagerApply_UnavailableWithLimitsRefuses(t *testing.T) {
	f := newFakeCgroupFS()
	f.seedFile("/sys/fs/cgroup/cgroup.controllers", "cpu pids")
	own := "/sys/fs/cgroup/system.slice/agentsh.service"
	f.seedFile(own+"/cgroup.controllers", "cpu pids")

	m, err := newCgroupManagerFS(context.Background(), f, own, false)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	_, err = m.Apply("agentsh-sess-cmd", 1234, CgroupV2Limits{MaxMemoryBytes: 8 << 20})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	var ue *CgroupUnavailableError
	if !errors.As(err, &ue) {
		t.Fatalf("expected *CgroupUnavailableError, got %T: %v", err, err)
	}
	if !strings.Contains(ue.Reason, "memory") {
		t.Fatalf("reason should mention missing memory: %q", ue.Reason)
	}
}

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

	// Make the per-command child memory.max write fail (deterministic path from the name arg).
	childMemMax := DefaultSliceDir + "/agentsh-sess-cmd/memory.max"
	f.writeErrs[childMemMax] = syscall.EPERM

	_, err = m.Apply("agentsh-sess-cmd", 1234, CgroupV2Limits{MaxMemoryBytes: 8 << 20})
	var rlErr *CgroupResourceLimitsUnavailableError
	if !errors.As(err, &rlErr) {
		t.Fatalf("error type: got %T (%v), want *CgroupResourceLimitsUnavailableError", err, err)
	}
	if _, statErr := f.Stat(DefaultSliceDir + "/agentsh-sess-cmd"); statErr == nil {
		t.Errorf("orphan child cgroup dir left behind after EPERM write")
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
