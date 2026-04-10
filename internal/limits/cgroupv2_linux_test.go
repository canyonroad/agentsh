//go:build linux

package limits

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestEnableControllers_ReturnsError(t *testing.T) {
	// Create a fake FS where subtree_control exists but WriteString injects EBUSY.
	f := newFakeCgroupFS()
	f.seedFile("/sys/fs/cgroup/system.slice/agentsh.service/cgroup.subtree_control", "")
	f.openErrs["/sys/fs/cgroup/system.slice/agentsh.service/cgroup.subtree_control:write"] = syscall.EBUSY

	err := enableControllersFS(f, "/sys/fs/cgroup/system.slice/agentsh.service", []string{"cpu", "memory", "pids"})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	var ece *EnableControllersError
	if !errors.As(err, &ece) {
		t.Fatalf("expected *EnableControllersError, got %T: %v", err, err)
	}
	if ece.Controller != "cpu" {
		t.Fatalf("expected first failing controller to be 'cpu', got %q", ece.Controller)
	}
	if !errors.Is(err, syscall.EBUSY) {
		t.Fatalf("expected wrapped EBUSY, got %v", err)
	}
}

func TestEnableControllers_OpenFileFailure(t *testing.T) {
	// When OpenFile itself fails (subtree_control doesn't exist or is inaccessible),
	// the error should use Controller:"*" and wrap the OS error.
	f := newFakeCgroupFS()
	f.seedDir("/sys/fs/cgroup/system.slice/agentsh.service")
	// Do NOT seed cgroup.subtree_control — OpenFile will return ENOENT.

	err := enableControllersFS(f, "/sys/fs/cgroup/system.slice/agentsh.service", []string{"cpu", "memory", "pids"})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	var ece *EnableControllersError
	if !errors.As(err, &ece) {
		t.Fatalf("expected *EnableControllersError, got %T: %v", err, err)
	}
	if ece.Controller != "*" {
		t.Fatalf("expected Controller='*' for open failure, got %q", ece.Controller)
	}
	if !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("expected wrapped ENOENT, got %v", err)
	}
}

func TestManagerApply_CreatesAndCleansUp_Integration(t *testing.T) {
	if !DetectCgroupV2() {
		t.Skip("cgroup v2 not available")
	}

	cmd := exec.Command("sleep", "0.2")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sleep: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	m, err := NewCgroupManager(context.Background(), "")
	if err != nil {
		t.Skipf("cannot construct cgroup manager: %v", err)
	}
	if m.Probe().Mode == ModeUnavailable {
		t.Skipf("cgroup enforcement unavailable: %s", m.Probe().Reason)
	}

	cg, err := m.Apply("agentsh-test-"+strings.ReplaceAll(t.Name(), "/", "_"), cmd.Process.Pid, CgroupV2Limits{
		PidsMax: 100,
	})
	if err != nil {
		t.Skipf("cannot apply cgroup limits in this environment: %v", err)
	}
	if cg == nil || cg.Path == "" {
		t.Fatalf("expected cgroup path")
	}
	if !strings.HasPrefix(cg.Path, "/sys/fs/cgroup") {
		t.Fatalf("unexpected cgroup path: %q", cg.Path)
	}
	if filepath.Base(cg.Path) == "" {
		t.Fatalf("expected basename for cgroup path: %q", cg.Path)
	}

	_ = cmd.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := cg.Close(ctx); err != nil {
		t.Fatalf("close cgroup: %v", err)
	}
}
