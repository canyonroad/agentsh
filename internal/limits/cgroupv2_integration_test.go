//go:build linux && cgroup_integration

package limits

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Run with:
//   go test -tags cgroup_integration ./internal/limits/... -v
// on a Linux host with privileges to write /sys/fs/cgroup.

func TestIntegration_ProbeReal(t *testing.T) {
	if !DetectCgroupV2() {
		t.Skip("cgroup v2 not mounted")
	}
	m, err := NewCgroupManager(context.Background(), "")
	if err != nil {
		t.Fatalf("NewCgroupManager: %v", err)
	}
	p := m.Probe()
	t.Logf("probe: mode=%s reason=%s own=%s slice=%s io=%v",
		p.Mode, p.Reason, p.OwnCgroup, p.SliceDir, p.IOAvailable)
	switch p.Mode {
	case ModeNested, ModeTopLevel, ModeUnavailable:
	default:
		t.Fatalf("unexpected mode %q", p.Mode)
	}
}

func TestIntegration_TopLevelApplyAndEnforce(t *testing.T) {
	if !DetectCgroupV2() {
		t.Skip("cgroup v2 not mounted")
	}
	m, err := NewCgroupManager(context.Background(), "")
	if err != nil {
		t.Fatalf("NewCgroupManager: %v", err)
	}
	if m.Probe().Mode != ModeTopLevel {
		t.Skipf("not in top-level mode (got %s)", m.Probe().Mode)
	}

	cmd := exec.Command("sleep", "0.2")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sleep: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	cg, err := m.Apply("agentsh-integ-top-level", cmd.Process.Pid, CgroupV2Limits{
		MaxMemoryBytes: 8 << 20,
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = cg.Close(ctx)
	}()
	if !strings.HasPrefix(cg.Path, DefaultSliceDir) {
		t.Fatalf("expected top-level path under %s, got %q", DefaultSliceDir, cg.Path)
	}
	data, err := os.ReadFile(filepath.Join(cg.Path, "memory.max"))
	if err != nil {
		t.Fatalf("read memory.max: %v", err)
	}
	if strings.TrimSpace(string(data)) != "8388608" {
		t.Fatalf("memory.max: got %q, want 8388608", data)
	}
	_ = cmd.Wait()
}

func TestIntegration_OrphanReap(t *testing.T) {
	if !DetectCgroupV2() {
		t.Skip("cgroup v2 not mounted")
	}
	// This test only runs meaningfully in top-level mode.
	probe, err := ProbeCgroupsV2(context.Background(), osCgroupFS{}, "")
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if probe.Mode != ModeTopLevel {
		t.Skipf("not in top-level mode (got %s)", probe.Mode)
	}

	orphan := filepath.Join(DefaultSliceDir, "integ-orphan")
	if err := os.Mkdir(orphan, 0o755); err != nil && !os.IsExist(err) {
		t.Fatalf("mkdir orphan: %v", err)
	}
	// Pre-verify the orphan is unpopulated.
	if _, err := os.ReadFile(filepath.Join(orphan, "cgroup.events")); err != nil {
		t.Fatalf("read events on orphan: %v", err)
	}

	// Re-probe to trigger reap.
	probe2, err := ProbeCgroupsV2(context.Background(), osCgroupFS{}, "")
	if err != nil {
		t.Fatalf("re-probe: %v", err)
	}
	_ = probe2
	if _, err := os.Stat(orphan); err == nil {
		t.Fatalf("orphan %s should have been reaped", orphan)
	}
}
