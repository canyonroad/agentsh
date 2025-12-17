//go:build linux

package limits

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestApplyCgroupV2_CreatesAndCleansUp(t *testing.T) {
	if !DetectCgroupV2() {
		t.Skip("cgroup v2 not available")
	}

	// Start a short-lived process and attach it to a new cgroup.
	cmd := exec.Command("sleep", "0.2")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sleep: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	cg, err := ApplyCgroupV2("", "agentsh-test-"+strings.ReplaceAll(t.Name(), "/", "_"), cmd.Process.Pid, CgroupV2Limits{
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
