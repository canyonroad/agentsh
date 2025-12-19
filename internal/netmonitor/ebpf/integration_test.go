//go:build linux && integration

package ebpf

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/limits"
	"github.com/agentsh/agentsh/internal/netmonitor/ebpf"
)

// Integration test: attach BPF to a temp cgroup, populate allowlist, attempt a denied connect via nc.
// Requires root; skipped otherwise.
func TestIntegration_AttachAndEnforce(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if !limits.DetectCgroupV2() {
		t.Skip("cgroup v2 required")
	}

	// Create a temp cgroup and move self into it.
	tmp := filepath.Join(os.TempDir(), "agentsh-ebpf-test")
	_ = os.RemoveAll(tmp)
	if _, err := limits.ApplyCgroupV2("/sys/fs/cgroup", filepath.Base(tmp), os.Getpid(), limits.CgroupV2Limits{}); err != nil {
		t.Skipf("cgroup create failed: %v", err)
	}
	defer os.RemoveAll(tmp)

	coll, detach, err := AttachConnectToCgroup(tmp)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	defer detach()
	defer coll.Close()

	cgid, err := CgroupID(tmp)
	if err != nil {
		t.Fatalf("cgroup id: %v", err)
	}

	// Allow nothing; set default deny.
	if err := PopulateAllowlist(coll, cgid, nil, nil, nil, nil, true); err != nil {
		t.Fatalf("populate: %v", err)
	}

	// Attempt a connect to 1.1.1.1:80 using nc; expect failure (-EPERM).
	cmd := exec.Command("nc", "-z", "1.1.1.1", "80")
	err = cmd.Run()
	if err == nil {
		t.Fatalf("expected connect to be blocked")
	}
}

// Integration test: explicit deny without default deny.
func TestIntegration_DenyWithoutDefaultDeny(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if !limits.DetectCgroupV2() {
		t.Skip("cgroup v2 required")
	}

	tmp := filepath.Join(os.TempDir(), "agentsh-ebpf-deny-test")
	_ = os.RemoveAll(tmp)
	if _, err := limits.ApplyCgroupV2("/sys/fs/cgroup", filepath.Base(tmp), os.Getpid(), limits.CgroupV2Limits{}); err != nil {
		t.Skipf("cgroup create failed: %v", err)
	}
	defer os.RemoveAll(tmp)

	coll, detach, err := AttachConnectToCgroup(tmp)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	defer detach()
	defer coll.Close()

	cgid, err := CgroupID(tmp)
	if err != nil {
		t.Fatalf("cgroup id: %v", err)
	}

	deny := []ebpf.AllowKey{
		{Family: 2, Dport: 80, Addr: [16]byte{1, 1, 1, 1}},
	}
	if err := PopulateAllowlist(coll, cgid, nil, nil, deny, nil, false); err != nil {
		t.Fatalf("populate deny: %v", err)
	}

	cmd := exec.Command("nc", "-z", "1.1.1.1", "80")
	err = cmd.Run()
	if err == nil {
		t.Fatalf("expected connect to be blocked by deny map")
	}
}
