//go:build linux && integration

package ebpf_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	cgDir := filepath.Join("/sys/fs/cgroup", filepath.Base(tmp))
	_ = os.Remove(cgDir) // clean up from interrupted prior runs
	if err := os.Mkdir(cgDir, 0o755); err != nil {
		t.Skipf("cgroup mkdir failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cgDir, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		_ = os.Remove(cgDir)
		t.Skipf("cgroup attach failed: %v", err)
	}
	defer os.RemoveAll(cgDir)

	coll, detach, err := ebpf.AttachConnectToCgroup(cgDir)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	defer detach()
	defer coll.Close()

	cgid, err := ebpf.CgroupID(cgDir)
	if err != nil {
		t.Fatalf("cgroup id: %v", err)
	}

	// Allow nothing; set default deny.
	if err := ebpf.PopulateAllowlist(coll, cgid, nil, nil, nil, nil, true); err != nil {
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
	cgDir := filepath.Join("/sys/fs/cgroup", filepath.Base(tmp))
	_ = os.Remove(cgDir) // clean up from interrupted prior runs
	if err := os.Mkdir(cgDir, 0o755); err != nil {
		t.Skipf("cgroup mkdir failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cgDir, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		_ = os.Remove(cgDir)
		t.Skipf("cgroup attach failed: %v", err)
	}
	defer os.RemoveAll(cgDir)

	coll, detach, err := ebpf.AttachConnectToCgroup(cgDir)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	defer detach()
	defer coll.Close()

	cgid, err := ebpf.CgroupID(cgDir)
	if err != nil {
		t.Fatalf("cgroup id: %v", err)
	}

	deny := []ebpf.AllowKey{
		{Family: 2, Dport: 80, Addr: [16]byte{1, 1, 1, 1}},
	}
	if err := ebpf.PopulateAllowlist(coll, cgid, nil, nil, deny, nil, false); err != nil {
		t.Fatalf("populate deny: %v", err)
	}

	cmd := exec.Command("nc", "-z", "1.1.1.1", "80")
	err = cmd.Run()
	if err == nil {
		t.Fatalf("expected connect to be blocked by deny map")
	}
}
