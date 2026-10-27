//go:build linux && integration

package ebpf_test

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/limits"
	"github.com/agentsh/agentsh/internal/netmonitor/ebpf"
)

func TestIntegration_CIDRAllowAndBlock(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if !limits.DetectCgroupV2() {
		t.Skip("cgroup v2 required")
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	allowedPort := uint16(listener.Addr().(*net.TCPAddr).Port)
	blockedPort := allowedPort + 1
	if allowedPort == 65535 {
		blockedPort = allowedPort - 1
	}

	cgDir := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("agentsh-ebpf-lpm-%d", os.Getpid()))
	if err := os.Mkdir(cgDir, 0o755); err != nil {
		t.Fatalf("cgroup mkdir: %v", err)
	}
	origCgroup, err := limits.CurrentCgroupDir()
	if err != nil {
		t.Fatalf("current cgroup: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cgDir, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		t.Fatalf("move into cgroup: %v", err)
	}
	defer func() {
		if err := os.WriteFile(filepath.Join(origCgroup, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
			t.Errorf("restore cgroup: %v", err)
			return
		}
		if err := os.Remove(cgDir); err != nil {
			t.Errorf("remove cgroup: %v", err)
		}
	}()

	coll, detach, err := ebpf.AttachConnectToCgroup(cgDir)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	defer detach()

	cgroupID, err := ebpf.CgroupID(cgDir)
	if err != nil {
		t.Fatalf("cgroup id: %v", err)
	}
	allowCIDRs := []ebpf.AllowCIDR{{
		Family:    2,
		PrefixLen: 24,
		Dport:     allowedPort,
		Addr:      [16]byte{127, 0, 0, 0},
	}}
	if err := ebpf.PopulateAllowlist(coll, cgroupID, nil, allowCIDRs, nil, nil, true); err != nil {
		t.Fatalf("populate: %v", err)
	}

	allowed, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("allowed CIDR connect: %v", err)
	}
	allowed.Close()

	blockedAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(blockedPort)))
	blocked, err := net.DialTimeout("tcp4", blockedAddr, time.Second)
	if blocked != nil {
		blocked.Close()
	}
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("wrong-port connect error = %v, want EPERM", err)
	}
}

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
	origCgroup, _ := limits.CurrentCgroupDir()
	if err := os.WriteFile(filepath.Join(cgDir, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		_ = os.Remove(cgDir)
		t.Skipf("cgroup attach failed: %v", err)
	}
	defer func() {
		// Move process back so the cgroup can be removed.
		if origCgroup != "" {
			if err := os.WriteFile(filepath.Join(origCgroup, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
				t.Errorf("restore cgroup: %v", err)
			}
		}
		if err := os.Remove(cgDir); err != nil {
			t.Errorf("remove cgroup: %v", err)
		}
	}()

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
	origCgroup, _ := limits.CurrentCgroupDir()
	if err := os.WriteFile(filepath.Join(cgDir, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		_ = os.Remove(cgDir)
		t.Skipf("cgroup attach failed: %v", err)
	}
	defer func() {
		if origCgroup != "" {
			if err := os.WriteFile(filepath.Join(origCgroup, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
				t.Errorf("restore cgroup: %v", err)
			}
		}
		if err := os.Remove(cgDir); err != nil {
			t.Errorf("remove cgroup: %v", err)
		}
	}()

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
