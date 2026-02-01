//go:build windows

package wsl2

import (
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestNewResourceLimiter(t *testing.T) {
	skipIfWSLUnavailable(t)
	p := &Platform{distro: "Ubuntu"}
	r := NewResourceLimiter(p)

	if r == nil {
		t.Fatal("NewResourceLimiter() returned nil")
	}

	if r.platform != p {
		t.Error("platform not set correctly")
	}
}

func TestResourceLimiter_Available(t *testing.T) {
	p := &Platform{distro: "Ubuntu"}
	r := &ResourceLimiter{
		platform:  p,
		available: true,
	}

	if !r.Available() {
		t.Error("Available() should return true when available is true")
	}

	r.available = false
	if r.Available() {
		t.Error("Available() should return false when available is false")
	}
}

func TestResourceLimiter_SupportedLimits(t *testing.T) {
	p := &Platform{distro: "Ubuntu"}
	r := &ResourceLimiter{
		platform:  p,
		available: true,
		supportedLimits: []platform.ResourceType{
			platform.ResourceCPU,
			platform.ResourceMemory,
			platform.ResourceProcessCount,
		},
	}

	limits := r.SupportedLimits()
	if len(limits) != 3 {
		t.Errorf("SupportedLimits() = %d items, want 3", len(limits))
	}
}

func TestResourceLimiter_Apply(t *testing.T) {
	// This test can only run when WSL2 is actually available
	// Skip when just checking logic - the implementation now makes real calls
	t.Skip("Requires real WSL2 environment")
}

func TestResourceLimiter_Apply_NotAvailable(t *testing.T) {
	p := &Platform{distro: "Ubuntu"}
	r := &ResourceLimiter{
		platform:  p,
		available: false,
		handles:   make(map[string]*ResourceHandle),
	}

	cfg := platform.ResourceConfig{
		Name: "test-cgroup",
	}

	_, err := r.Apply(cfg)
	if err == nil {
		t.Error("Apply() should error when not available")
	}
}

func TestResourceHandle_Stats(t *testing.T) {
	h := &ResourceHandle{
		name:   "test-cgroup",
		cgPath: "", // Empty cgPath
	}

	stats := h.Stats()

	// Should return empty stats when cgPath is empty
	if stats.MemoryMB != 0 {
		t.Errorf("MemoryMB = %d, want 0", stats.MemoryMB)
	}
}

func TestResourceHandle_Release(t *testing.T) {
	h := &ResourceHandle{
		name:   "test-cgroup",
		cgPath: "", // Empty cgPath should return nil
	}

	err := h.Release()
	if err != nil {
		t.Errorf("Release() error = %v", err)
	}
}

func TestResourceHandle_AssignProcess(t *testing.T) {
	h := &ResourceHandle{
		name:   "test-cgroup",
		cgPath: "", // Empty cgPath
	}

	// AssignProcess should error when cgPath is empty
	err := h.AssignProcess(1234)
	if err == nil {
		t.Error("AssignProcess() should error when cgPath is empty")
	}
}

func TestResourceHandle_AssignProcess_WithPath(t *testing.T) {
	// This test can only run when WSL2 is actually available
	t.Skip("Requires real WSL2 environment")
}

func TestDetectSupportedLimits_NotAvailable(t *testing.T) {
	p := &Platform{distro: "Ubuntu"}
	r := &ResourceLimiter{
		platform:  p,
		available: false,
	}

	limits := r.detectSupportedLimits()
	if limits != nil {
		t.Errorf("detectSupportedLimits() with unavailable = %v, want nil", limits)
	}
}

func TestCgroupPath(t *testing.T) {
	// Test the cgroup path construction
	expected := "/sys/fs/cgroup/agentsh"
	got := cgroupBasePath + "/" + agentshCgroupDir
	if got != expected {
		t.Errorf("Cgroup path = %q, want %q", got, expected)
	}
}

func TestResourceLimiter_InterfaceCompliance(t *testing.T) {
	var _ platform.ResourceLimiter = (*ResourceLimiter)(nil)
	var _ platform.ResourceHandle = (*ResourceHandle)(nil)
}
