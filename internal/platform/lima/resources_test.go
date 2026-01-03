//go:build darwin

package lima

import (
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestResourceLimiter_Available(t *testing.T) {
	// Without a real Lima VM, limiter won't be available
	r := &ResourceLimiter{
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
	r := &ResourceLimiter{
		supportedLimits: []platform.ResourceType{
			platform.ResourceCPU,
			platform.ResourceMemory,
			platform.ResourceProcessCount,
		},
	}

	limits := r.SupportedLimits()
	if len(limits) != 3 {
		t.Errorf("SupportedLimits() returned %d items, want 3", len(limits))
	}

	// Verify expected types
	found := make(map[platform.ResourceType]bool)
	for _, l := range limits {
		found[l] = true
	}

	if !found[platform.ResourceCPU] {
		t.Error("SupportedLimits() should include ResourceCPU")
	}
	if !found[platform.ResourceMemory] {
		t.Error("SupportedLimits() should include ResourceMemory")
	}
	if !found[platform.ResourceProcessCount] {
		t.Error("SupportedLimits() should include ResourceProcessCount")
	}
}

func TestResourceLimiter_ApplyNotAvailable(t *testing.T) {
	r := &ResourceLimiter{
		available: false,
		handles:   make(map[string]*ResourceHandle),
	}

	_, err := r.Apply(platform.ResourceConfig{Name: "test"})
	if err == nil {
		t.Error("Apply() should error when cgroups not available")
	}
}

func TestResourceHandle_AssignProcess_NoCgPath(t *testing.T) {
	h := &ResourceHandle{
		cgPath: "",
	}

	err := h.AssignProcess(1234)
	if err == nil {
		t.Error("AssignProcess() should error when cgPath is empty")
	}
}

func TestResourceHandle_Stats_NoCgPath(t *testing.T) {
	h := &ResourceHandle{
		cgPath: "",
	}

	stats := h.Stats()
	if stats.MemoryMB != 0 || stats.CPUPercent != 0 || stats.ProcessCount != 0 {
		t.Error("Stats() should return empty stats when cgPath is empty")
	}
}

func TestResourceHandle_Release_NoCgPath(t *testing.T) {
	h := &ResourceHandle{
		cgPath: "",
	}

	err := h.Release()
	if err != nil {
		t.Errorf("Release() should return nil when cgPath is empty, got: %v", err)
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
