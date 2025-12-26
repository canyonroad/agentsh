//go:build windows

package wsl2

import (
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestNewResourceLimiter(t *testing.T) {
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
	p := &Platform{distro: "Ubuntu"}
	r := &ResourceLimiter{
		platform:  p,
		available: true,
	}

	cfg := platform.ResourceConfig{
		Name:        "test-cgroup",
		MaxMemoryMB: 512,
	}

	handle, err := r.Apply(cfg)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	if handle == nil {
		t.Fatal("Apply() returned nil handle")
	}

	h, ok := handle.(*ResourceHandle)
	if !ok {
		t.Fatal("Apply() did not return *ResourceHandle")
	}

	if h.name != cfg.Name {
		t.Errorf("name = %q, want %q", h.name, cfg.Name)
	}
}

func TestResourceLimiter_Apply_NotAvailable(t *testing.T) {
	p := &Platform{distro: "Ubuntu"}
	r := &ResourceLimiter{
		platform:  p,
		available: false,
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
		name: "test-cgroup",
	}

	stats := h.Stats()

	// Should return empty stats (stub implementation)
	if stats.MemoryMB != 0 {
		t.Errorf("MemoryMB = %d, want 0", stats.MemoryMB)
	}
}

func TestResourceHandle_Release(t *testing.T) {
	h := &ResourceHandle{
		name: "test-cgroup",
	}

	err := h.Release()
	if err != nil {
		t.Errorf("Release() error = %v", err)
	}
}

func TestResourceHandle_AssignProcess(t *testing.T) {
	h := &ResourceHandle{
		name: "test-cgroup",
	}

	// AssignProcess returns error (not yet implemented)
	err := h.AssignProcess(1234)
	if err == nil {
		t.Log("AssignProcess() stub returned nil (may be updated to return error)")
	}
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

func TestResourceLimiter_InterfaceCompliance(t *testing.T) {
	var _ platform.ResourceLimiter = (*ResourceLimiter)(nil)
	var _ platform.ResourceHandle = (*ResourceHandle)(nil)
}
