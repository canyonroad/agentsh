//go:build linux

package linux

import (
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestNewResourceLimiter(t *testing.T) {
	r := NewResourceLimiter()
	if r == nil {
		t.Fatal("NewResourceLimiter returned nil")
	}

	available := r.Available()
	t.Logf("Resource limiter available: %v", available)

	limits := r.SupportedLimits()
	t.Logf("Supported limits: %v", limits)
}

func TestResourceLimiter_SupportedLimits(t *testing.T) {
	r := NewResourceLimiter()
	if !r.Available() {
		t.Skip("Cgroups v2 not available")
	}

	limits := r.SupportedLimits()
	if len(limits) == 0 {
		t.Error("No supported limits detected on cgroups v2 system")
	}

	// Check for expected limits
	hasMemory := false
	hasCPU := false
	for _, l := range limits {
		if l == platform.ResourceMemory {
			hasMemory = true
		}
		if l == platform.ResourceCPU {
			hasCPU = true
		}
	}

	t.Logf("Has memory limit: %v, Has CPU limit: %v", hasMemory, hasCPU)
}

func TestResourceLimiter_Apply(t *testing.T) {
	r := NewResourceLimiter()
	if !r.Available() {
		t.Skip("Cgroups v2 not available")
	}

	config := platform.ResourceConfig{
		Name:          "test-limits",
		MaxMemoryMB:   512,
		MaxCPUPercent: 50,
		MaxProcesses:  100,
	}

	handle, err := r.Apply(config)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	defer handle.Release()

	if handle == nil {
		t.Error("Apply() returned nil handle")
	}
}

func TestResourceHandle_Stats(t *testing.T) {
	r := NewResourceLimiter()
	if !r.Available() {
		t.Skip("Cgroups v2 not available")
	}

	config := platform.ResourceConfig{
		Name:          "stats-test",
		MaxMemoryMB:   256,
		MaxCPUPercent: 25,
	}

	handle, err := r.Apply(config)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	defer handle.Release()

	// Stats should work even without processes assigned
	stats := handle.Stats()
	t.Logf("Stats: MemoryMB=%d, CPUPercent=%.2f, ProcessCount=%d",
		stats.MemoryMB, stats.CPUPercent, stats.ProcessCount)
}

func TestResourceHandle_Release(t *testing.T) {
	r := NewResourceLimiter()
	if !r.Available() {
		t.Skip("Cgroups v2 not available")
	}

	config := platform.ResourceConfig{
		Name: "release-test",
	}

	handle, err := r.Apply(config)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	// Release should succeed
	if err := handle.Release(); err != nil {
		t.Errorf("Release() error = %v", err)
	}

	// Second release should also succeed (idempotent)
	if err := handle.Release(); err != nil {
		t.Errorf("Second Release() error = %v", err)
	}
}

// Compile-time interface checks
var (
	_ platform.ResourceLimiter = (*ResourceLimiter)(nil)
	_ platform.ResourceHandle  = (*ResourceHandle)(nil)
)
