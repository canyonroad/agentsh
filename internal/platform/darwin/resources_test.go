//go:build darwin && cgo

package darwin

import (
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestResourceLimiterAvailable(t *testing.T) {
	r := NewResourceLimiter()
	if !r.Available() {
		t.Error("ResourceLimiter should be available on macOS")
	}
}

func TestResourceLimiterSupportedLimits(t *testing.T) {
	r := NewResourceLimiter()
	supported := r.SupportedLimits()

	hasCPU := false
	for _, rt := range supported {
		if rt == platform.ResourceCPU {
			hasCPU = true
		}
	}

	if !hasCPU {
		t.Error("expected ResourceCPU to be supported")
	}

	// Memory is NOT supported until RLIMIT_AS enforcement is implemented
	for _, rt := range supported {
		if rt == platform.ResourceMemory {
			t.Error("ResourceMemory should not be in SupportedLimits until implemented")
		}
	}
}

func TestResourceLimiterApply(t *testing.T) {
	r := NewResourceLimiter()

	// Only CPU limits are currently supported
	config := platform.ResourceConfig{
		Name:          "test-limits",
		MaxCPUPercent: 50,
	}

	handle, err := r.Apply(config)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if handle == nil {
		t.Fatal("expected non-nil handle")
	}

	// Cleanup
	handle.Release()
}

func TestResourceLimiterApplyUnsupportedMemory(t *testing.T) {
	r := NewResourceLimiter()

	config := platform.ResourceConfig{
		Name:        "test-limits",
		MaxMemoryMB: 256,
	}

	_, err := r.Apply(config)
	if err == nil {
		t.Error("expected error for unsupported memory limits")
	}
}

func TestResourceLimiterApplyUnsupportedProcessCount(t *testing.T) {
	r := NewResourceLimiter()

	config := platform.ResourceConfig{
		Name:         "test-limits",
		MaxProcesses: 10,
	}

	_, err := r.Apply(config)
	if err == nil {
		t.Error("expected error for unsupported MaxProcesses")
	}
}

func TestResourceLimiterApplyUnsupportedDiskIO(t *testing.T) {
	r := NewResourceLimiter()

	config := platform.ResourceConfig{
		Name:            "test-limits",
		MaxDiskReadMBps: 100,
	}

	_, err := r.Apply(config)
	if err == nil {
		t.Error("expected error for unsupported disk I/O limits")
	}
}

func TestResourceLimiterApplyUnsupportedAffinity(t *testing.T) {
	r := NewResourceLimiter()

	config := platform.ResourceConfig{
		Name:        "test-limits",
		CPUAffinity: []int{0, 1},
	}

	_, err := r.Apply(config)
	if err == nil {
		t.Error("expected error for unsupported CPU affinity")
	}
}
