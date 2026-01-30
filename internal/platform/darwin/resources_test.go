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

	hasMemory := false
	hasCPU := false
	for _, rt := range supported {
		if rt == platform.ResourceMemory {
			hasMemory = true
		}
		if rt == platform.ResourceCPU {
			hasCPU = true
		}
	}

	if !hasMemory {
		t.Error("expected ResourceMemory to be supported")
	}
	if !hasCPU {
		t.Error("expected ResourceCPU to be supported")
	}
}

func TestResourceLimiterApply(t *testing.T) {
	r := NewResourceLimiter()

	config := platform.ResourceConfig{
		Name:          "test-limits",
		MaxMemoryMB:   256,
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
