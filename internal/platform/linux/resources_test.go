//go:build linux

package linux

import (
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestCgroupResourceLimiter_Available(t *testing.T) {
	r := &cgroupResourceLimiter{}
	// On a Linux system with cgroup v2, Available should return true.
	// We don't assert the value since it depends on the host, just verify no panic.
	_ = r.Available()
}

func TestCgroupResourceLimiter_SupportedLimits(t *testing.T) {
	r := &cgroupResourceLimiter{}
	limits := r.SupportedLimits()
	if r.Available() {
		if len(limits) != 3 {
			t.Fatalf("expected 3 supported limits, got %d", len(limits))
		}
		expected := map[platform.ResourceType]bool{
			platform.ResourceCPU:          true,
			platform.ResourceMemory:       true,
			platform.ResourceProcessCount: true,
		}
		for _, l := range limits {
			if !expected[l] {
				t.Errorf("unexpected supported limit: %v", l)
			}
		}
	} else {
		if limits != nil {
			t.Fatalf("expected nil when unavailable, got %v", limits)
		}
	}
}

func TestCgroupResourceLimiter_RejectUnsupportedLimits(t *testing.T) {
	r := &cgroupResourceLimiter{}
	if !r.Available() {
		t.Skip("cgroup v2 not available")
	}

	tests := []struct {
		name   string
		config platform.ResourceConfig
	}{
		{
			name: "disk read",
			config: platform.ResourceConfig{
				Name:            "test-disk-read",
				MaxDiskReadMBps: 100,
			},
		},
		{
			name: "disk write",
			config: platform.ResourceConfig{
				Name:             "test-disk-write",
				MaxDiskWriteMBps: 50,
			},
		},
		{
			name: "network",
			config: platform.ResourceConfig{
				Name:           "test-net",
				MaxNetworkMbps: 100,
			},
		},
		{
			name: "cpu affinity",
			config: platform.ResourceConfig{
				Name:        "test-affinity",
				CPUAffinity: []int{0, 1},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := r.Apply(tt.config)
			if err == nil {
				t.Fatalf("expected error for unsupported limit %q", tt.name)
			}
		})
	}
}

func TestCgroupResourceLimiter_DuplicateHandleName(t *testing.T) {
	r := &cgroupResourceLimiter{}
	if !r.Available() {
		t.Skip("cgroup v2 not available")
	}

	config := platform.ResourceConfig{
		Name:          "test-dup",
		MaxMemoryMB:   64,
		MaxCPUPercent: 50,
	}

	h1, err := r.Apply(config)
	if err != nil {
		t.Fatalf("first Apply: %v", err)
	}

	_, err = r.Apply(config)
	if err == nil {
		t.Fatalf("expected error for duplicate handle name")
	}

	// After releasing, the name should be available again.
	_ = h1.Release()

	_, err = r.Apply(config)
	if err != nil {
		t.Fatalf("Apply after release should succeed: %v", err)
	}
}

func TestCgroupResourceHandle_AssignAfterRelease(t *testing.T) {
	r := &cgroupResourceLimiter{}
	if !r.Available() {
		t.Skip("cgroup v2 not available")
	}

	config := platform.ResourceConfig{
		Name:          "test-release",
		MaxMemoryMB:   64,
		MaxCPUPercent: 50,
	}

	h, err := r.Apply(config)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if err := h.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}

	if err := h.AssignProcess(1234); err == nil {
		t.Fatalf("expected error on AssignProcess after Release")
	}
}

func TestCgroupResourceHandle_ReleaseIdempotent(t *testing.T) {
	r := &cgroupResourceLimiter{}
	if !r.Available() {
		t.Skip("cgroup v2 not available")
	}

	config := platform.ResourceConfig{
		Name: "test-idem",
	}

	h, err := r.Apply(config)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if err := h.Release(); err != nil {
		t.Fatalf("first Release: %v", err)
	}
	if err := h.Release(); err != nil {
		t.Fatalf("second Release should be idempotent: %v", err)
	}
}

func TestCgroupResourceHandle_StatsBeforeAssign(t *testing.T) {
	r := &cgroupResourceLimiter{}
	if !r.Available() {
		t.Skip("cgroup v2 not available")
	}

	config := platform.ResourceConfig{
		Name: "test-stats",
	}

	h, err := r.Apply(config)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer h.Release()

	// Stats before AssignProcess should return zero values (no cgroup yet).
	stats := h.Stats()
	if stats.MemoryMB != 0 || stats.ProcessCount != 0 {
		t.Fatalf("expected zero stats before AssignProcess, got %+v", stats)
	}
}
