//go:build darwin && cgo

package darwin

import (
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestResourceHandleGetRlimits(t *testing.T) {
	h := &ResourceHandle{
		name: "test",
		config: platform.ResourceConfig{
			MaxMemoryMB: 512,
		},
		rlimitAS: 512 * 1024 * 1024,
	}

	rlimits := h.GetRlimits()
	if len(rlimits) != 1 {
		t.Fatalf("expected 1 rlimit, got %d", len(rlimits))
	}

	if rlimits[0].Resource != RlimitAS {
		t.Errorf("expected RLIMIT_AS, got %d", rlimits[0].Resource)
	}

	expected := uint64(512 * 1024 * 1024)
	if rlimits[0].Cur != expected {
		t.Errorf("expected cur=%d, got %d", expected, rlimits[0].Cur)
	}
}

func TestResourceHandleGetRlimitsEmpty(t *testing.T) {
	h := &ResourceHandle{
		name:   "test",
		config: platform.ResourceConfig{},
	}

	rlimits := h.GetRlimits()
	if len(rlimits) != 0 {
		t.Errorf("expected 0 rlimits for no memory limit, got %d", len(rlimits))
	}
}

func TestResourceHandleStats(t *testing.T) {
	h := &ResourceHandle{
		name:     "test",
		monitors: make(map[int]*cpuMonitor),
	}

	// Stats should return empty stats when no processes assigned
	stats := h.Stats()
	if stats.MemoryMB != 0 {
		t.Errorf("expected 0 memory, got %d", stats.MemoryMB)
	}
}
