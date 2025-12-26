//go:build windows

package windows

import (
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestNewResourceLimiter(t *testing.T) {
	r := NewResourceLimiter()

	if r == nil {
		t.Fatal("NewResourceLimiter() returned nil")
	}

	if !r.available {
		t.Error("available should be true")
	}

	if r.handles == nil {
		t.Error("handles map is nil")
	}
}

func TestResourceLimiter_Available(t *testing.T) {
	r := NewResourceLimiter()
	if !r.Available() {
		t.Error("Available() should return true on Windows")
	}
}

func TestResourceLimiter_SupportedLimits(t *testing.T) {
	r := NewResourceLimiter()
	limits := r.SupportedLimits()

	if len(limits) == 0 {
		t.Error("SupportedLimits() returned empty list")
	}

	// Check for expected limits
	found := make(map[platform.ResourceType]bool)
	for _, l := range limits {
		found[l] = true
	}

	expected := []platform.ResourceType{
		platform.ResourceCPU,
		platform.ResourceMemory,
		platform.ResourceProcessCount,
		platform.ResourceCPUAffinity,
	}

	for _, e := range expected {
		if !found[e] {
			t.Errorf("SupportedLimits() missing %v", e)
		}
	}
}

func TestResourceLimiter_Apply(t *testing.T) {
	r := NewResourceLimiter()

	config := platform.ResourceConfig{
		Name:          "test-job",
		MaxMemoryMB:   512,
		MaxCPUPercent: 50,
		MaxProcesses:  10,
		CPUAffinity:   []int{0, 1},
	}

	handle, err := r.Apply(config)
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

	if h.name != config.Name {
		t.Errorf("name = %q, want %q", h.name, config.Name)
	}
}

func TestResourceLimiter_Apply_Duplicate(t *testing.T) {
	r := NewResourceLimiter()

	config := platform.ResourceConfig{
		Name:        "test-job",
		MaxMemoryMB: 512,
	}

	_, err := r.Apply(config)
	if err != nil {
		t.Fatalf("First Apply() error = %v", err)
	}

	// Second apply with same name should error
	_, err = r.Apply(config)
	if err == nil {
		t.Error("Second Apply() with same name should error")
	}
}

func TestResourceLimiter_CalculateLimitFlags(t *testing.T) {
	r := NewResourceLimiter()

	tests := []struct {
		name   string
		config platform.ResourceConfig
		want   uint32
	}{
		{
			name:   "empty config",
			config: platform.ResourceConfig{},
			want:   JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
		{
			name:   "memory limit",
			config: platform.ResourceConfig{MaxMemoryMB: 512},
			want:   JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
		{
			name:   "process limit",
			config: platform.ResourceConfig{MaxProcesses: 10},
			want:   JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
		{
			name:   "affinity",
			config: platform.ResourceConfig{CPUAffinity: []int{0, 1}},
			want:   JOB_OBJECT_LIMIT_AFFINITY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
		{
			name: "all limits",
			config: platform.ResourceConfig{
				MaxMemoryMB:  512,
				MaxProcesses: 10,
				CPUAffinity:  []int{0},
			},
			want: JOB_OBJECT_LIMIT_JOB_MEMORY |
				JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
				JOB_OBJECT_LIMIT_AFFINITY |
				JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := r.calculateLimitFlags(tt.config)
			if flags != tt.want {
				t.Errorf("calculateLimitFlags() = 0x%x, want 0x%x", flags, tt.want)
			}
		})
	}
}

func TestResourceLimiter_CalculateCPURate(t *testing.T) {
	r := NewResourceLimiter()

	tests := []struct {
		percent uint32
		want    uint32
	}{
		{0, 0},
		{50, 5000},
		{100, 10000},
		{150, 10000}, // Capped at 100%
	}

	for _, tt := range tests {
		config := platform.ResourceConfig{MaxCPUPercent: tt.percent}
		got := r.calculateCPURate(config)
		if got != tt.want {
			t.Errorf("calculateCPURate(%d%%) = %d, want %d", tt.percent, got, tt.want)
		}
	}
}

func TestResourceLimiter_CalculateMemoryLimit(t *testing.T) {
	r := NewResourceLimiter()

	tests := []struct {
		mb   uint64
		want uint64
	}{
		{0, 0},
		{512, 512 * 1024 * 1024},
		{1024, 1024 * 1024 * 1024},
	}

	for _, tt := range tests {
		config := platform.ResourceConfig{MaxMemoryMB: tt.mb}
		got := r.calculateMemoryLimit(config)
		if got != tt.want {
			t.Errorf("calculateMemoryLimit(%d MB) = %d, want %d", tt.mb, got, tt.want)
		}
	}
}

func TestResourceLimiter_CalculateAffinityMask(t *testing.T) {
	r := NewResourceLimiter()

	tests := []struct {
		cpus []int
		want uint64
	}{
		{nil, 0},
		{[]int{}, 0},
		{[]int{0}, 0x1},
		{[]int{1}, 0x2},
		{[]int{0, 1}, 0x3},
		{[]int{0, 2}, 0x5},
		{[]int{0, 1, 2, 3}, 0xF},
		{[]int{63}, 0x8000000000000000},
		{[]int{-1}, 0},  // Invalid CPU
		{[]int{64}, 0},  // Invalid CPU
		{[]int{100}, 0}, // Invalid CPU
	}

	for _, tt := range tests {
		config := platform.ResourceConfig{CPUAffinity: tt.cpus}
		got := r.calculateAffinityMask(config)
		if got != tt.want {
			t.Errorf("calculateAffinityMask(%v) = 0x%x, want 0x%x", tt.cpus, got, tt.want)
		}
	}
}

func TestResourceLimiter_GetHandle(t *testing.T) {
	r := NewResourceLimiter()

	config := platform.ResourceConfig{Name: "test-job"}
	r.Apply(config)

	handle, ok := r.GetHandle("test-job")
	if !ok {
		t.Error("GetHandle() returned false for existing handle")
	}
	if handle == nil {
		t.Error("GetHandle() returned nil for existing handle")
	}

	_, ok = r.GetHandle("nonexistent")
	if ok {
		t.Error("GetHandle() returned true for non-existent handle")
	}
}

func TestResourceLimiter_Release(t *testing.T) {
	r := NewResourceLimiter()

	config := platform.ResourceConfig{Name: "test-job"}
	r.Apply(config)

	err := r.Release("test-job")
	if err != nil {
		t.Errorf("Release() error = %v", err)
	}

	_, ok := r.GetHandle("test-job")
	if ok {
		t.Error("Handle should not exist after Release()")
	}

	// Release non-existent should error
	err = r.Release("nonexistent")
	if err == nil {
		t.Error("Release() should error for non-existent handle")
	}
}

func TestResourceHandle_AssignProcess(t *testing.T) {
	h := &ResourceHandle{name: "test"}

	// Should not error (stub implementation)
	err := h.AssignProcess(1234)
	if err != nil {
		t.Errorf("AssignProcess() error = %v", err)
	}
}

func TestResourceHandle_AssignProcess_Closed(t *testing.T) {
	h := &ResourceHandle{name: "test", closed: true}

	err := h.AssignProcess(1234)
	if err == nil {
		t.Error("AssignProcess() should error when closed")
	}
}

func TestResourceHandle_Stats(t *testing.T) {
	h := &ResourceHandle{name: "test"}

	stats := h.Stats()
	// Stub returns zero values
	if stats.MemoryMB != 0 {
		t.Errorf("MemoryMB = %d, want 0", stats.MemoryMB)
	}
}

func TestResourceHandle_Stats_Closed(t *testing.T) {
	h := &ResourceHandle{name: "test", closed: true}

	stats := h.Stats()
	if stats.MemoryMB != 0 || stats.CPUPercent != 0 {
		t.Error("Stats() should return zero values when closed")
	}
}

func TestResourceHandle_Getters(t *testing.T) {
	h := &ResourceHandle{
		name:         "test",
		limitFlags:   0x1234,
		cpuRate:      5000,
		memoryLimit:  1024 * 1024 * 1024,
		processLimit: 10,
		affinityMask: 0xF,
	}

	if h.Name() != "test" {
		t.Errorf("Name() = %q, want test", h.Name())
	}
	if h.LimitFlags() != 0x1234 {
		t.Errorf("LimitFlags() = 0x%x, want 0x1234", h.LimitFlags())
	}
	if h.CPURate() != 5000 {
		t.Errorf("CPURate() = %d, want 5000", h.CPURate())
	}
	if h.MemoryLimit() != 1024*1024*1024 {
		t.Errorf("MemoryLimit() = %d, want 1GB", h.MemoryLimit())
	}
	if h.ProcessLimit() != 10 {
		t.Errorf("ProcessLimit() = %d, want 10", h.ProcessLimit())
	}
	if h.AffinityMask() != 0xF {
		t.Errorf("AffinityMask() = 0x%x, want 0xF", h.AffinityMask())
	}
}

func TestResourceHandle_Release(t *testing.T) {
	h := &ResourceHandle{name: "test"}

	err := h.Release()
	if err != nil {
		t.Errorf("Release() error = %v", err)
	}

	if !h.closed {
		t.Error("closed should be true after Release()")
	}

	// Release again should not error
	err = h.Release()
	if err != nil {
		t.Errorf("Release() second time error = %v", err)
	}
}

func TestResourceLimiter_InterfaceCompliance(t *testing.T) {
	var _ platform.ResourceLimiter = (*ResourceLimiter)(nil)
	var _ platform.ResourceHandle = (*ResourceHandle)(nil)
}
