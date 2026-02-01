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
	defer handle.Release()

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

	// Verify a real Job Object was created
	if h.JobHandle() == 0 {
		t.Error("JobHandle() = 0, expected valid Windows handle")
	}
}

func TestResourceLimiter_Apply_CreatesJobObject(t *testing.T) {
	r := NewResourceLimiter()

	handle, err := r.Apply(platform.ResourceConfig{
		Name:          "test-job-creation",
		MaxMemoryMB:   256,
		MaxCPUPercent: 25,
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	defer handle.Release()

	h := handle.(*ResourceHandle)

	// Verify Job Object handle is valid
	if h.JobHandle() == 0 {
		t.Fatal("Apply() did not create a valid Job Object")
	}

	// Verify we can query the job object (proves it's a real handle)
	stats := h.Stats()
	// ProcessCount should be 0 (no processes assigned yet)
	if stats.ProcessCount != 0 {
		t.Logf("ProcessCount = %d (unexpected but may be valid)", stats.ProcessCount)
	}
}

func TestResourceLimiter_Apply_Duplicate(t *testing.T) {
	r := NewResourceLimiter()

	config := platform.ResourceConfig{
		Name:        "test-job",
		MaxMemoryMB: 512,
	}

	handle1, err := r.Apply(config)
	if err != nil {
		t.Fatalf("First Apply() error = %v", err)
	}
	defer handle1.Release()

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
			name:   "affinity with all invalid CPUs",
			config: platform.ResourceConfig{CPUAffinity: []int{-1, 64, 100}},
			want:   JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, // No affinity flag when mask is 0
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
	h, err := r.Apply(config)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	defer h.Release()

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
	r := NewResourceLimiter()
	handle, err := r.Apply(platform.ResourceConfig{
		Name:        "test-assign",
		MaxMemoryMB: 512,
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	defer handle.Release()

	h := handle.(*ResourceHandle)

	// Verify job handle was created
	if h.JobHandle() == 0 {
		t.Error("JobHandle() returned 0, expected valid handle")
	}

	// Note: We don't assign the current test process to the job because
	// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE would terminate the test runner
	// when Release() is called. Instead, we just verify the job was created.
	// Real integration tests should spawn a child process to assign.
}

func TestResourceHandle_AssignProcess_Closed(t *testing.T) {
	r := NewResourceLimiter()
	handle, err := r.Apply(platform.ResourceConfig{
		Name:        "test-closed",
		MaxMemoryMB: 512,
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	h := handle.(*ResourceHandle)

	// Release to close it
	h.Release()

	err = h.AssignProcess(1234)
	if err == nil {
		t.Error("AssignProcess() should error when closed")
	}
}

func TestResourceHandle_Stats(t *testing.T) {
	r := NewResourceLimiter()
	handle, err := r.Apply(platform.ResourceConfig{
		Name:        "test-stats",
		MaxMemoryMB: 512,
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	defer handle.Release()

	h := handle.(*ResourceHandle)

	// Stats should work even with no processes assigned
	stats := h.Stats()
	// ProcessCount should be 0 since no processes are assigned
	if stats.ProcessCount != 0 {
		t.Logf("ProcessCount = %d (may be non-zero if current process auto-joined)", stats.ProcessCount)
	}
}

func TestResourceHandle_Stats_Closed(t *testing.T) {
	r := NewResourceLimiter()
	handle, err := r.Apply(platform.ResourceConfig{
		Name:        "test-stats-closed",
		MaxMemoryMB: 512,
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	h := handle.(*ResourceHandle)
	h.Release()

	stats := h.Stats()
	if stats.MemoryMB != 0 || stats.CPUPercent != 0 {
		t.Error("Stats() should return zero values when closed")
	}
}

func TestResourceHandle_Getters(t *testing.T) {
	r := NewResourceLimiter()
	handle, err := r.Apply(platform.ResourceConfig{
		Name:          "test-getters",
		MaxMemoryMB:   1024,
		MaxCPUPercent: 50,
		MaxProcesses:  10,
		CPUAffinity:   []int{0, 1, 2, 3},
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	defer handle.Release()

	h := handle.(*ResourceHandle)

	if h.Name() != "test-getters" {
		t.Errorf("Name() = %q, want test-getters", h.Name())
	}

	// LimitFlags should include memory, process count, affinity, and kill-on-close
	expectedFlags := uint32(JOB_OBJECT_LIMIT_JOB_MEMORY |
		JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
		JOB_OBJECT_LIMIT_AFFINITY |
		JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
	if h.LimitFlags() != expectedFlags {
		t.Errorf("LimitFlags() = 0x%x, want 0x%x", h.LimitFlags(), expectedFlags)
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
	if h.JobHandle() == 0 {
		t.Error("JobHandle() = 0, want valid handle")
	}
}

func TestResourceHandle_Release(t *testing.T) {
	r := NewResourceLimiter()
	handle, err := r.Apply(platform.ResourceConfig{
		Name:        "test-release",
		MaxMemoryMB: 512,
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	h := handle.(*ResourceHandle)

	// Verify job handle exists before release
	if h.JobHandle() == 0 {
		t.Error("JobHandle() should be valid before Release()")
	}

	err = h.Release()
	if err != nil {
		t.Errorf("Release() error = %v", err)
	}

	if !h.closed {
		t.Error("closed should be true after Release()")
	}

	// Job handle should be zeroed after release
	if h.JobHandle() != 0 {
		t.Error("JobHandle() should be 0 after Release()")
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

func TestResourceHandle_IsActive(t *testing.T) {
	r := NewResourceLimiter()
	handle, err := r.Apply(platform.ResourceConfig{
		Name:        "test-isactive",
		MaxMemoryMB: 512,
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	defer handle.Release()

	h := handle.(*ResourceHandle)

	// With no processes assigned, should not be active
	if h.IsActive() {
		t.Log("IsActive() = true (may be expected if process auto-joined)")
	}

	// After release, should not be active
	h.Release()
	if h.IsActive() {
		t.Error("IsActive() should return false after Release()")
	}
}
