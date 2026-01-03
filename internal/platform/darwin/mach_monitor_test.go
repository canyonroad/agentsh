//go:build darwin

package darwin

import (
	"os"
	"testing"
	"time"
)

func TestNewMachMonitor(t *testing.T) {
	m := NewMachMonitor()
	if m == nil {
		t.Fatal("NewMachMonitor() returned nil")
	}
	if m.lastSamples == nil {
		t.Error("lastSamples map is nil")
	}
}

func TestMachMonitor_GetProcessInfo_Self(t *testing.T) {
	m := NewMachMonitor()
	pid := os.Getpid()

	info, err := m.GetProcessInfo(pid)
	if err != nil {
		t.Fatalf("GetProcessInfo(%d) error = %v", pid, err)
	}

	// Our own process should have reasonable values
	if info.ResidentSize == 0 {
		t.Error("ResidentSize should be > 0 for current process")
	}
	if info.VirtualSize == 0 {
		t.Error("VirtualSize should be > 0 for current process")
	}
	if info.NumThreads < 1 {
		t.Errorf("NumThreads = %d, want >= 1", info.NumThreads)
	}

	t.Logf("Process info: RSS=%d bytes, VSZ=%d bytes, Threads=%d, UserTime=%d ns, SysTime=%d ns",
		info.ResidentSize, info.VirtualSize, info.NumThreads, info.UserTime, info.SystemTime)
}

func TestMachMonitor_GetProcessInfo_InvalidPID(t *testing.T) {
	m := NewMachMonitor()

	// PID -1 and very high PIDs should fail
	_, err := m.GetProcessInfo(-1)
	if err == nil {
		t.Error("GetProcessInfo(-1) should return error")
	}

	// Very high PID unlikely to exist
	_, err = m.GetProcessInfo(999999999)
	if err == nil {
		t.Error("GetProcessInfo(999999999) should return error")
	}
}

func TestMachMonitor_GetMemory(t *testing.T) {
	m := NewMachMonitor()
	pid := os.Getpid()

	rss, vms, err := m.GetMemory(pid)
	if err != nil {
		t.Fatalf("GetMemory(%d) error = %v", pid, err)
	}

	if rss == 0 {
		t.Error("RSS should be > 0 for current process")
	}
	if vms == 0 {
		t.Error("VMS should be > 0 for current process")
	}
	if rss > vms {
		t.Errorf("RSS (%d) should be <= VMS (%d)", rss, vms)
	}

	t.Logf("Memory: RSS=%d bytes (%.2f MB), VMS=%d bytes (%.2f MB)",
		rss, float64(rss)/(1024*1024), vms, float64(vms)/(1024*1024))
}

func TestMachMonitor_GetCPUPercent(t *testing.T) {
	m := NewMachMonitor()
	pid := os.Getpid()

	// First call should return 0 (baseline sample)
	pct1, err := m.GetCPUPercent(pid)
	if err != nil {
		t.Fatalf("GetCPUPercent(%d) first call error = %v", pid, err)
	}
	if pct1 != 0 {
		t.Errorf("First GetCPUPercent call should return 0, got %f", pct1)
	}

	// Do some CPU work
	sum := 0
	for i := 0; i < 10000000; i++ {
		sum += i
	}
	_ = sum

	// Small delay to ensure wall time passes
	time.Sleep(10 * time.Millisecond)

	// Second call should return actual CPU percentage
	pct2, err := m.GetCPUPercent(pid)
	if err != nil {
		t.Fatalf("GetCPUPercent(%d) second call error = %v", pid, err)
	}

	// CPU percentage should be non-negative
	if pct2 < 0 {
		t.Errorf("CPU percentage = %f, should be >= 0", pct2)
	}

	t.Logf("CPU percentage after work: %.2f%%", pct2)
}

func TestMachMonitor_GetThreadCount(t *testing.T) {
	m := NewMachMonitor()
	pid := os.Getpid()

	count, err := m.GetThreadCount(pid)
	if err != nil {
		t.Fatalf("GetThreadCount(%d) error = %v", pid, err)
	}

	// Go runtime uses multiple threads
	if count < 1 {
		t.Errorf("ThreadCount = %d, want >= 1", count)
	}

	t.Logf("Thread count: %d", count)
}

func TestMachMonitor_Cleanup(t *testing.T) {
	m := NewMachMonitor()
	pid := os.Getpid()

	// Create a sample
	_, err := m.GetCPUPercent(pid)
	if err != nil {
		t.Fatalf("GetCPUPercent error = %v", err)
	}

	// Verify sample exists
	m.mu.RLock()
	_, exists := m.lastSamples[pid]
	m.mu.RUnlock()
	if !exists {
		t.Error("Sample should exist after GetCPUPercent")
	}

	// Cleanup
	m.Cleanup(pid)

	// Verify sample is removed
	m.mu.RLock()
	_, exists = m.lastSamples[pid]
	m.mu.RUnlock()
	if exists {
		t.Error("Sample should not exist after Cleanup")
	}
}

func TestIsCGOEnabled(t *testing.T) {
	// Just verify it returns a boolean (implementation depends on build tags)
	enabled := IsCGOEnabled()
	t.Logf("CGO enabled: %v", enabled)

	// Verify the constant matches the function
	if enabled != cgoEnabled {
		t.Errorf("IsCGOEnabled() = %v, but cgoEnabled = %v", enabled, cgoEnabled)
	}
}

func TestMachMonitor_ConsistentResults(t *testing.T) {
	m := NewMachMonitor()
	pid := os.Getpid()

	// Get info multiple times, results should be consistent
	info1, err := m.GetProcessInfo(pid)
	if err != nil {
		t.Fatalf("First GetProcessInfo error = %v", err)
	}

	info2, err := m.GetProcessInfo(pid)
	if err != nil {
		t.Fatalf("Second GetProcessInfo error = %v", err)
	}

	// Thread count should be stable
	if info1.NumThreads != info2.NumThreads {
		t.Logf("Note: Thread count changed between calls: %d -> %d", info1.NumThreads, info2.NumThreads)
	}

	// Memory values should be in same ballpark (allow some variation)
	rssDiff := float64(info2.ResidentSize) / float64(info1.ResidentSize)
	if rssDiff < 0.5 || rssDiff > 2.0 {
		t.Errorf("RSS values too different: %d vs %d", info1.ResidentSize, info2.ResidentSize)
	}
}

