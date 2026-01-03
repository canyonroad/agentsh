//go:build darwin

// Package darwin provides macOS-specific platform implementations.
package darwin

import (
	"sync"
	"time"
)

// ProcessTaskInfo contains resource usage information for a process
// obtained via Mach APIs (proc_pidinfo with PROC_PIDTASKINFO flavor).
type ProcessTaskInfo struct {
	// ResidentSize is the resident memory in bytes (RSS).
	ResidentSize uint64

	// VirtualSize is the virtual memory in bytes.
	VirtualSize uint64

	// UserTime is the total user CPU time in nanoseconds.
	UserTime uint64

	// SystemTime is the total system CPU time in nanoseconds.
	SystemTime uint64

	// TotalTime is UserTime + SystemTime.
	TotalTime uint64

	// NumThreads is the number of threads.
	NumThreads int

	// Priority is the scheduling priority.
	Priority int
}

// ProcessSample stores a snapshot of process resource usage for calculating
// CPU percentage over time.
type ProcessSample struct {
	Timestamp time.Time
	UserTime  uint64 // nanoseconds
	SysTime   uint64 // nanoseconds
}

// MachMonitor provides native Mach API-based resource monitoring for macOS.
// It uses proc_pidinfo() to get process information without spawning external
// commands, which is faster and more accurate than using ps/pgrep.
type MachMonitor struct {
	mu          sync.RWMutex
	lastSamples map[int]*ProcessSample // pid -> last sample for CPU calculation
}

// NewMachMonitor creates a new Mach-based process monitor.
func NewMachMonitor() *MachMonitor {
	return &MachMonitor{
		lastSamples: make(map[int]*ProcessSample),
	}
}

// GetProcessInfo returns detailed task information for a process.
// This is the main entry point - it calls the platform-specific implementation.
func (m *MachMonitor) GetProcessInfo(pid int) (*ProcessTaskInfo, error) {
	return getProcessTaskInfo(pid)
}

// GetMemory returns current memory usage for a process in bytes.
// Returns (rss, virtual, error).
func (m *MachMonitor) GetMemory(pid int) (rss, vms uint64, err error) {
	info, err := m.GetProcessInfo(pid)
	if err != nil {
		return 0, 0, err
	}
	return info.ResidentSize, info.VirtualSize, nil
}

// GetCPUPercent calculates CPU usage percentage for a process.
// This requires at least two samples over time to calculate the percentage.
// On the first call for a PID, returns 0.0 (baseline sample taken).
func (m *MachMonitor) GetCPUPercent(pid int) (float64, error) {
	info, err := m.GetProcessInfo(pid)
	if err != nil {
		return 0, err
	}

	now := time.Now()
	current := &ProcessSample{
		Timestamp: now,
		UserTime:  info.UserTime,
		SysTime:   info.SystemTime,
	}

	m.mu.Lock()
	prev := m.lastSamples[pid]
	m.lastSamples[pid] = current
	m.mu.Unlock()

	if prev == nil {
		// First sample, can't calculate percentage yet
		return 0, nil
	}

	// Calculate elapsed wall-clock time
	wallElapsed := current.Timestamp.Sub(prev.Timestamp).Seconds()
	if wallElapsed <= 0 {
		return 0, nil
	}

	// Calculate elapsed CPU time (already in nanoseconds)
	userElapsed := float64(current.UserTime-prev.UserTime) / 1e9
	sysElapsed := float64(current.SysTime-prev.SysTime) / 1e9
	cpuElapsed := userElapsed + sysElapsed

	// CPU percentage = (CPU time / wall time) * 100
	cpuPercent := (cpuElapsed / wallElapsed) * 100.0

	// Cap at reasonable max (threads * 100%)
	maxPercent := float64(info.NumThreads) * 100.0
	if cpuPercent > maxPercent {
		cpuPercent = maxPercent
	}

	return cpuPercent, nil
}

// GetThreadCount returns the current thread count for a process.
func (m *MachMonitor) GetThreadCount(pid int) (int, error) {
	info, err := m.GetProcessInfo(pid)
	if err != nil {
		return 0, err
	}
	return info.NumThreads, nil
}

// Cleanup removes cached samples for a process.
// Call this when a process exits to free memory.
func (m *MachMonitor) Cleanup(pid int) {
	m.mu.Lock()
	delete(m.lastSamples, pid)
	m.mu.Unlock()
}

// IsCGOEnabled returns whether CGO is enabled (native Mach APIs available).
func IsCGOEnabled() bool {
	return cgoEnabled
}
