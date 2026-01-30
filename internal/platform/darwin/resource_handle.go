//go:build darwin && cgo

package darwin

import (
	"sync"
	"syscall"

	"github.com/agentsh/agentsh/internal/platform"
)

// RlimitAS is the syscall constant for RLIMIT_AS (address space limit).
const RlimitAS = syscall.RLIMIT_AS

// RlimitConfig represents an rlimit to be applied to a process.
type RlimitConfig struct {
	Resource int    // e.g., syscall.RLIMIT_AS
	Cur      uint64 // soft limit
	Max      uint64 // hard limit
}

// ResourceHandle represents applied resource limits on macOS.
type ResourceHandle struct {
	name   string
	config platform.ResourceConfig

	mu sync.Mutex

	// Memory limiting via RLIMIT_AS
	rlimitAS uint64 // 0 means no limit

	// CPU monitoring
	monitors map[int]*cpuMonitor // pid -> monitor
	pids     []int
}

// newResourceHandle creates a new resource handle.
func newResourceHandle(name string, config platform.ResourceConfig) *ResourceHandle {
	h := &ResourceHandle{
		name:     name,
		config:   config,
		monitors: make(map[int]*cpuMonitor),
	}

	if config.MaxMemoryMB > 0 {
		h.rlimitAS = config.MaxMemoryMB * 1024 * 1024
	}

	return h
}

// GetRlimits returns the rlimits to apply in the child process.
func (h *ResourceHandle) GetRlimits() []RlimitConfig {
	var limits []RlimitConfig

	if h.rlimitAS > 0 {
		limits = append(limits, RlimitConfig{
			Resource: RlimitAS,
			Cur:      h.rlimitAS,
			Max:      h.rlimitAS,
		})
	}

	return limits
}

// AssignProcess adds a process to this resource handle.
func (h *ResourceHandle) AssignProcess(pid int) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.pids = append(h.pids, pid)

	// Start CPU monitoring if CPU limit is configured
	if h.config.MaxCPUPercent > 0 {
		monitor := newCPUMonitor(pid, h.config.MaxCPUPercent)
		h.monitors[pid] = monitor
		monitor.start()
	}

	return nil
}

// Stats returns current resource usage.
func (h *ResourceHandle) Stats() platform.ResourceStats {
	h.mu.Lock()
	defer h.mu.Unlock()

	stats := platform.ResourceStats{}

	for _, pid := range h.pids {
		rusage, err := getProcRusage(pid)
		if err != nil {
			continue
		}
		stats.MemoryMB += rusage.ResidentSize / (1024 * 1024)
	}

	// Get CPU percent from first active monitor
	for _, monitor := range h.monitors {
		stats.CPUPercent = monitor.getCPUPercent()
		break
	}

	stats.ProcessCount = len(h.pids)

	return stats
}

// Release stops all monitors and cleans up.
func (h *ResourceHandle) Release() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Stop all CPU monitors
	for pid, monitor := range h.monitors {
		// Send SIGCONT in case process is stopped
		syscall.Kill(pid, syscall.SIGCONT)
		monitor.stop()
	}

	h.monitors = make(map[int]*cpuMonitor)
	h.pids = nil

	return nil
}

// Compile-time interface check
var _ platform.ResourceHandle = (*ResourceHandle)(nil)
