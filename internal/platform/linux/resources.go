//go:build linux

package linux

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/agentsh/agentsh/internal/limits"
	"github.com/agentsh/agentsh/internal/platform"
)

// ResourceLimiter implements platform.ResourceLimiter for Linux using cgroups v2.
type ResourceLimiter struct {
	available       bool
	supportedLimits []platform.ResourceType
	mu              sync.Mutex
	handles         map[string]*ResourceHandle
}

// NewResourceLimiter creates a new Linux resource limiter.
func NewResourceLimiter() *ResourceLimiter {
	r := &ResourceLimiter{
		handles: make(map[string]*ResourceHandle),
	}
	r.available = r.checkAvailable()
	r.supportedLimits = r.detectSupportedLimits()
	return r
}

// checkAvailable checks if cgroups v2 is available.
func (r *ResourceLimiter) checkAvailable() bool {
	return limits.DetectCgroupV2()
}

// detectSupportedLimits determines which resource limits are available.
func (r *ResourceLimiter) detectSupportedLimits() []platform.ResourceType {
	if !r.available {
		return nil
	}

	var supported []platform.ResourceType

	// Check which controllers are available
	cgDir, err := limits.CurrentCgroupDir()
	if err != nil {
		return nil
	}

	controllers, err := os.ReadFile(filepath.Join(cgDir, "cgroup.controllers"))
	if err != nil {
		return nil
	}

	ctrlList := strings.Fields(string(controllers))
	ctrlSet := make(map[string]bool)
	for _, c := range ctrlList {
		ctrlSet[c] = true
	}

	// Map controllers to resource types
	if ctrlSet["cpu"] {
		supported = append(supported, platform.ResourceCPU)
		supported = append(supported, platform.ResourceCPUAffinity)
	}
	if ctrlSet["memory"] {
		supported = append(supported, platform.ResourceMemory)
	}
	if ctrlSet["pids"] {
		supported = append(supported, platform.ResourceProcessCount)
	}
	if ctrlSet["io"] {
		supported = append(supported, platform.ResourceDiskIO)
	}
	// Network bandwidth limiting requires tc/eBPF, not cgroups
	// We don't claim support for it here

	return supported
}

// Available returns whether resource limiting is available.
func (r *ResourceLimiter) Available() bool {
	return r.available
}

// SupportedLimits returns which resource types can be limited.
func (r *ResourceLimiter) SupportedLimits() []platform.ResourceType {
	return r.supportedLimits
}

// Apply applies resource limits using cgroups v2.
func (r *ResourceLimiter) Apply(config platform.ResourceConfig) (platform.ResourceHandle, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Convert platform config to limits package config
	lim := limits.CgroupV2Limits{}

	if config.MaxMemoryMB > 0 {
		lim.MaxMemoryBytes = int64(config.MaxMemoryMB) * 1024 * 1024
	}
	if config.MaxCPUPercent > 0 {
		lim.CPUQuotaPct = int(config.MaxCPUPercent)
	}
	if config.MaxProcesses > 0 {
		lim.PidsMax = int(config.MaxProcesses)
	}

	// Create handle with config stored (we'll apply when a process is assigned)
	handle := &ResourceHandle{
		name:   config.Name,
		config: config,
		limits: lim,
	}

	r.handles[config.Name] = handle
	return handle, nil
}

// ResourceHandle implements platform.ResourceHandle for Linux cgroups.
type ResourceHandle struct {
	name   string
	config platform.ResourceConfig
	limits limits.CgroupV2Limits
	cgroup *limits.CgroupV2
	mu     sync.Mutex
}

// AssignProcess adds a process to this cgroup.
func (h *ResourceHandle) AssignProcess(pid int) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Create or reuse cgroup
	if h.cgroup == nil {
		cg, err := limits.ApplyCgroupV2("", h.name, pid, h.limits)
		if err != nil {
			return err
		}
		h.cgroup = cg
	} else {
		// Add to existing cgroup
		procsPath := filepath.Join(h.cgroup.Path, "cgroup.procs")
		if err := os.WriteFile(procsPath, []byte(strconv.Itoa(pid)), 0o644); err != nil {
			return err
		}
	}

	return nil
}

// Stats returns current resource usage from the cgroup.
func (h *ResourceHandle) Stats() platform.ResourceStats {
	h.mu.Lock()
	defer h.mu.Unlock()

	stats := platform.ResourceStats{}

	if h.cgroup == nil {
		return stats
	}

	// Read memory usage
	if data, err := os.ReadFile(filepath.Join(h.cgroup.Path, "memory.current")); err == nil {
		if bytes, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil {
			stats.MemoryMB = uint64(bytes / (1024 * 1024))
		}
	}

	// Read CPU usage (requires calculating delta, simplified here)
	if data, err := os.ReadFile(filepath.Join(h.cgroup.Path, "cpu.stat")); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "usage_usec ") {
				// This is total CPU time, not percentage
				// Would need sampling to calculate percentage
			}
		}
	}

	// Read process count
	if data, err := os.ReadFile(filepath.Join(h.cgroup.Path, "pids.current")); err == nil {
		if count, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			stats.ProcessCount = count
		}
	}

	// Read IO stats
	if data, err := os.ReadFile(filepath.Join(h.cgroup.Path, "io.stat")); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			for _, f := range fields {
				if strings.HasPrefix(f, "rbytes=") {
					if v, err := strconv.ParseInt(strings.TrimPrefix(f, "rbytes="), 10, 64); err == nil {
						stats.DiskReadMB += v / (1024 * 1024)
					}
				}
				if strings.HasPrefix(f, "wbytes=") {
					if v, err := strconv.ParseInt(strings.TrimPrefix(f, "wbytes="), 10, 64); err == nil {
						stats.DiskWriteMB += v / (1024 * 1024)
					}
				}
			}
		}
	}

	return stats
}

// Release removes the cgroup.
func (h *ResourceHandle) Release() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.cgroup == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5)
	defer cancel()

	err := h.cgroup.Close(ctx)
	h.cgroup = nil
	return err
}

// Compile-time interface checks
var (
	_ platform.ResourceLimiter = (*ResourceLimiter)(nil)
	_ platform.ResourceHandle  = (*ResourceHandle)(nil)
)
