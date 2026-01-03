//go:build windows

package wsl2

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/agentsh/agentsh/internal/platform"
)

const (
	// cgroupBasePath is the base path for cgroups v2 inside WSL2
	cgroupBasePath = "/sys/fs/cgroup"
	// agentshCgroupDir is the subdirectory for agentsh cgroups
	agentshCgroupDir = "agentsh"
)

// ResourceLimiter implements platform.ResourceLimiter for WSL2.
// It delegates to the Linux cgroups v2 implementation running inside WSL2.
type ResourceLimiter struct {
	platform        *Platform
	available       bool
	supportedLimits []platform.ResourceType
	handles         map[string]*ResourceHandle
	mu              sync.Mutex
}

// NewResourceLimiter creates a new WSL2 resource limiter.
func NewResourceLimiter(p *Platform) *ResourceLimiter {
	r := &ResourceLimiter{
		platform: p,
		handles:  make(map[string]*ResourceHandle),
	}
	r.available = r.checkAvailable()
	r.supportedLimits = r.detectSupportedLimits()

	// Ensure agentsh cgroup directory exists
	if r.available {
		r.ensureAgentshCgroup()
	}

	return r
}

// checkAvailable checks if cgroups v2 is available in WSL2.
func (r *ResourceLimiter) checkAvailable() bool {
	out, err := r.platform.RunInWSL("cat", "/proc/filesystems")
	if err != nil {
		return false
	}
	return strings.Contains(out, "cgroup2")
}

// detectSupportedLimits checks which cgroup controllers are available.
func (r *ResourceLimiter) detectSupportedLimits() []platform.ResourceType {
	if !r.available {
		return nil
	}

	// Check which controllers are available
	out, err := r.platform.RunInWSL("cat", "/sys/fs/cgroup/cgroup.controllers")
	if err != nil {
		return nil
	}

	controllers := strings.Fields(out)
	ctrlSet := make(map[string]bool)
	for _, c := range controllers {
		ctrlSet[c] = true
	}

	var supported []platform.ResourceType

	if ctrlSet["cpu"] {
		supported = append(supported, platform.ResourceCPU, platform.ResourceCPUAffinity)
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

	return supported
}

// ensureAgentshCgroup creates the agentsh cgroup directory if it doesn't exist.
func (r *ResourceLimiter) ensureAgentshCgroup() {
	cgPath := fmt.Sprintf("%s/%s", cgroupBasePath, agentshCgroupDir)
	// mkdir -p and enable controllers
	_, _ = r.platform.RunInWSL("sudo", "mkdir", "-p", cgPath)

	// Enable controllers in parent
	controllers := "+cpu +memory +pids +io"
	_, _ = r.platform.RunInWSL("sudo", "sh", "-c",
		fmt.Sprintf("echo '%s' > %s/cgroup.subtree_control 2>/dev/null || true", controllers, cgroupBasePath))
}

// Available returns whether resource limiting is available.
func (r *ResourceLimiter) Available() bool {
	return r.available
}

// SupportedLimits returns which resource types can be limited.
func (r *ResourceLimiter) SupportedLimits() []platform.ResourceType {
	return r.supportedLimits
}

// Apply applies resource limits using cgroups inside WSL2.
func (r *ResourceLimiter) Apply(config platform.ResourceConfig) (platform.ResourceHandle, error) {
	if !r.available {
		return nil, fmt.Errorf("cgroups not available in WSL2")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	name := config.Name
	if name == "" {
		name = "default"
	}

	cgPath := fmt.Sprintf("%s/%s/%s", cgroupBasePath, agentshCgroupDir, name)

	// Create cgroup directory
	if _, err := r.platform.RunInWSL("sudo", "mkdir", "-p", cgPath); err != nil {
		return nil, fmt.Errorf("create cgroup: %w", err)
	}

	// Apply memory limit
	if config.MaxMemoryMB > 0 {
		memBytes := config.MaxMemoryMB * 1024 * 1024
		if _, err := r.platform.RunInWSL("sudo", "sh", "-c",
			fmt.Sprintf("echo %d > %s/memory.max", memBytes, cgPath)); err != nil {
			return nil, fmt.Errorf("set memory.max: %w", err)
		}
	}

	// Apply CPU limit (cpu.max format: "quota period" in microseconds)
	if config.MaxCPUPercent > 0 {
		// period = 100000us (100ms), quota = percent * 1000
		period := 100000
		quota := int(config.MaxCPUPercent) * 1000
		if _, err := r.platform.RunInWSL("sudo", "sh", "-c",
			fmt.Sprintf("echo '%d %d' > %s/cpu.max", quota, period, cgPath)); err != nil {
			return nil, fmt.Errorf("set cpu.max: %w", err)
		}
	}

	// Apply process limit
	if config.MaxProcesses > 0 {
		if _, err := r.platform.RunInWSL("sudo", "sh", "-c",
			fmt.Sprintf("echo %d > %s/pids.max", config.MaxProcesses, cgPath)); err != nil {
			return nil, fmt.Errorf("set pids.max: %w", err)
		}
	}

	// Apply I/O limits (requires knowing the device, skip for now if not provided)
	// io.max format: "MAJOR:MINOR rbps=BYTES wbps=BYTES"
	if config.MaxDiskReadMBps > 0 || config.MaxDiskWriteMBps > 0 {
		// Get root device major:minor
		deviceOut, err := r.platform.RunInWSL("sh", "-c",
			"lsblk -o MAJ:MIN,MOUNTPOINT | grep ' /$' | awk '{print $1}'")
		if err == nil && strings.TrimSpace(deviceOut) != "" {
			device := strings.TrimSpace(deviceOut)
			rbps := uint64(config.MaxDiskReadMBps) * 1024 * 1024
			wbps := uint64(config.MaxDiskWriteMBps) * 1024 * 1024
			ioMax := fmt.Sprintf("%s rbps=%d wbps=%d", device, rbps, wbps)
			_, _ = r.platform.RunInWSL("sudo", "sh", "-c",
				fmt.Sprintf("echo '%s' > %s/io.max", ioMax, cgPath))
		}
	}

	handle := &ResourceHandle{
		name:     name,
		config:   config,
		platform: r.platform,
		cgPath:   cgPath,
	}

	r.handles[name] = handle
	return handle, nil
}

// ResourceHandle represents applied resource limits via cgroups in WSL2.
type ResourceHandle struct {
	name     string
	config   platform.ResourceConfig
	platform *Platform
	cgPath   string // cgroup path inside WSL2
}

// AssignProcess adds a process to this cgroup inside WSL2.
func (h *ResourceHandle) AssignProcess(pid int) error {
	if h.cgPath == "" {
		return fmt.Errorf("cgroup path not set")
	}

	// Write PID to cgroup.procs
	_, err := h.platform.RunInWSL("sudo", "sh", "-c",
		fmt.Sprintf("echo %d > %s/cgroup.procs", pid, h.cgPath))
	if err != nil {
		return fmt.Errorf("assign process %d to cgroup: %w", pid, err)
	}

	return nil
}

// Stats returns current resource usage from cgroups.
func (h *ResourceHandle) Stats() platform.ResourceStats {
	stats := platform.ResourceStats{}

	if h.cgPath == "" {
		return stats
	}

	// Read memory.current
	if out, err := h.platform.RunInWSL("cat", h.cgPath+"/memory.current"); err == nil {
		if bytes, err := strconv.ParseUint(strings.TrimSpace(out), 10, 64); err == nil {
			stats.MemoryMB = bytes / 1024 / 1024
		}
	}

	// Read cpu.stat for usage_usec
	if out, err := h.platform.RunInWSL("cat", h.cgPath+"/cpu.stat"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "usage_usec ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if usec, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
						// Convert to rough percentage (usec since start)
						stats.CPUPercent = float64(usec) / 1000000.0
					}
				}
			}
		}
	}

	// Read cgroup.procs for process count
	if out, err := h.platform.RunInWSL("cat", h.cgPath+"/cgroup.procs"); err == nil {
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if lines[0] != "" {
			stats.ProcessCount = len(lines)
		}
	}

	// Read io.stat for disk I/O
	if out, err := h.platform.RunInWSL("cat", h.cgPath+"/io.stat"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			for _, f := range fields {
				if strings.HasPrefix(f, "rbytes=") {
					if v, err := strconv.ParseInt(strings.TrimPrefix(f, "rbytes="), 10, 64); err == nil {
						stats.DiskReadMB += v / 1024 / 1024
					}
				}
				if strings.HasPrefix(f, "wbytes=") {
					if v, err := strconv.ParseInt(strings.TrimPrefix(f, "wbytes="), 10, 64); err == nil {
						stats.DiskWriteMB += v / 1024 / 1024
					}
				}
			}
		}
	}

	return stats
}

// Release removes the cgroup.
func (h *ResourceHandle) Release() error {
	if h.cgPath == "" {
		return nil
	}

	// Kill all processes in cgroup first
	_, _ = h.platform.RunInWSL("sudo", "sh", "-c",
		fmt.Sprintf("cat %s/cgroup.procs 2>/dev/null | xargs -r kill -9 2>/dev/null || true", h.cgPath))

	// Remove the cgroup directory
	_, err := h.platform.RunInWSL("sudo", "rmdir", h.cgPath)
	if err != nil {
		// May fail if processes still running, try again after a delay
		return fmt.Errorf("remove cgroup: %w", err)
	}

	return nil
}

// Compile-time interface checks
var (
	_ platform.ResourceLimiter = (*ResourceLimiter)(nil)
	_ platform.ResourceHandle  = (*ResourceHandle)(nil)
)
