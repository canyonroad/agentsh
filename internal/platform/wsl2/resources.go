//go:build windows

package wsl2

import (
	"fmt"
	"strings"

	"github.com/agentsh/agentsh/internal/platform"
)

// ResourceLimiter implements platform.ResourceLimiter for WSL2.
// It delegates to the Linux cgroups v2 implementation running inside WSL2.
type ResourceLimiter struct {
	platform        *Platform
	available       bool
	supportedLimits []platform.ResourceType
}

// NewResourceLimiter creates a new WSL2 resource limiter.
func NewResourceLimiter(p *Platform) *ResourceLimiter {
	r := &ResourceLimiter{
		platform: p,
	}
	r.available = r.checkAvailable()
	r.supportedLimits = r.detectSupportedLimits()
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

	// TODO: Create cgroup inside WSL2 and apply limits
	handle := &ResourceHandle{
		name:     config.Name,
		config:   config,
		platform: r.platform,
	}

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
	// TODO: Write PID to cgroup.procs inside WSL2
	return fmt.Errorf("WSL2 cgroup process assignment not yet implemented")
}

// Stats returns current resource usage from cgroups.
func (h *ResourceHandle) Stats() platform.ResourceStats {
	// TODO: Read cgroup stats from WSL2
	return platform.ResourceStats{}
}

// Release removes the cgroup.
func (h *ResourceHandle) Release() error {
	// TODO: Remove cgroup inside WSL2
	return nil
}

// Compile-time interface checks
var (
	_ platform.ResourceLimiter = (*ResourceLimiter)(nil)
	_ platform.ResourceHandle  = (*ResourceHandle)(nil)
)
