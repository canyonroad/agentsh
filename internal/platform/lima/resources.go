//go:build darwin

package lima

import (
	"fmt"
	"strings"

	"github.com/agentsh/agentsh/internal/platform"
)

// ResourceLimiter implements platform.ResourceLimiter for Lima.
// It delegates to the Linux cgroups v2 implementation running inside the Lima VM.
type ResourceLimiter struct {
	platform        *Platform
	available       bool
	supportedLimits []platform.ResourceType
}

// NewResourceLimiter creates a new Lima resource limiter.
func NewResourceLimiter(p *Platform) *ResourceLimiter {
	r := &ResourceLimiter{
		platform: p,
	}
	r.available = r.checkAvailable()
	r.supportedLimits = r.detectSupportedLimits()
	return r
}

// checkAvailable checks if cgroups v2 is available in the Lima VM.
func (r *ResourceLimiter) checkAvailable() bool {
	out, err := r.platform.RunInLima("cat", "/proc/filesystems")
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
	out, err := r.platform.RunInLima("cat", "/sys/fs/cgroup/cgroup.controllers")
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

// Apply applies resource limits using cgroups inside the Lima VM.
func (r *ResourceLimiter) Apply(config platform.ResourceConfig) (platform.ResourceHandle, error) {
	if !r.available {
		return nil, fmt.Errorf("cgroups not available in Lima VM")
	}

	// TODO: Create cgroup inside Lima VM and apply limits
	handle := &ResourceHandle{
		name:     config.Name,
		config:   config,
		platform: r.platform,
	}

	return handle, nil
}

// ResourceHandle represents applied resource limits via cgroups in the Lima VM.
type ResourceHandle struct {
	name     string
	config   platform.ResourceConfig
	platform *Platform
	cgPath   string // cgroup path inside Lima VM
}

// AssignProcess adds a process to this cgroup inside the Lima VM.
func (h *ResourceHandle) AssignProcess(pid int) error {
	// TODO: Write PID to cgroup.procs inside Lima VM
	return fmt.Errorf("Lima cgroup process assignment not yet implemented")
}

// Stats returns current resource usage from cgroups.
func (h *ResourceHandle) Stats() platform.ResourceStats {
	// TODO: Read cgroup stats from Lima VM
	return platform.ResourceStats{}
}

// Release removes the cgroup.
func (h *ResourceHandle) Release() error {
	// TODO: Remove cgroup inside Lima VM
	return nil
}

// Compile-time interface checks
var (
	_ platform.ResourceLimiter = (*ResourceLimiter)(nil)
	_ platform.ResourceHandle  = (*ResourceHandle)(nil)
)
