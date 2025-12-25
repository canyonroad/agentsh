//go:build windows

package windows

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/platform"
)

// ResourceLimiter implements platform.ResourceLimiter for Windows.
// Uses Job Objects for process resource limits.
type ResourceLimiter struct {
	available       bool
	supportedLimits []platform.ResourceType
}

// NewResourceLimiter creates a new Windows resource limiter.
func NewResourceLimiter() *ResourceLimiter {
	r := &ResourceLimiter{
		available: true, // Job Objects always available on modern Windows
	}
	r.supportedLimits = r.detectSupportedLimits()
	return r
}

// detectSupportedLimits returns which resource types can be limited.
func (r *ResourceLimiter) detectSupportedLimits() []platform.ResourceType {
	// Job Objects support CPU, memory, and process count limits
	return []platform.ResourceType{
		platform.ResourceCPU,
		platform.ResourceMemory,
		platform.ResourceProcessCount,
		platform.ResourceCPUAffinity,
	}
}

// Available returns whether resource limiting is available.
func (r *ResourceLimiter) Available() bool {
	return r.available
}

// SupportedLimits returns which resource types can be limited.
func (r *ResourceLimiter) SupportedLimits() []platform.ResourceType {
	return r.supportedLimits
}

// Apply applies resource limits using Job Objects.
// Note: Full implementation requires Windows API calls.
func (r *ResourceLimiter) Apply(config platform.ResourceConfig) (platform.ResourceHandle, error) {
	if !r.available {
		return nil, fmt.Errorf("resource limiting not available")
	}

	// TODO: Implement Job Object creation with limits
	// This would involve:
	// 1. CreateJobObject
	// 2. SetInformationJobObject with JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	// 3. AssignProcessToJobObject for each process

	handle := &ResourceHandle{
		name:   config.Name,
		config: config,
	}

	return handle, nil
}

// ResourceHandle represents applied resource limits via Job Objects.
type ResourceHandle struct {
	name   string
	config platform.ResourceConfig
	// TODO: Add Windows HANDLE for the Job Object
}

// AssignProcess adds a process to this Job Object.
func (h *ResourceHandle) AssignProcess(pid int) error {
	// TODO: Implement AssignProcessToJobObject
	return fmt.Errorf("Job Object process assignment not yet implemented")
}

// Stats returns current resource usage.
func (h *ResourceHandle) Stats() platform.ResourceStats {
	// TODO: Query Job Object for resource usage statistics
	return platform.ResourceStats{}
}

// Release removes the resource limits by closing the Job Object.
func (h *ResourceHandle) Release() error {
	// TODO: CloseHandle on Job Object
	return nil
}

// Compile-time interface checks
var (
	_ platform.ResourceLimiter = (*ResourceLimiter)(nil)
	_ platform.ResourceHandle  = (*ResourceHandle)(nil)
)
