//go:build darwin && cgo

package darwin

import (
	"fmt"
	"sync"

	"github.com/agentsh/agentsh/internal/platform"
)

// ResourceLimiter implements platform.ResourceLimiter for macOS.
// Uses userspace CPU monitoring with SIGSTOP/SIGCONT throttling.
//
// Note: Memory limits via RLIMIT_AS are not yet implemented because Go's
// exec.Cmd does not support setting rlimits via SysProcAttr on darwin.
// A future implementation could use a wrapper script or CGO-based fork/exec.
type ResourceLimiter struct {
	available       bool
	supportedLimits []platform.ResourceType
	mu              sync.Mutex
	handles         map[string]*ResourceHandle
}

// NewResourceLimiter creates a new macOS resource limiter.
func NewResourceLimiter() *ResourceLimiter {
	r := &ResourceLimiter{
		available: true,
		supportedLimits: []platform.ResourceType{
			platform.ResourceCPU,
			// Note: ResourceMemory is NOT listed because RLIMIT_AS enforcement
			// is not yet implemented. See package comment.
		},
		handles: make(map[string]*ResourceHandle),
	}
	return r
}

// Available returns whether resource limiting is available.
func (r *ResourceLimiter) Available() bool {
	return r.available
}

// SupportedLimits returns which resource types can be limited.
func (r *ResourceLimiter) SupportedLimits() []platform.ResourceType {
	return r.supportedLimits
}

// Apply applies resource limits.
func (r *ResourceLimiter) Apply(config platform.ResourceConfig) (platform.ResourceHandle, error) {
	// Validate: reject unsupported limits
	if config.MaxMemoryMB > 0 {
		return nil, fmt.Errorf("memory limits not yet implemented on macOS (requires RLIMIT_AS enforcement in child process)")
	}
	if config.MaxProcesses > 0 {
		return nil, fmt.Errorf("process count limits not supported on macOS")
	}
	if config.MaxDiskReadMBps > 0 || config.MaxDiskWriteMBps > 0 {
		return nil, fmt.Errorf("disk I/O limits not supported on macOS")
	}
	if len(config.CPUAffinity) > 0 {
		return nil, fmt.Errorf("CPU affinity not supported on macOS")
	}
	if config.MaxNetworkMbps > 0 {
		return nil, fmt.Errorf("network bandwidth limits not supported on macOS")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for duplicate
	if _, exists := r.handles[config.Name]; exists {
		return nil, fmt.Errorf("resource handle %q already exists", config.Name)
	}

	handle := newResourceHandle(config.Name, config)
	r.handles[config.Name] = handle

	return handle, nil
}

// GetHandle returns an existing handle by name.
func (r *ResourceLimiter) GetHandle(name string) (*ResourceHandle, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.handles[name]
	return h, ok
}

// Release removes a resource handle.
func (r *ResourceLimiter) Release(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	h, ok := r.handles[name]
	if !ok {
		return fmt.Errorf("handle %q not found", name)
	}

	if err := h.Release(); err != nil {
		return err
	}

	delete(r.handles, name)
	return nil
}

// Compile-time interface check
var _ platform.ResourceLimiter = (*ResourceLimiter)(nil)
