//go:build darwin && cgo

package darwin

import (
	"fmt"
	"sync"

	"github.com/agentsh/agentsh/internal/platform"
)

// ResourceLimiter implements platform.ResourceLimiter for macOS.
// Uses userspace CPU monitoring with SIGSTOP/SIGCONT throttling.
// Memory limits are enforced via RLIMIT_AS using the agentsh-rlimit-exec wrapper.
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
			platform.ResourceMemory, // Via agentsh-rlimit-exec wrapper
			platform.ResourceCPU,    // Via SIGSTOP/SIGCONT throttling
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
