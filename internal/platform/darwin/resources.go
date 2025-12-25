//go:build darwin

package darwin

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/platform"
)

// ResourceLimiter implements platform.ResourceLimiter for macOS.
// Note: macOS lacks cgroups. Process limits can be set via setrlimit
// but this is much more limited than Linux cgroups.
type ResourceLimiter struct {
	available       bool
	supportedLimits []platform.ResourceType
}

// NewResourceLimiter creates a new macOS resource limiter.
func NewResourceLimiter() *ResourceLimiter {
	r := &ResourceLimiter{
		available:       false, // No cgroups on macOS
		supportedLimits: nil,
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
// Note: Returns error as cgroups are not available on macOS.
func (r *ResourceLimiter) Apply(config platform.ResourceConfig) (platform.ResourceHandle, error) {
	return nil, fmt.Errorf("resource limiting not available on macOS (no cgroups)")
}

// Compile-time interface check
var _ platform.ResourceLimiter = (*ResourceLimiter)(nil)
