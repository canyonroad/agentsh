//go:build darwin && !cgo

package darwin

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/platform"
)

// ResourceLimiter implements platform.ResourceLimiter for macOS without CGO.
// This stub returns "not available" since resource control requires CGO.
type ResourceLimiter struct {
	available       bool
	supportedLimits []platform.ResourceType
}

// NewResourceLimiter creates a new macOS resource limiter (stub).
func NewResourceLimiter() *ResourceLimiter {
	return &ResourceLimiter{
		available:       false,
		supportedLimits: nil,
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

// Apply applies resource limits.
func (r *ResourceLimiter) Apply(config platform.ResourceConfig) (platform.ResourceHandle, error) {
	return nil, fmt.Errorf("resource limiting not available (requires CGO)")
}

// Compile-time interface check
var _ platform.ResourceLimiter = (*ResourceLimiter)(nil)
