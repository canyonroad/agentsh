//go:build !linux && !darwin && !windows

package limits

import (
	"fmt"
)

// NoopLimiter is a no-op implementation for unsupported platforms.
type NoopLimiter struct{}

// NewNoopLimiter creates a no-op limiter.
func NewNoopLimiter() *NoopLimiter {
	return &NoopLimiter{}
}

// Apply implements ResourceLimiter.
func (l *NoopLimiter) Apply(pid int, limits ResourceLimits) error {
	return fmt.Errorf("resource limits not supported on this platform")
}

// Usage implements ResourceLimiter.
func (l *NoopLimiter) Usage(pid int) (*ResourceUsage, error) {
	return nil, fmt.Errorf("resource limits not supported on this platform")
}

// CheckLimits implements ResourceLimiter.
func (l *NoopLimiter) CheckLimits(pid int) (*LimitViolation, error) {
	return nil, nil
}

// Cleanup implements ResourceLimiter.
func (l *NoopLimiter) Cleanup(pid int) error {
	return nil
}

// Capabilities implements ResourceLimiter.
func (l *NoopLimiter) Capabilities() LimiterCapabilities {
	return LimiterCapabilities{}
}

// Ensure interface compliance
var _ ResourceLimiter = (*NoopLimiter)(nil)
