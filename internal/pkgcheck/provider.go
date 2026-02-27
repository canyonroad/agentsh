package pkgcheck

import (
	"context"
	"time"
)

// CheckProvider inspects packages for security issues.
type CheckProvider interface {
	// Name returns the provider's identifier.
	Name() string

	// Capabilities returns the finding types this provider can produce.
	Capabilities() []FindingType

	// CheckBatch checks a batch of packages and returns findings.
	CheckBatch(ctx context.Context, req CheckRequest) (*CheckResponse, error)
}

// CheckRequest describes what to check.
type CheckRequest struct {
	Ecosystem Ecosystem    `json:"ecosystem" yaml:"ecosystem"`
	Packages  []PackageRef `json:"packages" yaml:"packages"`
	Config    map[string]string `json:"config,omitempty" yaml:"config,omitempty"`
}

// CheckResponse holds the results from a single provider.
type CheckResponse struct {
	Provider string           `json:"provider" yaml:"provider"`
	Findings []Finding        `json:"findings,omitempty" yaml:"findings,omitempty"`
	Metadata ResponseMetadata `json:"metadata" yaml:"metadata"`
}

// ResponseMetadata holds operational details about a provider response.
type ResponseMetadata struct {
	Duration    time.Duration `json:"duration" yaml:"duration"`
	FromCache   bool          `json:"from_cache,omitempty" yaml:"from_cache,omitempty"`
	RateLimited bool          `json:"rate_limited,omitempty" yaml:"rate_limited,omitempty"`
	Partial     bool          `json:"partial,omitempty" yaml:"partial,omitempty"`
	Error       string        `json:"error,omitempty" yaml:"error,omitempty"`
}
