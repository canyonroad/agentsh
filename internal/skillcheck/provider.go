package skillcheck

import (
	"context"
	"fmt"
	"time"
)

// CheckProvider scans a single skill for security issues.
type CheckProvider interface {
	// Name returns the provider identifier (e.g. "snyk").
	Name() string

	// Capabilities returns the finding types this provider can produce.
	// May return an empty slice if the provider has no signal for the
	// given runtime configuration (e.g. skills_sh with Origin == nil).
	Capabilities() []FindingType

	// Scan inspects one skill and returns findings.
	Scan(ctx context.Context, req ScanRequest) (*ScanResponse, error)
}

// ProviderEntry pairs a CheckProvider with timeout and failure handling config.
type ProviderEntry struct {
	Provider  CheckProvider
	Timeout   time.Duration
	OnFailure string // "warn" | "block" | "allow" | "approve"
}

// ProviderError records a failure from a single provider.
type ProviderError struct {
	Provider  string
	Err       error
	OnFailure string
}

// Error implements the error interface.
func (e ProviderError) Error() string {
	return fmt.Sprintf("provider %s: %v", e.Provider, e.Err)
}
