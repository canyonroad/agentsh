package pkgcheck

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ProviderEntry pairs a CheckProvider with timeout and failure handling config.
type ProviderEntry struct {
	Provider  CheckProvider
	Timeout   time.Duration
	OnFailure string // "warn" | "deny" | "allow" | "approve"
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

// OrchestratorConfig holds configuration for the check orchestrator.
type OrchestratorConfig struct {
	Providers map[string]ProviderEntry
}

// Orchestrator fans out check requests to all enabled providers in parallel,
// handles per-provider timeouts and failures, and merges the results.
type Orchestrator struct {
	cfg OrchestratorConfig
}

// NewOrchestrator creates a new Orchestrator with the given configuration.
func NewOrchestrator(cfg OrchestratorConfig) *Orchestrator {
	return &Orchestrator{cfg: cfg}
}

// CheckAll dispatches the request to all configured providers in parallel and
// collects the merged findings and any provider errors.
func (o *Orchestrator) CheckAll(ctx context.Context, req CheckRequest) ([]Finding, []ProviderError) {
	if len(o.cfg.Providers) == 0 {
		return nil, nil
	}

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		findings []Finding
		errs     []ProviderError
	)

	for name, entry := range o.cfg.Providers {
		wg.Add(1)
		go func(name string, entry ProviderEntry) {
			defer wg.Done()

			providerCtx := ctx
			if entry.Timeout > 0 {
				var cancel context.CancelFunc
				providerCtx, cancel = context.WithTimeout(ctx, entry.Timeout)
				defer cancel()
			}

			resp, err := entry.Provider.CheckBatch(providerCtx, req)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				errs = append(errs, ProviderError{
					Provider:  name,
					Err:       err,
					OnFailure: entry.OnFailure,
				})
				return
			}

			if resp != nil && len(resp.Findings) > 0 {
				findings = append(findings, resp.Findings...)
			}
		}(name, entry)
	}

	wg.Wait()
	return findings, errs
}
