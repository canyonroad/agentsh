package skillcheck

import (
	"context"
	"fmt"
	"sync"
)

// OrchestratorConfig holds configuration for the scan orchestrator.
type OrchestratorConfig struct {
	Providers map[string]ProviderEntry
}

// Orchestrator fans out scan requests to all enabled providers in parallel,
// applies per-provider timeouts, and merges the results.
type Orchestrator struct {
	cfg OrchestratorConfig
}

// NewOrchestrator creates a new Orchestrator with the given configuration.
// It defensively copies the Providers map to prevent external mutation.
func NewOrchestrator(cfg OrchestratorConfig) *Orchestrator {
	providers := make(map[string]ProviderEntry, len(cfg.Providers))
	for k, v := range cfg.Providers {
		providers[k] = v
	}
	return &Orchestrator{cfg: OrchestratorConfig{Providers: providers}}
}

// ScanAll dispatches the request to every configured provider concurrently,
// collects all findings, and records any provider-level errors.
func (o *Orchestrator) ScanAll(ctx context.Context, req ScanRequest) ([]Finding, []ProviderError) {
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

			if entry.Provider == nil {
				mu.Lock()
				errs = append(errs, ProviderError{
					Provider:  name,
					Err:       fmt.Errorf("provider is nil"),
					OnFailure: entry.OnFailure,
				})
				mu.Unlock()
				return
			}

			pctx := ctx
			if entry.Timeout > 0 {
				var cancel context.CancelFunc
				pctx, cancel = context.WithTimeout(ctx, entry.Timeout)
				defer cancel()
			}

			resp, err := entry.Provider.Scan(pctx, req)

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

			if resp != nil && resp.Metadata.Error != "" {
				errs = append(errs, ProviderError{
					Provider:  name,
					Err:       fmt.Errorf("%s", resp.Metadata.Error),
					OnFailure: entry.OnFailure,
				})
			}

			if resp != nil && len(resp.Findings) > 0 {
				findings = append(findings, resp.Findings...)
			}
		}(name, entry)
	}

	wg.Wait()
	return findings, errs
}
