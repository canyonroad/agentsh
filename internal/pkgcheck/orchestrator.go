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
	Providers     map[string]ProviderEntry
	PrivacyFilter *PrivacyFilter // optional; nil means no filtering
}

// Orchestrator fans out check requests to all enabled providers in parallel,
// handles per-provider timeouts and failures, and merges the results.
type Orchestrator struct {
	cfg OrchestratorConfig
}

// NewOrchestrator creates a new Orchestrator with the given configuration.
func NewOrchestrator(cfg OrchestratorConfig) *Orchestrator {
	// Defensively copy the Providers map to prevent external mutation.
	providers := make(map[string]ProviderEntry, len(cfg.Providers))
	for k, v := range cfg.Providers {
		providers[k] = v
	}
	return &Orchestrator{cfg: OrchestratorConfig{
		Providers:     providers,
		PrivacyFilter: cfg.PrivacyFilter,
	}}
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

			// Guard against nil provider to prevent panics.
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

// isLocalProvider reports whether a CheckProvider implements the optional
// LocalProvider interface and returns true from IsLocal().
func isLocalProvider(p CheckProvider) bool {
	lp, ok := p.(LocalProvider)
	return ok && lp.IsLocal()
}

// CheckAllWithPrivacy applies the configured PrivacyFilter (if any) before
// dispatching the request to all providers. Returns merged findings, provider
// errors, and the list of packages that were not externally scanned.
//
// Local providers (those implementing LocalProvider and returning true from
// IsLocal) bypass the privacy filter — they run in-process with no network
// calls, so private packages should still receive license/metadata checks.
//
// External providers see only the filtered (scan) list. If the filter leaves
// no packages eligible for external scanning and there are no local providers,
// external providers are not invoked at all to avoid spurious API-key /
// transport errors from a fan-out over an empty list.
func (o *Orchestrator) CheckAllWithPrivacy(ctx context.Context, req CheckRequest) ([]Finding, []ProviderError, []SkippedPackage) {
	fullPackages := req.Packages
	var skipped []SkippedPackage
	if o.cfg.PrivacyFilter != nil {
		scan, skip := o.cfg.PrivacyFilter.Partition(req.Packages)
		req.Packages = scan
		skipped = skip
	}

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		findings []Finding
		errs     []ProviderError
	)

	hasWork := len(req.Packages) > 0
	for _, entry := range o.cfg.Providers {
		if isLocalProvider(entry.Provider) {
			hasWork = true
			break
		}
	}
	if !hasWork {
		return nil, nil, skipped
	}

	for name, entry := range o.cfg.Providers {
		// When the privacy filter has skipped every package, external
		// providers have nothing to do — calling them would fire empty
		// HTTP requests at remote APIs. Skip them. Local providers still
		// run on the full original list (license/metadata checks remain
		// useful for private packages).
		if len(req.Packages) == 0 && !isLocalProvider(entry.Provider) {
			continue
		}
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

			providerCtx := ctx
			if entry.Timeout > 0 {
				var cancel context.CancelFunc
				providerCtx, cancel = context.WithTimeout(ctx, entry.Timeout)
				defer cancel()
			}

			// Local providers see the full (unfiltered) package list so that
			// private packages still receive license/metadata checks.
			providerReq := req
			if isLocalProvider(entry.Provider) {
				providerReq.Packages = fullPackages
			}

			resp, err := entry.Provider.CheckBatch(providerCtx, providerReq)

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
	return findings, errs, skipped
}
