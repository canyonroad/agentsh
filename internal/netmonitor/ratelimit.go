package netmonitor

import (
	"sync"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/pkg/ratelimit"
)

// DomainRateLimiter manages rate limits for network domains.
type DomainRateLimiter struct {
	cfg     config.NetworkRateLimitsConfig
	global  *ratelimit.Limiter
	domains map[string]*ratelimit.Limiter
	mu      sync.RWMutex
}

// NewDomainRateLimiter creates a new domain rate limiter.
func NewDomainRateLimiter(cfg config.NetworkRateLimitsConfig) *DomainRateLimiter {
	var global *ratelimit.Limiter
	if cfg.GlobalRPM > 0 {
		global = ratelimit.NewLimiter(float64(cfg.GlobalRPM)/60.0, cfg.GlobalBurst)
	}

	return &DomainRateLimiter{
		cfg:     cfg,
		global:  global,
		domains: make(map[string]*ratelimit.Limiter),
	}
}

// Allow checks if a request to a domain is allowed.
func (d *DomainRateLimiter) Allow(domain string) bool {
	if !d.cfg.Enabled {
		return true
	}

	// Check global limit first
	if d.global != nil && !d.global.Allow() {
		return false
	}

	// Check per-domain limit
	limiter := d.getDomainLimiter(domain)
	if limiter != nil {
		return limiter.Allow()
	}

	return true
}

// AllowN checks if n requests to a domain are allowed.
func (d *DomainRateLimiter) AllowN(domain string, n int) bool {
	if !d.cfg.Enabled {
		return true
	}

	// Check global limit first
	if d.global != nil && !d.global.AllowN(n) {
		return false
	}

	// Check per-domain limit
	limiter := d.getDomainLimiter(domain)
	if limiter != nil {
		return limiter.AllowN(n)
	}

	return true
}

func (d *DomainRateLimiter) getDomainLimiter(domain string) *ratelimit.Limiter {
	// Check if there's a specific config for this domain
	domainCfg, exists := d.cfg.PerDomain[domain]
	if !exists {
		// Check for wildcard
		domainCfg, exists = d.cfg.PerDomain["*"]
		if !exists {
			return nil
		}
	}

	d.mu.RLock()
	limiter, ok := d.domains[domain]
	d.mu.RUnlock()

	if ok {
		return limiter
	}

	// Create new limiter
	d.mu.Lock()
	defer d.mu.Unlock()

	// Double-check after acquiring write lock
	if limiter, ok = d.domains[domain]; ok {
		return limiter
	}

	limiter = ratelimit.NewLimiter(
		float64(domainCfg.RequestsPerMinute)/60.0,
		domainCfg.Burst,
	)
	d.domains[domain] = limiter
	return limiter
}

// Stats returns current token counts.
func (d *DomainRateLimiter) Stats() map[string]float64 {
	d.mu.RLock()
	defer d.mu.RUnlock()

	stats := make(map[string]float64)
	if d.global != nil {
		stats["_global"] = d.global.Tokens()
	}
	for domain, limiter := range d.domains {
		stats[domain] = limiter.Tokens()
	}
	return stats
}

// Reset clears all domain limiters (useful for testing or config reload).
func (d *DomainRateLimiter) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.domains = make(map[string]*ratelimit.Limiter)
}
