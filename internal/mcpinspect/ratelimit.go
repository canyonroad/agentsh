package mcpinspect

import (
	"sync"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/pkg/ratelimit"
)

// RateLimiterRegistry manages rate limiters for MCP servers.
type RateLimiterRegistry struct {
	cfg      config.MCPRateLimitsConfig
	limiters map[string]*ratelimit.Limiter
	mu       sync.RWMutex
}

// NewRateLimiterRegistry creates a new rate limiter registry.
func NewRateLimiterRegistry(cfg config.MCPRateLimitsConfig) *RateLimiterRegistry {
	return &RateLimiterRegistry{
		cfg:      cfg,
		limiters: make(map[string]*ratelimit.Limiter),
	}
}

// Allow checks if a call to a server/tool is allowed under rate limits.
func (r *RateLimiterRegistry) Allow(serverID, toolName string) bool {
	if !r.cfg.Enabled {
		return true
	}

	limiter := r.getLimiter(serverID)
	return limiter.Allow()
}

// AllowN checks if n calls are allowed.
func (r *RateLimiterRegistry) AllowN(serverID, toolName string, n int) bool {
	if !r.cfg.Enabled {
		return true
	}

	limiter := r.getLimiter(serverID)
	return limiter.AllowN(n)
}

func (r *RateLimiterRegistry) getLimiter(serverID string) *ratelimit.Limiter {
	r.mu.RLock()
	limiter, ok := r.limiters[serverID]
	r.mu.RUnlock()

	if ok {
		return limiter
	}

	// Create new limiter
	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check after acquiring write lock
	if limiter, ok = r.limiters[serverID]; ok {
		return limiter
	}

	// Check for per-server config
	rate := float64(r.cfg.DefaultRPM) / 60.0 // Convert RPM to RPS
	burst := r.cfg.DefaultBurst

	if serverCfg, exists := r.cfg.PerServer[serverID]; exists {
		rate = float64(serverCfg.CallsPerMinute) / 60.0
		burst = serverCfg.Burst
	}

	limiter = ratelimit.NewLimiter(rate, burst)
	r.limiters[serverID] = limiter
	return limiter
}

// Reset clears all limiters (useful for testing or config reload).
func (r *RateLimiterRegistry) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.limiters = make(map[string]*ratelimit.Limiter)
}

// Stats returns current token counts for all tracked servers.
func (r *RateLimiterRegistry) Stats() map[string]float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := make(map[string]float64, len(r.limiters))
	for serverID, limiter := range r.limiters {
		stats[serverID] = limiter.Tokens()
	}
	return stats
}
