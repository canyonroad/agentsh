package netmonitor

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

func TestDomainRateLimiter_PerDomainLimits(t *testing.T) {
	cfg := config.NetworkRateLimitsConfig{
		Enabled:     true,
		GlobalRPM:   600,
		GlobalBurst: 50,
		PerDomain: map[string]config.DomainRateLimit{
			"api.openai.com": {RequestsPerMinute: 60, Burst: 10},
		},
	}

	limiter := NewDomainRateLimiter(cfg)

	// OpenAI should have strict limits
	for i := 0; i < 10; i++ {
		limiter.Allow("api.openai.com")
	}
	if limiter.Allow("api.openai.com") {
		t.Error("api.openai.com should be limited after burst of 10")
	}

	// Other domains use global limits
	for i := 0; i < 50; i++ {
		limiter.Allow("example.com")
	}
	if limiter.Allow("example.com") {
		t.Error("example.com should be limited after burst of 50")
	}
}

func TestDomainRateLimiter_Disabled(t *testing.T) {
	cfg := config.NetworkRateLimitsConfig{
		Enabled: false,
	}

	limiter := NewDomainRateLimiter(cfg)

	// All calls should be allowed when disabled
	for i := 0; i < 1000; i++ {
		if !limiter.Allow("any.domain.com") {
			t.Error("All calls should be allowed when disabled")
		}
	}
}

func TestDomainRateLimiter_WildcardDefault(t *testing.T) {
	cfg := config.NetworkRateLimitsConfig{
		Enabled:     true,
		GlobalRPM:   600,
		GlobalBurst: 50,
		PerDomain: map[string]config.DomainRateLimit{
			"*": {RequestsPerMinute: 120, Burst: 5},
		},
	}

	limiter := NewDomainRateLimiter(cfg)

	// Wildcard should apply to unlisted domains
	for i := 0; i < 5; i++ {
		limiter.Allow("unknown.domain.com")
	}
	if limiter.Allow("unknown.domain.com") {
		t.Error("unknown.domain.com should use wildcard limit (burst 5)")
	}
}

func TestDomainRateLimiter_Stats(t *testing.T) {
	cfg := config.NetworkRateLimitsConfig{
		Enabled:     true,
		GlobalRPM:   60,
		GlobalBurst: 10,
		PerDomain: map[string]config.DomainRateLimit{
			"api.example.com": {RequestsPerMinute: 30, Burst: 5},
		},
	}

	limiter := NewDomainRateLimiter(cfg)

	// Make some requests
	limiter.Allow("api.example.com")
	limiter.Allow("other.com")

	stats := limiter.Stats()

	// Should have global stats
	if _, ok := stats["_global"]; !ok {
		t.Error("Stats should include _global")
	}

	// Should have domain-specific stats
	if _, ok := stats["api.example.com"]; !ok {
		t.Error("Stats should include api.example.com")
	}
}
