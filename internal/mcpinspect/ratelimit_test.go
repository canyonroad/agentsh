package mcpinspect

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

func TestRateLimiterRegistry_DefaultLimits(t *testing.T) {
	cfg := config.MCPRateLimitsConfig{
		Enabled:      true,
		DefaultRPM:   60,
		DefaultBurst: 10,
	}

	reg := NewRateLimiterRegistry(cfg)

	// First call should be allowed
	if !reg.Allow("github", "create_issue") {
		t.Error("First call should be allowed")
	}

	// Exhaust burst
	for i := 0; i < 9; i++ {
		reg.Allow("github", "create_issue")
	}

	// Next call should be blocked (burst exhausted)
	if reg.Allow("github", "create_issue") {
		t.Error("Call after burst exhausted should be blocked")
	}
}

func TestRateLimiterRegistry_PerServerLimits(t *testing.T) {
	cfg := config.MCPRateLimitsConfig{
		Enabled:      true,
		DefaultRPM:   60,
		DefaultBurst: 10,
		PerServer: map[string]config.MCPRateLimit{
			"slow-server": {CallsPerMinute: 6, Burst: 2},
		},
	}

	reg := NewRateLimiterRegistry(cfg)

	// slow-server should have stricter limits
	reg.Allow("slow-server", "tool1")
	reg.Allow("slow-server", "tool2")
	if reg.Allow("slow-server", "tool3") {
		t.Error("slow-server should be limited after burst of 2")
	}

	// other servers use default
	for i := 0; i < 10; i++ {
		reg.Allow("fast-server", "tool1")
	}
	if reg.Allow("fast-server", "tool1") {
		t.Error("fast-server should be limited after burst of 10")
	}
}

func TestRateLimiterRegistry_Disabled(t *testing.T) {
	cfg := config.MCPRateLimitsConfig{
		Enabled: false,
	}

	reg := NewRateLimiterRegistry(cfg)

	// All calls should be allowed when disabled
	for i := 0; i < 1000; i++ {
		if !reg.Allow("any", "tool") {
			t.Error("All calls should be allowed when disabled")
		}
	}
}
