package llmproxy

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

func TestLLMRateLimiter_RPM(t *testing.T) {
	lim := NewLLMRateLimiter(config.LLMRateLimitsConfig{
		Enabled:           true,
		RequestsPerMinute: 10,
		RequestBurst:      2,
	})
	for i := 0; i < 2; i++ {
		if !lim.AllowRequest() {
			t.Fatalf("request %d should be allowed (within burst)", i)
		}
	}
	if lim.AllowRequest() {
		t.Fatal("request 3 should be blocked (burst exceeded)")
	}
}

func TestLLMRateLimiter_TPM(t *testing.T) {
	lim := NewLLMRateLimiter(config.LLMRateLimitsConfig{
		Enabled:         true,
		TokensPerMinute: 100,
		TokenBurst:      50,
	})
	if !lim.AllowTokens(40) {
		t.Fatal("40 tokens should be allowed")
	}
	if lim.AllowTokens(20) {
		t.Fatal("20 more should be blocked (only ~10 left)")
	}
}

func TestLLMRateLimiter_Disabled(t *testing.T) {
	lim := NewLLMRateLimiter(config.LLMRateLimitsConfig{Enabled: false})
	for i := 0; i < 100; i++ {
		if !lim.AllowRequest() {
			t.Fatal("should always allow when disabled")
		}
	}
}

func TestLLMRateLimiter_DefaultBurst(t *testing.T) {
	// When burst is not set, it should default to max(RPM/6, 1)
	lim := NewLLMRateLimiter(config.LLMRateLimitsConfig{
		Enabled:           true,
		RequestsPerMinute: 60,
		// RequestBurst not set, should default to 60/6 = 10
	})
	// Should allow up to 10 requests (default burst)
	for i := 0; i < 10; i++ {
		if !lim.AllowRequest() {
			t.Fatalf("request %d should be allowed (within default burst of 10)", i)
		}
	}
	if lim.AllowRequest() {
		t.Fatal("request 11 should be blocked (default burst exceeded)")
	}
}

func TestLLMRateLimiter_ConsumeTokens(t *testing.T) {
	lim := NewLLMRateLimiter(config.LLMRateLimitsConfig{
		Enabled:         true,
		TokensPerMinute: 100,
		TokenBurst:      50,
	})
	// Consume tokens, then check remaining budget
	lim.ConsumeTokens(30)
	if !lim.AllowTokens(15) {
		t.Fatal("15 tokens should be allowed after consuming 30 of 50 burst")
	}
	if lim.AllowTokens(10) {
		t.Fatal("10 more tokens should be blocked (only ~5 left)")
	}
}

func TestLLMRateLimiter_ConsumeTokensZero(t *testing.T) {
	lim := NewLLMRateLimiter(config.LLMRateLimitsConfig{
		Enabled:         true,
		TokensPerMinute: 100,
		TokenBurst:      50,
	})
	// Consuming zero or negative should be a no-op
	lim.ConsumeTokens(0)
	lim.ConsumeTokens(-5)
	if !lim.AllowTokens(50) {
		t.Fatal("full burst should still be available after consuming 0 tokens")
	}
}

func TestLLMRateLimiter_OnlyRPM(t *testing.T) {
	lim := NewLLMRateLimiter(config.LLMRateLimitsConfig{
		Enabled:           true,
		RequestsPerMinute: 10,
		RequestBurst:      2,
		// No TPM configured
	})
	// RPM should work
	if !lim.AllowRequest() {
		t.Fatal("request should be allowed")
	}
	// TPM should always allow (not configured)
	if !lim.AllowTokens(1000000) {
		t.Fatal("tokens should always be allowed when TPM not configured")
	}
}

func TestLLMRateLimiter_OnlyTPM(t *testing.T) {
	lim := NewLLMRateLimiter(config.LLMRateLimitsConfig{
		Enabled:         true,
		TokensPerMinute: 100,
		TokenBurst:      50,
		// No RPM configured
	})
	// RPM should always allow (not configured)
	for i := 0; i < 100; i++ {
		if !lim.AllowRequest() {
			t.Fatal("requests should always be allowed when RPM not configured")
		}
	}
	// TPM should work
	if !lim.AllowTokens(40) {
		t.Fatal("40 tokens should be allowed")
	}
}
