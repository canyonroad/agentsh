package llmproxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

func TestLLMRateLimiter_TokenBudgetAvailable(t *testing.T) {
	lim := NewLLMRateLimiter(config.LLMRateLimitsConfig{
		Enabled:         true,
		TokensPerMinute: 100,
		TokenBurst:      50,
	})

	// Initially budget should be available
	if !lim.TokenBudgetAvailable() {
		t.Fatal("token budget should be available initially")
	}

	// Force-consume more than the burst to drive bucket negative
	lim.ConsumeTokens(100)

	// Now budget should be depleted
	if lim.TokenBudgetAvailable() {
		t.Fatal("token budget should be depleted after consuming 100 tokens (burst was 50)")
	}
}

func TestProxy_TPM_Returns429(t *testing.T) {
	// Upstream returns a response with high token usage to deplete TPM budget.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Report 500 input + 500 output = 1000 total tokens
		w.Write([]byte(`{"id":"msg_test","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"model":"claude-sonnet-4-20250514","usage":{"input_tokens":500,"output_tokens":500}}`))
	}))
	defer upstream.Close()

	storageDir := t.TempDir()
	cfg := Config{
		SessionID: "test-tpm-ratelimit",
		Proxy: config.ProxyConfig{
			Mode: "embedded",
			Port: 0,
			Providers: config.ProxyProvidersConfig{
				Anthropic: upstream.URL,
			},
			RateLimits: config.LLMRateLimitsConfig{
				Enabled:         true,
				TokensPerMinute: 6000,
				TokenBurst:      100, // First response (1000 tokens) will exceed burst
			},
		},
		DLP: config.DefaultDLPConfig(),
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy, err := New(cfg, storageDir, logger)
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	ctx := context.Background()
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		proxy.Stop(shutdownCtx)
	}()

	time.Sleep(10 * time.Millisecond)

	addr := proxy.Addr()
	if addr == nil {
		t.Fatal("proxy address is nil")
	}
	proxyURL := "http://" + addr.String()

	makeRequest := func() *http.Response {
		req, _ := http.NewRequest("POST", proxyURL+"/v1/messages",
			strings.NewReader(`{"model":"claude-sonnet-4-20250514","messages":[{"role":"user","content":"hi"}]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", "test-key")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp
	}

	// First request succeeds; upstream reports 1000 tokens which depletes the 100-token burst budget.
	resp1 := makeRequest()
	if resp1.StatusCode == http.StatusTooManyRequests {
		t.Fatal("first request should not be rate limited")
	}

	// Second request should be rate limited (429) because token budget is depleted.
	resp2 := makeRequest()
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Errorf("second request should be 429 (TPM depleted), got %d", resp2.StatusCode)
	}
	if resp2.Header.Get("Retry-After") == "" {
		t.Error("TPM rate limited response should include Retry-After header")
	}
}

func TestProxy_RPM_Returns429(t *testing.T) {
	// Create a mock upstream that returns a valid Anthropic response
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"msg_test","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"model":"claude-sonnet-4-20250514","usage":{"input_tokens":5,"output_tokens":2}}`))
	}))
	defer upstream.Close()

	storageDir := t.TempDir()
	cfg := Config{
		SessionID: "test-ratelimit",
		Proxy: config.ProxyConfig{
			Mode: "embedded",
			Port: 0,
			Providers: config.ProxyProvidersConfig{
				Anthropic: upstream.URL,
			},
			RateLimits: config.LLMRateLimitsConfig{
				Enabled:           true,
				RequestsPerMinute: 60,
				RequestBurst:      1, // Only allow 1 request
			},
		},
		DLP: config.DefaultDLPConfig(),
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy, err := New(cfg, storageDir, logger)
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	ctx := context.Background()
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		proxy.Stop(shutdownCtx)
	}()

	time.Sleep(10 * time.Millisecond)

	addr := proxy.Addr()
	if addr == nil {
		t.Fatal("proxy address is nil")
	}
	proxyURL := "http://" + addr.String()

	makeRequest := func() *http.Response {
		req, _ := http.NewRequest("POST", proxyURL+"/v1/messages",
			strings.NewReader(`{"model":"claude-sonnet-4-20250514","messages":[{"role":"user","content":"hi"}]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", "test-key")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp
	}

	// First request should succeed (uses the 1 burst token)
	resp1 := makeRequest()
	if resp1.StatusCode == http.StatusTooManyRequests {
		t.Fatal("first request should not be rate limited")
	}

	// Second request should be rate limited (429)
	resp2 := makeRequest()
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Errorf("second request should be 429, got %d", resp2.StatusCode)
	}
	if resp2.Header.Get("Retry-After") == "" {
		t.Error("rate limited response should include Retry-After header")
	}
}
