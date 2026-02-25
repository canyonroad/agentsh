package llmproxy

import (
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/pkg/ratelimit"
)

// LLMRateLimiter enforces RPM (requests per minute) and TPM (tokens per minute)
// rate limits on LLM API calls to prevent denial-of-wallet attacks.
type LLMRateLimiter struct {
	enabled  bool
	reqLimit *ratelimit.Limiter
	tpmLimit *ratelimit.Limiter
}

// NewLLMRateLimiter creates a new LLM rate limiter from configuration.
func NewLLMRateLimiter(cfg config.LLMRateLimitsConfig) *LLMRateLimiter {
	l := &LLMRateLimiter{enabled: cfg.Enabled}
	if !cfg.Enabled {
		return l
	}
	if cfg.RequestsPerMinute > 0 {
		rate := float64(cfg.RequestsPerMinute) / 60.0
		burst := cfg.RequestBurst
		if burst <= 0 {
			burst = max(cfg.RequestsPerMinute/6, 1)
		}
		l.reqLimit = ratelimit.NewLimiter(rate, burst)
	}
	if cfg.TokensPerMinute > 0 {
		rate := float64(cfg.TokensPerMinute) / 60.0
		burst := cfg.TokenBurst
		if burst <= 0 {
			burst = max(cfg.TokensPerMinute/6, 1)
		}
		l.tpmLimit = ratelimit.NewLimiter(rate, burst)
	}
	return l
}

// AllowRequest checks whether a new request is allowed under the RPM limit.
func (l *LLMRateLimiter) AllowRequest() bool {
	if !l.enabled || l.reqLimit == nil {
		return true
	}
	return l.reqLimit.Allow()
}

// AllowTokens checks whether the given number of tokens is allowed under the TPM limit.
func (l *LLMRateLimiter) AllowTokens(n int) bool {
	if !l.enabled || l.tpmLimit == nil {
		return true
	}
	return l.tpmLimit.AllowN(n)
}

// ConsumeTokens deducts tokens from the TPM budget after a response is received.
// Uses force-consume since the operation already happened and must be accounted for.
func (l *LLMRateLimiter) ConsumeTokens(n int) {
	if !l.enabled || l.tpmLimit == nil || n <= 0 {
		return
	}
	l.tpmLimit.ForceConsumeN(n)
}
