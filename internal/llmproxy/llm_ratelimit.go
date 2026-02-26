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
	// inFlight limits concurrent requests when TPM is enabled, bounding
	// overspend from requests that pass the pre-request budget check before
	// post-response token accounting occurs.
	inFlight chan struct{}
}

// defaultMaxInFlight is the concurrency cap when TPM is enabled.
// This bounds worst-case overspend to maxInFlight * avgTokensPerRequest.
const defaultMaxInFlight = 4

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
		l.inFlight = make(chan struct{}, defaultMaxInFlight)
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

// TokenBudgetAvailable returns true if the TPM bucket is not depleted.
// Use this as a pre-request gate: if previous responses have driven the
// token bucket negative (via ForceConsumeN), block new requests until
// tokens replenish.
func (l *LLMRateLimiter) TokenBudgetAvailable() bool {
	if !l.enabled || l.tpmLimit == nil {
		return true
	}
	return l.tpmLimit.Tokens() > 0
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

// TPMEnabled returns true if tokens-per-minute limiting is active.
func (l *LLMRateLimiter) TPMEnabled() bool {
	return l.enabled && l.tpmLimit != nil
}

// inFlightEnabled returns true if the in-flight concurrency limiter is active.
func (l *LLMRateLimiter) inFlightEnabled() bool {
	return l.inFlight != nil
}

// AcquireInFlight attempts to acquire an in-flight slot (when TPM is enabled).
// Returns false if TPM is not configured or the concurrency cap is reached.
// Non-blocking: if all slots are occupied, returns false immediately so the
// caller can reject the request (e.g. 429) instead of piling up goroutines.
func (l *LLMRateLimiter) AcquireInFlight() bool {
	if l.inFlight == nil {
		return false
	}
	select {
	case l.inFlight <- struct{}{}:
		return true
	default:
		return false
	}
}

// ReleaseInFlight releases an in-flight slot. Must be called after
// AcquireInFlight returns true, typically in a defer.
func (l *LLMRateLimiter) ReleaseInFlight() {
	if l.inFlight == nil {
		return
	}
	<-l.inFlight
}
