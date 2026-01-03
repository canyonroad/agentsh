// Package llmproxy provides an embedded HTTP proxy for intercepting LLM API requests.
// It supports multiple LLM providers (Anthropic, OpenAI) in passthrough mode with
// optional DLP (Data Loss Prevention) processing.
package llmproxy

import (
	"net/http"
	"net/url"
	"strings"
)

// Dialect represents an LLM API provider dialect.
type Dialect string

const (
	DialectUnknown   Dialect = "unknown"
	DialectAnthropic Dialect = "anthropic"
	DialectOpenAI    Dialect = "openai"
)

// chatGPTUpstream is the hardcoded ChatGPT backend URL, used only when
// OpenAI provider is set to the default URL and an OAuth token is detected.
const chatGPTUpstream = "https://chatgpt.com/backend-api"

// DialectConfig holds configuration for a specific LLM provider dialect.
type DialectConfig struct {
	// Upstream is the base URL for the provider's API.
	Upstream *url.URL

	// AuthHeader is the header name used for authentication.
	// e.g., "x-api-key" for Anthropic, "Authorization" for OpenAI
	AuthHeader string

	// PathPrefixes are path prefixes that identify this dialect.
	PathPrefixes []string
}

// DefaultDialectConfigs returns the default configuration for each dialect.
func DefaultDialectConfigs() map[Dialect]*DialectConfig {
	anthropicURL, _ := url.Parse("https://api.anthropic.com")
	openaiURL, _ := url.Parse("https://api.openai.com")

	return map[Dialect]*DialectConfig{
		DialectAnthropic: {
			Upstream:     anthropicURL,
			AuthHeader:   "x-api-key",
			PathPrefixes: []string{"/v1/messages", "/v1/complete"},
		},
		DialectOpenAI: {
			Upstream:     openaiURL,
			AuthHeader:   "Authorization",
			PathPrefixes: []string{"/v1/chat/completions", "/v1/responses", "/v1/embeddings", "/backend-api/"},
		},
	}
}

// DialectDetector detects the LLM provider dialect from HTTP requests.
type DialectDetector struct {
	configs map[Dialect]*DialectConfig
}

// NewDialectDetector creates a new dialect detector with the given configs.
func NewDialectDetector(configs map[Dialect]*DialectConfig) *DialectDetector {
	if configs == nil {
		configs = DefaultDialectConfigs()
	}
	return &DialectDetector{configs: configs}
}

// Detect determines the dialect from the request.
// Detection order:
// 1. x-api-key header -> Anthropic
// 2. anthropic-version header -> Anthropic
// 3. Authorization header present -> OpenAI
// 4. No auth -> Unknown
func (d *DialectDetector) Detect(r *http.Request) Dialect {
	// 1. Anthropic x-api-key header
	if r.Header.Get("x-api-key") != "" {
		return DialectAnthropic
	}

	// 2. Anthropic version header
	if r.Header.Get("anthropic-version") != "" {
		return DialectAnthropic
	}

	// 3. Any Authorization header -> OpenAI dialect
	if r.Header.Get("Authorization") != "" {
		return DialectOpenAI
	}

	return DialectUnknown
}

// IsChatGPTToken returns true if the Authorization header contains an OAuth token
// (non-sk-* Bearer token), indicating ChatGPT login flow.
func IsChatGPTToken(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	// OpenAI API keys start with sk-, ChatGPT OAuth tokens don't
	return !strings.HasPrefix(token, "sk-")
}

// GetUpstream returns the upstream URL for the given dialect.
func (d *DialectDetector) GetUpstream(dialect Dialect) *url.URL {
	if cfg, ok := d.configs[dialect]; ok {
		return cfg.Upstream
	}
	return nil
}

// RequestRewriter rewrites requests for forwarding to upstream.
type RequestRewriter struct {
	detector *DialectDetector
}

// NewRequestRewriter creates a new request rewriter.
func NewRequestRewriter(detector *DialectDetector) *RequestRewriter {
	return &RequestRewriter{detector: detector}
}

// Rewrite modifies the request for forwarding to the upstream provider.
// It updates the URL scheme/host and adjusts headers as needed.
func (rw *RequestRewriter) Rewrite(r *http.Request, dialect Dialect) (*http.Request, error) {
	upstream := rw.detector.GetUpstream(dialect)
	if upstream == nil {
		return r, nil // passthrough unchanged
	}

	// Clone the request
	outReq := r.Clone(r.Context())

	// Update URL to point to upstream
	outReq.URL.Scheme = upstream.Scheme
	outReq.URL.Host = upstream.Host

	// Set Host header to upstream
	outReq.Host = upstream.Host

	// Remove proxy-specific headers
	outReq.Header.Del("X-LLM-Dialect")
	outReq.Header.Del("X-Forwarded-Host")
	outReq.Header.Del("X-Session-ID") // We capture this but don't forward

	return outReq, nil
}
