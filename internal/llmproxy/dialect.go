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
	DialectChatGPT   Dialect = "chatgpt" // OpenAI via ChatGPT account login
)

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
	chatgptURL, _ := url.Parse("https://chatgpt.com/backend-api")

	return map[Dialect]*DialectConfig{
		DialectAnthropic: {
			Upstream:     anthropicURL,
			AuthHeader:   "x-api-key",
			PathPrefixes: []string{"/v1/messages", "/v1/complete"},
		},
		DialectOpenAI: {
			Upstream:     openaiURL,
			AuthHeader:   "Authorization",
			PathPrefixes: []string{"/v1/chat/completions", "/v1/responses", "/v1/embeddings"},
		},
		DialectChatGPT: {
			Upstream:     chatgptURL,
			AuthHeader:   "Authorization",
			PathPrefixes: []string{"/backend-api/"},
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
// 1. X-LLM-Dialect header (explicit override)
// 2. Request path matching
// 3. Host header hints
// 4. Auth header inspection
func (d *DialectDetector) Detect(r *http.Request) Dialect {
	// 1. Explicit header override
	if dialect := r.Header.Get("X-LLM-Dialect"); dialect != "" {
		switch strings.ToLower(dialect) {
		case "anthropic":
			return DialectAnthropic
		case "openai":
			return DialectOpenAI
		case "chatgpt":
			return DialectChatGPT
		}
	}

	// 2. Path-based detection
	path := r.URL.Path

	// ChatGPT backend-api is distinctive
	if strings.HasPrefix(path, "/backend-api/") {
		return DialectChatGPT
	}

	// Anthropic uses /v1/messages primarily
	if strings.HasPrefix(path, "/v1/messages") || strings.HasPrefix(path, "/v1/complete") {
		// Could be either, check for Anthropic-specific headers
		if r.Header.Get("x-api-key") != "" || r.Header.Get("anthropic-version") != "" {
			return DialectAnthropic
		}
	}

	// OpenAI uses /v1/chat/completions, /v1/responses
	if strings.HasPrefix(path, "/v1/chat/completions") || strings.HasPrefix(path, "/v1/responses") {
		return DialectOpenAI
	}

	// 3. Host header hints (for proxied requests that include original host)
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	if strings.Contains(host, "anthropic.com") {
		return DialectAnthropic
	}
	if strings.Contains(host, "openai.com") {
		return DialectOpenAI
	}
	if strings.Contains(host, "chatgpt.com") {
		return DialectChatGPT
	}

	// 4. Auth header inspection
	if r.Header.Get("x-api-key") != "" {
		return DialectAnthropic
	}
	if r.Header.Get("anthropic-version") != "" {
		return DialectAnthropic
	}

	return DialectUnknown
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

	// For ChatGPT backend-api, the path structure is different
	if dialect == DialectChatGPT {
		// Requests come in as /backend-api/..., upstream expects the same
		// but we need to ensure the base path is correct
		if !strings.HasPrefix(outReq.URL.Path, "/backend-api") {
			outReq.URL.Path = "/backend-api" + outReq.URL.Path
		}
	}

	// Set Host header to upstream
	outReq.Host = upstream.Host

	// Remove proxy-specific headers
	outReq.Header.Del("X-LLM-Dialect")
	outReq.Header.Del("X-Forwarded-Host")
	outReq.Header.Del("X-Session-ID") // We capture this but don't forward

	return outReq, nil
}
