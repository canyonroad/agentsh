package llmproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/mcpinspect"
	"github.com/agentsh/agentsh/internal/mcpregistry"
)

// Config holds the proxy configuration using config package types.
type Config struct {
	// SessionID is the current session ID (set by agentsh).
	SessionID string

	// Proxy contains proxy mode and upstream settings.
	Proxy config.ProxyConfig

	// DLP is the DLP configuration.
	DLP config.DLPConfig

	// Storage is the storage configuration.
	Storage config.LLMStorageConfig

	// MCP is the MCP security policy configuration.
	MCP config.SandboxMCPConfig
}

// Proxy is an HTTP proxy that intercepts LLM API requests.
type Proxy struct {
	cfg             Config
	detector        *DialectDetector
	rewriter        *RequestRewriter
	dlp             *DLPProcessor
	storage         *Storage
	logger          *slog.Logger
	isCustomOpenAI  bool
	chatGPTUpstream *url.URL
	registry         *mcpregistry.Registry
	// policy is immutable after construction — set once in New(), never changed.
	policy           *mcpinspect.PolicyEvaluator
	// onInterceptEvent is called for each MCP tool call intercept event.
	// Set via SetEventCallback; the API layer uses it to persist events.
	onInterceptEvent func(mcpinspect.MCPToolCallInterceptedEvent)
	// sessionAnalyzer detects cross-server attack patterns. When non-nil,
	// tool calls are checked against cross-server rules before regular policy.
	sessionAnalyzer *mcpinspect.SessionAnalyzer
	// rateLimiter applies per-server rate limits to MCP tool calls.
	rateLimiter *mcpinspect.RateLimiterRegistry
	// llmRateLimiter enforces RPM and TPM limits on LLM API calls.
	llmRateLimiter *LLMRateLimiter

	server   *http.Server
	listener net.Listener
	mu       sync.Mutex
}

// New creates a new LLM proxy.
func New(cfg Config, storagePath string, logger *slog.Logger) (*Proxy, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Run retention cleanup asynchronously if configured
	// storagePath is like ~/.agentsh/sessions/<session-id>/llm-logs
	// sessionsDir is ~/.agentsh/sessions
	if storagePath != "" && (cfg.Storage.Retention.MaxAgeDays > 0 || cfg.Storage.Retention.MaxSizeMB > 0) {
		sessionsDir := filepath.Dir(filepath.Dir(storagePath))
		retentionCfg := RetentionConfig{
			MaxAgeDays: cfg.Storage.Retention.MaxAgeDays,
			MaxSizeMB:  cfg.Storage.Retention.MaxSizeMB,
			Eviction:   cfg.Storage.Retention.Eviction,
		}
		go RunRetention(sessionsDir, retentionCfg, cfg.SessionID, logger)
	}

	// Build dialect configs with any overrides from ProxyConfig.Providers
	configs := DefaultDialectConfigs()
	if cfg.Proxy.Providers.Anthropic != "" {
		if u, err := parseURL(cfg.Proxy.Providers.Anthropic); err == nil {
			configs[DialectAnthropic].Upstream = u
		}
	}
	if cfg.Proxy.Providers.OpenAI != "" {
		if u, err := parseURL(cfg.Proxy.Providers.OpenAI); err == nil {
			configs[DialectOpenAI].Upstream = u
		}
	}

	// Parse ChatGPT upstream for fallback
	chatGPTURL, _ := parseURL(chatGPTUpstream)

	detector := NewDialectDetector(configs)
	rewriter := NewRequestRewriter(detector)
	dlp := NewDLPProcessor(cfg.DLP)
	storage, err := NewStorage(storagePath, cfg.SessionID, cfg.Storage.StoreBodies)
	if err != nil {
		return nil, fmt.Errorf("create storage: %w", err)
	}

	llmRL := NewLLMRateLimiter(cfg.Proxy.RateLimits)

	return &Proxy{
		cfg:             cfg,
		detector:        detector,
		rewriter:        rewriter,
		dlp:             dlp,
		storage:         storage,
		logger:          logger,
		isCustomOpenAI:  cfg.Proxy.Providers.IsCustomOpenAI(),
		chatGPTUpstream: chatGPTURL,
		policy:          newPolicyEvaluator(cfg.MCP),
		rateLimiter:     newRateLimiter(cfg.MCP),
		llmRateLimiter:  llmRL,
	}, nil
}

// newPolicyEvaluator creates a PolicyEvaluator if policy enforcement is enabled.
func newPolicyEvaluator(mcpCfg config.SandboxMCPConfig) *mcpinspect.PolicyEvaluator {
	if !mcpCfg.EnforcePolicy {
		return nil
	}
	return mcpinspect.NewPolicyEvaluator(mcpCfg)
}

func newRateLimiter(mcpCfg config.SandboxMCPConfig) *mcpinspect.RateLimiterRegistry {
	if !mcpCfg.RateLimits.Enabled {
		return nil
	}
	return mcpinspect.NewRateLimiterRegistry(mcpCfg.RateLimits)
}

func (p *Proxy) versionPinCfg() *config.MCPVersionPinningConfig {
	if !p.cfg.MCP.VersionPinning.Enabled {
		return nil
	}
	return &p.cfg.MCP.VersionPinning
}

// hasInterception returns true if any MCP interception control is active
// (policy, rate limiter, or version pinning). Used to determine whether to
// run the interception pipeline, even when EnforcePolicy is false.
func (p *Proxy) hasInterception() bool {
	return p.policy != nil || p.rateLimiter != nil || p.versionPinCfg() != nil
}

// SetRegistry sets the MCP tool registry on the proxy. It is safe for
// concurrent use and is called once the shim has finished discovering tools.
func (p *Proxy) SetRegistry(r *mcpregistry.Registry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.registry = r
}

// SetEventCallback sets a callback that is invoked for each MCP tool call
// intercept event. It is safe for concurrent use.
func (p *Proxy) SetEventCallback(fn func(mcpinspect.MCPToolCallInterceptedEvent)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onInterceptEvent = fn
}

// getEventCallback returns the current event callback in a thread-safe manner.
func (p *Proxy) getEventCallback() func(mcpinspect.MCPToolCallInterceptedEvent) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.onInterceptEvent
}

// SetSessionAnalyzer sets the cross-server analyzer on the proxy. It is safe
// for concurrent use and is called once the analyzer has been created.
func (p *Proxy) SetSessionAnalyzer(analyzer *mcpinspect.SessionAnalyzer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sessionAnalyzer = analyzer
}

// getSessionAnalyzer returns the current session analyzer in a thread-safe manner.
func (p *Proxy) getSessionAnalyzer() *mcpinspect.SessionAnalyzer {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sessionAnalyzer
}

// getUpstreamForRequest returns the appropriate upstream URL for the request.
// For OpenAI dialect with default URL, it checks if this is a ChatGPT OAuth
// token and routes to ChatGPT backend if so.
func (p *Proxy) getUpstreamForRequest(r *http.Request, dialect Dialect) *url.URL {
	if dialect == DialectOpenAI && !p.isCustomOpenAI && IsChatGPTToken(r) {
		return p.chatGPTUpstream
	}
	return p.detector.GetUpstream(dialect)
}

// Start starts the proxy server.
func (p *Proxy) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	addr := fmt.Sprintf("127.0.0.1:%d", p.cfg.Proxy.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	p.listener = listener

	p.server = &http.Server{
		Handler:      p,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 5 * time.Minute, // Long timeout for streaming responses
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		if err := p.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			p.logger.Error("proxy server error", "error", err)
		}
	}()

	p.logger.Info("proxy started", "addr", listener.Addr().String())
	return nil
}

// Stop stops the proxy server.
func (p *Proxy) Stop(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.server != nil {
		if err := p.server.Shutdown(ctx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
	}

	if err := p.storage.Close(); err != nil {
		return fmt.Errorf("close storage: %w", err)
	}

	p.logger.Info("proxy stopped")
	return nil
}

// Addr returns the proxy's listening address.
func (p *Proxy) Addr() net.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener == nil {
		return nil
	}
	return p.listener.Addr()
}

// ServeHTTP implements http.Handler.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := generateRequestID()
	startTime := time.Now()

	// Detect dialect
	dialect := p.detector.Detect(r)
	if dialect == DialectUnknown {
		p.logger.Warn("unknown dialect", "path", r.URL.Path, "request_id", requestID)
		http.Error(w, "unknown LLM dialect", http.StatusBadRequest)
		return
	}

	// Extract session ID from header or use configured one
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		sessionID = p.cfg.SessionID
	}

	// Check RPM rate limit before processing the request
	if !p.llmRateLimiter.AllowRequest() {
		p.logger.Warn("LLM API rate limited (RPM)", "request_id", requestID, "session_id", sessionID)
		w.Header().Set("Retry-After", "5")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Check TPM budget — block if token budget is depleted from previous responses
	if !p.llmRateLimiter.TokenBudgetAvailable() {
		p.logger.Warn("LLM API rate limited (TPM)", "request_id", requestID, "session_id", sessionID)
		w.Header().Set("Retry-After", "10")
		http.Error(w, "token budget exceeded", http.StatusTooManyRequests)
		return
	}

	// Acquire an in-flight slot to bound concurrent requests when TPM is
	// enabled. This prevents bulk overspend from requests that pass the
	// pre-check before post-response token accounting occurs.
	if acquired := p.llmRateLimiter.AcquireInFlight(); acquired {
		defer p.llmRateLimiter.ReleaseInFlight()
	}

	p.logger.Debug("proxying request",
		"request_id", requestID,
		"dialect", dialect,
		"path", r.URL.Path,
		"session_id", sessionID,
	)

	// Read and process request body
	var reqBody []byte
	var dlpResult *DLPResult
	if r.Body != nil {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			p.logger.Error("read request body", "error", err, "request_id", requestID)
			http.Error(w, "failed to read request body", http.StatusInternalServerError)
			return
		}
		r.Body.Close()

		// Apply DLP
		dlpResult = p.dlp.Process(body, dialect)
		reqBody = dlpResult.ProcessedData

		// Replace body with processed version
		r.Body = io.NopCloser(bytes.NewReader(reqBody))
		r.ContentLength = int64(len(reqBody))
	}

	// Get upstream URL (may route to ChatGPT for OAuth tokens)
	upstream := p.getUpstreamForRequest(r, dialect)

	// Rewrite request for upstream
	outReq, err := p.rewriter.Rewrite(r, dialect, upstream)
	if err != nil {
		p.logger.Error("rewrite request", "error", err, "request_id", requestID)
		http.Error(w, "failed to rewrite request", http.StatusInternalServerError)
		return
	}

	// Log request before proxying
	p.logRequest(requestID, sessionID, dialect, outReq, reqBody, dlpResult)

	// Create SSE-aware transport that handles streaming responses.
	// When MCP policy is enabled, the transport uses an SSEInterceptor
	// for real-time tool call blocking.
	sseTransport := newSSEProxyTransport(
		http.DefaultTransport,
		w,
		func(resp *http.Response, body []byte) {
			// Log the response. MCP interception is handled inline by the
			// SSEInterceptor (if configured), so this callback only logs.
			p.logResponseDirect(requestID, sessionID, dialect, resp, body, startTime)
		},
	)

	// Configure real-time MCP interception if any control is active.
	if reg := p.getRegistry(); reg != nil && p.hasInterception() {
		sseTransport.SetInterceptor(
			reg, p.policy, dialect,
			sessionID, requestID,
			p.getEventCallback(),
			p.logger,
			p.getSessionAnalyzer(),
			p.rateLimiter,
			p.versionPinCfg(),
		)
	}

	// Create reverse proxy for this request
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = upstream.Scheme
			req.URL.Host = upstream.Host
			req.Host = upstream.Host
		},
		Transport: sseTransport,
		ModifyResponse: func(resp *http.Response) error {
			// Read body for both logging and MCP interception.
			var respBody []byte
			if resp.Body != nil {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					p.logger.Error("read response body", "error", err, "request_id", requestID)
					return nil
				}
				respBody = body
			}

			// MCP tool call interception (non-SSE only; SSE handled by SSEInterceptor).
			if reg := p.getRegistry(); reg != nil && p.hasInterception() && resp.StatusCode == http.StatusOK {
				result := interceptMCPToolCalls(respBody, dialect, reg, p.policy, requestID, sessionID, p.getSessionAnalyzer(), p.rateLimiter, p.versionPinCfg())
				for _, ev := range result.Events {
					p.logger.Info("mcp tool call intercepted",
						"tool", ev.ToolName, "action", ev.Action,
						"server", ev.ServerID, "request_id", requestID)
				}
				if cb := p.getEventCallback(); cb != nil {
					for _, ev := range result.Events {
						cb(ev)
					}
				}
				if result.HasBlocked && result.RewrittenBody != nil {
					respBody = result.RewrittenBody
				}
			}

			// Put body back for client.
			resp.Body = io.NopCloser(bytes.NewReader(respBody))
			resp.ContentLength = int64(len(respBody))
			resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(respBody)))

			// Log response with the (possibly rewritten) body.
			p.logResponseDirect(requestID, sessionID, dialect, resp, respBody, startTime)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// Don't log errSSEHandled - it's expected when SSE was handled directly
			if errors.Is(err, errSSEHandled) {
				return
			}
			p.logger.Error("proxy error", "error", err, "request_id", requestID)
			http.Error(w, "proxy error", http.StatusBadGateway)
		},
	}

	// Proxy the request
	proxy.ServeHTTP(w, outReq)
}

// logRequest logs the outgoing request to storage.
func (p *Proxy) logRequest(requestID, sessionID string, dialect Dialect, r *http.Request, body []byte, dlpResult *DLPResult) {
	entry := &RequestLogEntry{
		ID:        requestID,
		SessionID: sessionID,
		Timestamp: time.Now().UTC(),
		Dialect:   dialect,
		Request: RequestInfo{
			Method:   r.Method,
			Path:     r.URL.Path,
			Headers:  sanitizeHeaders(r.Header),
			BodySize: len(body),
			BodyHash: HashBody(body),
		},
	}

	if dlpResult != nil && len(dlpResult.Redactions) > 0 {
		entry.DLP = &DLPInfo{
			Redactions: dlpResult.Redactions,
		}
	}

	if err := p.storage.LogRequest(entry); err != nil {
		p.logger.Error("log request", "error", err, "request_id", requestID)
	}

	// Store full body if enabled
	if err := p.storage.StoreRequestBody(requestID, body); err != nil {
		p.logger.Error("store request body", "error", err, "request_id", requestID)
	}
}

// logResponse logs the response to storage.
func (p *Proxy) logResponse(requestID, sessionID string, dialect Dialect, resp *http.Response, startTime time.Time, dlpResult *DLPResult) {
	// Read response body for usage extraction
	// We must buffer it to put it back for the client
	var respBody []byte
	if resp.Body != nil {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			p.logger.Error("read response body", "error", err, "request_id", requestID)
		} else {
			respBody = body
			// Put the body back for the client
			resp.Body = io.NopCloser(bytes.NewReader(body))
		}
	}

	p.logResponseDirect(requestID, sessionID, dialect, resp, respBody, startTime)
}

// logResponseDirect logs a response with a pre-read body (used for SSE streams).
func (p *Proxy) logResponseDirect(requestID, sessionID string, dialect Dialect, resp *http.Response, respBody []byte, startTime time.Time) {
	// Extract token usage from the response.
	// Use Content-Type to detect SSE streams rather than body prefix heuristics.
	var usage Usage
	if IsSSEResponse(resp) {
		usage = ExtractSSEUsage(respBody, dialect)
	} else {
		usage = ExtractUsage(respBody, dialect)
	}

	// Consume tokens from the TPM budget for rate limiting
	totalTokens := usage.InputTokens + usage.OutputTokens
	if totalTokens > 0 {
		p.llmRateLimiter.ConsumeTokens(totalTokens)
	}

	entry := &ResponseLogEntry{
		RequestID:  requestID,
		SessionID:  sessionID,
		Timestamp:  time.Now().UTC(),
		DurationMs: time.Since(startTime).Milliseconds(),
		Response: ResponseInfo{
			Status:   resp.StatusCode,
			Headers:  sanitizeHeaders(resp.Header),
			BodySize: len(respBody),
			BodyHash: HashBody(respBody),
		},
		Usage: usage,
	}

	// Log usage to structured logger for observability
	if usage.InputTokens > 0 || usage.OutputTokens > 0 {
		p.logger.Debug("response with usage",
			"request_id", requestID,
			"input_tokens", usage.InputTokens,
			"output_tokens", usage.OutputTokens,
		)
	}

	if err := p.storage.LogResponse(entry); err != nil {
		p.logger.Error("log response", "error", err, "request_id", requestID)
	}

	// Store full body if enabled
	if err := p.storage.StoreResponseBody(requestID, respBody); err != nil {
		p.logger.Error("store response body", "error", err, "request_id", requestID)
	}
}

// sanitizeHeaders removes sensitive headers from logging.
func sanitizeHeaders(h http.Header) map[string][]string {
	result := make(map[string][]string)
	for k, v := range h {
		lk := http.CanonicalHeaderKey(k)
		switch lk {
		case "Authorization", "X-Api-Key", "Api-Key":
			result[k] = []string{"[REDACTED]"}
		default:
			result[k] = v
		}
	}
	return result
}

func generateRequestID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "req_" + hex.EncodeToString(b)
}

func parseURL(s string) (*url.URL, error) {
	return url.Parse(s)
}

// EnvVars returns the environment variables to set for the agent process.
func (p *Proxy) EnvVars() map[string]string {
	addr := p.Addr()
	if addr == nil {
		return nil
	}

	baseURL := fmt.Sprintf("http://%s", addr.String())
	return map[string]string{
		"ANTHROPIC_BASE_URL": baseURL,
		"OPENAI_BASE_URL":    baseURL,
		// Session ID is passed so agent can include it in headers
		// for correlation when using external proxy
		"AGENTSH_SESSION_ID": p.cfg.SessionID,
	}
}

// ProxyStatus contains the complete status of the proxy.
type ProxyStatus struct {
	State                  string   `json:"state"`
	Address                string   `json:"address"`
	Mode                   string   `json:"mode"`
	DLPMode                string   `json:"dlp_mode"`
	ActivePatterns         int      `json:"active_patterns"`
	PatternNames           []string `json:"pattern_names,omitempty"`
	TotalRequests          int      `json:"total_requests"`
	RequestsWithRedactions int      `json:"requests_with_redactions"`
	TotalInputTokens       int      `json:"total_input_tokens"`
	TotalOutputTokens      int      `json:"total_output_tokens"`
}

// Stats returns the current proxy status including usage statistics.
func (p *Proxy) Stats() (ProxyStatus, error) {
	status := ProxyStatus{
		Mode:           "embedded",
		DLPMode:        p.dlp.Mode(),
		ActivePatterns: p.dlp.PatternCount(),
		PatternNames:   p.dlp.PatternNames(),
	}

	p.mu.Lock()
	if p.listener != nil {
		status.State = "running"
		status.Address = p.listener.Addr().String()
	} else {
		status.State = "stopped"
		status.Address = ""
	}
	p.mu.Unlock()

	// Get stats from storage
	stats, err := p.storage.GetStats()
	if err != nil {
		return status, err
	}

	status.TotalRequests = stats.TotalRequests
	status.RequestsWithRedactions = stats.RequestsWithRedactions
	status.TotalInputTokens = stats.TotalInputTokens
	status.TotalOutputTokens = stats.TotalOutputTokens

	return status, nil
}
