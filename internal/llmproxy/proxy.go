package llmproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/config"
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

	server   *http.Server
	listener net.Listener
	mu       sync.Mutex
}

// New creates a new LLM proxy.
func New(cfg Config, storagePath string, logger *slog.Logger) (*Proxy, error) {
	if logger == nil {
		logger = slog.Default()
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
	storage, err := NewStorage(storagePath, cfg.SessionID)
	if err != nil {
		return nil, fmt.Errorf("create storage: %w", err)
	}

	return &Proxy{
		cfg:             cfg,
		detector:        detector,
		rewriter:        rewriter,
		dlp:             dlp,
		storage:         storage,
		logger:          logger,
		isCustomOpenAI:  cfg.Proxy.Providers.IsCustomOpenAI(),
		chatGPTUpstream: chatGPTURL,
	}, nil
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

	if p.server == nil {
		return nil
	}

	if err := p.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
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

	// Create reverse proxy for this request
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = upstream.Scheme
			req.URL.Host = upstream.Host
			req.Host = upstream.Host
		},
		ModifyResponse: func(resp *http.Response) error {
			// Log response
			p.logResponse(requestID, sessionID, dialect, resp, startTime, dlpResult)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			p.logger.Error("proxy error", "error", err, "request_id", requestID)
			http.Error(w, "proxy error", http.StatusBadGateway)
		},
	}

	// Log request before proxying
	p.logRequest(requestID, sessionID, dialect, outReq, reqBody, dlpResult)

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

	// Extract token usage from the response
	usage := ExtractUsage(respBody, dialect)

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
