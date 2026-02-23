package llmproxy

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/agentsh/agentsh/internal/mcpinspect"
	"github.com/agentsh/agentsh/internal/mcpregistry"
)

// IsSSEResponse returns true if the response is a Server-Sent Events stream.
func IsSSEResponse(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	return strings.HasPrefix(ct, "text/event-stream")
}

// errSSEHandled is a sentinel error indicating SSE was handled directly.
var errSSEHandled = errors.New("sse response handled directly")

// streamingResponseWriter wraps an http.ResponseWriter to capture streamed data
// while passing it through to the client immediately.
type streamingResponseWriter struct {
	w       http.ResponseWriter
	buf     bytes.Buffer
	mu      sync.Mutex
	status  int
	written bool
}

func newStreamingResponseWriter(w http.ResponseWriter) *streamingResponseWriter {
	return &streamingResponseWriter{
		w:      w,
		status: http.StatusOK,
	}
}

func (s *streamingResponseWriter) Header() http.Header {
	return s.w.Header()
}

func (s *streamingResponseWriter) WriteHeader(statusCode int) {
	s.status = statusCode
	s.w.WriteHeader(statusCode)
}

func (s *streamingResponseWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	s.buf.Write(p)
	s.written = true
	s.mu.Unlock()

	// Write through to client
	n, err := s.w.Write(p)

	// Flush if possible for immediate streaming
	if f, ok := s.w.(http.Flusher); ok {
		f.Flush()
	}

	return n, err
}

// Data returns all captured data.
func (s *streamingResponseWriter) Data() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Bytes()
}

// Status returns the HTTP status code.
func (s *streamingResponseWriter) Status() int {
	return s.status
}

// sseProxyTransport is a custom RoundTripper that handles SSE responses specially.
// For SSE, it streams directly to the client while buffering for logging.
type sseProxyTransport struct {
	base       http.RoundTripper
	w          http.ResponseWriter
	onComplete func(resp *http.Response, body []byte)
	// Optional MCP interception fields. When registry and policy are both
	// non-nil, SSE streams are processed through an SSEInterceptor instead
	// of io.Copy, enabling real-time tool call blocking.
	registry  *mcpregistry.Registry
	policy    *mcpinspect.PolicyEvaluator
	dialect   Dialect
	sessionID string
	requestID string
	onEvent   func(mcpinspect.MCPToolCallInterceptedEvent)
	logger    *slog.Logger
}

func newSSEProxyTransport(base http.RoundTripper, w http.ResponseWriter, onComplete func(resp *http.Response, body []byte)) *sseProxyTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &sseProxyTransport{
		base:       base,
		w:          w,
		onComplete: onComplete,
	}
}

// SetInterceptor configures the transport for real-time MCP tool call
// interception. When both registry and policy are non-nil, SSE streams
// are processed through an SSEInterceptor instead of io.Copy.
func (t *sseProxyTransport) SetInterceptor(
	registry *mcpregistry.Registry,
	policy *mcpinspect.PolicyEvaluator,
	dialect Dialect,
	sessionID, requestID string,
	onEvent func(mcpinspect.MCPToolCallInterceptedEvent),
	logger *slog.Logger,
) {
	t.registry = registry
	t.policy = policy
	t.dialect = dialect
	t.sessionID = sessionID
	t.requestID = requestID
	t.onEvent = onEvent
	t.logger = logger
}

func (t *sseProxyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// Check if this is an SSE response
	if IsSSEResponse(resp) {
		// For SSE, stream directly to client while buffering
		sw := newStreamingResponseWriter(t.w)

		// Copy headers to client
		for k, vv := range resp.Header {
			for _, v := range vv {
				sw.Header().Add(k, v)
			}
		}
		// When MCP interception is active, the body may be rewritten to a
		// different size, so remove Content-Length to force chunked transfer.
		if t.registry != nil && t.policy != nil {
			sw.Header().Del("Content-Length")
		}
		sw.WriteHeader(resp.StatusCode)

		// Stream body to client — with MCP interception if configured
		var bufferedBody []byte
		if t.registry != nil && t.policy != nil {
			interceptor := NewSSEInterceptor(
				t.registry, t.policy, t.dialect,
				t.sessionID, t.requestID, t.onEvent, t.logger,
			)
			bufferedBody = interceptor.Stream(resp.Body, sw)
		} else {
			// Fast path: no MCP policy — direct io.Copy
			_, copyErr := io.Copy(sw, resp.Body)
			if copyErr != nil {
				resp.Body.Close()
				return nil, copyErr
			}
		}
		resp.Body.Close()

		// Get buffered body for logging
		if bufferedBody == nil {
			bufferedBody = sw.Data()
		}

		// Call completion callback with buffered body
		if t.onComplete != nil {
			// Create a response copy for logging
			logResp := &http.Response{
				Status:        resp.Status,
				StatusCode:    resp.StatusCode,
				Header:        resp.Header,
				Body:          io.NopCloser(bytes.NewReader(bufferedBody)),
				ContentLength: int64(len(bufferedBody)),
			}
			t.onComplete(logResp, bufferedBody)
		}

		// Return sentinel error to prevent ReverseProxy from writing again
		// The error handler will check for this and not report it
		return nil, errSSEHandled
	}

	// Non-SSE: return normally for standard proxy flow
	return resp, nil
}
