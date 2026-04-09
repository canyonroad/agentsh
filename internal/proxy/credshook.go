package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"

	"github.com/agentsh/agentsh/internal/proxy/credsub"
)

// CredsSubHook performs credential substitution using a credsub.Table.
// PreHook replaces fake credentials with real ones in request bodies.
// PostHook replaces real credentials with fakes in response bodies.
type CredsSubHook struct {
	table *credsub.Table
}

// NewCredsSubHook returns a CredsSubHook that uses the given table.
func NewCredsSubHook(table *credsub.Table) *CredsSubHook {
	return &CredsSubHook{table: table}
}

func (h *CredsSubHook) Name() string { return "creds-sub" }

// PreHook replaces fake credentials with real ones in the request body.
func (h *CredsSubHook) PreHook(r *http.Request, _ *RequestContext) error {
	if r.Body == nil {
		return nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil // best-effort
	}

	replaced := h.table.ReplaceFakeToReal(body)
	r.Body = io.NopCloser(bytes.NewReader(replaced))
	r.ContentLength = int64(len(replaced))
	return nil
}

// PostHook replaces real credentials with fakes in the response body.
func (h *CredsSubHook) PostHook(resp *http.Response, _ *RequestContext) error {
	if resp.Body == nil {
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil // best-effort
	}

	replaced := h.table.ReplaceRealToFake(body)
	resp.Body = io.NopCloser(bytes.NewReader(replaced))
	resp.ContentLength = int64(len(replaced))
	return nil
}

// scanHeaders lists HTTP headers that LeakGuardHook scans for fakes.
var scanHeaders = []string{
	"Authorization",
	"X-Api-Key",
	"Api-Key",
	"X-Auth-Token",
}

// LeakGuardHook blocks requests that contain known fake credentials.
type LeakGuardHook struct {
	table  *credsub.Table
	logger *slog.Logger
}

// NewLeakGuardHook returns a LeakGuardHook that scans for fakes.
func NewLeakGuardHook(table *credsub.Table, logger *slog.Logger) *LeakGuardHook {
	return &LeakGuardHook{table: table, logger: logger}
}

func (h *LeakGuardHook) Name() string { return "leak-guard" }

func (h *LeakGuardHook) PreHook(r *http.Request, ctx *RequestContext) error {
	// Scan request body.
	if r.Body != nil {
		body, err := io.ReadAll(r.Body)
		if err == nil {
			r.Body = io.NopCloser(bytes.NewReader(body))
			if serviceName, found := h.table.ContainsFake(body); found {
				h.logLeak(ctx, serviceName, r.Host)
				return &HookAbortError{StatusCode: 403, Message: "credential leak blocked"}
			}
		}
	}

	// Scan URL query string.
	if rawQuery := r.URL.RawQuery; rawQuery != "" {
		if serviceName, found := h.table.ContainsFake([]byte(rawQuery)); found {
			h.logLeak(ctx, serviceName, r.Host)
			return &HookAbortError{StatusCode: 403, Message: "credential leak blocked"}
		}
	}

	// Scan select headers.
	for _, hdr := range scanHeaders {
		if val := r.Header.Get(hdr); val != "" {
			if serviceName, found := h.table.ContainsFake([]byte(val)); found {
				h.logLeak(ctx, serviceName, r.Host)
				return &HookAbortError{StatusCode: 403, Message: "credential leak blocked"}
			}
		}
	}

	return nil
}

func (h *LeakGuardHook) PostHook(_ *http.Response, _ *RequestContext) error {
	return nil
}

func (h *LeakGuardHook) logLeak(ctx *RequestContext, serviceName, requestHost string) {
	h.logger.Warn("secret_leak_blocked",
		"session_id", ctx.SessionID,
		"request_id", ctx.RequestID,
		"service_name", serviceName,
		"request_host", requestHost,
	)
}
