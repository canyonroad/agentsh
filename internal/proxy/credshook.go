package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/agentsh/agentsh/internal/proxy/credsub"
)

// CredsSubHook performs credential substitution using a credsub.Table.
// PreHook replaces fake credentials with real ones in request bodies.
// PostHook replaces real credentials with fakes in response bodies.
type CredsSubHook struct {
	table         *credsub.Table
	scrubServices map[string]bool
}

// NewCredsSubHook returns a CredsSubHook that uses the given table.
// scrubServices controls which services have response scrubbing enabled.
// Pass nil to scrub all responses (backward-compatible default).
func NewCredsSubHook(table *credsub.Table, scrubServices map[string]bool) *CredsSubHook {
	return &CredsSubHook{table: table, scrubServices: scrubServices}
}

func (h *CredsSubHook) Name() string { return "creds-sub" }

// PreHook replaces fake credentials with real ones in the request
// body, header values, URL query string, and URL path.
func (h *CredsSubHook) PreHook(r *http.Request, _ *RequestContext) error {
	// Body substitution.
	if r.Body != nil {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil // best-effort
		}
		replaced := h.table.ReplaceFakeToReal(body)
		r.Body = io.NopCloser(bytes.NewReader(replaced))
		r.ContentLength = int64(len(replaced))
	}

	// Header value substitution.
	for key, vals := range r.Header {
		for i, v := range vals {
			replaced := h.table.ReplaceFakeToReal([]byte(v))
			r.Header[key][i] = string(replaced)
		}
	}

	// URL query substitution.
	if rq := r.URL.RawQuery; rq != "" {
		replaced := string(h.table.ReplaceFakeToReal([]byte(rq)))
		r.URL.RawQuery = replaced
	}

	// URL path substitution.
	if p := r.URL.Path; p != "" {
		replaced := string(h.table.ReplaceFakeToReal([]byte(p)))
		r.URL.Path = replaced
	}
	if rp := r.URL.RawPath; rp != "" {
		replaced := string(h.table.ReplaceFakeToReal([]byte(rp)))
		r.URL.RawPath = replaced
	}

	return nil
}

// PostHook replaces real credentials with fakes in the response body.
// When scrubServices is non-nil, scrubbing is skipped for services not in the map.
func (h *CredsSubHook) PostHook(resp *http.Response, ctx *RequestContext) error {
	if resp.Body == nil {
		return nil
	}
	// Check per-service scrub config.
	if h.scrubServices != nil && !h.scrubServices[ctx.ServiceName] {
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
				if serviceName != ctx.ServiceName {
					h.logLeak(ctx, serviceName, r.Host)
					return &HookAbortError{StatusCode: 403, Message: "credential leak blocked"}
				}
			}
		}
	}

	// Scan URL query string.
	if rawQuery := r.URL.RawQuery; rawQuery != "" {
		if serviceName, found := h.table.ContainsFake([]byte(rawQuery)); found {
			if serviceName != ctx.ServiceName {
				h.logLeak(ctx, serviceName, r.Host)
				return &HookAbortError{StatusCode: 403, Message: "credential leak blocked"}
			}
		}
	}

	// Scan ALL header values.
	for _, vals := range r.Header {
		for _, val := range vals {
			if serviceName, found := h.table.ContainsFake([]byte(val)); found {
				if serviceName != ctx.ServiceName {
					h.logLeak(ctx, serviceName, r.Host)
					return &HookAbortError{StatusCode: 403, Message: "credential leak blocked"}
				}
			}
		}
	}

	// Scan URL path.
	if p := r.URL.Path; p != "" {
		if serviceName, found := h.table.ContainsFake([]byte(p)); found {
			if serviceName != ctx.ServiceName {
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

// HeaderInjectionHook injects the real credential into a request header.
// Registered per service name so it only fires for matched requests.
type HeaderInjectionHook struct {
	serviceName string
	headerName  string
	template    string
	table       *credsub.Table
}

// NewHeaderInjectionHook creates a hook that injects the real credential
// for serviceName into the header specified by headerName using template.
// The template must contain "{{secret}}" which is replaced with the real
// credential at request time.
func NewHeaderInjectionHook(serviceName, headerName, template string, table *credsub.Table) *HeaderInjectionHook {
	return &HeaderInjectionHook{
		serviceName: serviceName,
		headerName:  headerName,
		template:    template,
		table:       table,
	}
}

func (h *HeaderInjectionHook) Name() string { return "header-inject" }

// HeaderName returns the header that this hook injects. Used by the
// declared-service log path to redact the injected value from audit
// records.
func (h *HeaderInjectionHook) HeaderName() string { return h.headerName }

func (h *HeaderInjectionHook) PreHook(r *http.Request, _ *RequestContext) error {
	real, ok := h.table.RealForService(h.serviceName)
	if !ok {
		return nil // service not in table, skip
	}
	defer func() {
		for i := range real {
			real[i] = 0
		}
	}()

	value := strings.Replace(h.template, "{{secret}}", string(real), 1)
	r.Header.Del(h.headerName)
	r.Header.Set(h.headerName, value)
	return nil
}

func (h *HeaderInjectionHook) PostHook(_ *http.Response, _ *RequestContext) error {
	return nil
}
