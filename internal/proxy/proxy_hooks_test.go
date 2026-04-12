package proxy

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxy_HookRegistry_Accessor(t *testing.T) {
	cfg := Config{SessionID: "test-session"}
	p, err := New(cfg, "", nil)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if p.HookRegistry() == nil {
		t.Fatal("HookRegistry() returned nil")
	}
}

func TestProxy_PreHookAbortError_Returns403(t *testing.T) {
	cfg := Config{SessionID: "test-session"}
	p, err := New(cfg, "", nil)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	abortHook := &fakeHook{
		name:   "abort",
		preErr: &HookAbortError{StatusCode: 403, Message: "blocked"},
	}
	p.HookRegistry().Register("", abortHook)

	req := httptest.NewRequest(http.MethodPost, "http://localhost/v1/messages", bytes.NewReader([]byte(`{"test":"data"}`)))
	req.Header.Set("x-api-key", "sk-ant-test")
	req.Header.Set("anthropic-version", "2023-06-01")
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestProxy_PreHookPlainError_Returns502(t *testing.T) {
	cfg := Config{SessionID: "test-session"}
	p, err := New(cfg, "", nil)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	errHook := &fakeHook{
		name:   "broken",
		preErr: errors.New("internal hook failure"),
	}
	p.HookRegistry().Register("", errHook)

	req := httptest.NewRequest(http.MethodPost, "http://localhost/v1/messages", bytes.NewReader([]byte(`{"test":"data"}`)))
	req.Header.Set("x-api-key", "sk-ant-test")
	req.Header.Set("anthropic-version", "2023-06-01")
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	if w.Code != 502 {
		t.Errorf("status = %d, want 502", w.Code)
	}
}

// Silence unused import warnings for io — used by future post-hook tests.
var _ = io.NopCloser

// serviceRecorderHook is a test double whose PreHook invokes a callback
// with the request and context, allowing tests to inspect ServiceName
// and other fields.
type serviceRecorderHook struct {
	name  string
	preFn func(*http.Request, *RequestContext) error
}

func (h *serviceRecorderHook) Name() string { return h.name }

func (h *serviceRecorderHook) PreHook(r *http.Request, ctx *RequestContext) error {
	if h.preFn != nil {
		return h.preFn(r, ctx)
	}
	return nil
}

func (h *serviceRecorderHook) PostHook(_ *http.Response, _ *RequestContext) error { return nil }

func TestProxy_PreHookAbortError_NonErrorStatus_Falls502(t *testing.T) {
	tests := []struct {
		name string
		code int
	}{
		{"zero", 0},
		{"1xx_continue", 100},
		{"2xx_ok", 200},
		{"2xx_no_content", 204},
		{"3xx_redirect", 302},
		{"over_599", 1000},
		{"negative", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{SessionID: "test-session"}
			p, err := New(cfg, "", nil)
			if err != nil {
				t.Fatalf("New() error: %v", err)
			}

			abortHook := &fakeHook{
				name:   "bad-code",
				preErr: &HookAbortError{StatusCode: tt.code, Message: "test"},
			}
			p.HookRegistry().Register("", abortHook)

			req := httptest.NewRequest(http.MethodPost, "http://localhost/v1/messages", bytes.NewReader([]byte(`{"test":"data"}`)))
			req.Header.Set("x-api-key", "sk-ant-test")
			req.Header.Set("anthropic-version", "2023-06-01")
			w := httptest.NewRecorder()

			p.ServeHTTP(w, req)

			if w.Code != 502 {
				t.Errorf("status = %d, want 502 for non-error status code %d", w.Code, tt.code)
			}
		})
	}
}
