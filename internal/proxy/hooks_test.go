package proxy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeHook is a test double that records every call and can be configured
// to return an error on PreHook or PostHook.
type fakeHook struct {
	name     string
	preErr   error
	postErr  error
	preCalls int
	postCalls int
}

func (h *fakeHook) Name() string { return h.name }

func (h *fakeHook) PreHook(_ *http.Request, _ *RequestContext) error {
	h.preCalls++
	return h.preErr
}

func (h *fakeHook) PostHook(_ *http.Response, _ *RequestContext) error {
	h.postCalls++
	return h.postErr
}

func TestRegistry_RegisterAndApply(t *testing.T) {
	r := NewRegistry()
	h1 := &fakeHook{name: "first"}
	h2 := &fakeHook{name: "second"}
	r.Register("anthropic", h1)
	r.Register("anthropic", h2)

	req := httptest.NewRequest(http.MethodPost, "http://example/", nil)
	ctx := &RequestContext{RequestID: "r1", SessionID: "s1", ServiceName: "anthropic"}

	if err := r.ApplyPreHooks("anthropic", req, ctx); err != nil {
		t.Fatalf("ApplyPreHooks returned unexpected error: %v", err)
	}
	if h1.preCalls != 1 || h2.preCalls != 1 {
		t.Errorf("expected both hooks called once on pre, got h1=%d h2=%d", h1.preCalls, h2.preCalls)
	}

	resp := &http.Response{StatusCode: http.StatusOK}
	if err := r.ApplyPostHooks("anthropic", resp, ctx); err != nil {
		t.Fatalf("ApplyPostHooks returned unexpected error: %v", err)
	}
	if h1.postCalls != 1 || h2.postCalls != 1 {
		t.Errorf("expected both hooks called once on post, got h1=%d h2=%d", h1.postCalls, h2.postCalls)
	}
}

func TestRegistry_UnknownServiceIsNoOp(t *testing.T) {
	r := NewRegistry()
	h := &fakeHook{name: "unused"}
	r.Register("anthropic", h)

	req := httptest.NewRequest(http.MethodPost, "http://example/", nil)
	ctx := &RequestContext{RequestID: "r1", ServiceName: "github"}

	if err := r.ApplyPreHooks("github", req, ctx); err != nil {
		t.Fatalf("ApplyPreHooks unknown service returned error: %v", err)
	}
	if h.preCalls != 0 {
		t.Errorf("expected zero calls for unrelated service, got %d", h.preCalls)
	}
}

func TestRegistry_EmptyServiceNameRunsGlobally(t *testing.T) {
	r := NewRegistry()
	global := &fakeHook{name: "global"}
	scoped := &fakeHook{name: "scoped"}
	r.Register("", global)
	r.Register("anthropic", scoped)

	req := httptest.NewRequest(http.MethodPost, "http://example/", nil)
	ctx := &RequestContext{RequestID: "r1", ServiceName: "anthropic"}

	if err := r.ApplyPreHooks("anthropic", req, ctx); err != nil {
		t.Fatalf("ApplyPreHooks returned error: %v", err)
	}
	if global.preCalls != 1 {
		t.Errorf("global hook should run for every service; got %d calls", global.preCalls)
	}
	if scoped.preCalls != 1 {
		t.Errorf("scoped hook should run for its service; got %d calls", scoped.preCalls)
	}
}

func TestRegistry_PreHookErrorShortCircuits(t *testing.T) {
	r := NewRegistry()
	boom := errors.New("pre boom")
	h1 := &fakeHook{name: "first", preErr: boom}
	h2 := &fakeHook{name: "second"}
	r.Register("svc", h1)
	r.Register("svc", h2)

	req := httptest.NewRequest(http.MethodPost, "http://example/", nil)
	ctx := &RequestContext{RequestID: "r1", ServiceName: "svc"}

	err := r.ApplyPreHooks("svc", req, ctx)
	if !errors.Is(err, boom) {
		t.Fatalf("expected boom error, got %v", err)
	}
	if h1.preCalls != 1 {
		t.Errorf("first hook should have been called once, got %d", h1.preCalls)
	}
	if h2.preCalls != 0 {
		t.Errorf("second hook should NOT have been called after first failed, got %d", h2.preCalls)
	}
}

func TestRegistry_PostHookErrorsCollected(t *testing.T) {
	r := NewRegistry()
	boom1 := errors.New("post boom 1")
	boom2 := errors.New("post boom 2")
	h1 := &fakeHook{name: "first", postErr: boom1}
	h2 := &fakeHook{name: "second", postErr: boom2}
	r.Register("svc", h1)
	r.Register("svc", h2)

	resp := &http.Response{StatusCode: http.StatusOK}
	ctx := &RequestContext{RequestID: "r1", ServiceName: "svc"}

	err := r.ApplyPostHooks("svc", resp, ctx)
	if !errors.Is(err, boom1) {
		t.Fatalf("expected first error returned, got %v", err)
	}
	if h1.postCalls != 1 || h2.postCalls != 1 {
		t.Errorf("both post hooks should run even on error, got h1=%d h2=%d", h1.postCalls, h2.postCalls)
	}
}
