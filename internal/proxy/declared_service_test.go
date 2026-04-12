package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/proxy/credsub"
)

// fakeApprovalsManager is a deterministic HTTPServiceApprovalsManager used
// by the approval-gating tests for the /svc/ path. It short-circuits the
// full approvals.Manager pipeline (TTY prompt, TOTP, WebAuthn) and returns
// a fixed Resolution so tests can pin down the approved/denied branches.
type fakeApprovalsManager struct {
	approve bool
	gotReq  approvals.Request
}

func (f *fakeApprovalsManager) RequestApproval(ctx context.Context, req approvals.Request) (approvals.Resolution, error) {
	f.gotReq = req
	return approvals.Resolution{Approved: f.approve}, nil
}

func init() {
	policy.SetAllowInsecureHTTPServiceUpstreamForTest(true)
}

func newTestProxyWithHTTPService(t *testing.T, upstream string, rules []policy.HTTPServiceRule) *Proxy {
	t.Helper()
	return newTestProxyWithNamedHTTPService(t, "github", upstream, rules)
}

// newTestProxyWithNamedHTTPService is like newTestProxyWithHTTPService but
// lets the caller pin the declared service name (for tests that deliberately
// exercise case-mismatched URLs).
func newTestProxyWithNamedHTTPService(t *testing.T, name, upstream string, rules []policy.HTTPServiceRule) *Proxy {
	t.Helper()
	cfg := Config{SessionID: "test-session"}
	p, err := New(cfg, "", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	svcs := []policy.HTTPService{{
		Name: name, Upstream: upstream, Default: "deny", Rules: rules,
	}}
	if err := policy.ValidateHTTPServices(svcs); err != nil {
		t.Fatalf("validate: %v", err)
	}
	pol := &policy.Policy{HTTPServices: svcs}
	eng, err := policy.NewEngine(pol, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	p.SetPolicyEngine(eng)
	p.SetHTTPServices(svcs)
	return p
}

func TestServeHTTP_PathPrefixDispatch_NoSuchService(t *testing.T) {
	p := newTestProxyWithHTTPService(t, "https://api.github.com", nil)

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/svc/nosuch/foo", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	body, _ := io.ReadAll(w.Body)
	if !strings.Contains(string(body), "no such service") {
		t.Errorf("body = %q, want 'no such service'", body)
	}
}

func TestServeDeclaredService_Deny(t *testing.T) {
	p := newTestProxyWithHTTPService(t, "https://api.github.com", []policy.HTTPServiceRule{
		{Name: "block-delete", Methods: []string{"DELETE"}, Paths: []string{"/repos/**"}, Decision: "deny", Message: "no deletes"},
	})

	req := httptest.NewRequest(http.MethodDelete, "http://127.0.0.1/svc/github/repos/a/b", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	body, _ := io.ReadAll(w.Body)
	if !strings.Contains(string(body), "no deletes") {
		t.Errorf("body = %q, want 'no deletes'", body)
	}
}

// TestServeDeclaredService_Approve_Returns501 pins down the interim behavior
// for `approve` rules when no approvals manager is wired. Task 10 replaces
// the always-501 stub with approvals.Manager consultation, but leaves the
// manager optional: when the manager is nil (e.g. in a test proxy that
// never calls SetHTTPServiceApprovals), the handler must still return 501
// so operators can distinguish "no approval wired" from an internal error.
func TestServeDeclaredService_Approve_Returns501(t *testing.T) {
	p := newTestProxyWithHTTPService(t, "https://api.github.com", []policy.HTTPServiceRule{
		{Name: "approve-foo", Paths: []string{"/foo"}, Decision: "approve"},
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/svc/github/foo", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", w.Code)
	}
	body, _ := io.ReadAll(w.Body)
	if !strings.Contains(string(body), "approval not yet implemented") {
		t.Errorf("body = %q, want 'approval not yet implemented'", body)
	}
}

// TestServeDeclaredService_Approve_Approved pins down that when an
// approvals manager is wired and returns Approved=true, the request
// proceeds to the forwarding path and the upstream response is
// returned to the caller.
func TestServeDeclaredService_Approve_Approved(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "require-approval", Methods: []string{"POST"}, Paths: []string{"/issues"}, Decision: "approve"},
	})
	appr := &fakeApprovalsManager{approve: true}
	p.SetApprovalsForTest(appr)

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/svc/github/issues", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if appr.gotReq.Kind != "http_service" {
		t.Errorf("approval Kind = %q, want http_service", appr.gotReq.Kind)
	}
	if !strings.Contains(appr.gotReq.Target, "github") || !strings.Contains(appr.gotReq.Target, "POST") {
		t.Errorf("approval Target = %q, want to contain service name and method", appr.gotReq.Target)
	}
	if appr.gotReq.SessionID != "test-session" {
		t.Errorf("approval SessionID = %q, want test-session", appr.gotReq.SessionID)
	}
}

// TestServeDeclaredService_Approve_DoesNotSetBogusCommandID pins down that
// the approval request's CommandID is NOT populated with the proxy's
// per-request UUID. Declared-service requests do not originate from a
// single session command — they come from arbitrary HTTP calls the agent
// makes — so there is no real command to attach, and populating the field
// with the proxy's internal request ID corrupts downstream command-level
// correlation. The field must be left empty until a real session command
// ID can be plumbed through.
func TestServeDeclaredService_Approve_DoesNotSetBogusCommandID(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "require-approval", Methods: []string{"POST"}, Paths: []string{"/issues"}, Decision: "approve"},
	})
	appr := &fakeApprovalsManager{approve: true}
	p.SetApprovalsForTest(appr)

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/svc/github/issues", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if appr.gotReq.CommandID != "" {
		t.Errorf("approval CommandID = %q, want empty (declared-service requests have no session command)", appr.gotReq.CommandID)
	}
}

// TestServeDeclaredService_Approve_TargetIncludesQueryString pins down that
// the approval Target includes the raw query string when present, so the
// approver sees the full request the client is making — not just the path
// segment. Hiding the query string would obscure material details about
// what's being approved (e.g. a ?force=true override).
func TestServeDeclaredService_Approve_TargetIncludesQueryString(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "require-approval", Methods: []string{"POST"}, Paths: []string{"/issues"}, Decision: "approve"},
	})
	appr := &fakeApprovalsManager{approve: true}
	p.SetApprovalsForTest(appr)

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/svc/github/issues?force=true", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if !strings.Contains(appr.gotReq.Target, "?force=true") {
		t.Errorf("approval Target = %q, want to contain '?force=true'", appr.gotReq.Target)
	}
}

// TestServeDeclaredService_Approve_TargetPreservesEncodedPath pins down
// that the approval Target shows the approver the exact escaped bytes
// the client sent — not the decoded form. Before the fix, Target was
// built from r.URL.Path (decoded by net/http), so percent-encoded bytes
// like %2F collapsed to their literal characters and approvers saw a
// different or ambiguous path from what the client actually requested.
// The service rule matches the decoded form (/items/a/b) because
// CheckHTTPService runs against the decoded path; the Target string is
// human-facing and must preserve the original encoding.
func TestServeDeclaredService_Approve_TargetPreservesEncodedPath(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "require-approval", Methods: []string{"POST"}, Paths: []string{"/items/a/b"}, Decision: "approve"},
	})
	appr := &fakeApprovalsManager{approve: true}
	p.SetApprovalsForTest(appr)

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/svc/github/items/a%2Fb?force=true", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if got, want := appr.gotReq.Target, "github POST /items/a%2Fb?force=true"; got != want {
		t.Errorf("approval Target = %q, want %q", got, want)
	}
}

// TestServeDeclaredService_Approve_TargetFallsBackWhenNextByteIsEncoded
// pins down that the escaped-path prefix strip requires a '/' boundary
// immediately after the /svc/<name> prefix. When a client percent-encodes
// the slash after the service segment (e.g. /svc/github%2Fitems), the
// dispatcher decodes it to /svc/github/items and routes the request to
// service "github" with rest "/items". The approval Target must match
// the decoded "/items" that policy evaluation used — NOT the literal
// strip "%2Fitems" that a naive HasPrefix+TrimPrefix would produce,
// which would diverge from what the upstream actually receives and
// mislead the approver about what they're authorizing.
func TestServeDeclaredService_Approve_TargetFallsBackWhenNextByteIsEncoded(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "require-approval", Methods: []string{"POST"}, Paths: []string{"/items"}, Decision: "approve"},
	})
	appr := &fakeApprovalsManager{approve: true}
	p.SetApprovalsForTest(appr)

	// %2F immediately after the service name. Decoded form is
	// /svc/github/items so the dispatcher routes to service "github"
	// with rest "/items", and the POST /items rule evaluates as approve.
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/svc/github%2Fitems?force=true", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	// The target MUST use the decoded-and-re-escaped fallback form
	// ("/items") — not the literal-strip result ("%2Fitems") that a
	// naive HasPrefix+TrimPrefix would produce.
	if got, want := appr.gotReq.Target, "github POST /items?force=true"; got != want {
		t.Errorf("approval Target = %q, want %q", got, want)
	}
}

// TestServeDeclaredService_Approve_Denied pins down that when an approvals
// manager is wired and returns Approved=false, the handler must deny with
// 403 Forbidden and MUST NOT forward the request to the upstream.
func TestServeDeclaredService_Approve_Denied(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("upstream should not be reached when approval denies")
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "require-approval", Methods: []string{"POST"}, Paths: []string{"/issues"}, Decision: "approve"},
	})
	p.SetApprovalsForTest(&fakeApprovalsManager{approve: false})

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/svc/github/issues", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", w.Code, w.Body.String())
	}
}

func TestServeDeclaredService_Allow_Forwards(t *testing.T) {
	// Fake upstream that records the incoming request.
	var gotMethod, gotPath string
	var gotBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "post-issues", Methods: []string{"POST"}, Paths: []string{"/repos/*/*/issues"}, Decision: "allow"},
	})

	body := strings.NewReader(`{"title":"bug"}`)
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/svc/github/repos/anthropics/claude-code/issues", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", w.Code)
	}
	if gotMethod != "POST" {
		t.Errorf("upstream method = %q, want POST", gotMethod)
	}
	if gotPath != "/repos/anthropics/claude-code/issues" {
		t.Errorf("upstream path = %q, want /repos/anthropics/claude-code/issues", gotPath)
	}
	if string(gotBody) != `{"title":"bug"}` {
		t.Errorf("upstream body = %q", gotBody)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("response Content-Type = %q, want application/json", ct)
	}
}

// TestServeDeclaredService_PreservesEscapedPath pins down that percent-encoded
// bytes in the request path reach the upstream unchanged. Before the fix,
// /svc/github/items/a%2Fb was reconstructed from the decoded URL.Path as
// /items/a/b — a different resource.
func TestServeDeclaredService_PreservesEscapedPath(t *testing.T) {
	var gotEscaped, gotDecoded string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEscaped = r.URL.EscapedPath()
		gotDecoded = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "allow-items", Paths: []string{"/items/**"}, Decision: "allow"},
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/svc/github/items/a%2Fb", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if gotEscaped != "/items/a%2Fb" {
		t.Errorf("upstream EscapedPath = %q, want /items/a%%2Fb", gotEscaped)
	}
	if gotDecoded != "/items/a/b" {
		t.Errorf("upstream Path = %q, want /items/a/b", gotDecoded)
	}
}

// TestServeDeclaredService_StripsConnectionNominatedRequestHeaders pins down
// that headers listed in the client's Connection header are dropped before
// forwarding upstream, in addition to the fixed hop-by-hop set.
// RFC 7230 §6.1: any token in Connection is hop-by-hop for this hop.
func TestServeDeclaredService_StripsConnectionNominatedRequestHeaders(t *testing.T) {
	var gotHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "allow-foo", Paths: []string{"/foo"}, Decision: "allow"},
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/svc/github/foo", nil)
	req.Header.Set("Connection", "X-Sensitive, close")
	req.Header.Set("X-Sensitive", "secret")
	req.Header.Set("X-Allowed", "ok")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if v := gotHeaders.Get("X-Sensitive"); v != "" {
		t.Errorf("upstream X-Sensitive = %q, want empty (stripped by Connection)", v)
	}
	if v := gotHeaders.Get("Connection"); v != "" {
		t.Errorf("upstream Connection = %q, want empty (hop-by-hop)", v)
	}
	if v := gotHeaders.Get("X-Allowed"); v != "ok" {
		t.Errorf("upstream X-Allowed = %q, want ok (end-to-end header dropped)", v)
	}
}

// TestServeDeclaredService_StripsHopByHopResponseHeaders pins down that
// hop-by-hop headers and headers nominated by the upstream's Connection
// header are stripped from the response copied back to the caller. Real
// headers like X-Request-Id must pass through.
func TestServeDeclaredService_StripsHopByHopResponseHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "X-Upstream-Secret")
		w.Header().Set("X-Upstream-Secret", "shh")
		w.Header().Set("Keep-Alive", "timeout=5")
		w.Header().Set("X-Request-Id", "abc")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "allow-foo", Paths: []string{"/foo"}, Decision: "allow"},
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/svc/github/foo", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if v := w.Header().Get("X-Request-Id"); v != "abc" {
		t.Errorf("response X-Request-Id = %q, want abc (end-to-end header dropped)", v)
	}
	if v := w.Header().Get("X-Upstream-Secret"); v != "" {
		t.Errorf("response X-Upstream-Secret = %q, want empty (Connection-nominated)", v)
	}
	if v := w.Header().Get("Keep-Alive"); v != "" {
		t.Errorf("response Keep-Alive = %q, want empty (hop-by-hop)", v)
	}
	if v := w.Header().Get("Connection"); v != "" {
		t.Errorf("response Connection = %q, want empty (hop-by-hop)", v)
	}
}

// TestServeDeclaredService_PreservesEscapedPath_MixedCaseServiceName pins
// down that percent-encoded bytes survive case-mismatched service names.
// The declared service is "GitHub" (mixed case) but the request uses
// "/svc/github/..." (lowercase). declaredService must return the request's
// segment so serveDeclaredService can strip it from EscapedPath() with a
// case-sensitive HasPrefix — otherwise the fallback decodes %2F to /.
func TestServeDeclaredService_PreservesEscapedPath_MixedCaseServiceName(t *testing.T) {
	var gotEscaped string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEscaped = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Declared name "GitHub" — request uses "github".
	p := newTestProxyWithNamedHTTPService(t, "GitHub", upstream.URL, []policy.HTTPServiceRule{
		{Name: "allow-items", Paths: []string{"/items/**"}, Decision: "allow"},
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/svc/github/items/a%2Fb", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if gotEscaped != "/items/a%2Fb" {
		t.Errorf("upstream EscapedPath = %q, want /items/a%%2Fb", gotEscaped)
	}
}

// TestServeDeclaredService_PreservesEscapedPath_UppercaseRequest is the
// reverse: declared service is lowercase "github", request uses uppercase
// "/svc/GITHUB/...". Same invariant must hold.
func TestServeDeclaredService_PreservesEscapedPath_UppercaseRequest(t *testing.T) {
	var gotEscaped string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEscaped = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxyWithNamedHTTPService(t, "github", upstream.URL, []policy.HTTPServiceRule{
		{Name: "allow-items", Paths: []string{"/items/**"}, Decision: "allow"},
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/svc/GITHUB/items/a%2Fb", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if gotEscaped != "/items/a%2Fb" {
		t.Errorf("upstream EscapedPath = %q, want /items/a%%2Fb", gotEscaped)
	}
}

// TestServeDeclaredService_StripsMultipleConnectionRequestHeaders pins down
// RFC 7230 §3.2.2: a client sending Connection on multiple lines must have
// ALL nominated headers stripped, not just the first line's tokens.
// Header.Get returns only the first value — connectionNominatedDenylist
// must merge via Header.Values.
func TestServeDeclaredService_StripsMultipleConnectionRequestHeaders(t *testing.T) {
	var gotHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "allow-foo", Paths: []string{"/foo"}, Decision: "allow"},
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/svc/github/foo", nil)
	// Two separate Connection header lines.
	req.Header.Add("Connection", "X-Custom-Req")
	req.Header.Add("Connection", "X-Other-Req")
	req.Header.Set("X-Custom-Req", "one")
	req.Header.Set("X-Other-Req", "two")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if v := gotHeaders.Get("X-Custom-Req"); v != "" {
		t.Errorf("upstream X-Custom-Req = %q, want empty (first Connection line)", v)
	}
	if v := gotHeaders.Get("X-Other-Req"); v != "" {
		t.Errorf("upstream X-Other-Req = %q, want empty (second Connection line)", v)
	}
}

// TestServeDeclaredService_HooksRunPerService pins down that pre-hooks
// registered under a declared service's name are invoked in the /svc/
// forwarding path, and that the RequestContext is populated with the
// correct ServiceName. This is the knob that makes per-service header
// injection (HeaderInjectionHook) actually take effect at runtime.
func TestServeDeclaredService_HooksRunPerService(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "get", Methods: []string{"GET"}, Paths: []string{"/**"}, Decision: "allow"},
	})

	// Register a hook under "github" that sets the Authorization header.
	p.HookRegistry().Register("github", &serviceRecorderHook{
		name: "fake-injector",
		preFn: func(r *http.Request, ctx *RequestContext) error {
			r.Header.Set("Authorization", "Bearer real-token")
			if ctx.ServiceName != "github" {
				t.Errorf("ctx.ServiceName = %q, want github", ctx.ServiceName)
			}
			return nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/svc/github/user", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if gotAuth != "Bearer real-token" {
		t.Errorf("upstream Authorization = %q, want 'Bearer real-token'", gotAuth)
	}
}

// TestServeDeclaredService_HookAbortError_ReturnsStatusCode pins down that
// returning a *HookAbortError from a pre-hook in the /svc/ path causes the
// proxy to respond with the error's StatusCode and Message instead of
// forwarding the request upstream.
func TestServeDeclaredService_HookAbortError_ReturnsStatusCode(t *testing.T) {
	var upstreamCalled bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "get", Methods: []string{"GET"}, Paths: []string{"/**"}, Decision: "allow"},
	})

	p.HookRegistry().Register("github", &serviceRecorderHook{
		name: "abort",
		preFn: func(r *http.Request, ctx *RequestContext) error {
			return &HookAbortError{StatusCode: http.StatusForbidden, Message: "blocked by hook"}
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/svc/github/user", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if upstreamCalled {
		t.Error("upstream should not have been called after hook abort")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", w.Code, w.Body.String())
	}
	if body := w.Body.String(); !strings.Contains(body, "blocked by hook") {
		t.Errorf("body = %q, want 'blocked by hook'", body)
	}
}

// TestServeDeclaredService_StripsMultipleConnectionResponseHeaders is the
// response-side equivalent: when the upstream sends Connection on two
// lines, both lines' nominated headers must be dropped before copying
// headers back to the client.
func TestServeDeclaredService_StripsMultipleConnectionResponseHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Two separate Connection header lines.
		w.Header().Add("Connection", "X-Custom-Resp")
		w.Header().Add("Connection", "X-Other-Resp")
		w.Header().Set("X-Custom-Resp", "one")
		w.Header().Set("X-Other-Resp", "two")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "allow-foo", Paths: []string{"/foo"}, Decision: "allow"},
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/svc/github/foo", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if v := w.Header().Get("X-Custom-Resp"); v != "" {
		t.Errorf("response X-Custom-Resp = %q, want empty (first Connection line)", v)
	}
	if v := w.Header().Get("X-Other-Resp"); v != "" {
		t.Errorf("response X-Other-Resp = %q, want empty (second Connection line)", v)
	}
}

// TestServeDeclaredService_HooksRunForMixedCaseRequest pins down that
// pre-hooks registered under a declared service's canonical name fire
// even when the request URL's service segment uses a different case.
// Hook registration is keyed on the canonical name from the policy
// config (e.g. "github") — before the fix, serveDeclaredService passed
// the raw request segment ("GITHUB") to ApplyPreHooks, so the lookup
// missed the service-scoped hook and the Authorization header was
// never injected.
func TestServeDeclaredService_HooksRunForMixedCaseRequest(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Canonical name is lowercase "github"; request URL is uppercase.
	p := newTestProxyWithNamedHTTPService(t, "github", upstream.URL, []policy.HTTPServiceRule{
		{Name: "get", Methods: []string{"GET"}, Paths: []string{"/**"}, Decision: "allow"},
	})

	hookCalled := false
	p.HookRegistry().Register("github", &serviceRecorderHook{
		name: "fake-injector",
		preFn: func(r *http.Request, ctx *RequestContext) error {
			hookCalled = true
			if ctx.ServiceName != "github" {
				t.Errorf("ctx.ServiceName = %q, want github (canonical)", ctx.ServiceName)
			}
			r.Header.Set("Authorization", "Bearer real-token")
			return nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/svc/GITHUB/user", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if !hookCalled {
		t.Error("service-scoped hook was not called for mixed-case request")
	}
	if gotAuth != "Bearer real-token" {
		t.Errorf("upstream Authorization = %q, want 'Bearer real-token'", gotAuth)
	}
}

// TestServeDeclaredService_HooksRunForMixedCaseRequest_MixedCaseCanonical
// is the mirror case: canonical name is mixed case "GitHub" and the
// request uses lowercase "github". The hook is registered under the
// canonical name "GitHub" and must still fire.
func TestServeDeclaredService_HooksRunForMixedCaseRequest_MixedCaseCanonical(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxyWithNamedHTTPService(t, "GitHub", upstream.URL, []policy.HTTPServiceRule{
		{Name: "get", Methods: []string{"GET"}, Paths: []string{"/**"}, Decision: "allow"},
	})

	hookCalled := false
	p.HookRegistry().Register("GitHub", &serviceRecorderHook{
		name: "fake-injector",
		preFn: func(r *http.Request, ctx *RequestContext) error {
			hookCalled = true
			if ctx.ServiceName != "GitHub" {
				t.Errorf("ctx.ServiceName = %q, want GitHub (canonical)", ctx.ServiceName)
			}
			r.Header.Set("Authorization", "Bearer real-token")
			return nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/svc/github/user", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if !hookCalled {
		t.Error("service-scoped hook was not called for case-mismatched request")
	}
	if gotAuth != "Bearer real-token" {
		t.Errorf("upstream Authorization = %q, want 'Bearer real-token'", gotAuth)
	}
}

// TestServeDeclaredService_PreHookCanRewritePath pins down that pre-hook
// URL mutations (e.g. CredsSubHook substituting credentials in the URL
// path) reach the upstream. Before the fix, serveDeclaredService captured
// reqPath/escapedPath BEFORE running hooks and passed those stale values
// to buildUpstreamRequest, so any hook rewrites of r.URL.Path/RawPath
// were silently dropped.
func TestServeDeclaredService_PreHookCanRewritePath(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		// Policy rule is written against the *original* path, because
		// CheckHTTPService runs before hooks. The hook then rewrites
		// the URL to something the upstream serves.
		{Name: "allow-original", Paths: []string{"/original"}, Decision: "allow"},
	})

	p.HookRegistry().Register("github", &serviceRecorderHook{
		name: "path-rewriter",
		preFn: func(r *http.Request, _ *RequestContext) error {
			r.URL.Path = "/rewritten"
			r.URL.RawPath = "/rewritten"
			return nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/svc/github/original", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if gotPath != "/rewritten" {
		t.Errorf("upstream path = %q, want /rewritten (hook rewrite dropped?)", gotPath)
	}
}

// failingReader is an io.Reader that always returns an error. Used to
// simulate a client whose request body stream fails mid-read.
type failingReader struct{}

func (failingReader) Read(_ []byte) (int, error) { return 0, errors.New("boom") }

// TestServeDeclaredService_BodyReadError_Returns400 pins down that a
// failure to read the request body returns an HTTP 400 and does NOT
// forward the request upstream. Before the fix, io.ReadAll errors were
// silently swallowed and the (partially-drained) body was handed to
// hooks and the upstream, yielding a truncated forwarded request.
func TestServeDeclaredService_BodyReadError_Returns400(t *testing.T) {
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "allow-all", Methods: []string{"POST"}, Paths: []string{"/**"}, Decision: "allow"},
	})

	// httptest.NewRequest requires an io.Reader. The failing reader's
	// Read always errors, simulating a mid-stream failure.
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/svc/github/foo", failingReader{})
	// ContentLength > 0 so net/http doesn't helpfully short-circuit to
	// http.NoBody before the handler ever calls Read.
	req.ContentLength = 10
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if upstreamCalled {
		t.Error("upstream should not be called when request body read fails")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%q", w.Code, w.Body.String())
	}
	if body := w.Body.String(); !strings.Contains(body, "read request body") {
		t.Errorf("body = %q, want 'read request body' prefix", body)
	}
}

// TestServeDeclaredService_PreservesEscapedPath_WhenHookDoesNotTouchPath
// pins down that percent-encoded bytes in the request path reach the
// upstream unchanged even when a pre-hook runs — so long as the hook
// does not mutate r.URL.Path. The hook here injects a header (the common
// case for per-service hooks) and leaves the URL alone; the %2F must
// still survive to the upstream.
func TestServeDeclaredService_PreservesEscapedPath_WhenHookDoesNotTouchPath(t *testing.T) {
	var gotEscaped string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEscaped = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "allow-repos", Paths: []string{"/repos/**"}, Decision: "allow"},
	})

	p.HookRegistry().Register("github", &serviceRecorderHook{
		name: "header-only",
		preFn: func(r *http.Request, _ *RequestContext) error {
			// Hook leaves r.URL.Path and r.URL.RawPath alone.
			r.Header.Set("Authorization", "Bearer real-token")
			return nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/svc/github/repos/a%2Fb/issues", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if gotEscaped != "/repos/a%2Fb/issues" {
		t.Errorf("upstream EscapedPath = %q, want /repos/a%%2Fb/issues", gotEscaped)
	}
}

// TestServeDeclaredService_HookPathRewrite_DropsEncodedBytes documents
// the intentional limitation of the Path/RawPath contract: when a pre-hook
// mutates only r.URL.Path (not RawPath), percent-encoded bytes in other
// segments are LOST. The handler seeds r.URL.RawPath with the original
// escaped tail before running hooks (so built-in hooks like CredsSubHook,
// which update Path and RawPath in lockstep, can preserve encoded bytes),
// but a hook that only touches Path leaves a stale RawPath behind. The
// handler detects this post-hook and clears RawPath so Go's
// url.URL.EscapedPath() re-escapes from the mutated Path — which turns
// %2F in untouched segments into a literal '/'.
//
// Hooks that want to rewrite Path while preserving encoded bytes in
// untouched segments must update BOTH Path and RawPath together (see
// TestServeDeclaredService_HookRewritesBothPathAndRawPath). This matches
// what CredsSubHook does — see
// TestServeDeclaredService_CredsSubHook_PreservesEncodedSlash for the
// real-hook regression test.
func TestServeDeclaredService_HookPathRewrite_DropsEncodedBytes(t *testing.T) {
	var gotEscaped string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEscaped = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "allow-repos", Paths: []string{"/repos/**"}, Decision: "allow"},
	})

	p.HookRegistry().Register("github", &serviceRecorderHook{
		name: "path-suffix-rewrite",
		preFn: func(r *http.Request, _ *RequestContext) error {
			// Hook mutates only Path, leaving RawPath untouched. This
			// is the "common but wrong" pattern documented in the
			// fix's follow-up comment.
			r.URL.Path = strings.Replace(r.URL.Path, "/issues", "/pulls", 1)
			return nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/svc/github/repos/a%2Fb/issues", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	// The hook owns the re-escaping because it mutated Path without
	// updating RawPath. %2F is re-encoded from the decoded '/' to a
	// literal '/' in the upstream path. This is INTENTIONAL — it
	// documents the hook contract, not a regression.
	if gotEscaped != "/repos/a/b/pulls" {
		t.Errorf("upstream EscapedPath = %q, want /repos/a/b/pulls (hook owns encoding when mutating Path)", gotEscaped)
	}
}

// TestServeDeclaredService_HookRewritesBothPathAndRawPath pins down the
// opt-in path for hooks that need to rewrite the URL while preserving
// encoded bytes: set BOTH r.URL.Path and r.URL.RawPath. When RawPath is
// a valid encoding of Path, Go's EscapedPath() returns RawPath verbatim
// and the upstream receives exactly what the hook produced.
func TestServeDeclaredService_HookRewritesBothPathAndRawPath(t *testing.T) {
	var gotEscaped string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEscaped = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "allow-repos", Paths: []string{"/repos/**"}, Decision: "allow"},
	})

	p.HookRegistry().Register("github", &serviceRecorderHook{
		name: "path-suffix-rewrite-encoded",
		preFn: func(r *http.Request, _ *RequestContext) error {
			// Hook rewrites the suffix AND keeps the encoded byte in
			// the untouched prefix by updating both fields.
			r.URL.Path = "/repos/a/b/pulls"
			r.URL.RawPath = "/repos/a%2Fb/pulls"
			return nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/svc/github/repos/a%2Fb/issues", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if gotEscaped != "/repos/a%2Fb/pulls" {
		t.Errorf("upstream EscapedPath = %q, want /repos/a%%2Fb/pulls", gotEscaped)
	}
}

// TestServeDeclaredService_CredsSubHook_PreservesEncodedSlash is the
// real-hook regression test for the CredsSubHook path-rewriting branch.
// CredsSubHook updates r.URL.RawPath ONLY when RawPath is already set
// (see internal/proxy/credshook.go PreHook). If the declared-service
// handler clears RawPath before running hooks, CredsSubHook only
// rewrites Path and any encoded bytes elsewhere in the path (e.g. a
// %2F in a different segment) are lost when Go re-escapes Path from
// scratch.
//
// The handler must seed r.URL.RawPath with the escaped tail BEFORE
// running hooks so CredsSubHook's dual-update branch fires. Because
// the substitution is length-preserving and leaves non-substituted
// bytes intact, the %2F survives all the way to the upstream.
func TestServeDeclaredService_CredsSubHook_PreservesEncodedSlash(t *testing.T) {
	var gotEscaped string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEscaped = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		// Policy rule is written against the original decoded path.
		{Name: "allow-repos", Paths: []string{"/repos/**"}, Decision: "allow"},
	})

	// Build a credsub table with a fake/real pair of the same length
	// (24 chars — the table enforces length equality). The fake is
	// what the agent types; the real is what the upstream receives.
	tbl := credsub.New()
	if err := tbl.Add("github",
		[]byte("FAKE_PLACEHOLDER_12345678"),
		[]byte("REAL_CREDENTIAL_abcdef012"),
	); err != nil {
		t.Fatalf("credsub.Add: %v", err)
	}
	// Mirror llmproxy.go: register globally (empty service name) so
	// the hook fires for every declared service — including "github".
	p.HookRegistry().Register("", NewCredsSubHook(tbl, nil))

	// The request path contains BOTH:
	//   - an encoded slash (%2F) in one segment that CredsSubHook must
	//     not touch, and
	//   - a placeholder credential in another segment that CredsSubHook
	//     must substitute.
	req := httptest.NewRequest(http.MethodGet,
		"http://127.0.0.1/svc/github/repos/owner%2Fname/tokens/FAKE_PLACEHOLDER_12345678", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	// Upstream must see the substitution applied AND the encoded slash
	// preserved in the untouched segment.
	want := "/repos/owner%2Fname/tokens/REAL_CREDENTIAL_abcdef012"
	if gotEscaped != want {
		t.Errorf("upstream EscapedPath = %q, want %q", gotEscaped, want)
	}
}

// TestServeDeclaredService_HookRewritesOnlyRawPath pins down that a hook
// which mutates only r.URL.RawPath (leaving r.URL.Path unchanged) has
// its RawPath propagated to the upstream. Before the fix, the post-hook
// restore logic checked only Path and silently overwrote any
// hook-written RawPath with the original escaped tail, so hooks could
// not adjust escaping without also changing Path.
//
// The request URL uses an encoded byte (%62) so that the original
// escaped tail differs from the decoded Path — that's what triggered
// the old restore logic's "RawPath := escapedPath" branch. The hook
// then rewrites RawPath to a third (different) valid encoding, and
// the upstream must see exactly the hook's encoding.
func TestServeDeclaredService_HookRewritesOnlyRawPath(t *testing.T) {
	var gotEscaped string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEscaped = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "allow-items", Paths: []string{"/items/**"}, Decision: "allow"},
	})

	p.HookRegistry().Register("github", &serviceRecorderHook{
		name: "rawpath-only",
		preFn: func(r *http.Request, _ *RequestContext) error {
			// Leave r.URL.Path alone; rewrite only RawPath to a
			// different valid encoding of the same decoded Path.
			// The handler must trust the hook's RawPath.
			r.URL.RawPath = "/items/%61b"
			return nil
		},
	})

	// Encoded %62 ("b") — makes the original escapedPath "/items/a%62"
	// differ from the decoded Path "/items/ab". The old restore logic
	// saw Path unchanged and blindly re-applied "/items/a%62",
	// clobbering the hook's "/items/%61b".
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/svc/github/items/a%62", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if gotEscaped != "/items/%61b" {
		t.Errorf("upstream EscapedPath = %q, want /items/%%61b (hook-written RawPath clobbered?)", gotEscaped)
	}
}

// TestServeDeclaredService_LogRedactsInjectedAndCookieHeaders pins down
// that the declared-service audit log redacts session cookies,
// upstream-proxy credentials, and HeaderInjectionHook-registered
// headers — not just the three fixed LLM-path auth headers. Upstream
// Set-Cookie and Authorization values echoed in responses are also
// redacted so audit records cannot leak live credentials.
func TestServeDeclaredService_LogRedactsInjectedAndCookieHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "sid=abc123; Path=/")
		w.Header().Set("Authorization", "Bearer upstream-leak")
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"upstream\"")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()

	tmpDir := t.TempDir()
	storage, err := NewStorage(tmpDir, "test-session", false)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	defer storage.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "allow-user", Methods: []string{"GET"}, Paths: []string{"/user"}, Decision: "allow"},
	})
	p.SetStorageForTest(storage)

	// Build a credsub table and register a HeaderInjectionHook under
	// "github" that injects an arbitrary header name (X-Hub-Token) —
	// must be redacted in logs even though it is not in the shared LLM
	// auth denylist.
	tbl := credsub.New()
	if err := tbl.Add("github",
		[]byte("FAKE_PLACEHOLDER_12345678"),
		[]byte("REAL_CREDENTIAL_abcdef012"),
	); err != nil {
		t.Fatalf("credsub.Add: %v", err)
	}
	p.HookRegistry().Register("github", NewHeaderInjectionHook("github", "X-Hub-Token", "Bearer {{secret}}", tbl))

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/svc/github/user", nil)
	req.Header.Set("Cookie", "session=secret123")
	req.Header.Set("X-Hub-Token", "will-be-replaced")
	req.Header.Set("Authorization", "Bearer real-key")
	req.Header.Set("Proxy-Authorization", "Basic abc")
	req.Header.Set("User-Agent", "test-agent")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}

	// Validate request entry redactions.
	reqEntries := readAllRequestLogEntries(t, tmpDir, "test-session")
	if len(reqEntries) != 1 {
		t.Fatalf("got %d request log entries, want 1", len(reqEntries))
	}
	reqE := reqEntries[0]

	assertRedacted := func(m map[string][]string, key string) {
		t.Helper()
		v, ok := m[key]
		if !ok {
			// Try canonical form fallback.
			v, ok = m[http.CanonicalHeaderKey(key)]
		}
		if !ok {
			t.Errorf("expected header %q in log, not present", key)
			return
		}
		if len(v) == 0 || v[0] != "[REDACTED]" {
			t.Errorf("header %q = %v, want [REDACTED]", key, v)
		}
	}

	assertRedacted(reqE.Request.Headers, "Authorization")
	assertRedacted(reqE.Request.Headers, "Cookie")
	assertRedacted(reqE.Request.Headers, "X-Hub-Token")
	assertRedacted(reqE.Request.Headers, "Proxy-Authorization")

	// Non-sensitive header passes through.
	if ua, ok := reqE.Request.Headers["User-Agent"]; !ok || len(ua) == 0 || ua[0] != "test-agent" {
		t.Errorf("User-Agent = %v, want [test-agent]", ua)
	}

	// Validate response entry redactions: upstream-echoed Authorization
	// and Set-Cookie must be redacted.
	respEntries := readAllResponseLogEntries(t, tmpDir, "test-session")
	if len(respEntries) != 1 {
		t.Fatalf("got %d response log entries, want 1", len(respEntries))
	}
	respE := respEntries[0]

	assertRedacted(respE.Response.Headers, "Set-Cookie")
	assertRedacted(respE.Response.Headers, "Authorization")
	assertRedacted(respE.Response.Headers, "Proxy-Authenticate")
}

// TestServeDeclaredService_LogReflectsPostHookBody pins down that the
// request audit log records the body AFTER pre-hooks have run. Hooks
// (notably CredsSubHook) may replace r.Body with post-substitution
// bytes, and the audit entry must reflect what is actually forwarded
// upstream — not the pre-substitution bytes the agent originally sent.
// Otherwise BodySize / BodyHash silently diverge from the upstream
// request, breaking provenance and audit integrity.
func TestServeDeclaredService_LogReflectsPostHookBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	tmpDir := t.TempDir()
	storage, err := NewStorage(tmpDir, "test-session", false)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	defer storage.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "allow-upload", Methods: []string{"POST"}, Paths: []string{"/upload"}, Decision: "allow"},
	})
	p.SetStorageForTest(storage)

	// Hook that replaces r.Body with different-length bytes, to prove
	// the audit log reflects the post-hook value not the pre-hook value.
	const postHookBody = "POST_HOOK_BODY"
	p.HookRegistry().Register("github", &serviceRecorderHook{
		name: "body-rewriter",
		preFn: func(r *http.Request, _ *RequestContext) error {
			r.Body = io.NopCloser(bytes.NewReader([]byte(postHookBody)))
			r.ContentLength = int64(len(postHookBody))
			return nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/svc/github/upload", strings.NewReader("PRE_HOOK_BODY"))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}

	entries := readAllRequestLogEntries(t, tmpDir, "test-session")
	if len(entries) != 1 {
		t.Fatalf("got %d request log entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Request.BodySize != len(postHookBody) {
		t.Errorf("BodySize = %d, want %d (post-hook body length)", e.Request.BodySize, len(postHookBody))
	}
	wantHash := HashBody([]byte(postHookBody))
	if e.Request.BodyHash != wantHash {
		t.Errorf("BodyHash = %q, want %q (hash of post-hook body)", e.Request.BodyHash, wantHash)
	}
}

func TestServeDeclaredService_LogsRequestAndResponseToStorage(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"login":"octocat"}`)
	}))
	defer upstream.Close()

	// Point storage at a temp dir so we can read back the JSONL.
	tmpDir := t.TempDir()
	storage, err := NewStorage(tmpDir, "test-session", false)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	defer storage.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "read-user", Methods: []string{"GET"}, Paths: []string{"/user"}, Decision: "allow"},
	})
	p.SetStorageForTest(storage)

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/svc/github/user", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	entries := readAllRequestLogEntries(t, tmpDir, "test-session")
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}
	e := entries[0]
	if e.ServiceKind != "http_service" {
		t.Errorf("ServiceKind = %q, want http_service", e.ServiceKind)
	}
	if e.ServiceName != "github" {
		t.Errorf("ServiceName = %q, want github", e.ServiceName)
	}
	if e.RuleName != "read-user" {
		t.Errorf("RuleName = %q, want read-user", e.RuleName)
	}
	if e.Request.Method != "GET" || e.Request.Path != "/user" {
		t.Errorf("Request = %+v, want GET /user", e.Request)
	}
	if e.Dialect != "" {
		t.Errorf("Dialect = %q, want empty for http_service", e.Dialect)
	}

	resps := readAllResponseLogEntries(t, tmpDir, "test-session")
	if len(resps) != 1 {
		t.Fatalf("got %d response entries, want 1", len(resps))
	}
	if resps[0].Response.Status != http.StatusOK {
		t.Errorf("response status = %d, want 200", resps[0].Response.Status)
	}
}

// TestServeDeclaredService_StoresPreHookBodyDespitePostHookSubstitution
// pins down that on-disk body storage reflects the PRE-hook body (what
// the agent originally sent) while the audit record's BodySize/BodyHash
// reflect the POST-hook body (what was actually forwarded upstream).
//
// The split matters for CredsSubHook, which replaces fake-credential
// placeholders in the agent's request with the real upstream secret.
// If on-disk storage captured the post-hook bytes, every llm-bodies file
// would leak the real credential to disk — exactly what credsub exists
// to prevent. Conversely, the audit BodyHash must cover what was
// forwarded so provenance/integrity stamps describe the actual upstream
// payload, not the agent's typed input.
func TestServeDeclaredService_StoresPreHookBodyDespitePostHookSubstitution(t *testing.T) {
	// Upstream echoes the body it receives so we can sanity-check that
	// the hook's replacement really did reach the wire.
	var upstreamGot []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamGot, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(upstreamGot)
	}))
	defer upstream.Close()

	// storeBodies: true so StoreRequestBody actually writes to disk.
	tmpDir := t.TempDir()
	storage, err := NewStorage(tmpDir, "test-session", true)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	defer storage.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "allow-upload", Methods: []string{"POST"}, Paths: []string{"/upload"}, Decision: "allow"},
	})
	p.SetStorageForTest(storage)

	const preHookBody = "FAKE_PLACEHOLDER"
	const postHookBody = "REAL_SECRET_XYZ"
	p.HookRegistry().Register("github", &serviceRecorderHook{
		name: "body-replace",
		preFn: func(r *http.Request, _ *RequestContext) error {
			r.Body = io.NopCloser(bytes.NewReader([]byte(postHookBody)))
			r.ContentLength = int64(len(postHookBody))
			return nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/svc/github/upload", strings.NewReader(preHookBody))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	// Sanity: upstream really did see the post-hook body.
	if string(upstreamGot) != postHookBody {
		t.Fatalf("upstream received %q, want %q (hook did not take effect)", upstreamGot, postHookBody)
	}

	// Audit record must describe the FORWARDED body (post-hook).
	entries := readAllRequestLogEntries(t, tmpDir, "test-session")
	if len(entries) != 1 {
		t.Fatalf("got %d request log entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Request.BodySize != len(postHookBody) {
		t.Errorf("BodySize = %d, want %d (post-hook body length)", e.Request.BodySize, len(postHookBody))
	}
	wantHash := HashBody([]byte(postHookBody))
	if e.Request.BodyHash != wantHash {
		t.Errorf("BodyHash = %q, want %q (hash of post-hook body)", e.Request.BodyHash, wantHash)
	}

	// On-disk stored body must reflect the PRE-hook bytes. We pull the
	// request ID out of the audit entry (storage writes the body file
	// keyed on that ID).
	bodyPath := filepath.Join(tmpDir, "test-session", "llm-bodies", e.ID+".json")
	stored, err := os.ReadFile(bodyPath)
	if err != nil {
		t.Fatalf("read stored body %q: %v", bodyPath, err)
	}
	if string(stored) != preHookBody {
		t.Errorf("stored body = %q, want %q (pre-hook body)", stored, preHookBody)
	}
	if bytes.Contains(stored, []byte(postHookBody)) {
		t.Errorf("stored body leaked post-hook content %q: got %q", postHookBody, stored)
	}
}

// TestServeDeclaredService_HookNilsBody_LogsZeroAndStoresNothing pins
// down what happens when a pre-hook drops the request body entirely by
// setting r.Body = nil. In that case nothing is forwarded upstream, so
// the audit record must show BodySize=0/BodyHash="" and no file must
// land on disk under this request ID — otherwise the audit record and
// the on-disk copy describe a body that never actually went anywhere.
func TestServeDeclaredService_HookNilsBody_LogsZeroAndStoresNothing(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	tmpDir := t.TempDir()
	storage, err := NewStorage(tmpDir, "test-session", true)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	defer storage.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "allow-upload", Methods: []string{"POST"}, Paths: []string{"/upload"}, Decision: "allow"},
	})
	p.SetStorageForTest(storage)

	p.HookRegistry().Register("github", &serviceRecorderHook{
		name: "body-drop",
		preFn: func(r *http.Request, _ *RequestContext) error {
			r.Body = nil
			r.ContentLength = 0
			return nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/svc/github/upload", strings.NewReader("PAYLOAD"))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}

	entries := readAllRequestLogEntries(t, tmpDir, "test-session")
	if len(entries) != 1 {
		t.Fatalf("got %d request log entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Request.BodySize != 0 {
		t.Errorf("BodySize = %d, want 0 (hook dropped body)", e.Request.BodySize)
	}
	if e.Request.BodyHash != "" {
		t.Errorf("BodyHash = %q, want empty (hook dropped body)", e.Request.BodyHash)
	}

	// No file should exist in llm-bodies for this request ID — the hook
	// dropped the body, so there is nothing to persist.
	bodyPath := filepath.Join(tmpDir, "test-session", "llm-bodies", e.ID+".json")
	if _, statErr := os.Stat(bodyPath); !os.IsNotExist(statErr) {
		t.Errorf("expected no stored body file at %q, got err=%v", bodyPath, statErr)
	}
}

// TestServeDeclaredService_HookNilsBodyLeavesStaleContentLength_Normalized
// pins down that the proxy normalizes empty-body hooks so that a hook
// which sets r.Body = nil but forgets to zero r.ContentLength does NOT
// leak a stale positive Content-Length upstream. Relying on hook authors
// to zero ContentLength themselves is brittle; the proxy must normalize.
func TestServeDeclaredService_HookNilsBodyLeavesStaleContentLength_Normalized(t *testing.T) {
	var upstreamGotLen int64
	var upstreamGotBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamGotLen = r.ContentLength
		b, _ := io.ReadAll(r.Body)
		upstreamGotBody = b
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	tmpDir := t.TempDir()
	storage, err := NewStorage(tmpDir, "test-session", true)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	defer storage.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "allow-upload", Methods: []string{"POST"}, Paths: []string{"/upload"}, Decision: "allow"},
	})
	p.SetStorageForTest(storage)

	// Hook nils the body but deliberately leaves ContentLength stale.
	// The proxy must still normalize so Content-Length doesn't leak
	// upstream.
	p.HookRegistry().Register("github", &serviceRecorderHook{
		name: "body-nil-stale-clen",
		preFn: func(r *http.Request, _ *RequestContext) error {
			r.Body = nil
			// intentionally do NOT touch r.ContentLength
			return nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/svc/github/upload", strings.NewReader("PAYLOAD_WITH_LENGTH"))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}

	if upstreamGotLen != 0 {
		t.Errorf("upstream ContentLength = %d, want 0 (hook dropped body)", upstreamGotLen)
	}
	if len(upstreamGotBody) != 0 {
		t.Errorf("upstream received body %q, want empty (hook dropped body)", upstreamGotBody)
	}

	entries := readAllRequestLogEntries(t, tmpDir, "test-session")
	if len(entries) != 1 {
		t.Fatalf("got %d request log entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Request.BodySize != 0 {
		t.Errorf("BodySize = %d, want 0 (hook dropped body)", e.Request.BodySize)
	}
	if e.Request.BodyHash != "" {
		t.Errorf("BodyHash = %q, want empty (hook dropped body)", e.Request.BodyHash)
	}

	bodyPath := filepath.Join(tmpDir, "test-session", "llm-bodies", e.ID+".json")
	if _, statErr := os.Stat(bodyPath); !os.IsNotExist(statErr) {
		t.Errorf("expected no stored body file at %q, got err=%v", bodyPath, statErr)
	}
}

// TestServeDeclaredService_HookSetsHttpNoBody_Normalized pins down that a
// hook which uses the idiomatic http.NoBody sentinel is treated the same
// as r.Body = nil: nothing is forwarded upstream, nothing lands on disk,
// and the audit record shows BodySize=0/BodyHash="". The current code
// reads empty bytes into forwardedBody but does NOT zero storedBody, so
// the agent's pre-hook input still lands on disk even though nothing was
// actually forwarded.
func TestServeDeclaredService_HookSetsHttpNoBody_Normalized(t *testing.T) {
	var upstreamGotLen int64
	var upstreamGotBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamGotLen = r.ContentLength
		b, _ := io.ReadAll(r.Body)
		upstreamGotBody = b
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	tmpDir := t.TempDir()
	storage, err := NewStorage(tmpDir, "test-session", true)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	defer storage.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "allow-upload", Methods: []string{"POST"}, Paths: []string{"/upload"}, Decision: "allow"},
	})
	p.SetStorageForTest(storage)

	p.HookRegistry().Register("github", &serviceRecorderHook{
		name: "body-no-body",
		preFn: func(r *http.Request, _ *RequestContext) error {
			r.Body = http.NoBody
			r.ContentLength = 0
			return nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/svc/github/upload", strings.NewReader("PAYLOAD_WITH_LENGTH"))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}

	if upstreamGotLen != 0 {
		t.Errorf("upstream ContentLength = %d, want 0 (hook used http.NoBody)", upstreamGotLen)
	}
	if len(upstreamGotBody) != 0 {
		t.Errorf("upstream received body %q, want empty (hook used http.NoBody)", upstreamGotBody)
	}

	entries := readAllRequestLogEntries(t, tmpDir, "test-session")
	if len(entries) != 1 {
		t.Fatalf("got %d request log entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Request.BodySize != 0 {
		t.Errorf("BodySize = %d, want 0 (hook used http.NoBody)", e.Request.BodySize)
	}
	if e.Request.BodyHash != "" {
		t.Errorf("BodyHash = %q, want empty (hook used http.NoBody)", e.Request.BodyHash)
	}

	bodyPath := filepath.Join(tmpDir, "test-session", "llm-bodies", e.ID+".json")
	if _, statErr := os.Stat(bodyPath); !os.IsNotExist(statErr) {
		t.Errorf("expected no stored body file at %q, got err=%v", bodyPath, statErr)
	}
}

// TestServeDeclaredService_CredentialSubstitution_EndToEnd is a full e2e
// test: client sends fake in body -> upstream receives real (in body +
// injected header) -> response with real is scrubbed to fake.
func TestServeDeclaredService_CredentialSubstitution_EndToEnd(t *testing.T) {
	var upstreamAuthHeader string
	var upstreamBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuthHeader = r.Header.Get("Authorization")
		upstreamBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"echoed":"ghp_REAL1234567890abcdef"}`)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{{
		Name: "allow-repos", Methods: []string{"POST"}, Paths: []string{"/repos/**"}, Decision: "allow",
	}})

	tbl := credsub.New()
	if err := tbl.Add("github",
		[]byte("ghp_FAKE1234567890abcdef"),
		[]byte("ghp_REAL1234567890abcdef"),
	); err != nil {
		t.Fatal(err)
	}
	scrubServices := map[string]bool{"github": true}
	p.HookRegistry().Register("", NewLeakGuardHook(tbl, slog.Default()))
	p.HookRegistry().Register("", NewCredsSubHook(tbl, scrubServices))
	p.HookRegistry().Register("github", NewHeaderInjectionHook(
		"github", "Authorization", "Bearer {{secret}}", tbl))

	body := []byte(`{"token":"ghp_FAKE1234567890abcdef"}`)
	req := httptest.NewRequest(http.MethodPost,
		"http://127.0.0.1/svc/github/repos/owner/repo/issues", bytes.NewReader(body))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if upstreamAuthHeader != "Bearer ghp_REAL1234567890abcdef" {
		t.Errorf("upstream Auth = %q, want real credential injected", upstreamAuthHeader)
	}
	if !bytes.Contains(upstreamBody, []byte("ghp_REAL1234567890abcdef")) {
		t.Errorf("upstream body = %q, want real credential in body", upstreamBody)
	}
	respBody := w.Body.String()
	if strings.Contains(respBody, "ghp_REAL1234567890abcdef") {
		t.Error("response body contains real credential — scrubbing failed")
	}
	if !strings.Contains(respBody, "ghp_FAKE1234567890abcdef") {
		t.Error("response body should contain fake credential (scrubbed)")
	}
}

// TestServeDeclaredService_CredentialsDeny_UpstreamNotContacted pins down
// that when rules deny a request, the upstream is NOT contacted even though
// credentials are configured.
func TestServeDeclaredService_CredentialsDeny_UpstreamNotContacted(t *testing.T) {
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "read", Methods: []string{"GET"}, Paths: []string{"/repos/**"}, Decision: "allow"},
	})
	tbl := credsub.New()
	if err := tbl.Add("github",
		[]byte("ghp_FAKE1234567890abcdef"),
		[]byte("ghp_REAL1234567890abcdef"),
	); err != nil {
		t.Fatal(err)
	}
	p.HookRegistry().Register("", NewLeakGuardHook(tbl, slog.Default()))
	p.HookRegistry().Register("", NewCredsSubHook(tbl, nil))
	p.HookRegistry().Register("github", NewHeaderInjectionHook(
		"github", "Authorization", "Bearer {{secret}}", tbl))

	req := httptest.NewRequest(http.MethodDelete,
		"http://127.0.0.1/svc/github/repos/a/b", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if upstreamCalled {
		t.Error("upstream should NOT have been contacted for denied request")
	}
}

// TestServeDeclaredService_CredentialsOnly_AllRequestsAllowed pins down
// that a credentials-only service (no rules, has Secret) allows all
// methods/paths.
func TestServeDeclaredService_CredentialsOnly_AllRequestsAllowed(t *testing.T) {
	var upstreamApiKey string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamApiKey = r.Header.Get("X-Api-Key")
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	cfg := Config{SessionID: "test-session"}
	p, err := New(cfg, "", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	svcs := []policy.HTTPService{{
		Name: "anthropic", Upstream: upstream.URL,
		Secret: &policy.HTTPServiceSecret{Ref: "keyring://test#k", Format: "sk-ant_{rand:22}"},
		// No Default, no Rules -> credentials-only, defaults to allow.
	}}
	if err := policy.ValidateHTTPServices(svcs); err != nil {
		t.Fatalf("validate: %v", err)
	}
	pol := &policy.Policy{HTTPServices: svcs}
	eng, err := policy.NewEngine(pol, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	p.SetPolicyEngine(eng)
	p.SetHTTPServices(svcs)

	tbl := credsub.New()
	if err := tbl.Add("anthropic",
		[]byte("sk-ant-FAKE567890abcdef12"),
		[]byte("sk-ant-REAL567890abcdef12"),
	); err != nil {
		t.Fatal(err)
	}
	p.HookRegistry().Register("", NewCredsSubHook(tbl, nil))
	p.HookRegistry().Register("anthropic", NewHeaderInjectionHook(
		"anthropic", "X-Api-Key", "{{secret}}", tbl))

	req := httptest.NewRequest(http.MethodPost,
		"http://127.0.0.1/svc/anthropic/v1/messages", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (credentials-only allows all)", w.Code)
	}
	if upstreamApiKey != "sk-ant-REAL567890abcdef12" {
		t.Errorf("upstream X-Api-Key = %q, want real credential", upstreamApiKey)
	}
}

// TestServeDeclaredService_ScrubResponseFalse_RealsNotScrubbed pins down
// that when scrub_response is false, reals pass through in responses.
func TestServeDeclaredService_ScrubResponseFalse_RealsNotScrubbed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"key":"ghp_REAL1234567890abcdef"}`)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "allow-all", Paths: []string{"/**"}, Decision: "allow"},
	})

	tbl := credsub.New()
	if err := tbl.Add("github",
		[]byte("ghp_FAKE1234567890abcdef"),
		[]byte("ghp_REAL1234567890abcdef"),
	); err != nil {
		t.Fatal(err)
	}
	scrubServices := map[string]bool{} // empty = no services scrubbed
	p.HookRegistry().Register("", NewCredsSubHook(tbl, scrubServices))

	req := httptest.NewRequest(http.MethodGet,
		"http://127.0.0.1/svc/github/repos/owner/repo", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	respBody := w.Body.String()
	if !strings.Contains(respBody, "ghp_REAL1234567890abcdef") {
		t.Error("response should contain real credential (scrub disabled)")
	}
}

// TestServeDeclaredService_CredentialsOnly_ExplicitDeny_BlocksAll pins
// down emergency lockdown: credentials-only with explicit deny blocks
// everything.
func TestServeDeclaredService_CredentialsOnly_ExplicitDeny_BlocksAll(t *testing.T) {
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	cfg := Config{SessionID: "test-session"}
	p, err := New(cfg, "", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	svcs := []policy.HTTPService{{
		Name: "locked", Upstream: upstream.URL, Default: "deny",
	}}
	if err := policy.ValidateHTTPServices(svcs); err != nil {
		t.Fatalf("validate: %v", err)
	}
	pol := &policy.Policy{HTTPServices: svcs}
	eng, err := policy.NewEngine(pol, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	p.SetPolicyEngine(eng)
	p.SetHTTPServices(svcs)

	req := httptest.NewRequest(http.MethodGet,
		"http://127.0.0.1/svc/locked/anything", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (emergency lockdown)", w.Code)
	}
	if upstreamCalled {
		t.Error("upstream should NOT have been contacted during lockdown")
	}
}

// TestServeDeclaredService_CrossServiceLeak_BlockedWith403 pins down that
// cross-service leak is blocked: github's fake sent to stripe's service
// endpoint returns 403.
func TestServeDeclaredService_CrossServiceLeak_BlockedWith403(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not have been contacted")
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	cfg := Config{SessionID: "test-session"}
	p, err := New(cfg, "", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	svcs := []policy.HTTPService{
		{Name: "github", Upstream: upstream.URL, Default: "allow"},
		{Name: "stripe", Upstream: "https://api.stripe.com", Default: "allow"},
	}
	if err := policy.ValidateHTTPServices(svcs); err != nil {
		t.Fatalf("validate: %v", err)
	}
	pol := &policy.Policy{HTTPServices: svcs}
	eng, err := policy.NewEngine(pol, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	p.SetPolicyEngine(eng)
	p.SetHTTPServices(svcs)

	tbl := credsub.New()
	if err := tbl.Add("github",
		[]byte("ghp_FAKE1234567890abcdef"),
		[]byte("ghp_REAL1234567890abcdef"),
	); err != nil {
		t.Fatal(err)
	}
	if err := tbl.Add("stripe",
		[]byte("sk_live_FAKE567890abcdef12"),
		[]byte("sk_live_REAL567890abcdef12"),
	); err != nil {
		t.Fatal(err)
	}
	p.HookRegistry().Register("", NewLeakGuardHook(tbl, slog.Default()))
	p.HookRegistry().Register("", NewCredsSubHook(tbl, nil))

	body := []byte(`{"token":"ghp_FAKE1234567890abcdef"}`)
	req := httptest.NewRequest(http.MethodPost,
		"http://127.0.0.1/svc/stripe/v1/charges", bytes.NewReader(body))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (cross-service leak)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "credential leak blocked") {
		t.Errorf("body = %q, want 'credential leak blocked'", w.Body.String())
	}
}

// TestServeDeclaredService_FilteringOnly_NoCredentialHooks pins down that
// filtering-only (no credential hooks) passes the user-provided
// Authorization header through to the upstream.
func TestServeDeclaredService_FilteringOnly_NoCredentialHooks(t *testing.T) {
	var upstreamAuthHeader string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuthHeader = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "allow-read", Methods: []string{"GET"}, Paths: []string{"/**"}, Decision: "allow"},
	})

	req := httptest.NewRequest(http.MethodGet,
		"http://127.0.0.1/svc/github/repos/owner/repo", nil)
	req.Header.Set("Authorization", "Bearer user-provided-token")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if upstreamAuthHeader != "Bearer user-provided-token" {
		t.Errorf("upstream Auth = %q, want original token (no hook)", upstreamAuthHeader)
	}
}

// TestServeHTTP_HostHeaderOnly_DoesNotRouteToDeclaredService is a
// regression test: after matcher removal, Host header alone does NOT
// route to declared service.
func TestServeHTTP_HostHeaderOnly_DoesNotRouteToDeclaredService(t *testing.T) {
	p := newTestProxyWithHTTPService(t, "https://api.github.com", []policy.HTTPServiceRule{
		{Name: "allow-all", Paths: []string{"/**"}, Decision: "allow"},
	})

	req := httptest.NewRequest(http.MethodGet, "http://api.github.com/repos/owner/repo", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Error("Host-only request should NOT route to declared service (matcher removed)")
	}
}

// readAllRequestLogEntries reads the request JSONL file for a session and
// returns every RequestLogEntry. Lives next to the test so it can inspect
// unexported storage internals if needed.
//
// Note: Storage writes requests AND responses to the same file
// (llm-requests.jsonl — see internal/proxy/storage.go). We discriminate by
// looking at which JSON fields are populated: RequestLogEntry has the
// "request" object, ResponseLogEntry has the "response" object and a
// "request_id" field.
func readAllRequestLogEntries(t *testing.T, basePath, sessionID string) []RequestLogEntry {
	t.Helper()
	lines := readLogLines(t, basePath, sessionID)
	var out []RequestLogEntry
	for _, line := range lines {
		// Skip response entries by peeking at field names.
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(line, &probe); err != nil {
			t.Fatalf("unmarshal probe: %v", err)
		}
		if _, isResponse := probe["request_id"]; isResponse {
			continue
		}
		var e RequestLogEntry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("decode request log: %v", err)
		}
		out = append(out, e)
	}
	return out
}

func readAllResponseLogEntries(t *testing.T, basePath, sessionID string) []ResponseLogEntry {
	t.Helper()
	lines := readLogLines(t, basePath, sessionID)
	var out []ResponseLogEntry
	for _, line := range lines {
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(line, &probe); err != nil {
			t.Fatalf("unmarshal probe: %v", err)
		}
		if _, isResponse := probe["request_id"]; !isResponse {
			continue
		}
		var e ResponseLogEntry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("decode response log: %v", err)
		}
		out = append(out, e)
	}
	return out
}

// readLogLines reads the shared JSONL log file line-by-line.
func readLogLines(t *testing.T, basePath, sessionID string) [][]byte {
	t.Helper()
	path := filepath.Join(basePath, sessionID, "llm-requests.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	var lines [][]byte
	for _, l := range bytes.Split(data, []byte("\n")) {
		if len(l) == 0 {
			continue
		}
		lines = append(lines, l)
	}
	return lines
}
