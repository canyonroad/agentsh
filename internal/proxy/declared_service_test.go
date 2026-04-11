package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
