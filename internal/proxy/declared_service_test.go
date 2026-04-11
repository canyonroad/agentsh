package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
)

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
// for `approve` rules. Task 10 will replace this stub with the real approval
// flow; until then, an approve match must return 501 (not 500) so callers
// can distinguish "not yet implemented" from an internal error.
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
