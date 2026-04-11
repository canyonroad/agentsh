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
	cfg := Config{SessionID: "test-session"}
	p, err := New(cfg, "", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	svcs := []policy.HTTPService{{
		Name: "github", Upstream: upstream, Default: "deny", Rules: rules,
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
