package policy

import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

func newTestEngineForHTTP(t *testing.T, svcs []HTTPService) *Engine {
	t.Helper()
	p := &Policy{HTTPServices: svcs}
	if err := ValidateHTTPServices(p.HTTPServices); err != nil {
		t.Fatalf("validate: %v", err)
	}
	byName, byHost, err := compileHTTPServices(p.HTTPServices)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return &Engine{
		policy:           p,
		httpServices:     byName,
		httpServiceHosts: byHost,
		enforceApprovals: true,
	}
}

func TestCheckHTTPService(t *testing.T) {
	svcs := []HTTPService{{
		Name: "github", Upstream: "https://api.github.com",
		Default: "deny",
		Rules: []HTTPServiceRule{
			{Name: "read-issues", Methods: []string{"GET"}, Paths: []string{"/repos/*/*/issues", "/repos/*/*/issues/*"}, Decision: "allow"},
			{Name: "wildcard-subtree", Methods: []string{"GET"}, Paths: []string{"/orgs/**"}, Decision: "allow"},
			{Name: "any-method", Methods: []string{"*"}, Paths: []string{"/public/*"}, Decision: "allow"},
			{Name: "multi-method", Methods: []string{"PUT", "PATCH"}, Paths: []string{"/repos/*/*"}, Decision: "allow"},
			{Name: "block-delete", Methods: []string{"DELETE"}, Paths: []string{"/repos/**"}, Decision: "deny", Message: "no deletes"},
		},
	}, {
		Name: "open", Upstream: "https://open.example.com",
		Default: "allow",
	}}

	e := newTestEngineForHTTP(t, svcs)

	tests := []struct {
		name         string
		service      string
		method       string
		path         string
		wantDecision types.Decision
		wantRule     string
	}{
		{"simple allow", "github", "GET", "/repos/a/b/issues", types.DecisionAllow, "read-issues"},
		{"sub path allow", "github", "GET", "/repos/a/b/issues/42", types.DecisionAllow, "read-issues"},
		{"wildcard subtree", "github", "GET", "/orgs/acme/members/list", types.DecisionAllow, "wildcard-subtree"},
		{"method wildcard", "github", "POST", "/public/thing", types.DecisionAllow, "any-method"},
		{"multi method PUT", "github", "PUT", "/repos/a/b", types.DecisionAllow, "multi-method"},
		{"multi method PATCH", "github", "PATCH", "/repos/a/b", types.DecisionAllow, "multi-method"},
		{"delete denied by rule", "github", "DELETE", "/repos/a/b", types.DecisionDeny, "block-delete"},
		{"wrong method falls through", "github", "POST", "/repos/a/b/issues", types.DecisionDeny, "default"},
		{"default deny", "github", "GET", "/unmatched", types.DecisionDeny, "default"},
		{"lowercase method canonicalized", "github", "get", "/repos/a/b/issues", types.DecisionAllow, "read-issues"},
		{"unknown service deny", "nosuch", "GET", "/anything", types.DecisionDeny, ""},
		{"empty path coerced", "open", "GET", "", types.DecisionAllow, "default"},
		{"traversal rejected", "github", "GET", "/repos/../etc/passwd", types.DecisionDeny, ""},
		{"double slash rejected", "github", "GET", "/repos//a/b/issues", types.DecisionDeny, ""},
		{"dot segment rejected", "github", "GET", "/repos/./a/b/issues", types.DecisionDeny, ""},
		{"case sensitive path no match", "github", "GET", "/REPOS/a/b/issues", types.DecisionDeny, "default"},
		{"query string ignored", "github", "GET", "/repos/a/b/issues?state=open", types.DecisionAllow, "read-issues"},
		{"trailing slash allowed", "github", "GET", "/repos/a/b/issues/", types.DecisionAllow, "read-issues"},
		{"trailing slash any-method", "github", "POST", "/public/thing/", types.DecisionAllow, "any-method"},
		{"trailing slash wildcard-subtree", "github", "GET", "/orgs/acme/members/", types.DecisionAllow, "wildcard-subtree"},
		{"root slash open service", "open", "GET", "/", types.DecisionAllow, "default"},
		{"double slash at root", "github", "GET", "//", types.DecisionDeny, ""},
		{"trailing double slash", "github", "GET", "/repos/a/b/issues//", types.DecisionDeny, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Strip query string before calling — that's the gateway's job.
			reqPath := tc.path
			if idx := strings.Index(reqPath, "?"); idx != -1 {
				reqPath = reqPath[:idx]
			}
			dec := e.CheckHTTPService(tc.service, tc.method, reqPath)
			if dec.EffectiveDecision != tc.wantDecision {
				t.Errorf("decision = %q, want %q (rule=%q msg=%q)",
					dec.EffectiveDecision, tc.wantDecision, dec.Rule, dec.Message)
			}
			if tc.wantRule != "" && dec.Rule != tc.wantRule {
				t.Errorf("rule = %q, want %q", dec.Rule, tc.wantRule)
			}
		})
	}
}
