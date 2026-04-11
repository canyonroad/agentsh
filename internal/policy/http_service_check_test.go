package policy

import (
	"net"
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

func TestDeclaredHTTPServiceHost(t *testing.T) {
	svcs := []HTTPService{{
		Name:     "github",
		Upstream: "https://api.github.com",
		ExposeAs: "GITHUB_API_URL",
		Aliases:  []string{"api.github.example"},
		Rules: []HTTPServiceRule{{
			Name: "any", Paths: []string{"/**"}, Decision: "allow",
		}},
	}}
	e := newTestEngineForHTTP(t, svcs)

	tests := []struct {
		host    string
		wantOK  bool
		wantSvc string
		wantEnv string
	}{
		{"api.github.com", true, "github", "GITHUB_API_URL"},
		{"API.GITHUB.COM", true, "github", "GITHUB_API_URL"},
		{"api.github.com:443", true, "github", "GITHUB_API_URL"},
		{"api.github.com.", true, "github", "GITHUB_API_URL"},
		{"api.github.example", true, "github", "GITHUB_API_URL"},
		{"example.com", false, "", ""},
		{"", false, "", ""},
		{"::1", false, "", ""}, // bare IPv6 never resolves
	}
	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			svc, env, ok := e.DeclaredHTTPServiceHost(tc.host)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if svc != tc.wantSvc || env != tc.wantEnv {
				t.Errorf("got (%q, %q), want (%q, %q)", svc, env, tc.wantSvc, tc.wantEnv)
			}
		})
	}
}

func TestDeclaredHTTPServiceHost_BracketedIPv6(t *testing.T) {
	svcs := []HTTPService{{
		Name:     "local",
		Upstream: "https://[::1]",
		Rules: []HTTPServiceRule{{
			Name: "any", Paths: []string{"/**"}, Decision: "allow",
		}},
	}}
	e := newTestEngineForHTTP(t, svcs)

	// All of these should resolve to "local" because canonicalizeHost
	// strips brackets/ports and the compiler stored the canonical form.
	for _, h := range []string{"[::1]", "[::1]:443", "[::1]:9999"} {
		t.Run(h, func(t *testing.T) {
			svc, _, ok := e.DeclaredHTTPServiceHost(h)
			if !ok || svc != "local" {
				t.Errorf("%q → (%q, ok=%v), want (local, ok=true)", h, svc, ok)
			}
		})
	}
}

func TestDeclaredHTTPServiceHost_BareIPv6FromSplitHostPort(t *testing.T) {
	svcs := []HTTPService{{
		Name:     "local",
		Upstream: "https://[::1]",
		Rules: []HTTPServiceRule{{
			Name: "any", Paths: []string{"/**"}, Decision: "allow",
		}},
	}}
	e := newTestEngineForHTTP(t, svcs)

	// Simulate net.SplitHostPort("[::1]:443") → host="::1", port="443".
	host, port, err := net.SplitHostPort("[::1]:443")
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	if port != "443" || host != "::1" {
		t.Fatalf("unexpected SplitHostPort result: host=%q port=%q", host, port)
	}
	svc, _, ok := e.DeclaredHTTPServiceHost(host)
	if !ok || svc != "local" {
		t.Errorf("DeclaredHTTPServiceHost(%q) = (%q, ok=%v), want (local, ok=true)", host, svc, ok)
	}

	// Bare IPv6 with different spelling must also resolve.
	for _, h := range []string{"::1", "fe80::x"} {
		svc, _, ok := e.DeclaredHTTPServiceHost(h)
		if h == "::1" {
			if !ok || svc != "local" {
				t.Errorf("%q → (%q, ok=%v), want (local, ok=true)", h, svc, ok)
			}
		} else {
			// Invalid IPv6 — must not resolve, must not panic.
			if ok {
				t.Errorf("%q unexpectedly resolved to %q", h, svc)
			}
		}
	}
}

func TestHTTPServicesEnumeration(t *testing.T) {
	svcs := []HTTPService{
		{
			Name: "a", Upstream: "https://a.example.com",
			Aliases: []string{"a-alt.example.com"},
			Rules: []HTTPServiceRule{{
				Name:     "r",
				Methods:  []string{"GET", "POST"},
				Paths:    []string{"/**", "/v1/**"},
				Decision: "allow",
			}},
		},
		{
			Name: "b", Upstream: "https://b.example.com",
			Rules: []HTTPServiceRule{{Name: "r", Paths: []string{"/**"}, Decision: "allow"}},
		},
	}
	e := newTestEngineForHTTP(t, svcs)
	got := e.HTTPServices()
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
	if got[0].Name != "a" || got[1].Name != "b" {
		t.Errorf("ordering not preserved: %+v", got)
	}

	// Top-level mutation must not leak.
	got[0].Name = "MUTATED"
	if again := e.HTTPServices(); again[0].Name == "MUTATED" {
		t.Error("HTTPServices(): top-level mutation leaked through")
	}

	// Nested slice mutations must not leak either.
	got[0].Aliases[0] = "mutated-alias.example.com"
	got[0].Rules[0].Name = "MUTATED_RULE"
	got[0].Rules[0].Methods[0] = "DELETE"
	got[0].Rules[0].Paths[0] = "/mutated/**"

	again := e.HTTPServices()
	if again[0].Aliases[0] != "a-alt.example.com" {
		t.Errorf("Aliases nested mutation leaked: got %q", again[0].Aliases[0])
	}
	if again[0].Rules[0].Name != "r" {
		t.Errorf("Rules nested mutation leaked: got Name=%q", again[0].Rules[0].Name)
	}
	if again[0].Rules[0].Methods[0] != "GET" {
		t.Errorf("Rules[0].Methods nested mutation leaked: got %v", again[0].Rules[0].Methods)
	}
	if again[0].Rules[0].Paths[0] != "/**" {
		t.Errorf("Rules[0].Paths nested mutation leaked: got %v", again[0].Rules[0].Paths)
	}
}
