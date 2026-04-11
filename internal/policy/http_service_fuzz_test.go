package policy

import (
	"path"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

// FuzzCheckHTTPServicePath feeds random method/path combinations into the
// evaluator and asserts three invariants:
//
//  1. It never panics.
//  2. An allow decision implies the path survived path.Clean unchanged
//     after the evaluator's own trailing-slash normalization (traversal
//     attempts cannot reach upstream).
//  3. Method matching is stable under arbitrary casing.
func FuzzCheckHTTPServicePath(f *testing.F) {
	svcs := []HTTPService{{
		Name: "github", Upstream: "https://api.github.com",
		Default: "deny",
		Rules: []HTTPServiceRule{
			{Name: "read", Methods: []string{"GET"}, Paths: []string{"/repos/*/*"}, Decision: "allow"},
			{Name: "open", Methods: []string{"*"}, Paths: []string{"/public/**"}, Decision: "allow"},
		},
	}}
	if err := ValidateHTTPServices(svcs); err != nil {
		f.Fatal(err)
	}
	byName, byHost, err := compileHTTPServices(svcs)
	if err != nil {
		f.Fatal(err)
	}
	e := &Engine{
		policy:           &Policy{HTTPServices: svcs},
		httpServices:     byName,
		httpServiceHosts: byHost,
		enforceApprovals: true,
	}

	f.Add("GET", "/repos/a/b")
	f.Add("get", "/REPOS/a/b")
	f.Add("GET", "/repos/../etc/passwd")
	f.Add("GET", "/repos//a/b")
	f.Add("POST", "/public/\x00bar")
	f.Add("PUT", "/repos/a/b?%2e%2e")

	f.Fuzz(func(t *testing.T, method, reqPath string) {
		// Skip inputs with null bytes in the method — invalid HTTP.
		if strings.ContainsRune(method, 0) {
			return
		}
		dec := e.CheckHTTPService("github", method, reqPath)
		if dec.EffectiveDecision == types.DecisionAllow {
			// Invariant 2: allow implies the path was canonical AFTER
			// applying the same trailing-slash normalization the evaluator
			// itself performs. Without this mirror, a legitimately-allowed
			// path like "/repos/a/b/" would be reported as non-canonical.
			normalized := reqPath
			if normalized == "" {
				normalized = "/"
			}
			if len(normalized) > 1 && strings.HasSuffix(normalized, "/") {
				normalized = strings.TrimSuffix(normalized, "/")
			}
			if got := path.Clean(normalized); got != normalized {
				t.Errorf("allow decision with non-canonical path: reqPath=%q normalized=%q clean=%q", reqPath, normalized, got)
			}
		}
		// Invariant 3: casing-insensitive method.
		lower := strings.ToLower(method)
		upper := strings.ToUpper(method)
		decL := e.CheckHTTPService("github", lower, reqPath)
		decU := e.CheckHTTPService("github", upper, reqPath)
		if decL.EffectiveDecision != decU.EffectiveDecision {
			t.Errorf("case mismatch: lower=%q upper=%q dec differs", lower, upper)
		}
	})
}
