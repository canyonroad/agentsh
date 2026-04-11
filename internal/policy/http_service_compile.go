package policy

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/gobwas/glob"
)

// compiledHTTPServiceRule is an HTTPServiceRule with pre-compiled path
// globs and a method set for O(1) matching.
type compiledHTTPServiceRule struct {
	rule    HTTPServiceRule
	methods map[string]struct{} // uppercase; empty or containing "*" means any
	paths   []glob.Glob
}

// compiledHTTPService holds the compiled form of an HTTPService entry.
type compiledHTTPService struct {
	cfg             HTTPService
	rules           []compiledHTTPServiceRule
	upstream        *url.URL
	envVar          string // resolved ExposeAs or derived
	defaultDecision string // "allow" or "deny" (empty treated as "deny")
	upstreamHost    string // canonicalizeHost output for upstream (used for host-based lookup)
}

// compileHTTPServices transforms validated HTTPService entries into the
// compiled form used by CheckHTTPService and the netmonitor host check.
// Callers MUST call ValidateHTTPServices first; this function assumes
// invariants established there (valid URL, non-empty name, canonicalizable
// aliases, compilable globs).
func compileHTTPServices(svcs []HTTPService) (byName, byHost map[string]*compiledHTTPService, err error) {
	byName = make(map[string]*compiledHTTPService, len(svcs))
	byHost = make(map[string]*compiledHTTPService, len(svcs))
	for i := range svcs {
		s := svcs[i]
		u, parseErr := url.Parse(s.Upstream)
		if parseErr != nil {
			return nil, nil, fmt.Errorf("http_services[%q]: parse upstream: %w", s.Name, parseErr)
		}

		envVar := s.ExposeAs
		if envVar == "" {
			envVar = strings.ToUpper(s.Name) + "_API_URL"
		}
		defDec := s.Default
		if defDec == "" {
			defDec = "deny"
		}

		// Canonicalize the upstream host the SAME WAY ValidateHTTPServices
		// did (via canonicalizeHost), so runtime lookups by canonicalized
		// host string will hit the right service. This uses u.Host (not
		// u.Hostname()) so the canonicalizer sees IPv6 brackets.
		host, ok := canonicalizeHost(u.Host)
		if !ok {
			return nil, nil, fmt.Errorf("http_services[%q]: canonicalize upstream host %q", s.Name, u.Host)
		}

		cs := &compiledHTTPService{
			cfg:             s,
			upstream:        u,
			envVar:          envVar,
			defaultDecision: defDec,
			upstreamHost:    host,
		}
		for _, r := range s.Rules {
			cr := compiledHTTPServiceRule{rule: r}
			if len(r.Methods) > 0 {
				cr.methods = make(map[string]struct{}, len(r.Methods))
				for _, m := range r.Methods {
					cr.methods[strings.ToUpper(strings.TrimSpace(m))] = struct{}{}
				}
			}
			for _, pat := range r.Paths {
				g, gerr := glob.Compile(pat, '/')
				if gerr != nil {
					return nil, nil, fmt.Errorf("http_services[%q] rule %q: compile path %q: %w", s.Name, r.Name, pat, gerr)
				}
				cr.paths = append(cr.paths, g)
			}
			cs.rules = append(cs.rules, cr)
		}

		byName[strings.ToLower(s.Name)] = cs
		byHost[host] = cs
		for _, alias := range s.Aliases {
			a, ok := canonicalizeHost(alias)
			if !ok {
				// Validation should have rejected this. Treat as invariant break.
				return nil, nil, fmt.Errorf("http_services[%q]: canonicalize alias %q", s.Name, alias)
			}
			byHost[a] = cs
		}
	}
	return byName, byHost, nil
}
