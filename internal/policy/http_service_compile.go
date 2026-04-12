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
// In the normal policy-load path, ValidateHTTPServices runs first and
// errors are caught there; this compiler is also hardened against
// duplicate names/hosts and bad aliases so it remains safe if a caller
// bypasses validation (e.g. constructing a Policy in-memory for tests).
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
			if len(s.Rules) == 0 {
				defDec = "allow" // credentials-only service: no path filtering needed
			} else {
				defDec = "deny" // has rules: fail-closed
			}
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

		nameKey := strings.ToLower(s.Name)
		if _, exists := byName[nameKey]; exists {
			return nil, nil, fmt.Errorf("http_services: duplicate service name %q", s.Name)
		}
		byName[nameKey] = cs
		if other, exists := byHost[host]; exists {
			return nil, nil, fmt.Errorf("http_services[%q]: duplicate upstream host %q (also claimed by %q)", s.Name, host, other.cfg.Name)
		}
		byHost[host] = cs
		for _, alias := range s.Aliases {
			a, ok := canonicalizeHost(alias)
			if !ok {
				// Validation should have rejected this. Treat as invariant break.
				return nil, nil, fmt.Errorf("http_services[%q]: canonicalize alias %q", s.Name, alias)
			}
			if other, exists := byHost[a]; exists {
				return nil, nil, fmt.Errorf("http_services[%q]: duplicate upstream host %q via alias %q (also claimed by %q)", s.Name, a, alias, other.cfg.Name)
			}
			byHost[a] = cs
		}
	}
	return byName, byHost, nil
}
