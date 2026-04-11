package policy

import (
	"strings"
)

// CheckHTTPService evaluates method+reqPath against the rules for service.
// reqPath is the path portion AFTER the /svc/<name> prefix has been stripped
// and the query string removed. The gateway is responsible for stripping
// both before calling this method.
//
// A single trailing slash is permitted on reqPath for usability — the
// upstream API often accepts both forms — and is stripped before the rule
// matcher runs so policy authors only have to write the non-slashed form.
//
// Returns a wrapped Decision in the same shape as CheckNetworkCtx. First-
// match-wins on rules. If no rule matches, the service's Default applies
// (the compiler defaults empty to "deny"). Unknown services always deny.
func (e *Engine) CheckHTTPService(service, method, reqPath string) Decision {
	cs, ok := e.httpServices[strings.ToLower(service)]
	if !ok {
		return e.wrapDecision("deny", "", "unknown http_service", nil)
	}

	if reqPath == "" {
		reqPath = "/"
	}

	// Traversal/canonicalization guard. We reject:
	//   - any duplicate interior separator ("//")
	//   - any "." or ".." segment
	// We permit a single trailing slash for usability (the upstream API
	// often accepts both forms); it is stripped before rule matching so
	// policy authors only have to write the non-slashed form.
	if strings.Contains(reqPath, "//") {
		return e.wrapDecision("deny", "", "path traversal rejected", nil)
	}
	for _, seg := range strings.Split(strings.TrimPrefix(reqPath, "/"), "/") {
		if seg == "." || seg == ".." {
			return e.wrapDecision("deny", "", "path traversal rejected", nil)
		}
	}
	matchPath := reqPath
	if len(matchPath) > 1 && strings.HasSuffix(matchPath, "/") {
		matchPath = strings.TrimSuffix(matchPath, "/")
	}

	m := strings.ToUpper(method)

	for _, r := range cs.rules {
		if !methodMatchesHTTPRule(r, m) {
			continue
		}
		if !pathMatchesHTTPRule(r, matchPath) {
			continue
		}
		return e.wrapDecision(r.rule.Decision, r.rule.Name, r.rule.Message, nil)
	}

	if cs.defaultDecision == "allow" {
		return e.wrapDecision("allow", "default", "", nil)
	}
	return e.wrapDecision("deny", "default", "no rule matched", nil)
}

func methodMatchesHTTPRule(r compiledHTTPServiceRule, method string) bool {
	if len(r.methods) == 0 {
		return true
	}
	if _, ok := r.methods["*"]; ok {
		return true
	}
	_, ok := r.methods[method]
	return ok
}

func pathMatchesHTTPRule(r compiledHTTPServiceRule, reqPath string) bool {
	for _, g := range r.paths {
		if g.Match(reqPath) {
			return true
		}
	}
	return false
}

// DeclaredHTTPServiceHost reports whether host belongs to a declared
// http_services entry. host may include a port (bracket-aware strip),
// be in any case, end in a trailing dot, or be a bracketed IPv6 literal.
// It also accepts a bare IPv6 literal (e.g. from net.SplitHostPort on
// a bracketed authority), which callers may produce when dealing with
// post-parsed HTTP Host headers. Returns the canonical service name
// and the env var name used by the gateway.
func (e *Engine) DeclaredHTTPServiceHost(host string) (serviceName, envVar string, ok bool) {
	// Rewrap bare IPv6 literals so canonicalizeHost can see them.
	// A hostname never contains a colon, and host:port has exactly
	// one, so >= 2 colons on an unbracketed string unambiguously
	// indicates a bare IPv6 literal.
	if !strings.HasPrefix(host, "[") && strings.Count(host, ":") >= 2 {
		host = "[" + host + "]"
	}
	h, good := canonicalizeHost(host)
	if !good {
		return "", "", false
	}
	cs, found := e.httpServiceHosts[h]
	if !found {
		return "", "", false
	}
	return cs.cfg.Name, cs.envVar, true
}

// DeclaredHTTPServiceAllowsDirect returns true when the declared service
// matching host has allow_direct: true set in its YAML. Callers of
// DeclaredHTTPServiceHost should query this before denying direct access
// in the fail-closed netmonitor path — a true result means the service
// opted out of the gateway-only constraint.
//
// host follows the same canonicalization rules as DeclaredHTTPServiceHost
// (case, trailing dot, bracketed or bare IPv6, optional port). Returns
// false for unknown hosts — the caller already gated on DeclaredHTTPServiceHost.
func (e *Engine) DeclaredHTTPServiceAllowsDirect(host string) bool {
	if !strings.HasPrefix(host, "[") && strings.Count(host, ":") >= 2 {
		host = "[" + host + "]"
	}
	h, good := canonicalizeHost(host)
	if !good {
		return false
	}
	cs, found := e.httpServiceHosts[h]
	if !found {
		return false
	}
	return cs.cfg.AllowDirect
}

// HTTPServices returns a deep copy of the source HTTPService list.
// Used by the proxy to enumerate declared services for EnvVars()
// injection and by tests. Callers may mutate the returned slice and
// its contents without affecting engine state.
func (e *Engine) HTTPServices() []HTTPService {
	if e == nil || e.policy == nil || len(e.policy.HTTPServices) == 0 {
		return nil
	}
	out := make([]HTTPService, len(e.policy.HTTPServices))
	for i, src := range e.policy.HTTPServices {
		dst := src // copies scalar fields
		if len(src.Aliases) > 0 {
			dst.Aliases = append([]string(nil), src.Aliases...)
		}
		if len(src.Rules) > 0 {
			dst.Rules = make([]HTTPServiceRule, len(src.Rules))
			for j, r := range src.Rules {
				rc := r // copies scalar fields
				if len(r.Methods) > 0 {
					rc.Methods = append([]string(nil), r.Methods...)
				}
				if len(r.Paths) > 0 {
					rc.Paths = append([]string(nil), r.Paths...)
				}
				dst.Rules[j] = rc
			}
		}
		out[i] = dst
	}
	return out
}
