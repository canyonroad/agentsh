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
