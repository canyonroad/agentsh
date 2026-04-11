package proxy

import (
	"net/http"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/policy"
)

const declaredServicePathPrefix = "/svc/"

// SetPolicyEngine wires the policy engine for http_services dispatch.
// Called once during startup.
func (p *Proxy) SetPolicyEngine(e *policy.Engine) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.policyEngine = e
}

// declaredService resolves a request path to a compiled http_service entry
// if the path starts with /svc/<name>/. Returns the service name, the
// remaining path (starting with '/'), and ok=true when resolved.
//
// A path that starts with /svc/ but names a service that does not exist
// returns ok=false with name != "". Callers use the name vs "" distinction
// to decide between "fall through to LLM path" (no /svc/ prefix) and
// "return 404 for unknown declared service".
func (p *Proxy) declaredService(reqPath string) (name, rest string, ok bool) {
	if !strings.HasPrefix(reqPath, declaredServicePathPrefix) {
		return "", "", false
	}
	tail := strings.TrimPrefix(reqPath, declaredServicePathPrefix)
	slash := strings.IndexByte(tail, '/')
	if slash == -1 {
		name = tail
		rest = "/"
	} else {
		name = tail[:slash]
		rest = tail[slash:]
	}
	if name == "" {
		return "", "", false
	}

	p.mu.Lock()
	eng := p.policyEngine
	p.mu.Unlock()
	if eng == nil {
		// Not yet wired — treat as unknown so tests with no engine don't crash.
		return name, rest, false
	}
	for _, svc := range eng.HTTPServices() {
		if strings.EqualFold(svc.Name, name) {
			return svc.Name, rest, true
		}
	}
	return name, rest, false
}

// serveDeclaredService handles a request routed to a declared http_service.
// For Task 7, only the deny path is fully implemented. allow/audit return 501
// until Task 8 adds upstream forwarding.
func (p *Proxy) serveDeclaredService(w http.ResponseWriter, r *http.Request, svcName, reqPath, requestID string, startTime time.Time) {
	p.mu.Lock()
	eng := p.policyEngine
	p.mu.Unlock()
	if eng == nil {
		http.Error(w, "http_services not configured", http.StatusInternalServerError)
		return
	}

	// Strip query string before evaluation — the evaluator does not look at it.
	pathForEval := reqPath
	if idx := strings.IndexByte(pathForEval, '?'); idx != -1 {
		pathForEval = pathForEval[:idx]
	}

	dec := eng.CheckHTTPService(svcName, r.Method, pathForEval)

	switch dec.EffectiveDecision {
	case "deny":
		msg := dec.Message
		if msg == "" {
			msg = "blocked by http_services rule"
		}
		http.Error(w, msg, http.StatusForbidden)
		return
	case "allow", "audit":
		// Forwarding implemented in Task 8.
		http.Error(w, "forwarding not implemented", http.StatusNotImplemented)
		return
	default:
		http.Error(w, "unsupported decision", http.StatusInternalServerError)
		return
	}
}
