package proxy

import (
	"io"
	"net/http"
	"net/url"
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
// deny returns 403, approve returns 501 (wired in Task 10), allow/audit
// forward to the configured upstream. Hooks are wired in Task 9.
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
	case "approve":
		// Task 10 wires the real approval manager. Until then, fail closed
		// with a controlled 501 so callers get a semantically correct error
		// instead of a 500 "unsupported decision".
		http.Error(w, "approval not yet implemented", http.StatusNotImplemented)
		return
	case "allow", "audit":
		// Proceed to forwarding below.
	default:
		http.Error(w, "unsupported decision", http.StatusInternalServerError)
		return
	}

	svc := p.findHTTPService(eng, svcName)
	if svc == nil {
		http.Error(w, "service vanished", http.StatusInternalServerError)
		return
	}

	outReq, err := p.buildUpstreamRequest(r, svc.Upstream, reqPath)
	if err != nil {
		http.Error(w, "rewrite failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp, err := p.httpServiceTransport().RoundTrip(outReq)
	if err != nil {
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers and status, then body.
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// findHTTPService looks up a service by name from the engine's enumeration.
// Used in the serve path to access fields (Upstream, ExposeAs) that are
// not in the Decision struct.
func (p *Proxy) findHTTPService(eng *policy.Engine, name string) *policy.HTTPService {
	for _, s := range eng.HTTPServices() {
		if strings.EqualFold(s.Name, name) {
			s := s
			return &s
		}
	}
	return nil
}

// buildUpstreamRequest clones the inbound request and retargets it at
// svcUpstream + reqPath + (optional query string). Preserves method, body,
// and headers. Does NOT apply hooks — hooks are wired in Task 9.
func (p *Proxy) buildUpstreamRequest(r *http.Request, svcUpstream, reqPath string) (*http.Request, error) {
	u, err := url.Parse(svcUpstream)
	if err != nil {
		return nil, err
	}
	// Preserve query string if present on the inbound request.
	rawQuery := r.URL.RawQuery
	u.Path = singleSlashJoin(u.Path, reqPath)
	u.RawQuery = rawQuery

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, u.String(), r.Body)
	if err != nil {
		return nil, err
	}
	// Copy headers, excluding hop-by-hop.
	for k, vs := range r.Header {
		if isHopByHopHeader(k) {
			continue
		}
		for _, v := range vs {
			outReq.Header.Add(k, v)
		}
	}
	outReq.Host = u.Host
	outReq.ContentLength = r.ContentLength
	return outReq, nil
}

func singleSlashJoin(a, b string) string {
	aSlash := strings.HasSuffix(a, "/")
	bSlash := strings.HasPrefix(b, "/")
	switch {
	case aSlash && bSlash:
		return a + b[1:]
	case !aSlash && !bSlash:
		return a + "/" + b
	}
	return a + b
}

func isHopByHopHeader(h string) bool {
	switch strings.ToLower(h) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
		"te", "trailer", "transfer-encoding", "upgrade":
		return true
	}
	return false
}

// httpServiceTransport returns the transport used to forward declared-service
// requests. Currently http.DefaultTransport; testable via the setter below.
func (p *Proxy) httpServiceTransport() http.RoundTripper {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.httpSvcTransport != nil {
		return p.httpSvcTransport
	}
	return http.DefaultTransport
}

// SetHTTPServiceTransportForTest injects a RoundTripper used for
// declared-service forwarding. Test-only.
func (p *Proxy) SetHTTPServiceTransportForTest(rt http.RoundTripper) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.httpSvcTransport = rt
}
