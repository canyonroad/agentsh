package proxy

import (
	"bytes"
	"errors"
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
// if the path starts with /svc/<name>/. Returns the service name AS IT
// APPEARED IN THE REQUEST (preserving the caller's case), the remaining
// path (starting with '/'), and ok=true when resolved.
//
// The name is deliberately returned in the request's case (not the
// configured canonical form) so downstream callers can strip the exact
// prefix from r.URL.EscapedPath() — a case-insensitive lookup here paired
// with a case-sensitive strip later would corrupt requests whose service
// name case differs from the declared one. Downstream lookups
// (CheckHTTPService, findHTTPService) are themselves case-insensitive.
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
			// Return the request's segment (case-preserved), not svc.Name.
			// See doc comment for why.
			return name, rest, true
		}
	}
	return name, rest, false
}

// serveDeclaredService handles a request routed to a declared http_service.
// deny returns 403, approve returns 501 (wired in Task 10), allow/audit
// forward to the configured upstream after running per-service pre-hooks.
//
// rawSegment is the service name AS IT APPEARED IN THE REQUEST URL (with
// its original case preserved). It is used only for the literal
// escaped-path prefix strip below — the canonical name from the policy
// config (svc.Name) is used for everything else, including hook dispatch
// and RequestContext. This split exists because /svc matching is
// case-insensitive but the byte-level prefix strip against
// r.URL.EscapedPath() needs the exact request bytes.
func (p *Proxy) serveDeclaredService(w http.ResponseWriter, r *http.Request, rawSegment, reqPath, requestID string, startTime time.Time) {
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

	// CheckHTTPService MUST run against the path-below-/svc/<name> that
	// the policy author wrote their rules against. It runs BEFORE any
	// pre-hook URL mutation so hooks cannot inadvertently (or
	// deliberately) sidestep the decision by rewriting the path.
	dec := eng.CheckHTTPService(rawSegment, r.Method, pathForEval)

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

	svc := p.findHTTPService(eng, rawSegment)
	if svc == nil {
		http.Error(w, "service vanished", http.StatusInternalServerError)
		return
	}
	// canonicalName is the service name as written in the policy config.
	// Hook registration is keyed on this canonical form, so ApplyPreHooks
	// must use it — not the raw request segment, whose case may differ.
	canonicalName := svc.Name

	// Recover the original escaped path tail so encoded bytes (e.g. %2F)
	// reach the upstream unchanged. http.Request.URL.Path has already been
	// decoded — rebuilding the upstream URL from it would lose distinctions
	// like "/items/a%2Fb" vs "/items/a/b". EscapedPath() returns the
	// canonical escaped form (RawPath if set and valid, otherwise the
	// re-escaping of Path). The "/svc/<name>" prefix contains no characters
	// that would be percent-encoded (service names are validated against
	// ^[A-Za-z0-9._-]+$ in policy.ValidateHTTPServices), so in the common
	// case a literal prefix strip works. The literal strip uses rawSegment
	// (case-preserved from the request) rather than canonicalName so the
	// byte-level prefix matches exactly. If the client sent percent-encoded
	// bytes in the name portion (which decode to the same unencoded name),
	// fall back to re-escaping the decoded rest — that preserves safety
	// without preserving the caller's idiosyncratic encoding of the name.
	prefix := declaredServicePathPrefix + rawSegment
	escaped := r.URL.EscapedPath()
	var escapedPath string
	if strings.HasPrefix(escaped, prefix) {
		escapedPath = strings.TrimPrefix(escaped, prefix)
	} else {
		// Name was encoded or case-differs — re-escape the decoded rest.
		escapedPath = (&url.URL{Path: reqPath}).EscapedPath()
	}
	if escapedPath == "" {
		escapedPath = "/"
	}

	// Buffer the request body before dispatching hooks so they can
	// inspect it without exhausting the stream. PreHooks may replace
	// r.Body — buildUpstreamRequest reads whatever body is set after
	// hooks return. On read error we must fail closed: io.ReadAll may
	// have already drained part of the stream, so leaving r.Body in
	// place would hand hooks and the upstream a truncated request.
	if r.Body != nil {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read request body: "+err.Error(), http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}

	// Rewrite r.URL to the upstream-bound form BEFORE running hooks so
	// that any hook-driven URL mutations (e.g. CredsSubHook substituting
	// credentials in the URL path) are visible to buildUpstreamRequest,
	// which now reads from r.URL directly rather than captured copies.
	// The policy decision already ran against the pre-mutation path.
	//
	// Path/RawPath contract with hooks:
	//   - r.URL.Path is set to the decoded tail.
	//   - r.URL.RawPath is INTENTIONALLY LEFT EMPTY across the hook
	//     dispatch to avoid the stale-pre-seed footgun: if we pre-seeded
	//     RawPath with the escaped tail and a hook mutated r.URL.Path,
	//     the RawPath left behind would no longer match the new Path
	//     and Go's url.URL.EscapedPath() would silently fall back to
	//     re-escaping Path — dropping any %2F (or similar) bytes that
	//     lived in segments the hook didn't touch.
	//   - After hooks return, if r.URL.Path is byte-identical to the
	//     snapshot, we know the hook did not touch the path and it is
	//     safe to re-apply the original escaped tail so encoded bytes
	//     reach the upstream unchanged.
	//   - If the hook DID mutate r.URL.Path, the hook owns the
	//     encoding: Go will re-escape from r.URL.Path and any percent-
	//     encoded bytes in untouched segments are lost. Hooks that want
	//     to rewrite Path while preserving encoded bytes elsewhere
	//     MUST set both r.URL.Path and r.URL.RawPath consistently —
	//     this is Go's standard contract for url.URL.
	r.URL.Path = reqPath
	r.URL.RawPath = ""
	preHookPath := r.URL.Path

	// Build RequestContext for hook dispatch. The /svc/ path pins
	// ServiceName to the canonical service name (as written in the
	// policy config) so per-service hooks registered under that key —
	// e.g. HeaderInjectionHook — fire even when the caller used a
	// different case in the URL.
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		sessionID = p.cfg.SessionID
	}
	reqCtx := &RequestContext{
		RequestID:   requestID,
		SessionID:   sessionID,
		ServiceName: canonicalName,
		StartTime:   startTime,
		Attrs:       make(map[string]any),
	}

	if p.hookRegistry != nil {
		if err := p.hookRegistry.ApplyPreHooks(canonicalName, r, reqCtx); err != nil {
			var abortErr *HookAbortError
			if errors.As(err, &abortErr) {
				code := abortErr.StatusCode
				if code < 400 || code > 599 {
					code = http.StatusBadGateway
				}
				http.Error(w, abortErr.Message, code)
				return
			}
			http.Error(w, "hook error: "+err.Error(), http.StatusBadGateway)
			return
		}
	}

	// Re-apply the original escaped tail only if the hook left r.URL.Path
	// untouched. If the hook mutated Path, leave r.URL.RawPath empty so
	// Go's url.URL.EscapedPath() re-escapes r.URL.Path from scratch —
	// that's the hook's responsibility per the contract documented
	// above. Skip the re-apply when the escaped and decoded forms are
	// identical: setting RawPath equal to Path would be a redundant
	// string write and Go would treat it identically to the empty case.
	if r.URL.Path == preHookPath && escapedPath != preHookPath {
		r.URL.RawPath = escapedPath
	}

	outReq, err := p.buildUpstreamRequest(r, svc.Upstream)
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

	// Copy response headers and status, then body. Strip hop-by-hop headers
	// (RFC 7230 §6.1) plus any headers named in the upstream's Connection
	// header — real reverse proxies never forward these end-to-end.
	// RFC 7230 §3.2.2 allows repeated Connection header lines, so merge all
	// values (Header.Values) rather than reading only the first.
	respDenylist := connectionNominatedDenylist(resp.Header.Values("Connection"))
	for k, vs := range resp.Header {
		if isHopByHopHeader(k) {
			continue
		}
		if _, nominated := respDenylist[http.CanonicalHeaderKey(k)]; nominated {
			continue
		}
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
// svcUpstream + the current r.URL.Path (decoded) and r.URL.RawPath
// (escaped). Preserves method, body, and headers. Does NOT apply hooks —
// serveDeclaredService runs pre-hooks before invoking this function, so
// any hook-driven URL mutation is reflected here.
//
// The caller is responsible for rewriting r.URL to the upstream-bound
// form (stripping /svc/<name>) before calling. This function does not
// take reqPath/escapedPath parameters so it cannot be called with stale
// captured-before-hooks values — the only source of truth for the path
// is r.URL at the moment the request is about to be forwarded.
//
// Go preserves URL.RawPath only when it differs from URL.Path after
// decoding, and prefers RawPath in URL.String() when present — so we
// unconditionally populate both on the outbound URL.
func (p *Proxy) buildUpstreamRequest(r *http.Request, svcUpstream string) (*http.Request, error) {
	u, err := url.Parse(svcUpstream)
	if err != nil {
		return nil, err
	}
	// Preserve query string if present on the inbound request.
	rawQuery := r.URL.RawQuery
	// Read the decoded and escaped forms directly from r.URL so any
	// mutation pre-hooks performed (e.g. CredsSubHook substituting
	// credentials into the URL path) is carried through to the upstream.
	reqPath := r.URL.Path
	escapedPath := r.URL.EscapedPath()
	if escapedPath == "" {
		escapedPath = reqPath
	}
	// Build the decoded and escaped forms of the joined path. Go prefers
	// URL.RawPath in String() when it is a valid encoding of Path, so we
	// populate both: Path carries the decoded form, RawPath carries the
	// original escaped bytes. Use u.EscapedPath() for the upstream side
	// because the parsed URL may itself contain percent-encoded segments.
	u.RawPath = singleSlashJoin(u.EscapedPath(), escapedPath)
	u.Path = singleSlashJoin(u.Path, reqPath)
	u.RawQuery = rawQuery

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, u.String(), r.Body)
	if err != nil {
		return nil, err
	}
	// Copy headers, excluding hop-by-hop and any headers nominated as
	// connection-scoped by the client's Connection header (RFC 7230 §6.1).
	// Without this, a client could smuggle arbitrary headers upstream by
	// declaring them in Connection. RFC 7230 §3.2.2 allows repeated
	// Connection header lines, so merge all values (Header.Values) rather
	// than reading only the first.
	reqDenylist := connectionNominatedDenylist(r.Header.Values("Connection"))
	for k, vs := range r.Header {
		if isHopByHopHeader(k) {
			continue
		}
		if _, nominated := reqDenylist[http.CanonicalHeaderKey(k)]; nominated {
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

// connectionNominatedDenylist parses the values of one or more Connection
// header lines into a set of canonicalized header names that this hop must
// not forward. RFC 7230 §6.1 defines any token listed in Connection as
// hop-by-hop for this hop — in addition to the fixed hop-by-hop set
// returned by isHopByHopHeader. RFC 7230 §3.2.2 allows a field to appear
// on multiple lines, so callers pass Header.Values("Connection") and this
// function merges tokens across all lines. Empty tokens and the literal
// "close" / "keep-alive" control directives are skipped.
//
// Returns an empty (non-nil) map when there are no header lines so callers
// can use set lookup without nil-checks.
func connectionNominatedDenylist(connectionHeaders []string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, line := range connectionHeaders {
		if line == "" {
			continue
		}
		for _, tok := range strings.Split(line, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			// "close" and "keep-alive" are control directives, not header
			// names — drop them from the denylist so they don't accidentally
			// match a legitimate request header.
			switch strings.ToLower(tok) {
			case "close", "keep-alive":
				continue
			}
			out[http.CanonicalHeaderKey(tok)] = struct{}{}
		}
	}
	return out
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
