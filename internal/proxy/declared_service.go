package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

const declaredServicePathPrefix = "/svc/"

// HTTPServiceApprovalsManager is the subset of approvals.Manager needed by
// the declared-service path. Declared here as a local interface to keep
// the import surface narrow and to simplify testing — tests install a
// fake implementation via SetApprovalsForTest and don't have to spin up a
// real approvals.Manager with its TTY/TOTP/WebAuthn machinery.
type HTTPServiceApprovalsManager interface {
	RequestApproval(ctx context.Context, req approvals.Request) (approvals.Resolution, error)
}

// SetHTTPServiceApprovals wires the approvals manager consulted for
// `approve` decisions on declared services. Called once during startup
// from app.go alongside SetPolicyEngine and SetHTTPServices.
func (p *Proxy) SetHTTPServiceApprovals(m HTTPServiceApprovalsManager) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.httpSvcApprovals = m
}

// SetApprovalsForTest installs an approvals manager for the declared-
// service path. Test-only; production wiring goes through
// SetHTTPServiceApprovals.
func (p *Proxy) SetApprovalsForTest(m HTTPServiceApprovalsManager) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.httpSvcApprovals = m
}

// SetPolicyEngine wires the policy engine for http_services dispatch.
// Called once during startup.
func (p *Proxy) SetPolicyEngine(e *policy.Engine) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.policyEngine = e
}

// SetStorageForTest installs a Storage instance for the declared-service
// logging path. Production uses the same Storage that the LLM path uses;
// tests point it at a temp dir. Test-only setter to keep the dependency
// visible.
func (p *Proxy) SetStorageForTest(s *Storage) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.storage = s
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
// deny returns 403, approve consults the wired approvals manager (falling
// through to 501 when none is configured), and allow/audit forward to the
// configured upstream after running per-service pre-hooks.
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

	// Resolve sessionID up front so it is available to the approvals
	// request if the decision turns out to be `approve`. The same value
	// is reused later when constructing RequestContext for hook dispatch.
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		sessionID = p.cfg.SessionID
	}

	// Strip query string before evaluation — the evaluator does not look at it.
	pathForEval := reqPath
	if idx := strings.IndexByte(pathForEval, '?'); idx != -1 {
		pathForEval = pathForEval[:idx]
	}

	// Recover the original escaped path tail so encoded bytes (e.g. %2F)
	// are visible downstream unchanged — both for the approval Target (so
	// approvers see exactly what the client sent, including %2F/%3F) and
	// for the upstream forwarding path below. http.Request.URL.Path has
	// already been decoded — deriving either use from it would lose
	// distinctions like "/items/a%2Fb" vs "/items/a/b". EscapedPath()
	// returns the canonical escaped form (RawPath if set and valid,
	// otherwise the re-escaping of Path). The "/svc/<name>" prefix
	// contains no characters that would be percent-encoded (service names
	// are validated against ^[A-Za-z0-9._-]+$ in policy.ValidateHTTPServices),
	// so in the common case a literal prefix strip works. The literal
	// strip uses rawSegment (case-preserved from the request) rather than
	// a canonical name so the byte-level prefix matches exactly. If the
	// client sent percent-encoded bytes in the name portion (which decode
	// to the same unencoded name), fall back to re-escaping the decoded
	// rest — that preserves safety without preserving the caller's
	// idiosyncratic encoding of the name.
	prefix := declaredServicePathPrefix + rawSegment
	escaped := r.URL.EscapedPath()
	var escapedPath string
	// The literal strip is only safe when the byte immediately after the
	// prefix is '/' (the unencoded separator) or the prefix is the entire
	// escaped path. Otherwise the prefix "matches" a name whose trailing
	// bytes are percent-encoded into the next segment (e.g.
	// "/svc/github%2Fitems" has prefix "/svc/github" with a '%' next byte),
	// and stripping the prefix would leave "%2Fitems" — diverging from
	// the decoded rest ("/items") that policy evaluation and upstream
	// forwarding use. Fall back to re-escaping the decoded rest in that
	// case so the approval Target stays aligned with what the rest of
	// the pipeline sees.
	if strings.HasPrefix(escaped, prefix) && (len(escaped) == len(prefix) || escaped[len(prefix)] == '/') {
		escapedPath = strings.TrimPrefix(escaped, prefix)
	} else {
		// Name was encoded, case-differs, or bled into the next segment
		// via an encoded slash — re-escape the decoded rest.
		escapedPath = (&url.URL{Path: reqPath}).EscapedPath()
	}
	if escapedPath == "" {
		escapedPath = "/"
	}

	// CheckHTTPService MUST run against the path-below-/svc/<name> that
	// the policy author wrote their rules against. It runs BEFORE any
	// pre-hook URL mutation so hooks cannot inadvertently (or
	// deliberately) sidestep the decision by rewriting the path.
	dec := eng.CheckHTTPService(rawSegment, r.Method, pathForEval)

	// Gate approve decisions on an interactive approval. This mirrors the
	// logic in internal/netmonitor/proxy.go maybeApprove; the two call
	// sites are deliberately duplicated for minimal blast radius. A
	// follow-up refactor can consolidate them into a shared helper.
	//
	// When the manager is nil (operator hasn't wired one yet), the
	// decision is left untouched and falls through to the 501 branch in
	// the switch below — so the existing "approval not yet implemented"
	// contract still holds for un-wired tests and deployments.
	if dec.PolicyDecision == types.DecisionApprove && dec.EffectiveDecision == types.DecisionApprove {
		p.mu.Lock()
		appr := p.httpSvcApprovals
		p.mu.Unlock()
		if appr != nil {
			// Target uses the escaped-form path tail and the raw query
			// string (unparsed, as received from the client) when
			// present, so approvers see exactly what the client sent —
			// including encoded bytes like %2F/%3F that would otherwise
			// collapse to their decoded characters and misrepresent the
			// resource being approved. Hiding the query string would
			// similarly obscure material details (e.g. ?force=true).
			target := rawSegment + " " + r.Method + " " + escapedPath
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			// CommandID is intentionally left empty. Declared-service
			// requests aren't tied to a specific session command —
			// they come from arbitrary HTTP calls the agent makes, not
			// from a single tracked command. Populating this field
			// with the proxy's per-request UUID (which is NOT a real
			// session command ID) corrupts downstream command-level
			// correlation and indexes approval events under a command
			// ID that doesn't correspond to any real command. A future
			// improvement could attach a command ID if agentsh tracks
			// an "active command" per session.
			req := approvals.Request{
				ID:        "approval-" + uuid.NewString(),
				SessionID: sessionID,
				CommandID: "",
				Kind:      "http_service",
				Target:    target,
				Rule:      dec.Rule,
				Message:   dec.Message,
			}
			res, err := appr.RequestApproval(r.Context(), req)
			if dec.Approval != nil {
				dec.Approval.ID = req.ID
			}
			if err != nil || !res.Approved {
				dec.EffectiveDecision = types.DecisionDeny
			} else {
				dec.EffectiveDecision = types.DecisionAllow
			}
		}
	}

	switch dec.EffectiveDecision {
	case types.DecisionDeny:
		msg := dec.Message
		if msg == "" {
			msg = "blocked by http_services rule"
		}
		http.Error(w, msg, http.StatusForbidden)
		return
	case types.DecisionApprove:
		// Only reached when the decision was `approve` but no approvals
		// manager has been wired. Fail closed with a semantically distinct
		// 501 so operators can tell the difference between "approvals not
		// configured" and "policy returned an unsupported decision".
		http.Error(w, "approval not yet implemented", http.StatusNotImplemented)
		return
	case types.DecisionAllow, types.DecisionAudit:
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

	// Buffer the request body before dispatching hooks so they can
	// inspect it without exhausting the stream. PreHooks may replace
	// r.Body — buildUpstreamRequest reads whatever body is set after
	// hooks return. On read error we must fail closed: io.ReadAll may
	// have already drained part of the stream, so leaving r.Body in
	// place would hand hooks and the upstream a truncated request.
	//
	// storedBody is hoisted to function scope because it feeds the
	// on-disk copy written by StoreRequestBody below. It captures the
	// PRE-hook bytes — i.e. what the agent actually typed — so real
	// credentials that CredsSubHook substitutes in during PreHook never
	// land in llm-bodies. The post-hook (forwarded) view is captured
	// separately after the hook dispatch block, and only feeds the
	// audit BodySize/BodyHash integrity stamp.
	var storedBody []byte
	if r.Body != nil {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read request body: "+err.Error(), http.StatusBadRequest)
			return
		}
		storedBody = b
		r.Body = io.NopCloser(bytes.NewReader(storedBody))
		r.ContentLength = int64(len(storedBody))
	}

	// Rewrite r.URL to the upstream-bound form BEFORE running hooks so
	// that any hook-driven URL mutations (e.g. CredsSubHook substituting
	// credentials in the URL path) are visible to buildUpstreamRequest,
	// which now reads from r.URL directly rather than captured copies.
	// The policy decision already ran against the pre-mutation path.
	//
	// Path/RawPath contract with hooks:
	//   - r.URL.Path is set to the decoded tail.
	//   - r.URL.RawPath is SEEDED with the escaped tail so built-in
	//     hooks like CredsSubHook — whose RawPath substitution branch
	//     is gated on RawPath != "" — fire and update both fields in
	//     lockstep. Because CredsSubHook's substitution is length-
	//     preserving and leaves non-substituted bytes intact, encoded
	//     bytes in untouched segments (e.g. %2F) survive the rewrite.
	//   - After hooks return, four cases are possible:
	//       1. Neither Path nor RawPath changed: the seeded escapedTail
	//          is still correct. Nothing to do.
	//       2. Only Path changed (hook rewrote the decoded Path but
	//          didn't touch RawPath): the seeded RawPath is now stale
	//          and no longer a valid encoding of Path. Clear it so
	//          Go's url.URL.EscapedPath() re-escapes from Path from
	//          scratch. This loses encoded bytes in segments the hook
	//          didn't touch — a documented limitation. Hooks that need
	//          to preserve encoded bytes while rewriting Path must
	//          update BOTH fields (the CredsSubHook pattern).
	//          TODO(future): a common-prefix splice could preserve the
	//          untouched prefix's encoding when only Path changes,
	//          but that's out of scope for this commit.
	//       3. Only RawPath changed (hook explicitly rewrote the
	//          escaping without changing the decoded Path): trust the
	//          hook and leave its RawPath in place.
	//       4. Both Path and RawPath changed (CredsSubHook's path):
	//          trust the hook and leave both in place.
	r.URL.Path = reqPath
	r.URL.RawPath = escapedPath
	preHookPath := r.URL.Path
	preHookRawPath := r.URL.RawPath

	// Build RequestContext for hook dispatch. The /svc/ path pins
	// ServiceName to the canonical service name (as written in the
	// policy config) so per-service hooks registered under that key —
	// e.g. HeaderInjectionHook — fire even when the caller used a
	// different case in the URL. sessionID was resolved near the top of
	// this function so it was available for the approvals request.
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

	// Post-hook RawPath reconciliation. See the four-case table in the
	// pre-hook comment above for the rationale.
	pathChanged := r.URL.Path != preHookPath
	rawChanged := r.URL.RawPath != preHookRawPath
	if pathChanged && !rawChanged {
		// Case 2: hook rewrote Path without updating RawPath, so the
		// seeded RawPath is now stale. Clearing it lets Go re-escape
		// Path from scratch. Encoded bytes in untouched segments are
		// lost — documented limitation; hooks that care must update
		// both fields.
		r.URL.RawPath = ""
	}
	// Cases 1, 3, 4: leave r.URL as-is. The seeded escapedPath from
	// before hooks ran is still valid (case 1), or the hook explicitly
	// owns the encoding (cases 3 and 4).

	// Compute the two views of the request body:
	//   - storedBody (captured pre-hook, above): what the agent sent.
	//     Passed to StoreRequestBody so the on-disk copy in
	//     <session>/llm-bodies/<request_id>.json reflects the agent's
	//     original bytes — NOT the post-hook bytes, which for
	//     CredsSubHook contain real upstream credentials.
	//   - forwardedBody (captured here, post-hook): what actually
	//     goes upstream. Feeds BodySize and BodyHash in the audit
	//     record so the integrity stamp describes the forwarded
	//     request, not the agent's typed input.
	//
	// Empty-body normalization: pre-hooks may drop the body via
	// r.Body = nil, r.Body = http.NoBody, or by replacing it with a
	// zero-byte reader. All three mean "nothing forwarded". When we
	// detect any of them we:
	//   - Zero storedBody so no on-disk copy is written
	//   - Leave forwardedBody nil so BodySize/BodyHash describe "empty"
	//   - Reset r.Body = http.NoBody and r.ContentLength = 0 so
	//     buildUpstreamRequest does not forward a stale Content-Length
	//     header to the upstream. Relying on hook authors to zero
	//     ContentLength themselves is brittle and fails silently.
	var forwardedBody []byte
	if r.Body != nil && r.Body != http.NoBody {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "re-read request body: "+err.Error(), http.StatusBadGateway)
			return
		}
		forwardedBody = b
	}
	if len(forwardedBody) == 0 {
		storedBody = nil
		forwardedBody = nil
		r.Body = http.NoBody
		r.ContentLength = 0
	} else {
		r.Body = io.NopCloser(bytes.NewReader(forwardedBody))
		r.ContentLength = int64(len(forwardedBody))
	}

	// Audit the request AFTER hooks have run and after the RawPath
	// reconciliation, so the logged path reflects any hook-driven
	// rewrites. dec.Rule is the name of the matched rule (empty when
	// the decision came from the service default).
	p.logDeclaredServiceRequest(requestID, sessionID, canonicalName, dec.Rule, r, forwardedBody, storedBody)

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

	// Buffer the response body so we can log it and still write it
	// back. Unlike the LLM path, declared-service bodies are bounded
	// by real API responses (not model streams), so buffering is
	// acceptable. Spec §6 explicitly requires the body be logged,
	// which rules out pass-through streaming in v1.
	respBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		http.Error(w, "read upstream response: "+readErr.Error(), http.StatusBadGateway)
		return
	}

	// Apply post-hooks (e.g. credential scrubbing) before logging or
	// writing the response back to the client. This mirrors the LLM
	// path's post-hook dispatch so CredsSubHook.PostHook can replace
	// real credentials with fakes in the response body.
	if p.hookRegistry != nil && reqCtx != nil {
		resp.Body = io.NopCloser(bytes.NewReader(respBody))
		resp.ContentLength = int64(len(respBody))
		if hookErr := p.hookRegistry.ApplyPostHooks(reqCtx.ServiceName, resp, reqCtx); hookErr != nil {
			p.logger.Warn("post-hook error", "error", hookErr, "request_id", requestID)
		}
		// Re-read body in case a hook replaced it.
		if resp.Body != nil {
			hookBody, rErr := io.ReadAll(resp.Body)
			if rErr == nil {
				respBody = hookBody
			}
		}
	}

	p.logDeclaredServiceResponse(requestID, sessionID, canonicalName, resp, respBody, startTime)

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
	_, _ = w.Write(respBody)
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

// sanitizeHeadersForDeclaredService redacts headers that may carry
// credentials on the declared-service path. In addition to the fixed
// auth denylist shared with the LLM path (Authorization, X-Api-Key,
// Api-Key), it redacts:
//
//   - Cookie / Set-Cookie (session tokens)
//   - Proxy-Authorization / Proxy-Authenticate (upstream proxy creds)
//   - Any header name listed in injectedNames, which the caller
//     populates from Registry.InjectedHeaderNamesForService so
//     per-service HeaderInjectionHook credentials never hit disk.
//
// Comparison is case-insensitive via http.CanonicalHeaderKey. The
// returned map uses the original header key casing as received, to
// keep logs readable.
func sanitizeHeadersForDeclaredService(h http.Header, injectedNames []string) map[string][]string {
	denylist := map[string]struct{}{
		"Authorization":       {},
		"X-Api-Key":           {},
		"Api-Key":             {},
		"Cookie":              {},
		"Set-Cookie":          {},
		"Proxy-Authorization": {},
		"Proxy-Authenticate":  {},
	}
	for _, n := range injectedNames {
		denylist[http.CanonicalHeaderKey(n)] = struct{}{}
	}
	result := make(map[string][]string, len(h))
	for k, v := range h {
		if _, redacted := denylist[http.CanonicalHeaderKey(k)]; redacted {
			result[k] = []string{"[REDACTED]"}
			continue
		}
		result[k] = v
	}
	return result
}

// logDeclaredServiceRequest writes a RequestLogEntry for a declared-service
// request to p.storage, mirroring how logRequest works for the LLM path but
// without a Dialect and with ServiceKind/ServiceName/RuleName set.
//
// Matches the logRequest signature so future refactors can consolidate the
// two. ruleName is the name of the rule that matched; if the decision came
// from the service default (no rule matched), ruleName is the empty string.
//
// forwardedBody is the post-hook payload that will be sent upstream;
// BodySize and BodyHash describe THIS slice so the audit record
// describes what was actually forwarded. storedBody is the pre-hook
// payload (agent's original input); it is passed to StoreRequestBody
// so the on-disk copy never captures post-substitution credentials.
// When a hook drops the request body entirely, both are nil and
// StoreRequestBody no-ops (it already handles len(body) == 0).
func (p *Proxy) logDeclaredServiceRequest(requestID, sessionID, svcName, ruleName string, r *http.Request, forwardedBody, storedBody []byte) {
	if p.storage == nil {
		return
	}
	var injected []string
	if p.hookRegistry != nil {
		injected = p.hookRegistry.InjectedHeaderNamesForService(svcName)
	}
	entry := &RequestLogEntry{
		ID:          requestID,
		SessionID:   sessionID,
		Timestamp:   time.Now().UTC(),
		ServiceKind: "http_service",
		ServiceName: svcName,
		RuleName:    ruleName,
		Request: RequestInfo{
			Method:   r.Method,
			Path:     r.URL.Path,
			Headers:  sanitizeHeadersForDeclaredService(r.Header, injected),
			BodySize: len(forwardedBody),
			BodyHash: HashBody(forwardedBody),
		},
	}
	if err := p.storage.LogRequest(entry); err != nil {
		p.logger.Error("log declared-service request", "error", err, "request_id", requestID)
	}
	if err := p.storage.StoreRequestBody(requestID, storedBody); err != nil {
		p.logger.Error("store declared-service request body", "error", err, "request_id", requestID)
	}
}

// logDeclaredServiceResponse mirrors logResponseDirect for the declared-
// service path. resp.Body must already be drained into respBody; the
// caller is responsible for restoring resp.Body before writing it back
// to the client. svcName is the canonical service name so the response
// sanitizer can redact any HeaderInjectionHook-registered header names
// the upstream echoed back.
func (p *Proxy) logDeclaredServiceResponse(requestID, sessionID, svcName string, resp *http.Response, respBody []byte, startTime time.Time) {
	if p.storage == nil {
		return
	}
	var injected []string
	if p.hookRegistry != nil {
		injected = p.hookRegistry.InjectedHeaderNamesForService(svcName)
	}
	entry := &ResponseLogEntry{
		RequestID:  requestID,
		SessionID:  sessionID,
		Timestamp:  time.Now().UTC(),
		DurationMs: time.Since(startTime).Milliseconds(),
		Response: ResponseInfo{
			Status:   resp.StatusCode,
			Headers:  sanitizeHeadersForDeclaredService(resp.Header, injected),
			BodySize: len(respBody),
			BodyHash: HashBody(respBody),
		},
	}
	if err := p.storage.LogResponse(entry); err != nil {
		p.logger.Error("log declared-service response", "error", err, "request_id", requestID)
	}
	if err := p.storage.StoreResponseBody(requestID, respBody); err != nil {
		p.logger.Error("store declared-service response body", "error", err, "request_id", requestID)
	}
}
