package proxy

import (
	"net/http"
	"sync"
	"time"
)

// RequestContext carries per-request state shared between the proxy and
// any registered hooks. It is created by the proxy at the start of each
// request and passed to PreHook and PostHook callbacks.
//
// Attrs is a free-form map intended for hooks to communicate with each
// other — for example, a DLP hook storing its redaction result so a
// later logging hook can include it in the audit event. Keys should be
// namespaced with the hook's package name (e.g. "llm.dlp.result") to
// avoid collisions.
type RequestContext struct {
	// RequestID is a unique identifier assigned by the proxy for each
	// incoming request. Hooks may use it for correlation across logs.
	RequestID string

	// SessionID is the agentsh session ID that owns the spawned process
	// making this request.
	SessionID string

	// ServiceName is the name of the service this request was matched
	// to, or the empty string if no service matched. Hooks registered
	// under the empty service name run for every request regardless of
	// match.
	ServiceName string

	// StartTime is when the proxy first saw this request.
	StartTime time.Time

	// Attrs is a hook-private scratch area. Hooks must namespace their
	// keys to avoid colliding with other hooks.
	Attrs map[string]any
}

// Hook is an extension point registered with the proxy. Hooks are keyed
// by service name and invoked for every request routed to that service.
// A hook registered under the empty service name runs for every request
// regardless of which service (if any) matched.
//
// PreHook runs BEFORE the proxy forwards the request to the upstream.
// At this point the request body still contains whatever the agent sent
// (including any fake credentials that a later substitution pass will
// replace). A hook that needs to see the post-substitution body is out
// of scope for this plan — the Hook interface may grow a third phase in
// a later plan if that need is real.
//
// Returning a non-nil error from PreHook aborts the request. The proxy
// returns an HTTP 502 to the agent and logs the error. Remaining
// pre-hooks for the same request are NOT invoked.
//
// PostHook runs AFTER the upstream responds, but BEFORE the response is
// returned to the agent. This is where response-time concerns live
// (audit logging, response scrubbing, token accounting).
//
// Returning a non-nil error from PostHook is logged but does not change
// the response the agent sees. All post-hooks for the same request are
// invoked even if one fails.
type Hook interface {
	// Name returns a stable identifier for this hook, used in logs and
	// audit events.
	Name() string

	// PreHook is called before the request is forwarded upstream.
	PreHook(*http.Request, *RequestContext) error

	// PostHook is called after the upstream response arrives and before
	// it is returned to the agent.
	PostHook(*http.Response, *RequestContext) error
}

// Registry stores hooks keyed by service name. It is safe for concurrent
// use. Hooks registered for the same service name are invoked in
// registration order.
//
// The zero value of Registry is NOT usable — call NewRegistry.
type Registry struct {
	mu    sync.RWMutex
	hooks map[string][]Hook
}

// NewRegistry returns an empty hook registry.
func NewRegistry() *Registry {
	return &Registry{hooks: make(map[string][]Hook)}
}

// Register adds a hook under the given service name. A hook may be
// registered multiple times under different service names; a single
// service may have multiple hooks registered. Use the empty string as
// the service name to register a hook that runs for every request.
//
// Register panics if h is nil — all hooks must be non-nil interface
// values. This catches programmer errors at registration time rather
// than producing a confusing nil pointer dereference later inside
// ApplyPreHooks or ApplyPostHooks.
func (r *Registry) Register(serviceName string, h Hook) {
	if h == nil {
		panic("proxy: Registry.Register called with nil hook")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hooks[serviceName] = append(r.hooks[serviceName], h)
}

// snapshot returns defensive copies of the global and service-scoped
// hook slices under a single read lock acquisition. Callers invoke
// hooks on the returned slices AFTER releasing the lock to avoid
// holding the mutex during user-supplied callbacks.
func (r *Registry) snapshot(serviceName string) (global, scoped []Hook) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if g := r.hooks[""]; len(g) > 0 {
		global = make([]Hook, len(g))
		copy(global, g)
	}
	if serviceName != "" {
		if s := r.hooks[serviceName]; len(s) > 0 {
			scoped = make([]Hook, len(s))
			copy(scoped, s)
		}
	}
	return global, scoped
}

// ApplyPreHooks invokes PreHook on each hook registered under the empty
// service name followed by each hook registered under serviceName, in
// registration order. It stops at the first non-nil error and returns
// it. Hooks that have not been reached are not invoked.
func (r *Registry) ApplyPreHooks(serviceName string, req *http.Request, ctx *RequestContext) error {
	globalHooks, scopedHooks := r.snapshot(serviceName)
	for _, h := range globalHooks {
		if err := h.PreHook(req, ctx); err != nil {
			return err
		}
	}
	for _, h := range scopedHooks {
		if err := h.PreHook(req, ctx); err != nil {
			return err
		}
	}
	return nil
}

// ApplyPostHooks invokes PostHook on every hook registered under the
// empty service name and serviceName, in registration order. Unlike
// ApplyPreHooks, errors do NOT short-circuit — every hook is invoked
// even if an earlier one fails. The first error encountered is returned;
// subsequent errors are silently dropped (hooks that need their own
// error reporting should log internally).
func (r *Registry) ApplyPostHooks(serviceName string, resp *http.Response, ctx *RequestContext) error {
	globalHooks, scopedHooks := r.snapshot(serviceName)
	var firstErr error
	for _, h := range globalHooks {
		if err := h.PostHook(resp, ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, h := range scopedHooks {
		if err := h.PostHook(resp, ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
