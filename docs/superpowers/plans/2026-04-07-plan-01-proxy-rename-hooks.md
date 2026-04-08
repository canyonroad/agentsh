# Plan 1: Rename `internal/llmproxy` → `internal/proxy` + Introduce Hook Interface

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename the `internal/llmproxy` package to `internal/proxy` and introduce an empty `Hook` interface extension point. Unblocks the new package layout used by Plans 2–12 without migrating any existing behavior.

**Architecture:**
- Pure mechanical package rename — directory move, package declaration updates, import path updates across 2 consumer files + 1 CI workflow + 1 stale comment.
- Add a new `internal/proxy/hooks.go` file defining the `Hook` interface, `RequestContext` struct, and `Registry` type. Not wired into `ServeHTTP` in this plan — it is a new extension point that later plans will use.
- Session field rename (`llmProxyURL` → ???) is **deferred**: the name `ProxyURL` is already taken by the netmonitor transparent proxy in `internal/session/manager.go:57`. Resolving that collision is out of scope for Plan 1 and should happen in a dedicated plan that can touch both subsystems together.

**Tech Stack:** Go. No new dependencies.

**What is explicitly NOT in this plan:**
- No migration of `DLPProcessor`, `MCP interception`, or `DialectDetector` to the Hook interface. Those stay as direct method calls in `proxy.go` exactly as they are today.
- No split of `dlp.go`, `dialect.go`, `mcp_*.go` into an `internal/proxy/llm` subpackage. Spec Section 1 calls for that split; it is deferred to a later plan so Plan 1 stays purely mechanical.
- No rename of session struct fields / methods (`llmProxyURL`, `LLMProxyURL()`, `SetLLMProxy`, `CloseLLMProxy`, `LLMProxyEnvVars`, `types.Session.LLMProxyURL`). These remain as-is because the obvious target name collides with the existing netmonitor proxy.
- No rename of audit event types (`llm_logs` compatibility shim is deferred — no Go code actually emits that string anyway, it only appears in a comment in `proxy.go:84`).
- No addition of `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` environment variables. That change belongs with the MVP integration plan (Plan 4) where the substituting proxy handles non-LLM services.

---

## File Structure

**Files moved (via `git mv internal/llmproxy internal/proxy`):**

Every file in `internal/llmproxy/` moves to `internal/proxy/`:

```
internal/llmproxy/dialect.go                  → internal/proxy/dialect.go
internal/llmproxy/dialect_test.go             → internal/proxy/dialect_test.go
internal/llmproxy/dlp.go                      → internal/proxy/dlp.go
internal/llmproxy/dlp_test.go                 → internal/proxy/dlp_test.go
internal/llmproxy/integration_test.go         → internal/proxy/integration_test.go
internal/llmproxy/llm_ratelimit.go            → internal/proxy/llm_ratelimit.go
internal/llmproxy/mcp_intercept.go            → internal/proxy/mcp_intercept.go
internal/llmproxy/mcp_intercept_test.go       → internal/proxy/mcp_intercept_test.go
internal/llmproxy/mcp_streaming.go            → internal/proxy/mcp_streaming.go
internal/llmproxy/mcp_streaming_test.go       → internal/proxy/mcp_streaming_test.go
internal/llmproxy/proxy.go                    → internal/proxy/proxy.go
internal/llmproxy/proxy_ratelimit_test.go     → internal/proxy/proxy_ratelimit_test.go
internal/llmproxy/proxy_test.go               → internal/proxy/proxy_test.go
internal/llmproxy/retention.go                → internal/proxy/retention.go
internal/llmproxy/retention_integration_test.go → internal/proxy/retention_integration_test.go
internal/llmproxy/retention_test.go           → internal/proxy/retention_test.go
internal/llmproxy/sse_intercept.go            → internal/proxy/sse_intercept.go
internal/llmproxy/sse_intercept_test.go       → internal/proxy/sse_intercept_test.go
internal/llmproxy/sse_realtime_test.go        → internal/proxy/sse_realtime_test.go
internal/llmproxy/storage.go                  → internal/proxy/storage.go
internal/llmproxy/storage_test.go             → internal/proxy/storage_test.go
internal/llmproxy/streaming.go                → internal/proxy/streaming.go
internal/llmproxy/streaming_test.go           → internal/proxy/streaming_test.go
internal/llmproxy/usage.go                    → internal/proxy/usage.go
internal/llmproxy/usage_test.go               → internal/proxy/usage_test.go
```

25 files in total.

**Files modified (in-place edits):**

- `internal/api/app.go:21` — update import path
- `internal/api/app.go:503,1211,1224` — update `llmproxy.Proxy` → `proxy.Proxy`, `llmproxy.ProxyStatus` → `proxy.ProxyStatus` (and update the local import alias if needed)
- `internal/session/llmproxy.go:12` — update import path
- `internal/session/llmproxy.go:42,51` — update `llmproxy.Config` → `proxy.Config`, `llmproxy.New` → `proxy.New`
- `internal/session/manager.go:62` — update stale comment `*llmproxy.Proxy` → `*proxy.Proxy`
- `.github/workflows/ci.yml:209` — update integration test path `./internal/llmproxy/...` → `./internal/proxy/...`

Every moved `.go` file also needs its `package llmproxy` line changed to `package proxy`. 25 files.

**Files created:**

- `internal/proxy/hooks.go` — new file, defines `Hook` interface, `RequestContext`, `Registry`.
- `internal/proxy/hooks_test.go` — new file, tests the `Registry` (register + apply order).

---

## Task 1: Move the directory and update package declarations

**Files:**
- Move: `internal/llmproxy/*` → `internal/proxy/*`
- Modify: every `.go` file in the moved directory (`package llmproxy` → `package proxy`)
- Modify: doc comment on `internal/proxy/dialect.go:1` (currently `// Package llmproxy provides ...`)

- [ ] **Step 1: Verify no package named `proxy` already exists in the repo**

Run: grep for `^package proxy$` in all Go files under the repo.
```bash
grep -rn '^package proxy$' --include='*.go' .
```
Expected: **no output**. If any file prints, stop and flag it — there is already a `proxy` package somewhere that will collide.

- [ ] **Step 2: Verify the target directory does not exist**

Run: `ls internal/proxy 2>&1`
Expected: `ls: cannot access 'internal/proxy': No such file or directory`. If it exists, stop and investigate.

- [ ] **Step 3: Move the directory with git**

Run:
```bash
git mv internal/llmproxy internal/proxy
```
Expected: no stdout, exit 0. Verify with:
```bash
ls internal/proxy | head
```
Expected: lists `dialect.go`, `dlp.go`, `proxy.go`, ... (25 files total).

- [ ] **Step 4: Update package declaration in every Go file in the new directory**

The existing files all declare `package llmproxy`. Change each one to `package proxy`. One file — `dialect.go` — has a package doc comment that references `llmproxy`; update that too.

Run this one-liner to do the mechanical substitution:
```bash
find internal/proxy -name '*.go' -exec sed -i 's/^package llmproxy$/package proxy/' {} +
```

Then handle the doc comment in `dialect.go` manually. Open `internal/proxy/dialect.go` and change lines 1–4 from:

```go
// Package llmproxy provides an embedded HTTP proxy for intercepting LLM API requests.
// It supports multiple LLM providers (Anthropic, OpenAI) in passthrough mode with
// optional DLP (Data Loss Prevention) processing.
package proxy
```

to:

```go
// Package proxy provides an embedded HTTP proxy for intercepting outbound
// requests from the sandboxed agent. It supports multiple LLM providers
// (Anthropic, OpenAI) in passthrough mode with optional DLP (Data Loss
// Prevention) processing. In later releases it will also host generic
// egress substitution for non-LLM services.
package proxy
```

- [ ] **Step 5: Update stale header path comments in 3 files**

Three files have the old path in a header comment on line 1 that is not caught by the `package` sed substitution:

```
internal/proxy/usage.go:1         // internal/llmproxy/usage.go
internal/proxy/usage_test.go:1    // internal/llmproxy/usage_test.go
internal/proxy/dialect_test.go:1  // internal/llmproxy/dialect_test.go
```

Fix each one in place. For example, open `internal/proxy/usage.go` and change line 1 from:

```go
// internal/llmproxy/usage.go
```

to:

```go
// internal/proxy/usage.go
```

Do the same for `usage_test.go` and `dialect_test.go`.

Verify with:
```bash
grep -rn 'internal/llmproxy' --include='*.go' internal/proxy/
```
Expected: **no output**.

Note: the comment in `internal/proxy/proxy.go:84` (`// storagePath is like ~/.agentsh/sessions/<session-id>/llm-logs`) is fine and should be left alone — the directory is still called `llm-logs` on disk, and this comment is not about the Go package name.

- [ ] **Step 6: Verify all package declarations are updated**

Run:
```bash
grep -rn '^package llmproxy' internal/proxy/
```
Expected: **no output**.

```bash
grep -rn '^package proxy$' internal/proxy/ | wc -l
```
Expected: `25`.

- [ ] **Step 7: Verify the build breaks at external consumers (expected)**

Run: `go build ./...`
Expected: compile errors in `internal/api/app.go` and `internal/session/llmproxy.go` because they still import `internal/llmproxy`. This is expected — Task 2 fixes them. Do NOT commit yet.

---

## Task 2: Update imports in external consumers

**Files:**
- Modify: `internal/api/app.go` (import + 3 type references)
- Modify: `internal/session/llmproxy.go` (import + 2 type references)
- Modify: `internal/session/manager.go:62` (stale comment)

- [ ] **Step 1: Update `internal/api/app.go` import**

Open `internal/api/app.go`. Line 21 currently reads:
```go
	"github.com/agentsh/agentsh/internal/llmproxy"
```

Change to:
```go
	"github.com/agentsh/agentsh/internal/proxy"
```

- [ ] **Step 2: Update `internal/api/app.go` type references**

Same file has three references to `llmproxy.*`. Find them with:
```bash
grep -n 'llmproxy\.' internal/api/app.go
```
Expected output (line numbers approximate):
```
503:		if proxy, ok := proxyInst.(*llmproxy.Proxy); ok {
1211:		status := llmproxy.ProxyStatus{
1224:		if proxy, ok := proxyInst.(*llmproxy.Proxy); ok && proxy != nil {
```

**Problem:** the local variable name `proxy` will shadow the imported package name `proxy` after the rename. There are two such blocks.

**Block 1: starts at ~line 503, extends to ~line 555.** Read the whole block first (`proxyInst := s.ProxyInstance()` on the line before, through the closing `}` of the `if proxy, ok := ...` block). Inside the block, the variable `proxy` is used on multiple lines — e.g.:

```go
if proxy, ok := proxyInst.(*llmproxy.Proxy); ok {
    ...
    proxy.SetEventCallback(func(ev mcpinspect.MCPToolCallInterceptedEvent) { ... })
    ...
    proxy.SetSessionAnalyzer(analyzer)
    ...
}
```

Rename the local variable `proxy` to `p` at the declaration site AND every use inside the block. The `ok` identifier stays. After the edit the block opens with:

```go
if p, ok := proxyInst.(*proxy.Proxy); ok {
    ...
    p.SetEventCallback(func(ev mcpinspect.MCPToolCallInterceptedEvent) { ... })
    ...
    p.SetSessionAnalyzer(analyzer)
    ...
}
```

**Block 2: starts at ~line 1224, extends ~7 lines.** Shorter. The pattern:

```go
if proxy, ok := proxyInst.(*llmproxy.Proxy); ok && proxy != nil {
    var err error
    status, err = proxy.Stats()
    ...
}
```

becomes:

```go
if p, ok := proxyInst.(*proxy.Proxy); ok && p != nil {
    var err error
    status, err = p.Stats()
    ...
}
```

**Line 1211:** just `status := llmproxy.ProxyStatus{...}` — no local variable collision — rewrite as `status := proxy.ProxyStatus{...}`.

After editing, re-run the grep to confirm no stale references remain:
```bash
grep -n 'llmproxy\.' internal/api/app.go
```
Expected: **no output**.

- [ ] **Step 3: Update `internal/session/llmproxy.go` import**

Open `internal/session/llmproxy.go`. Line 12 currently reads:
```go
	"github.com/agentsh/agentsh/internal/llmproxy"
```

Change to:
```go
	"github.com/agentsh/agentsh/internal/proxy"
```

- [ ] **Step 4: Update `internal/session/llmproxy.go` type references**

Same file has two references. Find with:
```bash
grep -n 'llmproxy\.' internal/session/llmproxy.go
```
Expected:
```
42:	cfg := llmproxy.Config{
51:	proxy, err := llmproxy.New(cfg, storagePath, logger)
```

**Line 42** becomes simply `cfg := proxy.Config{...}` (no collision).

**Line 51** has the same local-variable shadow problem as `app.go`. The local variable `proxy` is declared on this line and then used further down the function. Find all uses with:
```bash
grep -n '\bproxy\b' internal/session/llmproxy.go
```
Expected hits (outside the package import on line 12) include lines ~51, 72, 78, 83, 86, 95, 100 — roughly:

```go
proxy, err := llmproxy.New(cfg, storagePath, logger)
...
proxy.SetRegistry(registry)
...
if err := proxy.Start(ctx); err != nil { ... }
...
addr := proxy.Addr()
...
_ = proxy.Stop(ctx)
...
return proxy.Stop(ctx)
...
sess.SetProxyInstance(proxy)
```

Rename the local variable `proxy` to `p` at every occurrence inside the function. Do NOT touch `proxyCfg` (a different variable), `proxyURL` (a different variable), `sess.SetProxyInstance` (a method call, not the variable `proxy`), or the package alias `proxy` that appears in type references.

After the edit, line 51 becomes:

```go
p, err := proxy.New(cfg, storagePath, logger)
```

and every subsequent use of `proxy` as a method receiver becomes `p.SetRegistry(...)`, `p.Start(...)`, `p.Addr()`, `p.Stop(...)`, `sess.SetProxyInstance(p)`.

Verify with:
```bash
grep -n 'llmproxy\.' internal/session/llmproxy.go
```
Expected: **no output**.

- [ ] **Step 5: Update the stale comment in `internal/session/manager.go`**

Open `internal/session/manager.go`. Line 62 currently reads:
```go
	llmProxy      interface{}   // *llmproxy.Proxy - stored as interface to avoid import cycle
```

Change the comment to:
```go
	llmProxy      interface{}   // *proxy.Proxy - stored as interface to avoid import cycle
```

Leave the field name `llmProxy` unchanged (see the "NOT in this plan" section at the top — session field renames are deferred).

- [ ] **Step 6: Build the whole repo**

Run: `go build ./...`
Expected: exit 0, no errors. If there are errors, read them carefully — the most likely cause is a leftover `llmproxy.` reference somewhere we missed. Run:
```bash
grep -rn 'llmproxy\.' --include='*.go' .
```
Expected: no hits (the only remaining hit might be the comment on manager.go:62 which we already fixed). Any other hit is a bug — fix it and re-run `go build ./...`.

- [ ] **Step 7: Run all tests**

Run: `go test ./...`
Expected: all tests pass. Some test files in `internal/proxy/` may be slow; give the run a few minutes. If any tests fail, read the failure — it should be a leftover import we missed, not a behavior change.

- [ ] **Step 8: Verify Windows cross-compile**

Per `CLAUDE.md` and `AGENTS.md`, always verify:
```bash
GOOS=windows go build ./...
```
Expected: exit 0, no errors. Some files in the repo use build tags for Linux-only functionality; cross-compile should still succeed because those files are excluded on Windows.

- [ ] **Step 9: Update the CI workflow path**

Open `.github/workflows/ci.yml`. Line 209 currently reads:
```yaml
        run: go test -v -tags=integration ./internal/api/... ./internal/llmproxy/...
```

Change to:
```yaml
        run: go test -v -tags=integration ./internal/api/... ./internal/proxy/...
```

- [ ] **Step 10: Stage and review the diff**

Run:
```bash
git status
git diff --stat
```
Expected: the status shows 25 renames under `internal/llmproxy/ -> internal/proxy/`, plus modifications to `internal/api/app.go`, `internal/session/llmproxy.go`, `internal/session/manager.go`, and `.github/workflows/ci.yml`.

Spot-check the diff on one moved file to confirm git recognized it as a rename (not delete + add):
```bash
git diff internal/proxy/proxy.go | head -5
```
Expected: shows a diff header like `diff --git a/internal/llmproxy/proxy.go b/internal/proxy/proxy.go` and `rename from ... rename to ...` rather than a big `+`/`-` block.

- [ ] **Step 11: Commit**

```bash
git add -A internal/proxy internal/llmproxy internal/api/app.go internal/session/llmproxy.go internal/session/manager.go .github/workflows/ci.yml
git commit -m "$(cat <<'EOF'
refactor: rename internal/llmproxy to internal/proxy

Mechanical rename only. No behavior changes. Unblocks the external-
secrets design (docs/superpowers/specs/2026-04-07-external-secrets-design.md)
which turns this package into the generic HTTP substituting proxy.

Session field names (llmProxyURL, LLMProxyURL(), etc.) are left as-is
because the target name "ProxyURL" collides with the existing netmonitor
transparent proxy. That rename is deferred to a dedicated plan.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

Expected: commit succeeds. `git log -1 --stat` shows ~30 files changed, mostly renames.

---

## Task 3: Add the Hook interface skeleton

**Files:**
- Create: `internal/proxy/hooks.go`
- Create: `internal/proxy/hooks_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/proxy/hooks_test.go` with the following content:

```go
package proxy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeHook is a test double that records every call and can be configured
// to return an error on PreHook or PostHook.
type fakeHook struct {
	name     string
	preErr   error
	postErr  error
	preCalls int
	postCalls int
}

func (h *fakeHook) Name() string { return h.name }

func (h *fakeHook) PreHook(_ *http.Request, _ *RequestContext) error {
	h.preCalls++
	return h.preErr
}

func (h *fakeHook) PostHook(_ *http.Response, _ *RequestContext) error {
	h.postCalls++
	return h.postErr
}

func TestRegistry_RegisterAndApply(t *testing.T) {
	r := NewRegistry()
	h1 := &fakeHook{name: "first"}
	h2 := &fakeHook{name: "second"}
	r.Register("anthropic", h1)
	r.Register("anthropic", h2)

	req := httptest.NewRequest(http.MethodPost, "http://example/", nil)
	ctx := &RequestContext{RequestID: "r1", SessionID: "s1", ServiceName: "anthropic"}

	if err := r.ApplyPreHooks("anthropic", req, ctx); err != nil {
		t.Fatalf("ApplyPreHooks returned unexpected error: %v", err)
	}
	if h1.preCalls != 1 || h2.preCalls != 1 {
		t.Errorf("expected both hooks called once on pre, got h1=%d h2=%d", h1.preCalls, h2.preCalls)
	}

	resp := &http.Response{StatusCode: http.StatusOK}
	if err := r.ApplyPostHooks("anthropic", resp, ctx); err != nil {
		t.Fatalf("ApplyPostHooks returned unexpected error: %v", err)
	}
	if h1.postCalls != 1 || h2.postCalls != 1 {
		t.Errorf("expected both hooks called once on post, got h1=%d h2=%d", h1.postCalls, h2.postCalls)
	}
}

func TestRegistry_UnknownServiceIsNoOp(t *testing.T) {
	r := NewRegistry()
	h := &fakeHook{name: "unused"}
	r.Register("anthropic", h)

	req := httptest.NewRequest(http.MethodPost, "http://example/", nil)
	ctx := &RequestContext{RequestID: "r1", ServiceName: "github"}

	if err := r.ApplyPreHooks("github", req, ctx); err != nil {
		t.Fatalf("ApplyPreHooks unknown service returned error: %v", err)
	}
	if h.preCalls != 0 {
		t.Errorf("expected zero calls for unrelated service, got %d", h.preCalls)
	}
}

func TestRegistry_EmptyServiceNameRunsGlobally(t *testing.T) {
	r := NewRegistry()
	global := &fakeHook{name: "global"}
	scoped := &fakeHook{name: "scoped"}
	r.Register("", global)
	r.Register("anthropic", scoped)

	req := httptest.NewRequest(http.MethodPost, "http://example/", nil)
	ctx := &RequestContext{RequestID: "r1", ServiceName: "anthropic"}

	if err := r.ApplyPreHooks("anthropic", req, ctx); err != nil {
		t.Fatalf("ApplyPreHooks returned error: %v", err)
	}
	if global.preCalls != 1 {
		t.Errorf("global hook should run for every service; got %d calls", global.preCalls)
	}
	if scoped.preCalls != 1 {
		t.Errorf("scoped hook should run for its service; got %d calls", scoped.preCalls)
	}
}

func TestRegistry_PreHookErrorShortCircuits(t *testing.T) {
	r := NewRegistry()
	boom := errors.New("pre boom")
	h1 := &fakeHook{name: "first", preErr: boom}
	h2 := &fakeHook{name: "second"}
	r.Register("svc", h1)
	r.Register("svc", h2)

	req := httptest.NewRequest(http.MethodPost, "http://example/", nil)
	ctx := &RequestContext{RequestID: "r1", ServiceName: "svc"}

	err := r.ApplyPreHooks("svc", req, ctx)
	if !errors.Is(err, boom) {
		t.Fatalf("expected boom error, got %v", err)
	}
	if h1.preCalls != 1 {
		t.Errorf("first hook should have been called once, got %d", h1.preCalls)
	}
	if h2.preCalls != 0 {
		t.Errorf("second hook should NOT have been called after first failed, got %d", h2.preCalls)
	}
}

func TestRegistry_PostHookErrorsCollected(t *testing.T) {
	r := NewRegistry()
	boom1 := errors.New("post boom 1")
	boom2 := errors.New("post boom 2")
	h1 := &fakeHook{name: "first", postErr: boom1}
	h2 := &fakeHook{name: "second", postErr: boom2}
	r.Register("svc", h1)
	r.Register("svc", h2)

	resp := &http.Response{StatusCode: http.StatusOK}
	ctx := &RequestContext{RequestID: "r1", ServiceName: "svc"}

	err := r.ApplyPostHooks("svc", resp, ctx)
	if !errors.Is(err, boom1) {
		t.Fatalf("expected first error returned, got %v", err)
	}
	if h1.postCalls != 1 || h2.postCalls != 1 {
		t.Errorf("both post hooks should run even on error, got h1=%d h2=%d", h1.postCalls, h2.postCalls)
	}
}
```

- [ ] **Step 2: Run the test and verify it fails**

Run:
```bash
go test ./internal/proxy/ -run TestRegistry -v
```
Expected: **compile error**. The test file references `NewRegistry`, `Hook`, `RequestContext`, `Registry.Register`, `ApplyPreHooks`, `ApplyPostHooks` which do not exist yet. The error should be something like `undefined: NewRegistry`.

- [ ] **Step 3: Create the Hook interface file**

Create `internal/proxy/hooks.go` with the following content:

```go
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
func (r *Registry) Register(serviceName string, h Hook) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hooks[serviceName] = append(r.hooks[serviceName], h)
}

// ApplyPreHooks invokes PreHook on each hook registered under the empty
// service name followed by each hook registered under serviceName, in
// registration order. It stops at the first non-nil error and returns
// it. Hooks that have not been reached are not invoked.
func (r *Registry) ApplyPreHooks(serviceName string, req *http.Request, ctx *RequestContext) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, h := range r.hooks[""] {
		if err := h.PreHook(req, ctx); err != nil {
			return err
		}
	}
	if serviceName != "" {
		for _, h := range r.hooks[serviceName] {
			if err := h.PreHook(req, ctx); err != nil {
				return err
			}
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
	r.mu.RLock()
	defer r.mu.RUnlock()
	var firstErr error
	for _, h := range r.hooks[""] {
		if err := h.PostHook(resp, ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if serviceName != "" {
		for _, h := range r.hooks[serviceName] {
			if err := h.PostHook(resp, ctx); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
```

- [ ] **Step 4: Run the tests and verify they pass**

Run:
```bash
go test ./internal/proxy/ -run TestRegistry -v
```
Expected output (abbreviated):
```
=== RUN   TestRegistry_RegisterAndApply
--- PASS: TestRegistry_RegisterAndApply
=== RUN   TestRegistry_UnknownServiceIsNoOp
--- PASS: TestRegistry_UnknownServiceIsNoOp
=== RUN   TestRegistry_EmptyServiceNameRunsGlobally
--- PASS: TestRegistry_EmptyServiceNameRunsGlobally
=== RUN   TestRegistry_PreHookErrorShortCircuits
--- PASS: TestRegistry_PreHookErrorShortCircuits
=== RUN   TestRegistry_PostHookErrorsCollected
--- PASS: TestRegistry_PostHookErrorsCollected
PASS
ok  	github.com/agentsh/agentsh/internal/proxy
```

Five passes. If any fail, read the failure and fix the implementation in `hooks.go`.

- [ ] **Step 5: Run the full test suite**

Run: `go test ./...`
Expected: all tests pass (including all the previously-passing `internal/proxy/` tests that were moved from `internal/llmproxy/`). This confirms adding `hooks.go` did not break anything. The test count should equal the pre-Task-3 count plus the 5 new tests.

- [ ] **Step 6: Verify Windows cross-compile**

Run: `GOOS=windows go build ./...`
Expected: exit 0. `hooks.go` uses only `net/http`, `sync`, `time` — all cross-platform.

- [ ] **Step 7: Commit**

```bash
git add internal/proxy/hooks.go internal/proxy/hooks_test.go
git commit -m "$(cat <<'EOF'
feat(proxy): add Hook interface extension point

Introduces Hook, RequestContext, and Registry in internal/proxy as the
extension point that later plans will use to migrate DLP, MCP
interception, and dialect-specific behavior out of the generic proxy
core. The Registry is not yet wired into ServeHTTP — this change is
purely additive.

See docs/superpowers/specs/2026-04-07-external-secrets-design.md
Section 1 for the migration target.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
EOF
)"
```

Expected: commit succeeds. `git log -1 --stat` shows `internal/proxy/hooks.go` (~150 lines) and `internal/proxy/hooks_test.go` (~130 lines) as new files.

---

## Task 4: Final verification

- [ ] **Step 1: Full build**

Run: `go build ./...`
Expected: exit 0.

- [ ] **Step 2: Full test**

Run: `go test ./...`
Expected: all tests pass. Note the time this takes — the `internal/proxy/` package has several large integration tests (`proxy_test.go` is ~1966 lines, `mcp_intercept_test.go` is ~1970 lines) and they may take 30–120 seconds.

- [ ] **Step 3: Cross-compile verify (Windows)**

Run: `GOOS=windows go build ./...`
Expected: exit 0.

- [ ] **Step 4: Verify git log is clean**

Run: `git log --oneline main..HEAD`
Expected: exactly 2 commits:
- `feat(proxy): add Hook interface extension point`
- `refactor: rename internal/llmproxy to internal/proxy`

- [ ] **Step 5: Verify no stale `llmproxy` references remain anywhere (except in docs)**

Run:
```bash
grep -rn 'llmproxy' --include='*.go' --include='*.yml' --include='*.yaml' .
```
Expected: **no output**. Stale references in `docs/plans/` (historical plan files) are acceptable — do not touch those. Stale references in `docs/superpowers/specs/2026-04-07-external-secrets-design.md` are the design spec which explicitly uses the old name in the "before" state — leave those too.

If the grep finds any non-doc hit, fix it and amend the most recent commit.

---

## Self-review checklist (for the implementer, before marking this plan done)

- [ ] Every `.go` file in `internal/proxy/` starts with `package proxy` (25 files)
- [ ] No `.go` file anywhere imports `github.com/agentsh/agentsh/internal/llmproxy`
- [ ] `go build ./...` passes
- [ ] `go test ./...` passes (same pre-existing tests + 5 new registry tests)
- [ ] `GOOS=windows go build ./...` passes
- [ ] `.github/workflows/ci.yml` references `./internal/proxy/...` not `./internal/llmproxy/...`
- [ ] `internal/proxy/hooks.go` and `internal/proxy/hooks_test.go` exist
- [ ] Two commits exist on the branch: the rename and the hook interface

---

## Notes for Plan 2 and beyond

After Plan 1 is merged:

- **Session field rename** (`llmProxyURL` → something) is still pending. The current name conflicts with `s.ProxyURL()` (netmonitor). A separate plan should pick a new name — candidates include `AppProxyURL`, `EgressProxyURL`, `SubstProxyURL` — and rename consistently across `internal/session/manager.go`, `internal/session/llmproxy.go` (which will itself be renamed to `proxy.go` at that point), `internal/cli/wrap.go`, `internal/api/exec.go`, `pkg/types/sessions.go`, and all tests.

- **Hook migration** (DLP, MCP, dialect, SSE) into the new `Hook` interface is deferred. The relevant refactor is that `proxy.go:ServeHTTP` currently calls `p.dlp.Process(...)`, `p.detector.Detect(...)`, `interceptMCPToolCalls(...)` inline. A later plan should:
  1. Define `dlpHook`, `mcpHook`, `dialectHook` structs in an `internal/proxy/llm/` subpackage
  2. Move the relevant files to that subpackage
  3. Update the proxy constructor to accept a `*Registry` and look it up instead of holding the concrete types as struct fields
  4. Keep all existing tests passing

- **`Hook` interface may grow** as Plan 4 wires in the substitution table and discovers the real set of state that hooks need to see. Add fields to `RequestContext` rather than changing the interface signature.
