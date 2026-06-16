# Decision-Context Policy Resolution from Watchtower

**Date:** 2026-06-16
**Status:** Design — approved for planning
**Author:** Eran Sandler (with Claude)

## Summary

AgentSH should be able to ask Watchtower (WT) which policy to enforce for a
session, based on a **decision context** it gathers locally. The context
includes identity signals (the signed-in OS user, or the Tailscale identity
when Tailscale is up) plus environmental signals (hostname, configured tags),
and is **extensible**. Watchtower owns all mapping logic and returns a **signed**
policy. AgentSH stays free of policy-selection logic.

The link already exists: the AgentSH↔WT WTP transport is a bidirectional gRPC
stream and already supports server-pushed **signed** policies
(`SessionAck` → `OnPolicyPushed`). This design adds a **session-correlated
request/response** on that same stream plus the local plumbing to gather
context, bootstrap safely, cache the last-known-good policy, and hot-swap when
WT answers.

## Goals

- Send a decision context to WT at session creation and enforce the policy WT
  returns, before the sandboxed process starts when possible.
- Never block session startup on WT availability: degrade to a safe bootstrap.
- Cache the last-known-good (signed) policy per context for fast, offline-capable
  startup.
- Keep all policy-selection logic on the WT side; AgentSH only reports context
  and enforces what it is given.
- Work on deployments with no WT configured (bootstrap-only) and on older WT
  servers that don't understand the new messages (graceful degrade).

## Non-goals (v1)

- Client-initiated re-resolution triggered by *local* context change (e.g.
  watching Tailscale go up/down mid-session). The wire contract supports it;
  it is a phase-2 extension. v1 resolves at creation and honors WT-initiated
  pushes at any time.
- Changing how policies are authored or signed by Watchtower.
- Any new second connection/credential path to WT.

## Key decisions (resolved during brainstorming)

1. **Timing — hybrid (block briefly, else bootstrap).** At creation, resolve
   context and wait for a WT answer up to a short timeout `T`. If WT answers in
   time, enforce before exec. If it times out, exec under the bootstrap policy
   and hot-swap when the answer arrives.
2. **Bootstrap/fallback order:** last-known-good (cached, signed, re-verified) →
   else `Config.Policies.Default` (deployed) → then the WT live answer
   hot-swaps the resolved policy.
3. **Context, not just identity.** AgentSH sends a *decision context*. Identity
   is one field. Core fields are typed; an open `extra` map allows new signals
   without a proto change.
4. **`user` is source-labeled** — `{ value, source: tailscale | os }`. The
   Tailscale identity, when available, fills the slot and is labeled
   `tailscale`; otherwise the OS user fills it labeled `os`. WT still sees which
   source produced the value (Tailscale is a stronger trust signal).
5. **Bundle all claims; WT decides.** AgentSH sends the whole context; WT owns
   the mapping. Last-known-good is cached keyed by a digest of the context.
6. **Transport — dedicated `PolicyRequest`/`PolicyResponse` on the existing
   stream.** Keeps event-session establishment separate from policy resolution,
   reuses the one authenticated/TLS stream, and naturally supports
   re-resolution.
7. **Deny — default `on_deny: lockdown`, `refuse` configurable.** WT-`Deny`
   installs a configurable lockdown (deny-most) policy via the normal swap path
   by default. `on_deny: refuse` is available for a hard gate: fail
   `createSession` if deny arrives before exec, terminate the running session if
   it arrives after.

## Architecture

Three new/extended units:

- **`ContextResolver`** *(new, local; package `internal/decisionctx`)* — pluggable
  sources produce a `DecisionContext`.
- **`PolicyCache`** *(new, local, on-disk; package `internal/policy/cache`)* —
  stores the last-known-good **signed** policy bundle keyed by a digest of the
  context.
- **WTP transport extension** — a session-correlated `PolicyRequest`/
  `PolicyResponse` multiplexed on the existing process-global stream, exposed to
  AgentSH as an optional `PolicyResolver` capability interface.

The WTP transport is **process-global**: `a.store` is a single `EventStore`
shared by all sessions, and the watchtower variant ships everything over one
stream, multiplexing sessions inside payloads. The existing
`SessionInit`/`SessionAck`/`OnPolicyPushed` operate at the **stream** level
(once per process) and therefore cannot express per-session resolution — which
is why a dedicated, session-correlated message pair is required.

### Data flow at `createSessionCore`

```
createSession(req)
  1. ctx := ContextResolver.Resolve()        // hostname, tags, user{value,source}, extra
  2. digest := ctx.Digest()
     bootstrap := PolicyCache.get(digest)     // verify sig; else Config.Policies.Default
     -> compile + install bootstrap engine
  3. if store implements PolicyResolver && WT advertised support:
        send PolicyRequest{sessionID, ctx, cachedHash}; await PolicyResponse up to T
          - answered:  verify sig -> compile -> install BEFORE exec; cache.put
          - timeout:   exec under bootstrap now
     else:
        exec under bootstrap (no request)
  4. exec sandboxed process
   ...later (timeout case OR WT-initiated re-push OR phase-2 context change):
     PolicyResponse / push arrives -> verify -> session.SetPolicyEngine() hot-swap -> cache.put
```

AgentSH always has *a* policy before exec (cache → default → WT). The WT answer
wins whenever it arrives.

## Components

### 1. `ContextResolver` — `internal/decisionctx` (local; no WT dependency)

```go
type User struct { Value string; Source string } // source: "tailscale" | "os"
type DecisionContext struct {
    Hostname string
    Tags     []string
    User     User
    Extra    map[string]string
}
func (c DecisionContext) Digest() string  // stable cache key; tags sorted before hashing

type Source interface { Name() string; Resolve(ctx context.Context, into *DecisionContext) error }
type Resolver struct { sources []Source } // ordered
func (r *Resolver) Resolve(ctx context.Context) (DecisionContext, error)
```

Sources: `hostname`, `config-tags` (from `cfg`), `os-user`, `tailscale`. Order
matters — `os-user` writes the `user` slot, then `tailscale` **overwrites** it
(`source: tailscale`) only if tailscaled is up. The tailscale source reads the
**local node's** identity via `local.Client.Status()` (`Self`/`User`), not
`WhoIs` (that is for remote peers), and degrades silently when absent. A source
erroring never fails resolution; it just omits its field (partial context).

The tailscale source depends on an injected local-client interface so it is
mockable and cross-compiles; it degrades when the daemon/socket is absent.

### 2. `PolicyCache` — `internal/policy/cache` (local, on-disk)

On-disk in the AgentSH state dir (next to `persistedAck`).

```go
type Entry struct { ResolvedPolicy; ContextDigest string; FetchedAt time.Time }
type Cache interface {
    Get(digest string) (*Entry, bool)  // returns ONLY if signature re-verifies
    Put(digest string, e Entry) error
}
```

Stores the **signed** bundle, so reusing a cache entry is trust-equivalent to a
fresh push. Reuses the existing signature verifier that `OnPolicyPushed` uses.

### 3. WTP transport extension (`PolicyResolver` capability)

Exposed as an **optional capability interface** so non-WT stores (local/sqlite)
keep working via type-assert:

```go
type PolicyResolver interface {
    RequestPolicy(ctx context.Context, sessionID string, dc DecisionContext, cachedHash string) (ResolvedPolicy, Outcome, error)
    SetSessionPolicyHandler(func(sessionID string, p ResolvedPolicy)) // WT-initiated re-push
}
// a.store.(PolicyResolver) — absent => bootstrap-only, no request
```

`RequestPolicy` sends a `PolicyRequest` with a fresh correlation id, registers a
waiter, and resolves on the matching `PolicyResponse` or ctx timeout.
Server-initiated pushes route by `session_id` to the handler.

### 4. `createSessionCore` integration — `internal/api/core.go`

A new helper `resolveSessionPolicy(ctx, req)`: resolve context → bootstrap from
cache/default → if `store` implements `PolicyResolver` and WT advertised
support, `RequestPolicy` with timeout `T` → install the winner via the existing
`compileDBPolicyForSession` + `SetPolicyEngine`. Registers the session so
re-pushes find it.

### 5. Hot-swap

Reuses existing `session.SetPolicyEngine()` (`internal/session/manager.go`); the
handler compiles pushed YAML → engine → swap under the session lock.

## Wire protocol (`canyonroad/wtp-protos` changes)

These land in the external `wtp-protos` repo first, then AgentSH bumps the
module — a cross-repo sequencing step (proto change → tag/release → `go get`
bump → regen).

```protobuf
enum UserSource { USER_SOURCE_UNSPECIFIED = 0; USER_SOURCE_OS = 1; USER_SOURCE_TAILSCALE = 2; }

message DecisionContext {
  string hostname = 1;
  repeated string tags = 2;
  message User { string value = 1; UserSource source = 2; }
  User user = 3;
  map<string, string> extra = 4;     // open extension — no schema bump for new signals
}

message PolicyRequest {              // added to ClientMessage oneof
  string correlation_id = 1;
  string session_id = 2;             // agentsh session (NOT the stream-level session)
  DecisionContext context = 3;
  string cached_content_hash = 4;    // lets WT answer "unchanged"
}

message PolicyResponse {             // added to ServerMessage oneof
  string correlation_id = 1;         // empty when server-initiated (re-push/revoke)
  string session_id = 2;
  oneof result {
    ResolvedPolicy policy = 3;       // REUSE the signed-policy message SessionAck already carries
    Unchanged      unchanged = 4;    // cached_content_hash still current -> keep cache
    Deny           deny = 5;
  }
}
```

Key points:

- `ResolvedPolicy` is **not** new — it is the existing signed-policy message
  `SessionAck`/`OnPolicyPushed` already uses (`policy_id`, `version`,
  `content_hash`, `content`, `signature`, `signer_key_id`, `overlay_ids`). Same
  verifier, same cache shape.
- **Correlation:** request carries a fresh `correlation_id`; the matching
  `PolicyResponse` resolves the waiter. A `PolicyResponse` with **empty**
  `correlation_id` but a set `session_id` is an **unsolicited** server push →
  routes to that session's hot-swap (re-resolution / revocation).
- **`cached_content_hash` → `Unchanged`:** on a returning context, the client
  sends its cached hash; WT replies `Unchanged` and the client keeps (and
  re-confirms) its cache — no content re-transfer.
- **Capability flag:** add `supports_policy_resolution` to the stream-level
  `SessionAck`. If the server doesn't advertise it (old WT), the client skips
  the request and goes straight to bootstrap instead of waiting out `T`. Adding
  oneof variants is wire-compatible, so old peers degrade safely.

## Error handling & security

- **Timeout / WT unreachable** — exec under bootstrap (cache → default); the
  later `PolicyResponse`/push hot-swaps. If `SessionAck` didn't advertise
  `supports_policy_resolution`, skip the wait entirely. Default `T` ~500ms–1s,
  configurable.
- **Signature & trust** — *every* `ResolvedPolicy` (fresh, cached, or re-pushed)
  is verified against `signer_key_id` before install **and** before cache write;
  cache entries are re-verified on load. An unverifiable signature is treated
  like unreachable → bootstrap + a security audit event (never installed).
  AgentSH is trusted to report `context` honestly (it already holds the WT
  bearer/cert); WT decides how much weight to give `source: os` vs
  `source: tailscale`.
- **Failure independence** — a source erroring degrades to partial context
  (omit `user`), never blocks creation. `store` not implementing
  `PolicyResolver` ⇒ silently bootstrap-only.
- **Hot-swap safety** — the engine pointer swaps under the session lock (atomic
  for subsequent checks). Documented accepted risk: a bootstrap→resolved swap
  going *looser→stricter* leaves a brief window where the agent already acted;
  mitigated by (a) bootstrap = last-known-good for returning contexts and (b)
  the block-briefly timing. No speculative complexity added (YAGNI).
- **Deny** — under the hybrid model deny can arrive before exec (within `T`) or
  after (timeout/mid-session revoke):
  - Default `on_deny: lockdown` — WT-`Deny` installs a configurable lockdown
    (deny-most) policy via the normal swap path; identical sync or async; the
    session stays observable.
  - `on_deny: refuse` — fail `createSession` if deny arrives before exec;
    **terminate** the running session if it arrives after.
- **Observability** — emit audit events for: context resolved (+source), policy
  requested, installed (`policy_id`/`version`/origin = wt|cache|default),
  timeout→bootstrap, signature failure, deny (+action), hot-swap. A
  denied/lockdown session **still emits**, so attempts are visible.
  ⚠️ New `events.EventType`s must also be registered in
  `internal/ocsf/registry.go` or the OCSF exhaustiveness test fails.

## Testing

Tests lead the implementation (TDD).

- **`ContextResolver` / sources (unit, table-driven):** os-user fills
  `user{source:os}`; tailscale-up overwrites → `user{source:tailscale}`;
  tailscale-absent/erroring leaves os-user and `Resolve` still succeeds (partial
  context); tailscale source mocked via injected client; `Digest()` stable,
  tags order-independent, changes on any field change.
- **`PolicyCache` (unit):** Put→Get round-trip; `Get` false on tampered
  content / bad signature / missing; persists across a fresh `Cache` instance.
- **WTP transport extension (unit, fake stream):** `RequestPolicy` emits
  `PolicyRequest` w/ correlation id and resolves on the match; deadline →
  timeout outcome; `Unchanged`/`Deny` outcomes; unsolicited response (empty
  correlation + session_id) routes to the session handler; correlation mismatch
  ignored; capability-absent short-circuits.
- **`createSessionCore` integration (extend `internal/store/watchtower/testserver`
  to answer `PolicyRequest`):** answer within `T` → resolved enforced before
  exec; timeout → cache bootstrap, later push hot-swaps; no-cache+timeout →
  default; no `PolicyResolver` → bootstrap-only; deny sync + `refuse` → create
  fails; deny async + `refuse` → running session terminated; deny + `lockdown` →
  lockdown installed; bad signature → bootstrap + security event.
- **Cross-cutting gates (AGENTS.md/CLAUDE.md):** full `go test ./...` (catches
  the OCSF exhaustiveness test) and `GOOS=windows go build ./...` (tailscale
  source compiles cross-platform and degrades when the socket is absent).

## Open items for planning

- Confirm the exact existing signed-policy proto message name to reuse for
  `ResolvedPolicy`, and the verifier entrypoint used by `OnPolicyPushed`.
- Confirm the AgentSH state-dir path used for `persistedAck` to co-locate the
  policy cache.
- Decide config surface: `T` timeout, `on_deny` mode, lockdown policy name,
  static `tags`, enable/disable tailscale source.
- Confirm `session.SetPolicyEngine` is safe to call on a running session from the
  push-handler goroutine (locking).
