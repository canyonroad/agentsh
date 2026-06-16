# Decision-Context Policy Resolution from Watchtower

**Date:** 2026-06-16
**Status:** Design — approved for planning (revised to approach A after grounding on `main`)
**Author:** Eran Sandler (with Claude)

## Summary

AgentSH should report a **decision context** to Watchtower (WT) so WT can resolve
which signed policy the agent enforces. The context includes identity signals
(the signed-in OS user, or the Tailscale identity when Tailscale is up) plus
environmental signals (hostname, configured tags), and is **extensible**. WT owns
all mapping logic; AgentSH only reports context and enforces what WT installs.

Grounding against `main` showed the protocol **already implements** an
agent-level resolve/deliver/re-resolve loop, so this feature is small:

- `SessionInit` already carries identity (`agent_id`, `context_digest`) and WT
  already resolves a bound policy and ships it in `SessionAck`'s policy fields.
- `SessionUpdate` (client→server) already signals **context change**; WT answers
  mid-session with `PolicyPush`.
- `makePolicyInstallHook` (`internal/server/wtp.go`) already verifies
  (ed25519 + sha256 against a local trust store) and installs by writing the
  signed YAML to `{policies.dir}/{policy_id}.yaml` + `Manager.Reload()` /
  `SwapPolicy`.
- `createSessionCore` already loads that file and re-verifies its signature.

So the work is: **add a `DecisionContext` message to the proto, carry it on
`SessionInit` (and `SessionUpdate`), and populate it on the agent from a new
`ContextResolver`.** The install path, signature verification, on-disk
persistence (which doubles as last-known-good), and re-resolution channel all
already exist and are reused unchanged.

## Decisions (resolved during brainstorming + grounding)

1. **Context, not just identity.** AgentSH sends a *decision context*; identity
   is one field. Core fields are typed; an open `extra` map allows new signals
   without a proto change.
2. **`user` is source-labeled** — `{ value, source: tailscale | os }`. The
   Tailscale identity, when available, fills the slot labeled `tailscale`;
   otherwise the OS user fills it labeled `os`.
3. **Bundle all signals; WT decides.** AgentSH sends the whole context; WT owns
   the mapping.
4. **Agent/process-level resolution.** The context (hostname/tags/user) is a
   property of the agent process/host, identical across every `createSession`
   in that process. Resolution happens once per agent stream (`SessionInit`),
   re-resolution via `SessionUpdate` on context change. No per-session
   correlation, no per-session in-memory engine swap.
5. **Approach A — extend `SessionInit`/`SessionUpdate`**, not a new
   `PolicyRequest`/`PolicyResponse`. The existing SessionInit→SessionAck and
   SessionUpdate→PolicyPush flows already are the agent-level request/response.
6. **Reuse the existing install + persistence path.** `makePolicyInstallHook`
   writes the resolved signed YAML to `policies.dir`; that file is the
   last-known-good bootstrap, loaded and re-verified by `createSessionCore`.
   No separate policy cache is introduced.
7. **Deny** maps onto the protocol's existing semantics: `policy_id == ""` means
   "unbind → revert to local file policy"; a restrictive ("lockdown") outcome is
   just a restrictive policy WT returns and the agent installs normally.
8. **`wtp-protos` workflow:** add the messages to a local clone of
   `github.com/canyonroad/wtp-protos`, regenerate with `make gen`, and wire a
   temporary `replace` in agentsh's `go.mod` for development. A real `v0.2.0`
   release replaces the `replace` later.

## Non-goals (v1)

- **Watchtower server-side resolution logic** — the mapping of DecisionContext →
  policy lives in the Watchtower server (separate repo: `canyonroad/watchtower`),
  not in agentsh. agentsh only *reports* context and *installs* what WT returns.
- **Mid-session re-resolution on local context change** (watching Tailscale go
  up/down and emitting `SessionUpdate`). The wire supports it; v1 resolves at
  `SessionInit`. Phase-2 extension.
- Changing how policies are signed, the install hook, or the integrity chain's
  `context_digest` (that field is owned by `chain.ComputeContextDigest` and is
  NOT repurposed).

## Architecture

One new local unit plus thin wiring; everything downstream is reused.

- **`ContextResolver`** *(new; package `internal/decisionctx`)* — pluggable
  sources produce a `DecisionContext`.
- **Wiring** — `buildWatchtowerStore` (`internal/server/wtp.go`) builds the
  `DecisionContext` and passes it through `watchtower.Options` →
  `transport.Options` → `sessionInit()`, alongside the existing `ContextDigest`
  (which is left untouched).
- **Reused unchanged** — `makePolicyInstallHook` (verify + write signed YAML +
  reload/swap), `createSessionCore` (load + verify the on-disk file),
  `SessionAck`/`PolicyPush` delivery, the integrity chain.

### Data flow

```
agent process start
  -> ContextResolver.Resolve()         // hostname, tags, user{value,source}, extra
  -> watchtower store built with DecisionContext
  ...WTP stream connects...
  -> SessionInit{ ..., decision_context }  ──► Watchtower
  Watchtower resolves policy from context  ──► SessionAck{ policy_* (signed) }
  -> makePolicyInstallHook: verify (ed25519+sha256) -> write {policies.dir}/{id}.yaml -> reload/SwapPolicy

createSession(req)  (any time)
  -> loads {policies.dir}/{policyName}.yaml (+ .sig verify)   // installed policy or local default = bootstrap

mid-session policy change (WT-initiated)
  -> PolicyPush{ policy_* } ──► same install hook (idempotent)

phase-2: local context change (Tailscale up/down)
  -> SessionUpdate{ decision_context } ──► Watchtower ──► PolicyPush
```

If WT is unreachable or returns `policy_id == ""`, the agent simply runs the
existing on-disk policy (last installed, or the configured local default) —
already the current behavior. No new bootstrap/timeout logic is required.

## Proto changes (`canyonroad/wtp-protos`)

In `proto/canyonroad/wtp/v1/wtp.proto`. Adding a message and optional fields is
non-breaking under the repo's `breaking: FILE` buf rule. Regenerate with
`make gen` (`buf lint && buf generate`) and `make tidy`.

```protobuf
enum UserSource {
  USER_SOURCE_UNSPECIFIED = 0;
  USER_SOURCE_OS          = 1;
  USER_SOURCE_TAILSCALE   = 2;
}

message DecisionContext {
  string hostname = 1;
  repeated string tags = 2;
  message User {
    string value = 1;
    UserSource source = 2;
  }
  User user = 3;
  map<string, string> extra = 4;   // open extension — no schema bump for new signals
}

message SessionInit {
  // ... existing fields 1..11 ...
  DecisionContext decision_context = 12;   // NEW; optional
}

message SessionUpdate {
  // ... existing fields 1..4 ...
  DecisionContext decision_context = 5;    // NEW; optional (phase-2 re-resolution)
}
```

`context_digest` (SessionInit field 6) is **left unchanged** — it belongs to the
integrity chain (`chain.ComputeContextDigest`), not to this feature.

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

type Source interface { Name() string; Resolve(ctx context.Context, into *DecisionContext) error }
type Resolver struct { sources []Source } // ordered
func (r *Resolver) Resolve(ctx context.Context) (DecisionContext, error)
```

Sources (ordered): `hostname`, `config-tags` (from config), `os-user`,
`tailscale`. `os-user` writes the `user` slot (`source: os`); `tailscale`
**overwrites** it (`source: tailscale`) only when tailscaled is up. A source
erroring never fails resolution; it omits its field (partial context).

**Tailscale source** reads the **local node's** identity (login name) from the
tailscaled **local API** over its unix socket
(`/run/tailscale/tailscaled.sock`, `GET /localapi/v0/status` → `Self.UserID` →
`User[UserID].LoginName`) via a **minimal HTTP-over-unix-socket client** — NOT
the heavy `tailscale.com` module. It is platform-guarded (Linux build has the
socket client; other GOOS gets a stub that returns "not available") and degrades
silently when the daemon/socket is absent. The source is injected behind an
interface so tests mock it without a live daemon.

### 2. Config — `internal/config` (`AuditWatchtowerConfig`)

Add a sub-struct (resolved at store-construction time, not in `applyDefaults`,
matching the existing `AgentID`/`SessionID` pattern):

```go
type WatchtowerDecisionContextConfig struct {
    Tags      []string                       `yaml:"tags"`
    Tailscale WatchtowerTailscaleConfig      `yaml:"tailscale"`
    Extra     map[string]string              `yaml:"extra"`
}
type WatchtowerTailscaleConfig struct {
    Enabled *bool  `yaml:"enabled"`   // nil => default enabled when socket present
    Socket  string `yaml:"socket"`    // optional override of the tailscaled socket path
}
// field on AuditWatchtowerConfig:
//   DecisionContext WatchtowerDecisionContextConfig `yaml:"decision_context"`
```

Hostname and OS user are auto-resolved; no config needed for them.

### 3. Wiring

- `transport.Options` gains `DecisionContext *wtpv1.DecisionContext`;
  `sessionInit()` sets `SessionInit.DecisionContext` from it.
- `watchtower.Options` gains a matching `DecisionContext *wtpv1.DecisionContext`,
  forwarded to `transport.New`.
- `buildWatchtowerStore` calls `decisionctx.Resolver.Resolve`, converts the
  result to `*wtpv1.DecisionContext`, and sets it on `watchtower.Options`.

### 4. Reused unchanged

`makePolicyInstallHook`, `createSessionCore` policy load/verify, the
SessionAck/PolicyPush install arms, and the integrity chain. No new cache, no
new request/response, no per-session swap.

## Error handling & security

- **WT unreachable / `policy_id == ""`** — agent runs the on-disk policy (last
  installed signed YAML, or the configured local default). Existing behavior; no
  new timeout/bootstrap code.
- **Signature & trust** — unchanged: `makePolicyInstallHook` verifies
  ed25519(content,sig) against the trust store by `SignerKeyID` and checks
  sha256==ContentHash before writing; `createSessionCore` re-verifies the file's
  `.sig` on load. A bad signature is never installed.
- **Failure independence** — a context source erroring degrades to partial
  context; it never blocks store construction or session creation. Tailscale
  absent ⇒ `user.source = os`.
- **Trust of `user.source`** — agentsh reports context honestly (it already
  holds the WT bearer/cert); WT decides how much to trust `os` vs `tailscale`.
- **Deny** — `policy_id == ""` ⇒ revert to local file policy; a lockdown outcome
  is a restrictive policy WT returns and the agent installs normally.
- **Observability** — v1 logs the resolved context via `slog` (with
  `user.source`, tag count, tailscale availability), matching the install hook's
  existing logging style, and relies on the install hook for policy
  receipt/install logs. We deliberately **do not** add a new emitted
  `events.EventType` in v1: `main` has an OCSF exhaustiveness test
  (`internal/ocsf/registry.go` `pendingTypes` + `exhaustiveness_test.go`) that
  any new emitted type would have to satisfy. A formal audit event type is a
  follow-up.

## Testing

Tests lead the implementation (TDD).

- **`ContextResolver` / sources (unit, table-driven):** os-user fills
  `user{source:os}`; tailscale-up overwrites → `user{source:tailscale}`;
  tailscale-absent/erroring leaves os-user and `Resolve` still succeeds (partial
  context); tailscale source mocked via injected client; hostname/tags
  deterministic.
- **Tailscale local-API client (unit):** parses a sample `/localapi/v0/status`
  JSON into the login name; missing socket → "not available" (no error
  propagated); platform stub returns "not available" on non-Linux.
- **Wiring (unit):** `sessionInit()` populates `SessionInit.DecisionContext` from
  `transport.Options`; `buildWatchtowerStore` produces the expected
  `*wtpv1.DecisionContext` from config + resolver.
- **Integration (extend `internal/store/watchtower/testserver`):** assert the
  server's captured `firstSessionInit.DecisionContext` matches what the agent
  resolved (add a `testserver/assertions.go` helper); drive a policy-bearing
  `SessionAck` (and a `PolicyPush` via `InjectAfterSessionAck`) and assert the
  existing install hook writes the signed YAML.
- **Cross-cutting gates (AGENTS.md/CLAUDE.md):** full `go test ./...` (catches
  any OCSF exhaustiveness test) and `GOOS=windows go build ./...` (the tailscale
  source must compile cross-platform via the platform stub and degrade when the
  socket is absent).

## Cross-repo sequencing

1. In `~/work/wtp-protos`: add `DecisionContext` + the two fields, `make gen`,
   `make tidy`, commit.
2. In agentsh `go.mod`: temporary
   `replace github.com/canyonroad/wtp-protos/gen/go => /home/eran/work/wtp-protos/gen/go`.
3. Implement + test agentsh side.
4. Later: tag `gen/go/v0.2.0` in wtp-protos, `go get` the new version in
   agentsh, drop the `replace`.

## Open items for planning

- Confirm the precise tailscaled status JSON shape for `Self.UserID` →
  `User[UserID].LoginName` against the installed tailscale version.

(Resolved during grounding: OCSF coupling avoided by using `slog` in v1, not a
new `EventType`; `os-user` uses `os/user.Current()` — the agent-process user,
the established pattern in `internal/cli/daemon.go`.)
