# db-access Plan 04 — PostgreSQL Proxy Skeleton (design)

Status: design approved 2026-05-10. Implementation plan to follow via writing-plans.

Cross-references:
- Roadmap: `docs/superpowers/specs/2026-05-08-db-access-phase-1-roadmap-design.md` §3 Plan 04.
- Spec: `docs/agentsh-db-access-spec.md` v0.8 §7.1 (wire framing), §8 (DBEvent), §11 (interception architecture), §13 (TLS), §14.1 / §14.4 (Simple Query and pre-forward semantics).
- Predecessors: Plans 01–03 already shipped (`internal/db/effects`, `internal/db/policy`, `internal/db/events` skeleton, `internal/db/service` config schema, `internal/db/classify/postgres`).

This document captures the package-shape, lifecycle, and interface decisions the spec leaves to the implementer for the first plan that introduces a wire-protocol surface. The §11 architecture and §13 TLS-mode contracts are authoritative upstream and are not re-derived here.

## 1. Scope

### In scope

- New package `internal/db/proxy/postgres/` (`//go:build linux`; non-Linux stub returns `errors.ErrUnsupported`).
- pgproto3 framing for client-facing and upstream-facing wire I/O.
- Startup-packet dispatch: `SSLRequest`, `GSSENCRequest`, `CancelRequest`, normal `StartupMessage` (§11.1).
- Three TLS modes per service: `passthrough`, `terminate_reissue`, `terminate_plaintext_upstream` (§13). Connection-level deny across modes (§13.3).
- Simple Query (`Q`) path only: classify → evaluate → forward-or-synthesize-deny → emit `DBEvent`.
- Default-deny replication and GSSENC; opt-in surfaces present and rule-evaluated but the proxy does no replication-protocol work — it enters byte-level passthrough on accept.
- `db_services` config recognition: at proxy boot, each declared service gets a Unix-socket listener bound at the configured path with `0700` perms; the proxy `accept()`s, reads `SO_PEERCRED` and verifies `peer_uid == proxy_uid`. (TCP listeners supported for tests but flagged in docs as test-only; UID match is meaningless without SO_PEERCRED on TCP.)
- Feature flag `policies.db.unavoidability: enforce | observe | off`, default `off`. With `off`, listeners are **not** bound — package is a no-op. With `observe` or `enforce`, listeners bind and the full simple-query path runs. Plan 04 does **not** generate the unavoidability bundle (network/file rules); that is Plan 07.
- DBEvent emission via a new `events.Sink` interface declared in the existing `internal/db/events` package, with a thin adapter to `internal/audit.SinkChain` and an in-memory test fake.
- Self-signed AgentSH-DB CA: `internal/db/tlsleaf/`. Lazily generated and persisted under the AgentSH state dir (path injected, not hard-coded). Leaves issued at connect time per upstream hostname, cached per-process. SCRAM-SHA-256-PLUS detected at upstream auth → fail-closed with structured error.
- Wire `internal/db/policy.EvaluateConnection` (already shipped in Plan 02) into the proxy at handshake time, with per-TLS-mode field-visibility validation extending Plan 02's existing `validate.go`.

### Out of scope (deferred to later plans)

- Extended Query (`Parse`/`Bind`/`Describe`/`Execute`/`Sync`/`Flush`/`Close`), SQL-level prepared cache, COPY data-frame handling, full transaction state machine, function-call escalation — Plan 05.
- `CancelRequest` mapping table — Plan 06. Plan 04 receives `CancelRequest`, evaluates connection rules with `match_kind: cancel`, and either drops or forwards to upstream **un-mapped**. This is broken-by-design until Plan 06 lands; documented in plan release notes.
- SO_PEERCRED → SessionID resolution, supervisor-spawned proxy under distinct SessionID, unavoidability bundle generation, integration test suite — Plan 07.

## 2. Architectural decisions

These decisions were settled during brainstorming and govern the rest of the design.

**D1. In-process library; Plan 07 lifts it.** Spec §12.4 mandates a separate-process proxy under a distinct SessionID, but the unavoidability bundle (which requires that distinct SessionID for egress denial) is explicitly Plan 07's deliverable. Plan 04 ships `internal/db/proxy/postgres` as a library with a `Server` type that the existing supervisor process (`internal/api`) instantiates and runs. Listener auth is SO_PEERCRED + UID-equality only. Plan 07 lifts the proxy into its own process and adds SessionID-aware listener auth. Public API is shaped to allow that lift without changing call sites.

**D2. Self-signed CA, lazy, persisted.** A single AgentSH-DB CA at `${StateDir}/db-ca.{key,crt}` (0600 / 0644), generated on first `terminate_reissue` connection, persisted across proxy restarts. Per-hostname leaves issued at connect time and cached in-process (LRU, capacity 256). No auto-distribution: operators copy the CA cert into client `sslrootcert`. SCRAM-SHA-256-PLUS detected at upstream handshake → fail-closed per spec §13.1.

**D3. RFQ-byte-only transaction tracking.** Plan 04 keeps a single byte of per-connection state — the latest `ReadyForQuery` status (`I`/`T`/`E`) observed from upstream — and uses it to switch deny semantics: outside-tx (or pre-auth) denies synthesize `ErrorResponse + ReadyForQuery(I)` locally per §14.4; in-tx denies (`T`/`E`) terminate the connection per §14.3 default. No BEGIN/COMMIT parser, no Extended Query state, no `upstream_dirty_since_sync`. Plan 05 replaces this with the full state machine.

**D4. `events.Sink` interface; thin audit adapter.** `internal/db/events` gains a `Sink` interface (`Emit(ctx, DBEvent) error`), a `NopSink`, and an `audit_adapter.go` that funnels events into the existing `internal/audit.SinkChain`. The proxy depends only on the interface; tests use a `SyncSink` that captures events for assertion. This keeps `internal/db/proxy/postgres` decoupled from `internal/audit` and trivially unit-testable.

**D5. `approve` verb is config-loadable but runtime-blocked.** Plan 04 treats `approve` rules as `deny + APPROVE_NOT_YET_SUPPORTED` because the approval mechanism (out-of-band waiting + timeouts) overlaps Plan 05's in-tx approval handling (§14.5). Config-load surfaces a warning when any rule has `decision: approve` and `Unavoidability != off`, so the operator is told plainly. Live verbs in Plan 04: `allow`, `audit`, `deny`.

## 3. Package layout

```
internal/db/proxy/postgres/                  //go:build linux
├── stub_other.go                            //go:build !linux  — Server stub returning errors.ErrUnsupported
├── server.go                                Server type: lifecycle, listener bind/close, ctx-driven shutdown
├── conn.go                                  perConnection state: client+upstream net.Conn, pgproto3.Frontend/Backend pair, last upstream RFQ status byte
├── handshake.go                             startup-packet dispatch (SSLRequest/GSSENC/Cancel/Startup), replication detection
├── tls.go                                   per-mode TLS plumbing (passthrough/terminate_reissue/terminate_plaintext_upstream)
├── auth.go                                  upstream auth forwarding; SCRAM-SHA-256-PLUS detection → fail-closed
├── simplequery.go                           Q-frame classify+evaluate+forward-or-deny loop
├── deny.go                                  ErrorResponse/ReadyForQuery synthesis; in-tx terminate path
├── eventbuilder.go                          ClassifiedStatement+Decision → DBEvent (with redaction tier applied)
├── peercred_linux.go                        SO_PEERCRED + UID-equality listener auth
└── *_test.go                                in-process pgproto3 round-trip tests, table-driven per file

internal/db/tlsleaf/
├── ca.go                                    lazy self-signed CA load-or-generate; persisted under StateDir
├── leaf.go                                  per-hostname leaf issuer with in-process LRU cache
└── *_test.go

internal/db/events/                          (existing — extended)
├── sink.go                                  NEW: Sink interface; NopSink; SyncSink test fake
└── audit_adapter.go                         NEW: adapter that emits DBEvent through internal/audit.SinkChain

internal/db/policy/                          (existing — extended)
└── validate.go                              MODIFIED: reject connection rules under tls_mode: passthrough that match passthrough-invisible fields (db_user, database, application_name)
                                                                        EvaluateConnection itself is already shipped in Plan 02 and used as-is.

internal/db/service/                         (existing — extended; minor)
└── flag.go                                  NEW: Unavoidability enum (off|observe|enforce) parsed from policies.db.unavoidability

internal/policy/load.go                      MODIFIED: accept policies.db.unavoidability field
internal/api/                                MODIFIED: at startup, if Unavoidability != off and Config.DBServices non-empty, instantiate Server and attach to lifecycle
```

### Boundary calls

- `internal/db/proxy/postgres` depends on `effects`, `policy` (consuming the existing `EvaluateConnection` and `Evaluate` plus a small `validate.go` extension), `classify/postgres`, `events` (incl. new `Sink`), `service`, `tlsleaf`. It does **not** import `internal/api`, `internal/audit`, or `internal/proxy`. The supervisor wiring lives in `internal/api`.
- `internal/db/tlsleaf` is its own package because it is reusable by Plans 05/06 and trivially testable in isolation.
- `events.Sink` lives in the existing `internal/db/events` package (not in `proxy/postgres`) so the audit adapter does not pull the proxy package into the audit graph.
- `peercred_linux.go` uses Go's `_linux` filename suffix; no explicit build tag required.

## 4. Public surface and lifecycle

`internal/db/proxy/postgres/server.go`:

```go
type Config struct {
    Services       []service.Service       // already-validated; from internal/db/service
    Unavoidability service.Unavoidability  // off|observe|enforce
    StateDir       string                  // for tlsleaf CA persistence
    Sink           events.Sink             // events drain here
    Policy         *policy.Snapshot        // current rule set; reloaded externally, swapped via Server.SetPolicy
    Classifier     postgres.Parser         // shared classifier (one per process)
    Logger         *slog.Logger
    Clock          clock.Clock             // injectable for tests
    MaxQueryBytes  int                     // default 1 MiB; statements above this get a synthetic 54000 + close
}

type Server struct { /* unexported state */ }

func New(cfg Config) (*Server, error)                  // validates config; lazy-loads CA if any service uses terminate_reissue
func (s *Server) Start(ctx context.Context) error      // binds all listeners; returns when first listener fails to bind
func (s *Server) Shutdown(ctx context.Context) error   // graceful: stop accept, drain in-flight, close listeners
func (s *Server) SetPolicy(p *policy.Snapshot)         // hot-swap; atomic; takes effect on next statement evaluation
```

### Lifecycle

1. `New(cfg)` validates `cfg`. If `Unavoidability == off`, returns a sentinel server whose `Start` is a no-op so callers do not have to special-case.
2. `Start(ctx)` iterates services. For each: validates the listener path's parent dir exists and is owned by current uid; `unix` listener calls `socket(AF_UNIX, SOCK_STREAM)` + `bind` + `chmod(0700)` + `listen`. Per-listener accept loop is its own goroutine; each accepted conn becomes a per-connection goroutine.
3. `ctx` cancellation triggers shutdown: stop accept, signal in-flight conns to close their client side, drain upstream cleanly, close listeners, unlink Unix socket paths.

### Per-connection flow

```
accept                                         peercred_linux.go
  → SO_PEERCRED, peer_uid == proxy_uid?        (deny → close silently + db_listener_auth_fail event)
  → handshake.go: read first message (4-byte length + body, no type byte)
      → SSLRequest        → tls.go             negotiate per service.tls_mode
      → GSSENCRequest     → respond 'N'        (allow_gss_encryption opt-in deferred to Plan 05)
      → CancelRequest     → policy.EvaluateConnect(match_kind: cancel)
                                deny  → close
                                allow → forward un-mapped to upstream (Plan 06 will do mapping)
      → StartupMessage    → extract user/database/application_name; replication=true → connection-rule eval
                                replication denied (default) → ErrorResponse(28000) + close
                                replication allowed → degraded_visibility_warning event + byte-level passthrough
                                normal → connection-rule eval (match_kind: connect)
                                  deny  → §13.3 (synthesize ErrorResponse or close TCP)
                                  allow → upstream connect → simplequery.go
  → simplequery.go: read frame
      'Q' (Query) → classify → policy.Evaluate per statement → forward all or synthesize deny
      'X' (Terminate) → forward + close
      'p' (Auth response) → forward (during auth phase only)
      anything else (Parse/Bind/Execute/etc.) → ErrorResponse + close, "Extended Query not supported in Phase 1 build N"
```

### Shutdown ordering

Listener-stop → per-conn cancel → drain upstream → close client → unlink. Single `errgroup` rooted at the server's ctx; `Shutdown` cancels it and waits with the caller's deadline.

## 5. TLS, CA, and SCRAM-SHA-256-PLUS

### Modes

| Mode | Inbound | Upstream | Visibility |
|------|---------|----------|------------|
| `passthrough` | `SSLRequest` → respond `S`, then byte-level passthrough of the encrypted stream both ways. SNI extracted best-effort from ClientHello. | Encrypted bytes forwarded as-is. | Connection-level only; no statement classification. |
| `terminate_reissue` | `SSLRequest` → respond `S`, then `tls.Server` with leaf reissued for the upstream hostname (CA from `tlsleaf`). | New `tls.Client` to upstream using upstream's actual cert chain (verified via system roots, not our CA). | Full. |
| `terminate_plaintext_upstream` | Same inbound termination as `terminate_reissue`. | Plaintext to upstream. Config-load rejects this mode if upstream is not loopback / RFC1918. | Full. |

### ClientHello SNI extraction (passthrough only)

A 4 KiB peeked buffer plus a hand-rolled ClientHello parser; no full TLS state machine. If ClientHello is fragmented across records or SNI is absent, the proxy records `sni: null` and continues. SNI is advisory per spec §13.2's footnote.

### `internal/db/tlsleaf` package

```go
type CA struct { /* unexported */ }

func LoadOrCreate(stateDir string, clock clock.Clock) (*CA, error)
    // ${stateDir}/db-ca.key (0600), ${stateDir}/db-ca.crt
    // CN: "AgentSH DB Proxy CA"; 10-year validity; 4096-bit RSA
    // First call generates; subsequent calls load.

func (c *CA) IssueLeaf(hostname string) (*tls.Certificate, error)
    // In-process LRU cache, capacity 256; key = hostname.
    // Leaf: 90-day validity, P-256, SAN = [hostname], rotated on hostname change only.
```

The CA cert path is logged at `Server.Start` so operators can copy it into client `sslrootcert`. There is no auto-distribution machinery in Plan 04.

### SCRAM-SHA-256-PLUS detection

During upstream auth forwarding (`auth.go`), the proxy parses each `AuthenticationSASL` frame's mechanism list. If the list contains `SCRAM-SHA-256-PLUS`, the proxy:

1. Closes upstream cleanly (does not respond).
2. Sends `ErrorResponse(SQLSTATE 28000, message="AgentSH DB proxy cannot terminate channel-bound SCRAM (SCRAM-SHA-256-PLUS). Disable channel binding upstream or use TLS passthrough; see docs/agentsh-db-access-spec.md §13.")` to client.
3. Closes client.
4. Emits a `db_handshake_fail` DBEvent with `result.error_code: SCRAM_PLUS_FAIL_CLOSED`.

This applies to `terminate_reissue` and `terminate_plaintext_upstream` only; under `passthrough` the proxy never sees the auth frames. Spec §13.1 mandates this fail-closed.

### Connection-rule timing under TLS modes

Connection rules that match only fields visible after StartupMessage (e.g. `db_user`) cannot fire under `passthrough` and are rejected at config-load by Plan 02's existing validator. Plan 04 extends that validator with a small one-line table of which fields are passthrough-invisible. `client_identity` rules can fire pre-handshake; they close the TCP connection and emit no protocol-level error, per §13.3.

## 6. Simple Query path

### Per-connection state (Plan 04 minimum)

```go
type connState struct {
    lastUpstreamRFQ byte    // 'I' | 'T' | 'E' | 0 (pre-auth)
    awaitingAuth    bool
    sessionID       string
    dbService       string
    dbUser          string
    database        string
    appName         string
    clientIdentity  string  // "uid:<peer_uid>" placeholder; Plan 07 swaps in real SessionID
    sniHostname     string  // passthrough only
    redactionLevel  events.Redaction  // resolved per-service from policy.Snapshot
}
```

`lastUpstreamRFQ` is updated on every observed `ReadyForQuery` byte from upstream (the type-`'Z'` frame, body byte 0). That is the entire transaction-state model in Plan 04. `awaitingAuth` flips to `false` on the first upstream `ReadyForQuery`.

### Simple Query (`Q`) flow

```
1. Read 'Q' frame from client; body = NUL-terminated SQL string.
2. Classify via cfg.Classifier.Classify(sql, sessionState{}, opts) → []ClassifiedStatement.
   sessionState{} is empty: Plan 04 does not track SET search_path / SET ROLE. Spec §7.7 says
   unqualified objects under no search_path → object_resolution=unresolved, which is fine and
   matches Plan 03 corpus expectations.
3. For each ClassifiedStatement:
     decision = policy.Evaluate(cs, ruleset)
     append to []decisions
4. anyDeny := any(decisions[i].verb == deny)
5. If !anyDeny:
     forward the original 'Q' frame upstream as-is (no modification — preserves bytes for
     SCRAM channel-binding edge cases and avoids classifier-vs-server disagreement).
     emit one DBEvent per ClassifiedStatement with verb from decisions[i] (allow/audit;
     approve→deny+APPROVE_NOT_YET_SUPPORTED per D5).
6. If anyDeny:
     forward NOTHING upstream (per §14.1: parse-all-before-forward).
     emit one DBEvent per ClassifiedStatement (deny statement gets verb=deny;
     others verb=denied_by_sibling).
     synthesize the deny per the RFQ tracker:
       lastUpstreamRFQ in {0, 'I'}: ErrorResponse + ReadyForQuery('I') → client. Done.
       lastUpstreamRFQ in {'T', 'E'}: ErrorResponse → client; close upstream + client.
                                      tx_context.deny_action = "connection_terminated".
```

### Deny synthesis (`deny.go`)

- `synthesizeDeny(rendered string, code string)` writes one `ErrorResponse{Severity: "ERROR", SQLState: "28000", Message: rendered}` plus `ReadyForQuery{TxStatus: 'I'}`.
- Rendered message comes from the rule's `deny_message` template (Plan 02 already supports templates) or a default `"denied by AgentSH policy: <rule_name>"`.
- For terminate-on-tx case: write `ErrorResponse` only; no RFQ; close.

### Frame budget

Simple Query bodies can be large (up to PG's 1 GiB protocol cap). Plan 04 caps client SQL at 1 MiB at the framer (`Server.Config.MaxQueryBytes`, default 1 MiB). Anything bigger gets a synthetic `ErrorResponse(54000, "statement too large for AgentSH proxy: NN bytes > 1 MiB cap")` and connection close. Spec does not mandate this; we adopt a generous-but-bounded cap to avoid memory griefing.

## 7. DBEvent, redaction, and Sink

### `internal/db/events/sink.go` (NEW)

```go
type Sink interface {
    Emit(ctx context.Context, ev DBEvent) error
}

type NopSink struct{}
func (NopSink) Emit(context.Context, DBEvent) error { return nil }

// SyncSink is in-memory; tests grab events synchronously.
type SyncSink struct { /* mutex-guarded slice */ }
func (s *SyncSink) Emit(...) error
func (s *SyncSink) Drain() []DBEvent
```

### `internal/db/events/audit_adapter.go` (NEW)

Wraps `internal/audit.SinkChain`. Marshals `DBEvent` to canonical JSON (the existing SinkChain expects an opaque payload + an event-kind tag) and emits with kind `db_statement` (statement events) or `db_lifecycle` (connection events: `db_handshake_fail`, `degraded_visibility_warning`, `db_listener_auth_fail`). The `event_id` field uses UUIDv7 (already imported in Plan 01).

### Event types Plan 04 emits

| Kind | Trigger | Carries |
|------|---------|---------|
| `db_statement` | Each ClassifiedStatement in a Simple Query | full §8 envelope (decision, effects, redacted statement_text per redaction tier, `parser_backend` from Plan 03) |
| `db_handshake_fail` | SCRAM-SHA-256-PLUS detected; replication denied; SSL/GSSENC malformed | minimal envelope: session_id, db_service, client_identity, kind, error_code |
| `db_listener_auth_fail` | SO_PEERCRED uid mismatch | session_id, db_service, peer_uid, peer_pid (best-effort, may be 0 on Linux variants) |
| `degraded_visibility_warning` | Replication-allowed connection or `tls_mode: passthrough` first connect | per spec §11.1: `reason: replication_passthrough | tls_passthrough` |

### Redaction tiers (§10.3)

Plan 02's evaluator already produces `redaction_level` per-statement. Plan 04 honors it:

| Tier | `statement_text` |
|------|------------------|
| `full` | Verbatim SQL bytes (decoded UTF-8). |
| `parameters_redacted` (default) | `pg_query_normalize` from libpg_query (Linux+CGO) or `wasilibs/go-pgquery`'s normalize (else). Replaces literals/parameters with `$N` placeholders, leaving structure visible. Non-Linux fall back to a regex-based scrubber over numeric/string literals — documented as best-effort. |
| `none` | Field omitted entirely. `statement_digest` (SHA-256 of normalized form) still present so events remain joinable. |

`statement_digest` is computed against the *normalized* form for `parameters_redacted` and `none`, and against the verbatim text for `full`. Tests fix the digest's input form so this does not drift.

### `client_identity` in Plan 04

Spec §12.4 says it is the AgentSH SessionID. Plan 07 wires SessionID resolution from SO_PEERCRED → ptrace registry. Plan 04 has SO_PEERCRED but no SessionID lookup, so `client_identity` is set to `"uid:<peer_uid>"` as a stable placeholder. The DBEvent field stays a string (no schema change); Plan 07 swaps in the real SessionID and operators reading event streams see the format flip from `uid:1000` to a session UUID. Documented in plan release notes.

## 8. Testing strategy

### Unit tests, table-driven, per file

| File | What it tests |
|------|---------------|
| `handshake_test.go` | Startup-packet dispatch — handcrafted bytes for SSLRequest / GSSENCRequest / CancelRequest / StartupMessage / replication-startup. Asserts correct response and next-state. Uses `net.Pipe()` for client side; no upstream. |
| `tls_test.go` | Each mode end-to-end with `crypto/tls` client and a fake upstream. Verifies leaf cert chains to the AgentSH CA in reissue mode; verifies plaintext-upstream refuses non-loopback at config-load. |
| `auth_test.go` | SCRAM-SHA-256-PLUS detection: synthetic upstream `AuthenticationSASL` listing `SCRAM-SHA-256-PLUS`. Asserts client gets `28000` and `db_handshake_fail` event with `SCRAM_PLUS_FAIL_CLOSED`. Mirror test with non-PLUS mech list passes through. |
| `simplequery_test.go` | Big table of `{sql, policy_yaml, classifier_result_stub, want_forwarded, want_synthesized, want_events}`. Covers allow, audit, deny pre-forward, multi-statement deny, anyDeny→noneForwarded invariant, denied_by_sibling event tagging, `approve→deny+APPROVE_NOT_YET_SUPPORTED`. Classifier injected via `cfg.Classifier`; no real pg_query needed. |
| `deny_test.go` | RFQ-tracker behavior: lastRFQ ∈ {0, I} → local synth; lastRFQ ∈ {T, E} → terminate. Including a sequence test that simulates `BEGIN` forwarded, `T` observed, then deny → terminate. |
| `eventbuilder_test.go` | Redaction tiers: `full` round-trips text; `parameters_redacted` matches the libpg_query-normalized form on Linux+CGO and the regex fallback elsewhere; `none` strips text but keeps digest stable across tiers. Has both build-tag variants. |
| `peercred_linux_test.go` | UID-equality auth: real `socketpair`, real SO_PEERCRED, asserts mismatch → silent close + `db_listener_auth_fail` event. Linux-only. |
| `tlsleaf/ca_test.go` | LoadOrCreate: first call creates files with 0600 perms; second call loads. Cross-process semantics not tested (single-process is the contract). |
| `tlsleaf/leaf_test.go` | Issues for hostname A and B; asserts SAN contents, validity windows, cache hit on repeat issue. |

### In-process round-trip test (the "skeleton spine" test)

One end-to-end test in `simplequery_test.go` that wires:

- Real `Server` with one service in `terminate_reissue` mode.
- Fake upstream: a goroutine speaking `pgproto3.Backend`, accepting one `Q`, replying with one `RowDescription` + `DataRow` + `CommandComplete` + `ReadyForQuery('I')`.
- Real `pgx` client (test-only dep) connecting via Unix socket through the proxy with the AgentSH CA in its trust store.
- Asserts: query result reaches client; one `db_statement` DBEvent in `SyncSink`.

This is the "does the whole shape compose" test. Everything else is a unit test against a smaller surface.

### Property tests

None for Plan 04 — the protocol surface here is enumerated, not algebraic. Plan 05's state machine is where property tests pay off.

### Cross-compile

`GOOS=windows go build ./...` runs in CI per CLAUDE.md. The non-Linux stub keeps this green.

### No integration tests with real Postgres in Plan 04

Real-PG integration lives in Plan 07 with testcontainers. Plan 04's spine test uses a fake upstream because we want to be able to inject malformed frames, slow responses, etc., and that is ergonomic only when we own both sides.

### Test isolation

All tests use `t.TempDir()` for the StateDir; no `/tmp` collisions, no test ordering dependencies, no shared CA.

## 9. Open questions and risks

### Open questions to flag (not blockers)

1. **`approve` semantics in observe mode.** With Plan 04 treating `approve` as `deny+APPROVE_NOT_YET_SUPPORTED`, an operator under flag=`observe` can never run any approve workflow — events stream but every approve-targeted statement returns an error to the client. Plan 05's in-tx approval (§14.5) brings the actual mechanism. Until then the only "live" verbs are `allow`, `audit`, `deny`.
2. **CancelRequest without mapping.** Plan 04 evaluates connection rules for `match_kind: cancel` but forwards the `CancelRequest` un-mapped (with the client's syn_pid/syn_secret). Upstream rejects these because they do not match a real backend. Broken-by-design until Plan 06; documented in release notes.
3. **GSSENC opt-in deferred to Plan 05.** Spec §11.1 supports `allow_gss_encryption: true` per service. The config field is parsed (no error on load) but ignored in Plan 04. Every GSSENCRequest gets `'N'`.
4. **`statement_digest` algorithm choice.** SHA-256 of the normalized form. Spec §8 does not pin an algorithm; we declare it here for cross-event joinability.
5. **CA persistence path.** `${StateDir}/db-ca.{key,crt}`. If the host operator rotates the AgentSH state dir, the CA regenerates and clients with the old CA pinned will see hostname verification failures. Documented but not solved here.

### Risks

- **Self-signed CA distribution.** Operators install the AgentSH-DB CA into PG client trust stores manually. For agent runtimes that build short-lived containers, this is friction. Mitigation in spec docs only; no code in Plan 04.
- **`approve→deny` surprise.** An operator pre-loading approve rules expecting them to gate may find every targeted statement failing. Loud, unambiguous error code helps but it is still surprising. Mitigation: a CONFIG-LOAD warning when any rule has `decision: approve` and `Unavoidability != off`.
- **Connection churn.** RFQ-byte deny→terminate inside `T` can churn connections under chatty agents. Acceptable for Plan 04 rollout (flag=`off` default; `observe` for early adopters). Plan 05 fixes with proper §14.3 modes.
- **CGO + libpg_query transitively imported by the proxy.** Plan 03 isolated this behind the `Parser` interface; Plan 04 just consumes the interface. CGO build is still required on Linux for `terminate_reissue` to be useful (since classification matters there).

### Deferred

- **To Plan 05.** Extended Query, SQL-level prepared cache, COPY data-frame handling, function-call escalation, full §14 deny flows including `rollback_then_continue`, `approve` runtime, GSSENC opt-in.
- **To Plan 06.** BackendKeyData mapping table, cancel governance via mapping lookup, R20 commit ordering.
- **To Plan 07.** Out-of-process proxy under distinct SessionID, SO_PEERCRED → SessionID resolution, unavoidability bundle (network/file rules) generation from `db_services`, real-PG integration tests, bypass-tool detection, recommendation flip to `enforce`.

## 10. Done definition

Plan 04 is done when:

- `internal/db/proxy/postgres` builds on Linux and stubs cleanly elsewhere; `GOOS=windows go build ./...` is green.
- All unit tests above pass, including the spine in-process round-trip test with real `pgx` against a fake upstream.
- A YAML config containing `policies.db.unavoidability: observe` and one `db_services` entry causes the supervisor to bind the configured Unix socket; an external `pgx` client with the AgentSH CA installed connects through it, runs a `SELECT`, and observes one `db_statement` event in the audit sink.
- A YAML config with `policies.db.unavoidability: off` is a no-op: no listener bound, no events emitted, no behavior change from `main`.
