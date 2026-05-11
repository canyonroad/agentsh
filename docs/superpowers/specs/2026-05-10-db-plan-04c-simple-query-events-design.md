# db-access Plan 04c — Simple Query + DBEvent Emission (design)

Status: design approved 2026-05-10. Implementation plan to follow via writing-plans.

Cross-references:
- Roadmap: `docs/superpowers/specs/2026-05-08-db-access-phase-1-roadmap-design.md` §3 Plan 04c.
- Plan 04 skeleton (parent design): `docs/superpowers/specs/2026-05-10-db-plan-04-pg-proxy-skeleton-design.md`.
- Plan 04b₂ (predecessor): `docs/superpowers/specs/2026-05-10-db-plan-04b2-upstream-passthrough-design.md`.
- Spec: `docs/agentsh-db-access-spec.md` v0.8 §7.1 (wire framing), §7.7 (search_path), §8 (DBEvent), §10.2 (most-restrictive), §10.3 (redaction tiers), §14.1 / §14.3 / §14.4 (Simple Query and pre-/in-tx deny semantics), §23.4 steps 5+7.
- Predecessors shipped: Plans 01 (effects), 02 (policy), 03 (classify/postgres), 04a (listener), 04b (handshake/TLS), 04b₂ (upstream wiring/passthrough/cancel).

This document covers the package-shape, control-flow, schema, and test decisions for the sub-plan that closes the Phase 1 Simple Query loop. The skeleton design's §6 sketched it; this expands it with the choices settled during brainstorming.

## 1. Scope

### In scope

- Continue the per-connection driver past the first upstream `ReadyForQuery`: from `forwardAuth`'s exit into a per-conn `simpleQueryLoop`.
- `'Q'`-frame handling: classify (Plan 03) → evaluate per statement (Plan 02) → forward-or-synthesize-deny → emit one `db_statement` event per `ClassifiedStatement`.
- Per-conn `lastUpstreamRFQ` status-byte tracker (`I` | `T` | `E` | 0), updated on every observed upstream `'Z'` frame. Drives deny synthesis.
- Multi-statement parse-all-before-forward: if any of N statements in a single `Q` body denies, forward none; emit N events.
- Per-frame demux of upstream response stream until trailing `'Z'`, accumulating `bytes_in`, `bytes_out`, `rows_returned`, `rows_affected`, `latency_ms`, `error_code` for `EventResult`.
- Deny synthesis:
  - `lastUpstreamRFQ ∈ {0, 'I'}` (out-of-tx / pre-auth): `ErrorResponse` + `ReadyForQuery('I')` locally; loop continues.
  - `lastUpstreamRFQ ∈ {'T', 'E'}` (in-tx): `ErrorResponse` only; close upstream + close client; `tx_context.deny_action = "connection_terminated"`.
- `approve` rule verb at runtime → synthesize `deny` with `error_code: APPROVE_NOT_YET_SUPPORTED`; emit a config-load warning when `Unavoidability != off` and any rule has `decision: approve`.
- Frame budget cap: `Q` body > `MaxQueryBytes` (default 1 MiB) → synthetic `ErrorResponse(54000, "statement too large for AgentSH proxy: N bytes > 1 MiB cap")` + `ReadyForQuery('I')` + close; emits a lifecycle event with `error_code: FRAME_TOO_LARGE`.
- Non-`'Q'` / non-`'X'` frame post-handshake → synthetic `ErrorResponse(0A000, "Extended Query / COPY / FunctionCall not supported in AgentSH proxy phase 1")` + close; lifecycle event `EXTENDED_QUERY_NOT_SUPPORTED` (or `FUNCTION_CALL_PROTOCOL_DENIED` for `'F'`).
- `events.DBEvent` extended with §8 sub-structs (`TLS`, `Decision`, `Result`, `TxContext`, `Predicates`). 04c populates `Decision`, `Result`, `TxContext.InTransaction`, `TxContext.DenyAction`, `Predicates.HasFilter`, `TLS.Mode`, `TLS.ClientSNI`.
- `Parser.Normalize(sql string) (string, error)` added to `internal/db/classify/postgres.Parser`. libpg_query backend calls `pg_query_normalize`; pure-Go backend uses a regex literal-scrubber. `statement_digest = sha256:` + hex(SHA-256(Normalize(sql))) for every tier — digest invariant under redaction.
- Per-dialect classifier map built in `postgres.Server.New()` keyed on `svc.Dialect`. Same dialect across services shares a `Parser` instance. Unexported test hook for fake injection.
- Hot-swappable policy: `Server.SetPolicy(*policy.RuleSet)` via `atomic.Pointer[policy.RuleSet]`. Each statement reads the snapshot once at evaluate time. No mid-statement swap.
- `effects.ClassifiedStatement` gains `SourceStart` / `SourceEnd` (byte offsets into the original `Q` body) for per-stmt text slicing under `RedactionFull`. libpg_query exposes `stmt_location` + `stmt_len`; pure-Go fallback re-uses its splitter.
- Spine integration test: real `jackc/pgx/v5` client → real `*Server` in `terminate_reissue` mode → fake upstream goroutine speaking `pgproto3.Backend`. Three subtests: allow, pre-tx deny, in-tx deny terminate. Adds `pgx` as test-only dep.

### Out of scope (deferred)

- Extended Query (`Parse`/`Bind`/`Describe`/`Execute`/`Sync`/`Flush`/`Close`), SQL-level prepared cache, COPY data-frame handling, FunctionCall sub-protocol semantics (we reject the frame; we do not honor it). — Plan 05.
- Full §14 deny modes (`rollback_then_continue`, `idle_until_next_simple_query`); `tx_context.tx_started_at`; `approve` runtime workflow; GSSENC opt-in; async LISTEN/NOTIFY push delivery between Q…Z round-trips. — Plan 05.
- `BackendKeyData` mapping table; cancel governance via mapping lookup. — Plan 06.
- Out-of-process proxy under distinct SessionID; SO_PEERCRED → SessionID resolution; unavoidability bundle; testcontainer integration suite; recommendation flip to `enforce`. — Plan 07.

## 2. Architectural decisions

**D1. Single per-conn driver, half-duplex.** Simple Query is half-duplex by spec (one `'Q'` → response frames → `'Z'`). One goroutine per connection drives `simpleQueryLoop`, which sequentially reads a client frame, dispatches `'Q'` / `'X'` / other, and on allow-forward runs `forwardUpstreamUntilRFQ` to read upstream frames one at a time. No fan-in goroutines, no shared state between client and upstream readers. Async upstream pushes outside a round-trip (LISTEN/NOTIFY) are documented as deferred to Plan 05's two-goroutine model.

**D2. Statement digest is invariant under redaction.** `statement_digest = sha256:` + hex(SHA-256(Normalize(stmt))) for all three tiers (`full` / `parameters_redacted` / `none`). Operators integrating across deployments with different `LogStatements` settings can still join events on digest. Documented cross-implementation caveat: libpg_query and pure-Go `Normalize` outputs may differ, so digests are stable *within an implementation*, not across.

**D3. `Normalize` on Parser, not in proxy.** `internal/db/classify/postgres.Parser` gains `Normalize(sql string) (string, error)`. libpg_query backend calls `pg_query_normalize`. Pure-Go backend does a regex literal-scrubber for `'…'` strings, `$tag$…$tag$` dollar-quotes, and numeric literals. On `unknown` classification the digest is computed off the verbatim trimmed SQL with a documented note. Avoids duplicating normalization logic in the proxy and keeps the classifier the single source of truth for SQL surface manipulation.

**D4. Per-frame demux for upstream response.** The allow-forward path reads upstream frames one at a time via `pc.state.upstreamFE.Receive()` until `'Z'`. Forwards each frame to the client; accumulates result counters. The alternative (bytePump + 'Z' snoop) was rejected because it cannot populate `rows_returned` / `rows_affected` / `latency_ms` for the DBEvent, which the spec §8 result struct mandates.

**D5. Full §8 DBEvent schema, partial population.** Plan 04c lands `Decision`, `Result`, `TxContext`, `Predicates`, `TLS` sub-structs on `events.DBEvent`. Populates what is knowable in 04c (RFQ-byte-only transaction state, no `tx_started_at`, no `rollback_injected`); Plan 05's state machine fills the rest. Schema-stable from 04c forward so downstream consumers (audit sinks, dashboards) are not on a moving target.

**D6. Auto-built per-dialect classifier map.** `Server.New()` constructs a `map[string]postgres.Parser` from the dialects of declared `cfg.Services`. Same dialect across services shares one `Parser` (parsers are expensive on Linux+CGO). An unexported `classifierForTest` test hook overrides the map per-test.

**D7. Hot-swappable policy via `atomic.Pointer`.** `Server.SetPolicy(*policy.RuleSet)` swaps the active rule set atomically. Each statement's classify+evaluate reads the current snapshot once; no mid-statement swap. Cheap, well-tested pattern elsewhere in the project. Supervisor reload paths plug in cleanly.

**D8. Cross-plan touch on Plan 03's `ClassifiedStatement`.** Per-stmt text slicing under `RedactionFull` requires byte spans. We add `SourceStart` / `SourceEnd` to `effects.ClassifiedStatement` as part of 04c rather than retrofitting later. libpg_query's `stmt_location` + `stmt_len` make this a one-field surface bump. Pure-Go fallback re-uses its splitter. Accepted scope creep — duplicating split logic in the proxy would be worse.

## 3. Package layout

New files under `internal/db/proxy/postgres/` (all `//go:build linux`; the existing `stub_other.go` keeps non-Linux compiling):

```
internal/db/proxy/postgres/
├── simplequery.go        simpleQueryLoop; handleQuery; non-Q/non-X dispatch; MaxQueryBytes
├── upstreamread.go       forwardUpstreamUntilRFQ; per-frame demux; counter accumulation;
│                         CommandComplete tag parsing; per-stmt counter attribution
├── deny.go               synthErrorAndRFQ; synthErrorOnly; pickDenySynth; SQLSTATE picker;
│                         deny_message template substitution
├── eventbuilder.go       buildStatementEvent (pure); redaction tier render; statement_digest;
│                         per-stmt slice via ClassifiedStatement.SourceStart/SourceEnd
├── classifiers.go        per-dialect Parser map; Server.classifierFor(dialect);
│                         test hook plumbing
└── *_test.go             unit + spine tests
```

Modified files:

```
internal/db/proxy/postgres/
├── server.go             Config gains MaxQueryBytes + classifierForTest; New() builds
│                         dialect→Parser map and validates dialects; SetPolicy method;
│                         policy() helper returning atomic snapshot
├── proxyconn.go          connState gains lastUpstreamRFQ, redactionTier, tlsMode;
│                         emit helpers for statement events + frame-too-large lifecycle event
├── handshake.go          dialUpstreamAndForward, after forwardAuth returns successfully,
│                         seeds lastUpstreamRFQ='I' and calls simpleQueryLoop instead of
│                         returning nil
└── authforward.go        forwardAuth writes the observed 'Z' status byte into connState
│                         before returning (avoids a re-read in simpleQueryLoop)

internal/db/classify/postgres/
├── parser.go             Parser interface gains Normalize(sql) (string, error)
├── libpgquery.go         wire pg_query_normalize
├── wasm.go               wire wasilibs/go-pgquery Normalize (or document regex fallback)
└── parser_normalize_test.go  per-implementation + parity-on-curated-subset tests

internal/db/effects/
├── statement.go          ClassifiedStatement gains SourceStart, SourceEnd (int byte offsets;
│                         zero-valued when parser cannot supply them, e.g. unknown stmt)
└── statement_test.go     coverage of the new fields

internal/db/events/
└── event.go              DBEvent extended with TLS, Decision, Result, TxContext, Predicates
                          sub-structs; types defined in same file or split per taste
```

### Boundary calls

- `internal/db/proxy/postgres` depends on `effects`, `policy`, `classify/postgres`, `events`, `service`, `tlsleaf` (already true in 04a/b/b₂). No new external deps in the production path.
- `pgx` is a **test-only** dep; added to `go.mod` under no build tag (Go's testing has no separate dep set) but only imported from `_test.go` files. `go mod tidy` must remain clean.
- `events.DBEvent` schema extension is consumed by callers in `internal/db/proxy/postgres/eventbuilder.go` only. No other package builds events today; safe.

## 4. Public surface

### `internal/db/proxy/postgres.Config` additions

```go
type Config struct {
    // existing fields unchanged...

    // MaxQueryBytes caps the 'Q' frame body length. Default 1 MiB when zero.
    // Statements above the cap get a synthetic ErrorResponse(54000) + close.
    MaxQueryBytes int

    // classifierForTest, when non-nil, overrides the per-dialect Parser map
    // built by New(). Test-only — production callsites must leave this nil.
    classifierForTest func(dialect string) postgres.Parser
}
```

### `Server` additions

```go
func (s *Server) SetPolicy(rs *policy.RuleSet)  // atomic.Pointer swap; nil → implicit-deny everywhere
func (s *Server) policy() *policy.RuleSet       // unexported; reads atomic snapshot
func (s *Server) classifierFor(dialect string) postgres.Parser  // unexported
```

`New(cfg)` additionally:

1. Validates each `svc.Dialect` is recognized (`postgres`, `aurora_postgres`, `cockroachdb`, `redshift`); rejects unknowns with a clear error.
2. Builds a `map[string]postgres.Parser` keyed by dialect; shared across services with the same dialect.
3. Applies `MaxQueryBytes` default of 1 MiB when `cfg.MaxQueryBytes == 0`.
4. Stores `cfg.Policy` in the atomic pointer.

### `connState` additions

```go
type connState struct {
    // existing fields unchanged...
    lastUpstreamRFQ byte                 // 'I' | 'T' | 'E' | 0
    redactionTier   policy.RedactionTier // resolved at handshake end from rs.Redaction().LogStatements
    tlsMode         string               // svc.TLSMode at handshake end, for EventTLS.Mode
}
```

## 5. Simple Query control flow

### Entry from `forwardAuth`

`handshake.go::dialUpstreamAndForward` currently returns `nil` after `forwardAuth` returns on the first observed upstream `'Z'`. 04c changes the tail of that function to:

```go
if err := forwardAuth(ctx, pc); err != nil { /* unchanged paths */ }
// forwardAuth wrote the observed 'Z' status byte into pc.state.lastUpstreamRFQ
// before returning, so we don't re-read.
pc.state.redactionTier = pc.srv.policy().Redaction().LogStatements
pc.state.tlsMode = pc.svc.TLSMode
return pc.simpleQueryLoop(ctx)
```

### `simpleQueryLoop`

```go
func (pc *proxyConn) simpleQueryLoop(ctx context.Context) error {
    for {
        if err := ctx.Err(); err != nil { return err }
        msg, err := pc.backend.Receive()
        if err != nil { return err }   // EOF / closed-pipe are normal terminations
        switch m := msg.(type) {
        case *pgproto3.Query:
            if err := pc.handleQuery(ctx, m); err != nil { return err }
        case *pgproto3.Terminate:
            pc.state.upstreamFE.Send(m)
            _ = pc.state.upstreamFE.Flush()
            return nil
        default:
            return pc.handleUnsupportedFrame(ctx, m)
        }
    }
}
```

`pc.backend.Receive` is the existing pgproto3 Backend already wired in 04b. `MaxQueryBytes` enforcement happens at the `handleQuery` entry against `len(q.String)` (cheap; pgproto3 has already allocated the body, so this is mitigation-against-griefing rather than a hard pre-allocation ceiling — Phase 1 trades off the perfect ceiling for code simplicity. Documented limitation.).

### `handleQuery`

```go
func (pc *proxyConn) handleQuery(ctx context.Context, q *pgproto3.Query) error {
    if len(q.String) > pc.srv.cfg.MaxQueryBytes {
        pc.emitFrameTooLarge(ctx, len(q.String))
        _ = pc.synthErrorAndRFQ("54000", frameTooLargeMsg(len(q.String)))
        return errFrameTooLargeClose
    }
    parser := pc.srv.classifierFor(pc.svc.Dialect)
    stmts, _ := parser.Classify(q.String, postgres.SessionState{}, postgres.Options{})
    rs := pc.srv.policy()
    decisions := make([]policy.Decision, len(stmts))
    anyDeny := false
    for i, s := range stmts {
        decisions[i] = policy.Evaluate(s, rs, policy.ServiceID(pc.svc.Name))
        if decisions[i].Verb == policy.VerbApprove {
            decisions[i] = synthApproveAsDeny(decisions[i]) // APPROVE_NOT_YET_SUPPORTED
        }
        if decisions[i].Verb == policy.VerbDeny { anyDeny = true }
    }

    if !anyDeny {
        sentAt := timeNow()
        pc.state.upstreamFE.Send(q)
        if err := pc.state.upstreamFE.Flush(); err != nil { return err }
        result, err := pc.forwardUpstreamUntilRFQ(ctx, sentAt, len(q.String))
        pc.emitAllowEvents(ctx, stmts, decisions, q.String, result)
        return err
    }

    pc.emitDenyEvents(ctx, stmts, decisions, q.String)
    rendered, denyCode := pickDenySynth(decisions)
    switch pc.state.lastUpstreamRFQ {
    case 0, 'I':
        return pc.synthErrorAndRFQ(denyCode, rendered)
    case 'T', 'E':
        _ = pc.synthErrorOnly(denyCode, rendered)
        return errInTxTerminate
    default:
        return fmt.Errorf("postgres.handleQuery: unexpected RFQ byte %q", pc.state.lastUpstreamRFQ)
    }
}
```

`SessionState{}` is the empty session state; 04c does not track `SET search_path` / `SET ROLE`. Per spec §7.7 unqualified objects under no search_path resolve to `object_resolution=unresolved`, which is the Plan 03 corpus expectation.

### `forwardUpstreamUntilRFQ` (in `upstreamread.go`)

Reads upstream frames one at a time:

```go
type result struct {
    BytesIn      int64
    BytesOut     int64
    RowsByStmt   []int64    // len == count of CommandComplete frames
    AffectedByStmt []int64
    LatencyMs    int64
    ErrorCode    string     // empty when no upstream ErrorResponse
}
```

Frame handling:

| Upstream frame | Action |
|---|---|
| `*RowDescription` | forward; row counter for current stmt resets to 0 |
| `*DataRow` | forward; increment current stmt's row counter; add body length to `BytesOut` |
| `*CommandComplete` | parse `CommandTag` for affected count (see below); push current stmt's row count to `RowsByStmt`; push affected to `AffectedByStmt`; advance current-stmt index; forward |
| `*ErrorResponse` | forward; capture `SQLState` into `result.ErrorCode`; remaining stmts (if known) get null counters and `error_code: STATEMENT_ABORTED_BY_PRIOR_ERROR` at event-builder time |
| `*ReadyForQuery` | update `pc.state.lastUpstreamRFQ = m.TxStatus`; forward; flush; `result.LatencyMs = (now - sentAt).ms`; return |
| `*NoticeResponse` / `*ParameterStatus` / `*NotificationResponse` | forward verbatim; do not affect counters |
| other (`*ParameterDescription`, etc.) | forward verbatim |

`CommandComplete.CommandTag` parsing:

- `INSERT <oid> <n>` → affected = n
- `UPDATE <n>`, `DELETE <n>`, `MOVE <n>`, `FETCH <n>`, `COPY <n>` → affected = n
- `SELECT <n>` → affected = nil; rows = n (already counted via DataRow)
- everything else (`CREATE TABLE`, `BEGIN`, `COMMIT`, `SET`, etc.) → both nil

### Per-statement counter attribution

The *i*-th `CommandComplete` belongs to the *i*-th `ClassifiedStatement`. `DataRow` frames between `CommandComplete[i-1]` and `CommandComplete[i]` belong to stmt *i*. `latency_ms` / `bytes_in` / `bytes_out` are batch-level metrics; we attribute the **same** value to every per-stmt event in the batch (documented in event-builder godoc). When counts don't line up (fewer `CommandComplete` frames than statements — happens when upstream `ErrorResponse` aborts mid-batch), the remaining stmts get null `rows_returned` / `rows_affected` and `error_code: STATEMENT_ABORTED_BY_PRIOR_ERROR`.

## 6. Deny synthesis (`deny.go`)

`synthErrorAndRFQ(sqlstate, message)` writes:

```
ErrorResponse{Severity:"ERROR", SQLState: sqlstate, Message: message}
ReadyForQuery{TxStatus:'I'}
```

both flushed before returning. Used when `lastUpstreamRFQ ∈ {0, 'I'}`.

`synthErrorOnly(sqlstate, message)` writes the `ErrorResponse` only; caller closes both conns. Used when `lastUpstreamRFQ ∈ {'T', 'E'}`.

`pickDenySynth(decisions)` returns `(rendered, sqlstate)`:

- Iterates decisions in order; first denying entry wins (most-restrictive is deterministic per §10.2 with stable rule order).
- `sqlstate` (on-wire `ErrorResponse.SQLState`): `28000` for connection-rule deny (matches 04b₂'s pattern); `42501` for statement-rule deny (PG-standard "insufficient privilege"); `42501` also for the approve→deny stub case (`decisions[i].Approval != nil`).
- `rendered`: from `decisions[i].DenyMessage` (Plan 02 template) if present; else `"denied by AgentSH policy: <RuleName>"` (or `"denied by AgentSH policy: <Reason>"` for implicit-deny entries with empty RuleName).

The synth function only owns the on-wire side. The corresponding `EventResult.ErrorCode` set by the event builder is:
- `APPROVE_NOT_YET_SUPPORTED` for approve→deny stubs.
- `DENIED_BY_SIBLING` for non-denying statements in a batch where another statement denied (see §8).
- empty for the actual denying statement (its `decision.verb=deny` carries the signal).

`pickDenySynth` never returns nil; deterministic for tests.

## 7. DBEvent schema (`internal/db/events/event.go`)

```go
type DBEvent struct {
    // existing fields unchanged...

    TLS        EventTLS        `json:"tls"`
    Decision   EventDecision   `json:"decision"`
    Result     EventResult     `json:"result"`
    TxContext  EventTxContext  `json:"tx_context"`
    Predicates EventPredicates `json:"predicates,omitempty"`
}

type EventTLS struct {
    Mode                string `json:"mode"`                 // passthrough|terminate_reissue|terminate_plaintext_upstream
    ClientSNI           string `json:"client_sni,omitempty"`
    UpstreamCertSubject string `json:"upstream_cert_subject,omitempty"` // empty in 04c
}

type EventDecision struct {
    Verb                   string   `json:"verb"`              // allow|deny|approve|audit (approve never emitted live in 04c)
    RuleKind               string   `json:"rule_kind"`         // statement|connection|cancel
    RuleName               string   `json:"rule_name,omitempty"`
    MatchingEffectIndex    int      `json:"matching_effect_index"`
    MatchingEffectGroup    string   `json:"matching_effect_group,omitempty"`
    Reason                 string   `json:"reason,omitempty"`
    ContributingAuditRules []string `json:"contributing_audit_rules,omitempty"`
}

type EventResult struct {
    RowsReturned *int64 `json:"rows_returned"`
    RowsAffected *int64 `json:"rows_affected"`
    BytesIn      int64  `json:"bytes_in"`
    BytesOut     int64  `json:"bytes_out"`
    LatencyMs    int64  `json:"latency_ms"`
    ErrorCode    string `json:"error_code,omitempty"`
}

type EventTxContext struct {
    InTransaction bool      `json:"in_transaction"`
    TxStartedAt   time.Time `json:"tx_started_at,omitempty"`  // zero in 04c; Plan 05
    DenyAction    string    `json:"deny_action"`              // none|rollback_injected|connection_terminated
}

type EventPredicates struct {
    HasFilter bool `json:"has_filter"`
}
```

`RowsReturned` / `RowsAffected` are `*int64` because the spec wire form needs `null` for "not applicable": a `SELECT` event gets `RowsReturned` and leaves `RowsAffected` null; an `INSERT` does the inverse; `CREATE TABLE` leaves both null.

## 8. Redaction and digest (`eventbuilder.go`)

`buildStatementEvent(stmt, decision, sql, result, denyAction, tier, conn)` is pure and unit-testable. Render table:

| `tier` | `StatementText` | `StatementDigest` |
|---|---|---|
| `RedactFull` | `sql[stmt.SourceStart:stmt.SourceEnd]` (verbatim per-stmt slice) | `sha256:` + hex(SHA-256(Normalize(slice))) |
| `RedactParametersRedacted` (default) | `Normalize(slice)` | same as above |
| `RedactNone` | omitted (empty) | same as above |

When `stmt.SourceStart == stmt.SourceEnd == 0` (parser couldn't supply span — `unknown` statement, or fallback's degenerate case), `slice = sql` and a `parser_backend_caveat: "no_span"` tag is set on the event's `ParserBackend` field (free-form per Plan 01's schema).

`Normalize` errors degrade to the verbatim trimmed SQL; the digest is still populated.

### Multi-statement deny tagging (`denied_by_sibling`)

When `anyDeny` is true and statement *i* is not itself denying, its emitted event carries:

- `decision.verb = "deny"` (most-restrictive batch outcome, per §10.2).
- `decision.rule_name = ""`, `decision.rule_kind = "statement"`, `decision.reason = "denied by sibling statement"`.
- `result.error_code = "DENIED_BY_SIBLING"`.
- `result.rows_returned = nil`, `result.rows_affected = nil`, `result.bytes_in = len(q.String)`, `result.bytes_out = 0`, `result.latency_ms = 0`.

The denying statement(s) emit a normal `verb=deny` event with the actual `rule_name` / `reason` from `decisions[i]` and empty `result.error_code`.

### `command_id` for multi-statement batches

`command_id = "<sha-of-q.String>:<idx>"` for each per-stmt event. Operators correlate batch members on this prefix. Open question for v0.9 spec discussion: whether `batch_id` deserves its own field.

## 9. Hot-swap and classifier wiring

### `Server.SetPolicy`

```go
type Server struct {
    // existing fields unchanged...
    policyPtr atomic.Pointer[policy.RuleSet]
}

func (s *Server) SetPolicy(rs *policy.RuleSet) { s.policyPtr.Store(rs) }
func (s *Server) policy() *policy.RuleSet      { return s.policyPtr.Load() }
```

`New(cfg)` calls `s.policyPtr.Store(cfg.Policy)` before returning. `nil` policy is legal and means "implicit deny everywhere" (matches Plan 02's `Evaluate(stmt, nil, _)` contract).

### `classifierFor`

```go
func (s *Server) classifierFor(dialect string) postgres.Parser {
    if s.cfg.classifierForTest != nil {
        return s.cfg.classifierForTest(dialect)
    }
    p, ok := s.classifiers[dialect]
    if !ok { return s.classifiers["postgres"] } // shouldn't happen — New validated
    return p
}
```

`s.classifiers` is set once in `New()`; no locking needed because it's read-only after construction.

## 10. Testing strategy

### Unit tests (table-driven, per file)

| File | Cases |
|---|---|
| `simplequery_test.go` | Single allow; single deny pre-tx; single deny in-tx (`'T'` and `'E'`); multi-stmt all-allow; multi-stmt anyDeny → none-forwarded + N events with denied_by_sibling tagging; approve → APPROVE_NOT_YET_SUPPORTED synth + event verb=deny; frame > MaxQueryBytes → 54000 + close + FRAME_TOO_LARGE lifecycle; non-Q/non-X → 0A000 + close + EXTENDED_QUERY_NOT_SUPPORTED; classifier returns `unknown` → strict-coverage deny via policy.Evaluate. Classifier injected via `classifierForTest`. |
| `upstreamread_test.go` | Per-frame demux: DataRow counting; CommandComplete tag parsing (`INSERT 0 5`, `UPDATE 3`, `SELECT 7`, `DELETE 0`, `MOVE 0`, `CREATE TABLE` → null); per-stmt split via CommandComplete boundaries; latency_ms monotonic; bytes_in/out; ErrorResponse mid-batch → remaining stmts get `STATEMENT_ABORTED_BY_PRIOR_ERROR`; lastUpstreamRFQ updates from various 'Z' status bytes. |
| `deny_test.go` | RFQ-byte gating: `{0, 'I'}` → local synth + loop continues; `{'T', 'E'}` → ErrorResponse only + terminate; BEGIN-then-deny sequence; SQLSTATE selection (28000 for conn rule; 42501 for stmt rule and APPROVE_NOT_YET_SUPPORTED); deny_message template substitution. |
| `eventbuilder_test.go` | Redaction tiers: full → verbatim per-stmt slice; parameters_redacted → Normalize; none → empty StatementText. Digest stability: identical across tiers for same stmt. Multi-stmt: distinct EventID per stmt; command_id = `<sha>:<idx>`. Predicates.HasFilter mirrored from ClassifiedStatement. EventTLS.Mode mirrors svc.TLSMode. |
| `classifiers_test.go` | New() builds Parser keyed by dialect; same dialect shares instance; unknown dialect → New() error; classifierForTest overrides. |
| `parser_normalize_test.go` (in classify/postgres) | Normalize on representative SQL: literal scrubbing, identifier preservation, multi-stmt, error path. Linux+CGO and pure-Go variants both tested via the existing build-tag split. Curated-subset parity test. |

### Spine integration test (`spine_test.go`)

One test, three parallel subtests, real `pgx` + real `*Server` + fake upstream:

- **Allow**: `SELECT 1` → fake upstream replies with `RowDescription` + `DataRow{[1]}` + `CommandComplete("SELECT 1")` + `ReadyForQuery('I')`. Client receives row 1; SyncSink has one `db_statement` event with `Verb=allow`, `RowsReturned=1`, `RowsAffected=nil`, `ErrorCode=""`.
- **Pre-tx deny**: `DELETE FROM t` → policy denies. Client receives `ErrorResponse(42501)` + `ReadyForQuery('I')`. Fake upstream asserts zero post-Startup bytes received. SyncSink has one `db_statement` event with `Verb=deny`.
- **In-tx deny terminate**: `BEGIN` (allowed) → fake upstream `'Z'` with `T`; then `DELETE FROM t` → policy denies. Client receives `ErrorResponse(42501)` and conn closes. SyncSink has BEGIN event `Verb=allow` and DELETE event `Verb=deny` with `tx_context.deny_action="connection_terminated"`.

`pgx` added to `go.mod` as a test-only dep (imported only from `_test.go`). `go mod tidy` clean after.

### Cross-compile

`GOOS=windows go build ./...` stays green via existing `stub_other.go`. New files all `//go:build linux`. `events.DBEvent` schema extension lives in a build-tag-free file so non-Linux callers compile.

### Test isolation

`t.TempDir()` for StateDir; per-subtest `*Server`; explicit `t.Cleanup` to drain goroutines; tight deadlines on Read/Write in spine test to avoid net.Pipe flake (see prior `internal/store` Windows-timer flake pattern in memory).

## 11. Open questions and risks

### Open questions

1. **`command_id` shape for multi-stmt batches.** Adopting `command_id = "<sha-of-q.String>:<idx>"` in 04c. Spec §8 doesn't pin a format. Whether to add a real `batch_id` field is a v0.9 spec discussion, not a 04c blocker.
2. **Upstream `ErrorResponse` SQLSTATE prefix.** When upstream errors on an allowed stmt, we record `result.error_code = "<SQLSTATE>"` (raw, no `UPSTREAM_` prefix). Documented for operator consumption.
3. **`STATEMENT_ABORTED_BY_PRIOR_ERROR`** is 04c-coined for "previous stmt errored mid-batch, this one never executed." Free-form per spec §8.
4. **Pure-Go `Normalize` divergence.** Digest stability is within an implementation, not across. Documented; cross-host normalization unification is a Plan 03 problem.
5. **Plan 03 `ClassifiedStatement.SourceStart/SourceEnd` surface bump** is owned by 04c; accepted scope creep.

### Risks

- **Async LISTEN/NOTIFY pushes outside Q…Z round-trips** are not delivered in 04c. Documented as a known limitation; Plan 05's two-goroutine state machine fixes it. Chief regression risk for chatty notification consumers.
- **`Normalize` cross-backend digest divergence** is operator-confusing on multi-host deployments.
- **Spine test flakiness via `net.Pipe`.** Mitigation: tight deadlines, explicit `t.Cleanup`, `-race` runs in CI.
- **DBEvent schema bump** is a wire-shape change. Safe in 04c — no external consumers of events yet.
- **`MaxQueryBytes` enforcement after pgproto3 body allocation** is mitigation-grade rather than a hard ceiling. Documented; a future plan can swap to a streaming framer if memory griefing becomes real.

### Deferred (covered earlier; restated for completeness)

- **To Plan 05.** Extended Query (Parse/Bind/Describe/Execute/Sync/Flush/Close), SQL-level prepared cache, COPY data-frame handling, FunctionCall semantics, full §14 deny modes including `rollback_then_continue`, `tx_started_at`, `approve` runtime, GSSENC opt-in, async LISTEN/NOTIFY delivery.
- **To Plan 06.** BackendKeyData mapping, cancel governance via mapping lookup.
- **To Plan 07.** SO_PEERCRED → SessionID, out-of-process proxy, unavoidability bundle, real-PG integration suite, bypass-tool detection, recommendation flip to `enforce`.

## 12. Rollout

Ships behind `policies.db.unavoidability: off` (default) — no listener bound, no behavior change. `observe` mode is the recommended first flip: listeners bind, queries are intercepted, `db_statement` events emit. `enforce` is **not recommended** in 04c — the unavoidability bundle (network/file rules preventing direct egress) is still Plan 07.

Plan release notes call out four known-limitation items:
- `approve` → `deny + APPROVE_NOT_YET_SUPPORTED`.
- `CancelRequest` forwarded un-mapped (broken-by-design until Plan 06).
- LISTEN/NOTIFY async pushes delivered only inside Q…Z round-trips.
- `client_identity` is `uid:<peer_uid>` not SessionID (Plan 07).

## 13. Done definition

Plan 04c is done when:

1. `internal/db/proxy/postgres` builds on Linux and stubs cleanly elsewhere; `GOOS=windows go build ./...` is green.
2. All unit tests above pass, including the spine integration test with real `pgx` + fake upstream covering allow / pre-tx deny / in-tx deny terminate.
3. A YAML config with `policies.db.unavoidability: observe`, one `db_services` entry, and a sample policy with both `allow` and `deny` rules produces:
   - A `pgx` client connecting through the Unix socket runs `SELECT 1` successfully.
   - The same client running a denied `DELETE` receives `ErrorResponse(42501)` + `ReadyForQuery('I')` without any upstream traffic.
   - The audit sink contains one `db_statement` event per statement with `verb`, `effects`, `statement_digest`, `statement_redaction`, `decision`, `result`, `tx_context`, `predicates`, and `tls` sub-structs populated.
4. A YAML config with `policies.db.unavoidability: off` remains a no-op: no listener bound, no events emitted, no behavior change.
5. `go test ./...` is green on Linux; `go mod tidy` clean after `pgx` test-only dep addition.
