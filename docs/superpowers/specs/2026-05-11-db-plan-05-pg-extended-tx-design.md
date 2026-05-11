# db-access Plan 05 — Extended Query, Transactions, SQL Prepared, FunctionCall, COPY, Approval (design)

Status: design draft 2026-05-11. Brainstormed via superpowers:brainstorming. Implementation plans to follow via superpowers:writing-plans, split into 05a / 05b / 05c per §3.

Cross-references:
- Roadmap: `docs/superpowers/specs/2026-05-08-db-access-phase-1-roadmap-design.md` §3 Plan 05.
- Spec: `docs/agentsh-db-access-spec.md` v0.8 §7.1 (wire framing), §7.3 (mapping incl. COPY rows), §7.4 (SQL-level prepared statements), §7.5 (FunctionCall sub-protocol), §7.6 (function-call escalation), §9.2 (DEALLOCATE / DISCARD coverage by `app-allow-safe-session-settings`), §14 (transaction correctness, deny modes, approval timeouts).
- Predecessor design: `docs/superpowers/specs/2026-05-10-db-plan-04-pg-proxy-skeleton-design.md` (shared design for 04a/04b/04b2/04c).
- Predecessor plans: `docs/superpowers/plans/2026-05-10-db-plan-04a-listener-skeleton.md`, `…-04b-handshake-tls.md`, `…-04b2-upstream-passthrough.md`, `…-04c-simple-query-events.md`.

This document covers Plan 05 in three sub-plans (05a, 05b, 05c) sharing one design pass. Each sub-plan gets its own implementation file written via `superpowers:writing-plans`.

## 1. Scope

### In scope across 05a/05b/05c

- **Extended Query state machine** (`Parse` / `Bind` / `Describe` / `Execute` / `Sync` / `Flush` / `Close`) per §14.2, including `upstream_dirty_since_sync` and `absorbing` flags.
- **Wire-protocol prepared statement cache** per connection (LRU cap 4096).
- **Full transaction state tracking** (`Idle | InTx | InTxError | InCopyIn | InCopyOut`) replacing 04c's RFQ-byte tracker.
- **`deny_mode_in_tx: terminate | rollback_then_continue`** field on `database_rules` per §14.3, with `tx_started_at` and `deny_action: rollback_injected` event fields populated.
- **SQL-level `PREPARE` / `EXECUTE` / `DEALLOCATE` / `DEALLOCATE ALL` / `DISCARD ALL` / `DISCARD PLANS`** per §7.4, with a *second* LRU instance per connection (same type as the wire cache; separate keyspace).
- **`DISCARD TEMP` / `DISCARD SEQUENCES`** classified as `session` per §7.3; no cache mutation. Covered by `app-allow-safe-session-settings` per §9.2 R1.
- **FunctionCall (`F`) sub-protocol** per §7.5: default-deny `42501` becomes a real enforcement path; per-service `allow_function_call_protocol: true` opt-in classifies as `procedural` / `function_call_protocol` and runs evaluate-or-deny.
- **Function-call escalation** per §7.6 inside the classifier: `policies.db.escalate_unknown_functions: true` + `policies.db.safe_function_allowlist: [...]` reclassifies `SELECT f()` as `procedural` / `escalated_function_call` when `f` is not in the allowlist.
- **COPY data-frame handling** for the duration of `bulk_load` / `bulk_export`: byte-passthrough of `CopyData`, exit on `CopyDone` / `CopyFail` / `ErrorResponse`, byte counters accumulate into `result.bytes_in` / `bytes_out`.
- **Approval runtime** per §14.5: `Approver` interface with `NopApprover` default; 60s default timeout; in-tx timeouts route through `deny_mode_in_tx`; client `Terminate` during wait → cancel via new `deny_action: cancelled_during_approval`.
- **Async upstream pushes** (`NotificationResponse`, `NoticeResponse`, `ParameterStatus`) outside an active Q…Z or Sync window are forwarded to the client transparently — implicit consequence of the new dispatcher continuously reading upstream; no special handling.

### Out of scope (deferred)

- BackendKeyData mapping table, cancel mapping (Plan 06).
- SO_PEERCRED → SessionID resolution, out-of-process proxy, unavoidability bundle, real-PG testcontainer integration tests, bypass-tool detection (Plan 07).
- Function OID → name resolution (Phase 2). FunctionCall events carry `function_oid: <int>` and `function_name: null`.
- Partial-approval semantics ("allow once, not always") (Phase 2+).
- Catalog-aware policy (Phase 7).
- Async LISTEN/NOTIFY *delivery quality-of-service* (e.g., backpressure on slow clients). The dispatcher forwards async pushes as-is; if the client is slow, normal TCP backpressure applies.

## 2. Architectural decisions

These decisions were settled during brainstorming and govern the three sub-plans.

**D1. Pure transition core + Action enum.** The Extended Query state machine lives in a new sub-package `internal/db/proxy/postgres/statemachine/` as a *pure function*: `Transition(state, frame, cacheView, ruleSet) → (nextState, []Action)`. The Action sum type (Forward, SynthError, SynthReadyForQuery, Suppress, InjectRollback, DrainUntilRFQ, Close, TrackUpstreamRFQ, CachePut/Lookup/Delete/Clear, ApproverWait, CopyEnter, CopyExit) is the only interface between transition logic and I/O. The dispatcher in `internal/db/proxy/postgres/extquery.go` executes Actions against `proxyConn`'s `pgproto3.Frontend`/`Backend` and the upstream conn. Rationale: §14.2 has a 3-way Sync sub-case × 2 absorbing × 2 dirty × 4 upstream RFQ states — a state-table that pays for property tests. Keeping I/O out of the core lets the table tests be exhaustive.

**D2. Three sub-plans sharing one design.** Plan 05's scope (Extended Query, tx state, SQL prepared, FunctionCall, escalation, COPY, approval) is too large for one plan; brainstorming on 2026-05-11 split it 05a/05b/05c by dependency lines, mirroring how Plan 04 split into 04a/04b/04b2/04c. The split is:

- **05a** — Extended Query state machine + transaction state machine + wire prepared cache + `deny_mode_in_tx` (§7.1 framing extensions, §14).
- **05b** — SQL-level PREPARE/EXECUTE/DEALLOCATE/DISCARD prepared cache + FunctionCall (`F`) opt-in + function-call escalation (§7.4, §7.5, §7.6).
- **05c** — COPY data-frame handling + Approver interface + approval-timeout runtime (§7.3 COPY rows, §14.5).

05a is on the critical path: 05b and 05c both depend on 05a's state machine and Action enum. 05b and 05c are independent of each other and may proceed in parallel after 05a lands.

**D3. Shared prepared-cache type, two instances per connection.** A single LRU implementation `internal/db/proxy/postgres/preparedcache/Cache` (cap 4096) is built in 05a. Each `proxyConn` carries two instances: `wireCache` (populated by 05a's Extended Query Parse handler) and `sqlCache` (populated by 05b's `PREPARE`/`EXECUTE` interception). The two are separate keyspaces per §7.4 last paragraph. 05a wires only `wireCache`; the `sqlCache` field exists but is unused until 05b lands.

**D4. `deny_mode_in_tx` is a per-rule field.** Spec §14.3 says default is `terminate` and soft mode is `rollback_then_continue`; the spec is silent on where the mode is configured. Decision: it's a field on `database_rules` entries (alongside `decision`, `deny_message`, etc.). Validator rejects the field on non-deny rules and rejects unknown values. Rationale: §14.3 calls soft mode "for development environments only" — global or per-service is too coarse; per-rule lets one dev rule flip soft mode while production rules stay terminate.

**D5. Approval runtime: `Approver` interface + `NopApprover` default.** §14.5 governs timeouts but is silent on the actual approval mechanism. Decision: a small `Approver` interface in `internal/db/policy/approver.go` with method `Decide(ctx context.Context, cs effects.ClassifiedStatement, timeout time.Duration) (approved bool, err error)`. The default `NopApprover` blocks until `ctx.Done()` or `timeout`, then returns `(false, nil)` — i.e., always denies on timeout. Plan 05c ships this default. A future plan can swap in a real implementation (HTTP-backed, signal-backed, etc.) without touching the dispatcher.

**D6. Function-call escalation in the classifier.** §7.6 reclassification (`SELECT f()` → `procedural` when `f ∉ safe_function_allowlist`) happens inside `internal/db/classify/postgres/`'s AST walk via two new `Options` fields (`EscalateUnknownFunctions bool`, `SafeFunctionAllowlist []string`). Rationale: the classifier already walks function-call nodes; post-processing in the proxy would mean either re-walking the AST or piping function names alongside `ClassifiedStatement`. Symmetric with existing classifier knobs.

**D7. COPY is byte-passthrough with counters; no cap.** The CopyData stream is byte-passed; counters accumulate into `result.bytes_in` / `bytes_out`. No `max_copy_bytes` cap. Rationale: 04c capped `Q`-frame size because a single body can balloon memory; COPY is streaming so there's no memory pressure. Operators rely on PG-side `statement_timeout` for runaway protection. Revisit in Phase 2 if needed.

**D8. `APPROVE_NOT_YET_SUPPORTED` warning lifecycle.** 04c's policy decoder emits this warning when any rule has `decision: approve` and `Unavoidability != off`. 05a keeps emitting it (approver runtime is not in 05a). 05c removes it once `NopApprover` is the default and `decision: approve` is a live verb. Operators on a 05a-only deploy still see the warning; operators on 05c see no warning but every approve-targeted statement deny on timeout under `NopApprover` until a real approver is wired. Documented in 05c release notes.

**D9. 05a routes Simple Query through the new state machine.** 04c's `simpleQueryLoop` reads `'Q'` and `'X'` frames; 05a extends this to also handle Parse/Bind/Describe/Execute/Sync/Flush/Close. Rather than maintain two parallel deny paths, 05a refactors `'Q'` handling to go through the same `denyRoute` helper that Extended Query uses. The §14.4 fork (out-of-tx vs in-tx + `terminate` vs `rollback_then_continue`) is implemented once and consumed twice.

## 3. Sub-plan deliverables

### 3.1 Plan 05a — Extended Query + transaction state machine

Spec-§: 7.1 (Extended Query framing), 14.2, 14.3, 14.4; roadmap §23.4 step 6.

Deliverables:

- New sub-package `internal/db/proxy/postgres/statemachine/`:
  - `state.go` — `ConnState{phase Phase, lastUpstreamRFQ byte, absorbing bool, upstreamDirtySinceSync bool, txStartedAt time.Time, currentSyncBoundary uint64}` plus `Phase` enum (`PreAuth`, `Idle`, `InQuery`, `InTx`, `InTxError`, `InCopyIn`, `InCopyOut`).
  - `action.go` — `Action` interface with private method; concrete types `ActionForward`, `ActionSynthError{SQLState, Message}`, `ActionSynthReadyForQuery{Status byte}`, `ActionSynthParseComplete`, `ActionSynthBindComplete`, `ActionSuppress`, `ActionInjectRollback`, `ActionDrainUntilRFQ`, `ActionClose`, `ActionTrackUpstreamRFQ{Status byte}`. (`ActionApproverWait`, `ActionCopyEnter`, `ActionCopyExit` added by 05c.) Cache mutations are *not* Actions — `Transition` mutates the `CacheView` directly. Rationale: keep `Action` focused on I/O the dispatcher must execute; tests observe cache mutations through a recording fake `CacheView`.
  - `transition.go` — `Transition(s ConnState, frame Frame, cache CacheView, rules *policy.RuleSet) (next ConnState, []Action)`.
  - `handle_extended.go` — one helper per frame kind: `handleParse`, `handleBind`, `handleDescribe`, `handleExecute`, `handleSync`, `handleFlush`, `handleClose`.
  - `handle_simple.go` — `handleSimpleQuery` reuses `denyRoute` so the §14.4 fork is shared.
  - `denyroute.go` — `denyRoute(s ConnState, rule policy.StatementRule, msg string) []Action` implementing §14.3/§14.4 fork.
  - `frame.go` — `Frame` interface; thin shim wrapping `pgproto3` message types so the state machine doesn't transitively import pgproto3 (test ergonomics).
  - `cacheview.go` — `CacheView` interface satisfied by `preparedcache.Cache` in production and a map in tests.

- New sub-package `internal/db/proxy/postgres/preparedcache/`:
  - `cache.go` — LRU; cap 4096; concurrency-safe (RWMutex); satisfies `statemachine.CacheView`.
  - `classification.go` — cached value type: `effects.ClassifiedStatement` + `policy.RedactionTier` snapshot at Parse time.

- New `internal/db/proxy/postgres/extquery.go` — dispatcher reading frames, calling `Transition`, executing Actions. Replaces 04c's `handleUnsupportedFrame` for the Extended Query frame kinds.
- Modifications:
  - `internal/db/proxy/postgres/simplequery.go` — `simpleQueryLoop` dispatches Parse/Bind/etc. to `extquery`; `handleQuery` (Q) reuses `statemachine.denyRoute` for in-tx denies.
  - `internal/db/proxy/postgres/proxyconn.go` — replace `lastUpstreamRFQ byte` with embedded `smState statemachine.ConnState`; add `wireCache *preparedcache.Cache`, `sqlCache *preparedcache.Cache` (latter unused until 05b); add `txStartedAt time.Time` accessor.
  - `internal/db/proxy/postgres/upstreamread.go` — every `Z` (RFQ) emits `ActionTrackUpstreamRFQ` so state stays consistent; CommandComplete tag parsing unchanged.
  - `internal/db/proxy/postgres/deny.go` — extends `pickDenySynth` to consult `statemachine.denyRoute` (effectively becomes a thin wrapper).
  - `internal/db/proxy/postgres/handshake.go` — `dialUpstreamAndForward` after-auth path enters the unified frame loop.
  - `internal/db/events/event.go` — `TxContext.TxStartedAt *time.Time` populated; `TxContext.DenyAction` accepts `"rollback_injected"`.
  - `internal/db/policy/types.go` — `StatementRule.DenyModeInTx string` (`""` | `"terminate"` | `"rollback_then_continue"`; `""` == terminate).
  - `internal/db/policy/validate.go` — reject `deny_mode_in_tx` on non-deny rules; reject unknown values; reject on `match_kind: cancel` rules (§9.4 already does this for `approve`; same idea).

Tests:

- `statemachine/transition_test.go` — ~80-row table test covering every §14.2 sub-case for every frame kind.
- `statemachine/property_test.go` — property test (rapid or testing/quick) generating random valid frame sequences; invariants enumerated in §6 below.
- `preparedcache/cache_test.go` — LRU eviction at 4096; get/put/delete/clear; concurrent stress.
- `extquery_test.go` — dispatcher feeds pgproto3 frames to fake `proxyConn`; asserts bytes back via `pgproto3.Backend`.
- `simplequery_test.go` (extends 04c) — `denyRoute` integration for Q-frame denies.
- `deny_test.go` (extends 04c) — in-tx + terminate and in-tx + rollback_then_continue rows.
- `policy/validate_test.go` (extends) — `deny_mode_in_tx` validation.
- `spine_test.go` (extends 04c) — three real-pgx subtests: extended-query happy path, extended-query deny, in-tx rollback_then_continue.

External behavior after 05a under flag = `observe`: Extended Query queries (e.g., `pgx`'s default driver path) classify and emit `db_statement` events; in-tx denies route per `deny_mode_in_tx`. `FunctionCall` still falls through to 04c's `42501` stub (Plan 05b fills it in). COPY frames still trip the `0A000` "unexpected frame" path (Plan 05c fills them in). `decision: approve` rules still deny with `APPROVE_NOT_YET_SUPPORTED` at config-load (Plan 05c removes the warning and enables the runtime).

### 3.2 Plan 05b — SQL prepared cache, FunctionCall, escalation

Spec-§: 7.4, 7.5, 7.6, 9.2 R1; roadmap §23.4 step 6 (SQL-prepared work) + step 9 (FunctionCall opt-in).

Deliverables:

- New files:
  - `internal/db/proxy/postgres/sqlprepared.go` — `Intercept(sql, sqlCache, ruleSet) → (Handled bool, []Action)`. Recognizes PREPARE/EXECUTE/DEALLOCATE/DEALLOCATE ALL/DISCARD ALL/DISCARD PLANS in the parsed AST; mutates `sqlCache`; returns `(true, denyRoute(...))` on policy-deny or cache-miss; returns `(false, nil)` to let the normal classify path proceed.
  - `internal/db/proxy/postgres/funccall.go` — replace 04c's `42501` stub: read `F` frame, check `service.AllowFunctionCallProtocol`, classify as `procedural`/`function_call_protocol` with `function_oid` populated, evaluate, Forward or `denyRoute`.
  - `internal/db/classify/postgres/escalate.go` — AST walk extension. For `SELECT` nodes (or any `read`-classified node containing function calls), if `opts.EscalateUnknownFunctions == true` and any called function name is not in `opts.SafeFunctionAllowlist`, replace the primary effect with `procedural`/`escalated_function_call`. Object list includes the offending function name(s).
  - `internal/db/classify/postgres/builtin_immutable.go` — hand-curated seed list of immutable PG builtins (~50 functions: `now`, `nextval`, `to_tsvector`, `length`, `abs`, …). Documented as "best-effort, not exhaustive."

- Modifications:
  - `internal/db/proxy/postgres/proxyconn.go` — wire `sqlCache` to use the existing field set up in 05a.
  - `internal/db/proxy/postgres/simplequery.go` — `handleQuery` calls `sqlprepared.Intercept` *before* classify so PREPARE/EXECUTE/etc. short-circuit appropriately.
  - `internal/db/classify/postgres/parser.go` — `Options{EscalateUnknownFunctions bool, SafeFunctionAllowlist []string}` fields; threaded through `classifyWithBackend`.
  - `internal/db/policy/types.go` — `policies.db.escalate_unknown_functions bool` (default false), `policies.db.safe_function_allowlist []string` (default = `builtin_immutable.Default()`).
  - `internal/db/service/types.go` — `db_services.<name>.allow_function_call_protocol bool` (default false).
  - `internal/db/events/event.go` — `Effect.FunctionOID *int32` (omitempty); populated only for `function_call_protocol` and `escalated_function_call` events.

Tests:

- `sqlprepared_test.go` — every §7.4 form: PREPARE allow/deny, EXECUTE hit/miss/deny-on-reeval (hot-reload), DEALLOCATE name/ALL, DISCARD ALL/PLANS, unnamed PREPARE/EXECUTE round-trip.
- `funccall_test.go` — default → `42501`; opt-in + deny → `denyRoute`; opt-in + allow → Forward + event with `function_oid`.
- `classify/postgres/escalate_test.go` — golden corpus rows: baseline `SELECT 1` (read), `SELECT now()` with escalation off (read), `SELECT now()` with escalation on + `now` in allowlist (read), `SELECT do_thing()` with escalation on + `do_thing` not in allowlist (procedural/escalated_function_call).
- `spine_test.go` (extends) — SQL-PREPARE deny round-trip and FunctionCall opt-in round-trip with a fake upstream that responds to `F`.

External behavior after 05b: `PREPARE name AS SELECT …` is classified and cached; subsequent `EXECUTE name(…)` re-evaluates from cache; FunctionCall opt-in surfaces real events. Escalation flag opt-in reclassifies volatile function calls.

### 3.3 Plan 05c — COPY frames + approval runtime

Spec-§: 7.3 (COPY rows), 7.5 (function call ack — already in 05b), 14.5; roadmap §23.4 step 6 (COPY) + step 9 (approval).

Deliverables:

- New files:
  - `internal/db/proxy/postgres/copyframes.go` — enter `InCopyIn`/`InCopyOut` phase when upstream sends `CopyInResponse`/`CopyOutResponse` for an allowed COPY; byte-pass `CopyData` frames; accumulate into `result.bytes_in`/`bytes_out`; exit on `CopyDone`/`CopyFail`/`ErrorResponse`. Client `Terminate` during COPY → send `CopyFail` upstream then close.
  - `internal/db/policy/approver.go` — `Approver` interface; `NopApprover` default; `ErrApproverNotConfigured` sentinel (kept for future use; `NopApprover` is the live default).
  - `internal/db/proxy/postgres/approvalwait.go` — dispatcher routine for `ActionApproverWait`: spawn goroutine `cfg.Approver.Decide(ctx, cs, timeout)`; concurrent `time.After(timeout)`; first-to-resolve wins; route result through `denyRoute` (approved → emit original frame's Forward action; denied/timed-out → emit deny with `deny_action: approval_timeout | approval_denied`). Client `Terminate` during wait → cancel + `deny_action: cancelled_during_approval`.

- Modifications:
  - `internal/db/proxy/postgres/statemachine/action.go` — add `ActionApproverWait{Timeout time.Duration, Decide func(context.Context) (bool, error), ResultFrame statemachine.Frame, Rule policy.StatementRule}`, `ActionCopyEnter{Direction CopyDir}`, `ActionCopyExit`.
  - `internal/db/proxy/postgres/statemachine/transition.go` — extended frame handlers route `decision: approve` to `ActionApproverWait`; upstream `CopyInResponse`/`CopyOutResponse` route to `ActionCopyEnter`; `CopyDone`/`CopyFail`/`ErrorResponse` while in COPY phase route to `ActionCopyExit`.
  - `internal/db/proxy/postgres/server.go` — `Config.Approver policy.Approver` field; default `policy.NopApprover{}`; `New()` plumbs into per-conn state.
  - `internal/db/policy/decode.go` — *remove* the `APPROVE_NOT_YET_SUPPORTED` warning emission.
  - `internal/db/policy/decode_test.go` — remove the warning-emission test; add coverage that `decision: approve` is no longer flagged.
  - `internal/db/events/event.go` — `TxContext.DenyAction` accepts `"approval_timeout"`, `"approval_denied"`, `"cancelled_during_approval"`.
  - `internal/db/effects/statement.go` — `ClassifiedStatement.BulkOp BulkOpKind` (`""` | `"copy_in"` | `"copy_out"`) so the dispatcher knows which COPY direction to enter after forwarding. Populated by the classifier from the existing COPY effect; backward-compatible.
  - `internal/db/classify/postgres/ast_walk.go` — populate `BulkOp` when classifying a COPY statement.

Tests:

- `copyframes_test.go` — bulk_load enter/byte-pass/exit; bulk_export enter/byte-pass/exit; mid-COPY upstream `ErrorResponse` exits cleanly; client `Terminate` mid-COPY sends `CopyFail` upstream + closes; counter accumulation asserted against the event payload.
- `approvalwait_test.go` — fake Approver returning `(true, nil)` → Forward; `(false, nil)` → deny with `approval_denied`; `NopApprover` + injected clock at 60s → deny with `approval_timeout`; client Terminate during wait → cancel + `cancelled_during_approval`.
- `policy/approver_test.go` — `NopApprover` ctx-cancel vs timeout ordering.
- `effects/statement_test.go` (extends) — `BulkOp` JSON round-trip with omitempty.
- `classify/postgres/ast_walk_test.go` (extends) — `BulkOp` population for each COPY form.
- `spine_test.go` (extends) — real-pgx COPY-out (bulk_export) round-trip with byte counter; one approve-rule round-trip that times out under `NopApprover` (clock injected).

External behavior after 05c: COPY-based bulk_export and bulk_load are fully observed with byte-count accounting. `decision: approve` rules block the statement for up to 60s (default) under `NopApprover`, then deny; the `APPROVE_NOT_YET_SUPPORTED` config-load warning is gone. A future plan can wire a real Approver without touching 05c.

## 4. Per-frame semantics (the §14.2 table, locked)

This is the authoritative table that drives 05a's `transition.go` and its table tests. Read it in conjunction with §14.3 / §14.4 — the "deny" rows defer to `denyRoute` defined below.

### 4.1 Extended Query per-frame

| Frame | Preconditions | Actions emitted | State changes |
|---|---|---|---|
| `Parse(name, sql)` | not absorbing; policy: allow / audit / approve | `Forward`, `cache.Put(name, cls)` (direct); if approve: `ApproverWait` instead of Forward | `upstreamDirtySinceSync=true` |
| `Parse(name, sql)` | not absorbing; policy: deny | `denyRoute(...)` (see §4.3) | `absorbing=true` if not closing |
| `Parse` | absorbing | `Suppress` | — |
| `Bind(portal, name, …)` | not absorbing; cache hit | `Forward` | `upstreamDirtySinceSync=true` |
| `Bind(portal, name, …)` | not absorbing; cache miss | `SynthError(34000, "prepared statement \"name\" does not exist")` | `absorbing=true` |
| `Bind` | absorbing | `Suppress` | — |
| `Describe(target)` | not absorbing | `Forward` | `upstreamDirtySinceSync=true` |
| `Describe` | absorbing | `Suppress` | — |
| `Execute(portal, max)` | not absorbing; re-eval cached cls → allow | `Forward` | `upstreamDirtySinceSync=true` |
| `Execute(portal, max)` | not absorbing; re-eval → deny | `denyRoute(...)` | `absorbing=true` if not closing |
| `Execute(portal, max)` | not absorbing; re-eval → approve | `ApproverWait` | (held; see §5) |
| `Execute` | absorbing | `Suppress` | — |
| `Flush` | not absorbing | `Forward` | — |
| `Flush` | absorbing | `Suppress` | — |
| `Close(target)` | not absorbing | `Forward`, `cache.Delete(name)` (direct, if statement target) | `upstreamDirtySinceSync=true` |
| `Close` | absorbing | `Suppress` | — |
| `Sync` | not absorbing, not dirty | `Forward`, `TrackUpstreamRFQ` (case 1 chosen: forward) | — |
| `Sync` | absorbing, dirty | `Forward`; forward upstream responses up to deny-point unchanged; **suppress** subsequent upstream responses until upstream RFQ; then `TrackUpstreamRFQ`; forward RFQ to client | reset `absorbing`, reset `upstreamDirtySinceSync` |
| `Sync` | absorbing, not dirty | `SynthReadyForQuery(I)` | reset `absorbing` |
| `Sync` | upstream phase=T (in-tx) | §14.3 governs; this row not entered — the deny that put us in-tx already emitted Close or InjectRollback | — |
| `Terminate (X)` | any | `Forward`, `Close` | — |
| `CopyData` / `CopyDone` / `CopyFail` | phase ∉ {InCopyIn, InCopyOut} | `SynthError(0A000, "unexpected COPY frame")`, `Close` | — |
| `CopyData` / `CopyDone` / `CopyFail` | phase ∈ {InCopyIn, InCopyOut} | byte-pass (handled by 05c's `copyframes.go`, outside the state machine) | counters updated; on `CopyDone`/`CopyFail` exit COPY phase |
| `FunctionCall (F)` | service.AllowFunctionCallProtocol=false | `SynthError(42501, "FunctionCall denied")`, `SynthReadyForQuery(I)` | — |
| `FunctionCall (F)` | service.AllowFunctionCallProtocol=true; deny | `denyRoute(...)` | — |
| `FunctionCall (F)` | service.AllowFunctionCallProtocol=true; allow | `Forward` | `upstreamDirtySinceSync=true` |

### 4.2 Simple Query (`'Q'`) — preserved from 04c, refactored to share `denyRoute`

| Sub-case | Actions |
|---|---|
| All allowed | `Forward(Q)` (entire body); per-stmt event emission unchanged from 04c |
| One or more denied | `denyRoute(s, deniedRule, msg)` per §14.4; suppress sibling forwards per 04c |
| `PREPARE name AS <inner>` (05b) | classify inner; if allow: `Forward(Q)` + `sqlCache.Put(name, innerCls)` (direct). If deny: `denyRoute` |
| `EXECUTE name(args)` (05b) | `sqlCache.Get(name)` (direct); hit + allow: `Forward(Q)`; hit + deny: `denyRoute`; miss: `SynthError(SQL_PREPARED_CACHE_MISS)`, `SynthReadyForQuery(I)` |
| `DEALLOCATE name` / `DEALLOCATE ALL` (05b) | `sqlCache.Delete(name)` / `sqlCache.Clear()` (direct); `Forward(Q)` |
| `DISCARD ALL` / `DISCARD PLANS` (05b) | `sqlCache.Clear()` (direct); `Forward(Q)` |
| `DISCARD TEMP` / `DISCARD SEQUENCES` (05b) | classified as `session` (per §7.3); `Forward(Q)`. Covered by `app-allow-safe-session-settings` per §9.2 R1. No cache mutation. |

### 4.3 `denyRoute` (the §14.3 + §14.4 fork)

```
denyRoute(s ConnState, rule StatementRule, msg string) []Action:
  // Out-of-tx: lastUpstreamRFQ in {0, 'I'}
  if s.lastUpstreamRFQ != 'T':
    if !s.upstreamDirtySinceSync:
      return [SynthError(rule.SQLState, msg), SynthReadyForQuery('I')]
    else:
      return [SynthError(rule.SQLState, msg), Forward(Sync), DrainUntilRFQ, /* forward upstream RFQ */]

  // In-tx: lastUpstreamRFQ == 'T'
  mode = rule.DenyModeInTx
  if mode == "" || mode == "terminate":
    return [SynthError(rule.SQLState, msg), Close]
  if mode == "rollback_then_continue":
    return [SynthError(rule.SQLState, msg), InjectRollback, DrainUntilRFQ, SynthReadyForQuery('I')]
```

This is the *only* place deny actions are constructed in 05a; Simple Query and Extended Query both funnel through it. 05c extends the "approve-timeout"/"approve-denied" paths by routing through the same fork with `deny_action` populated upstream of the call.

## 5. Approval runtime (Plan 05c, detail)

When the state machine encounters `decision.verb == approve`, it emits `ActionApproverWait{Timeout, Decide, ResultFrame, Rule}` and returns. The dispatcher:

1. Spawns `cfg.Approver.Decide(ctx, cs, timeout)` on a fresh goroutine.
2. Concurrent select on `(decideResult, time.After(timeout), client.Read())`.
3. First-to-resolve wins:
   - `decide → (true, nil)` → emit `[Forward(ResultFrame)]` actions (and any cache effects of an "allowed" Parse).
   - `decide → (false, nil)` or `(_, err)` → emit `denyRoute(s, Rule, "approval denied")` with `tx_context.deny_action = "approval_denied"`.
   - timeout → emit `denyRoute(s, Rule, "approval timeout")` with `tx_context.deny_action = "approval_timeout"`. In-tx behavior follows `Rule.DenyModeInTx`.
   - client `Terminate` → cancel the `Decide` ctx; emit one `db_statement` event with `tx_context.deny_action = "cancelled_during_approval"`; tear down.
4. During the wait the dispatcher does not consume further Extended-Query frames from the client (Parse / Bind / Execute / Sync stay buffered); it only watches for `Terminate (X)` via a non-blocking peek and cancels the Approver context if observed. After approve completes, the dispatcher returns to the normal read loop and any buffered pipelined frames are processed in order (suppressed if approve denied, executed if approve allowed).

`NopApprover`:

```go
type NopApprover struct{}

func (NopApprover) Decide(ctx context.Context, cs effects.ClassifiedStatement, timeout time.Duration) (bool, error) {
    select {
    case <-ctx.Done(): return false, ctx.Err()
    case <-time.After(timeout): return false, nil
    }
}
```

Under default config, every `decision: approve` rule will block its target for the full 60s timeout, then deny. Honest behavior; future plan wires a real approver.

## 6. State-machine invariants (drive property tests)

These invariants must hold after every legal frame sequence in 05a's property tests:

1. **No simultaneous `Forward` and `Suppress`** for the same input frame.
2. **No `Close` paired with `SynthReadyForQuery`** in the same Action list — terminate XOR rollback-continue.
3. **`upstreamDirtySinceSync == false`** after any sequence ending in a non-error `Sync` that the dispatcher forwarded.
4. **`absorbing == true` ⇒ every non-Sync frame yields `[Suppress]`** until the next `Sync` resolves the window.
5. **`InjectRollback` only emitted when `lastUpstreamRFQ == 'T'`** — soft mode in-tx only.
6. **`cache.Put` only called on allow/audit/approve Parse paths.** Never on deny, never during an absorbing window.
7. **`ApproverWait` never emitted while `absorbing == true`** — approve cannot interrupt a deny-absorb window.
8. **Phase transitions are linear**: `Idle → InQuery → Idle`, `Idle → InTx → InTxError → InTx → Idle`, `InQuery → InCopyIn|InCopyOut → InQuery`. Never InTx ↔ InCopyIn|InCopyOut without an intermediate phase.
9. **`TxStartedAt` is set on first `Z` byte = 'T'` after `Idle`, cleared on next `Z` byte = 'I'`.** Idempotent re-entries to InTx within the same tx (e.g., savepoints) do not reset it.

The property test generator emits frame sequences that bias toward boundary cases (Sync immediately after deny; back-to-back Parses; mid-pipeline Sync) and runs `Transition` to fixed-point per frame, asserting invariants after each step.

## 7. Configuration changes

**05a:**

- `database_rules[*].deny_mode_in_tx: "" | "terminate" | "rollback_then_continue"`. Default `""` (terminate). Validator rejects on non-deny rules and on `match_kind: cancel` rules.

**05b:**

- `db_services.<name>.allow_function_call_protocol: bool`. Default `false`.
- `policies.db.escalate_unknown_functions: bool`. Default `false`.
- `policies.db.safe_function_allowlist: [<func_name>, ...]`. Default = built-in immutable seed list.

**05c:**

- No new config fields. `Approver` is a programmatic dependency (Config field), not a config-file field.

All new fields are optional with backward-compatible defaults. Existing policies load unchanged.

## 8. DBEvent schema changes

**05a:**

- `TxContext.TxStartedAt *time.Time` — now populated (was always nil in 04c).
- `TxContext.DenyAction` accepts new value `"rollback_injected"`.

**05b:**

- `Effect.FunctionOID *int32` — populated for `function_call_protocol` (FunctionCall frame) and `escalated_function_call` (escalation) effects.

**05c:**

- `TxContext.DenyAction` accepts new values `"approval_timeout"`, `"approval_denied"`, `"cancelled_during_approval"`.
- `Result.BytesIn` / `Result.BytesOut` — populated for COPY events (already on the schema from 04c; previously only carried `'Q'`-frame counts).

All additions are backward-compatible (`omitempty` JSON tags on the new pointer fields).

## 9. Testing strategy

### 9.1 Unit tests (table-driven, per-file)

- **State machine** (05a): `statemachine/transition_test.go` — ~80 rows covering the §14.2 + §14.3 + §14.4 tables.
- **Property tests** (05a): `statemachine/property_test.go` — invariants from §6 above against random valid frame sequences.
- **Prepared cache** (05a): `preparedcache/cache_test.go` — LRU semantics; concurrent stress.
- **Dispatcher** (05a): `extquery_test.go` — pgproto3 round-trip through a fake `proxyConn`.
- **SQL prepared cache** (05b): `sqlprepared_test.go` — every §7.4 form.
- **FunctionCall** (05b): `funccall_test.go` — opt-in matrix.
- **Escalation** (05b): `classify/postgres/escalate_test.go` — golden corpus.
- **COPY frames** (05c): `copyframes_test.go` — enter/byte-pass/exit; cancellation; counters.
- **Approval wait** (05c): `approvalwait_test.go` — approve / deny / timeout / cancel.
- **Approver** (05c): `policy/approver_test.go` — `NopApprover` semantics.

### 9.2 Spine tests (real-pgx + fake upstream)

Each sub-plan extends the existing `spine_test.go`:

- 05a: extended-query happy path; extended-query deny; in-tx rollback_then_continue.
- 05b: SQL-PREPARE deny round-trip; FunctionCall opt-in round-trip.
- 05c: COPY-out bulk_export with byte counter; approve-rule that times out under `NopApprover` (clock injected).

### 9.3 No real-PG integration tests

Real-PG integration is Plan 07 with testcontainers. Plan 05's spine tests use the existing `testupstream_test.go` fake upstream extended with Extended Query response sequences (`ParseComplete`, `BindComplete`, `RowDescription`, `DataRow`, `CommandComplete`, `ReadyForQuery`), CopyInResponse/CopyOutResponse for COPY tests, and `FunctionCallResponse` for FunctionCall tests.

### 9.4 Cross-compile

`GOOS=windows go build ./...` remains green via the existing non-Linux stub (`stub_other.go`).

### 9.5 Test isolation

All tests use `t.TempDir()` for state dir; no shared state; `clock.Clock` injected for any test that hits timeouts. No `time.Sleep` in tests.

## 10. Open questions and risks

### Open questions to flag (not blockers)

1. **`APPROVE_NOT_YET_SUPPORTED` warning lifetime.** 05a keeps emitting it; 05c removes it. Operators on a 05a-only deploy still see the warning. Mitigation: 05a release notes call it out; 05c removes it once `NopApprover` is live.

2. **§14.2 case (3) "absorbing, not dirty" Sync.** The spec mandates local `ReadyForQuery(I)` synthesis. Rare but legal (Bind+Sync without a forwarded frame). We honor it as spec'd; flagged because it's the only §14.2 row that synthesizes RFQ locally inside an absorbing window.

3. **Unnamed prepared statements** (§7.4 last bullet): empty-string `name` is a legal cache key. We use the empty string. Overwritten on next unnamed PREPARE. Tests cover.

4. **Function OID resolution.** FunctionCall events carry `function_oid: <int>` and `function_name: null`. OID → name resolution requires either a `pg_proc` SELECT (catalog access) or a baked-in OID table. Phase 2 will pick.

5. **`escalate_unknown_functions` seed allowlist.** Hand-curated list of ~50 immutable PG builtins in `internal/db/classify/postgres/builtin_immutable.go`. Documented as best-effort. Operators may extend via `safe_function_allowlist`.

6. **`rollback_then_continue` and pipelined frames.** If the client pipelined frames after the deny target, `absorbing=true` plus `Suppress` handles them. After `RFQ(I)` is synthesized, the dispatcher reads the next client frame fresh. Tests cover.

7. **Approval wait + client `Terminate`.** §14.5 doesn't specify cancellation semantics. We treat client Terminate during a wait as "abandon": cancel Approver ctx, emit event with `deny_action: cancelled_during_approval`, tear down. Spec extension implicit.

8. **NopApprover blocks for 60s under default `decision: approve`.** Operators who load `decision: approve` rules under 05c without wiring a real Approver see every approve-targeted statement hang for 60s then error. Honest; the warning at config-load is gone in 05c. Maybe the warning should persist until a future plan ships a real approver? Open for discussion.

### Risks

- **State-machine surface area.** §14.2 sub-cases × frame kinds × absorbing × dirty × upstream RFQ is a real combinatorial space. Property tests mitigate; table tests pin the spec rows. Risk that a subtle case (e.g., Sync inside CopyIn) is missed. Mitigation: explicit "phase ∉ Copy*" guard in `Transition` (returns `SynthError(0A000)` + `Close` for any non-CopyData frame while in COPY phase).

- **`rollback_then_continue` + connection-rule re-eval.** After injecting ROLLBACK, the connection stays authenticated. We do NOT re-evaluate connection rules. If an operator wanted to revoke at this boundary, they can't. Acceptable for Phase 1; deferred to Plan 07's bundle.

- **Approver interface stability.** Locking `Decide(ctx, cs, timeout) → (bool, error)` now means a future HTTP approver has to fit this signature. Adequate for yes/no/timeout. Not adequate for partial approvals ("allow once, not always") — Phase 2+.

- **COPY byte counters under TLS.** Under `tls_mode: terminate_reissue`, decrypted bytes are counted. Under `passthrough`, the proxy doesn't see bytes at all (passthrough already blocks Extended Query at handshake via config validation, but COPY can happen under terminate_reissue / terminate_plaintext_upstream). Documented in 05c release notes.

- **Removing the `APPROVE_NOT_YET_SUPPORTED` warning.** Operator config-load tests pinning that warning need updating. Migration documented in 05c plan.

### Deferred

- **To Plan 06.** BackendKeyData mapping, cancel governance, R20 commit ordering.
- **To Plan 07.** Out-of-process proxy under distinct SessionID, SO_PEERCRED → SessionID, unavoidability bundle, real-PG testcontainer suite, bypass-tool detection, recommendation flip to `enforce`.
- **To Phase 2+.** Function OID → name resolution, partial-approval semantics, catalog-aware classification, MySQL/MongoDB adapters.

## 11. Done definition

Plan 05 is done when:

- 05a / 05b / 05c all merge to main behind `policies.db.unavoidability: observe`.
- `GOOS=windows go build ./...` is green via the existing stub.
- The spine test suite covers: Extended Query allow/deny/in-tx-rollback (05a), SQL-PREPARE allow/deny + FunctionCall opt-in (05b), COPY-out with byte counters + approve-rule timeout (05c).
- `decision: approve` is a live verb under `NopApprover`; `APPROVE_NOT_YET_SUPPORTED` warning is gone.
- A YAML config containing `database_rules` with `deny_mode_in_tx: rollback_then_continue` causes a denied statement in an explicit transaction to inject ROLLBACK and leave the connection live, observable through `tx_context.deny_action: rollback_injected` in the audit sink.
