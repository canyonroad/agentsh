# DB Plan 12 Redirect Runtime Integration Design

**Status:** Approved by operator direction on 2026-05-14.
**Owner:** Canyon Road
**Source specs:**
- `docs/agentsh-db-access-spec.md` v0.8, Phase 2 row.
- `docs/superpowers/specs/2026-05-14-db-phase-2-roadmap-design.md`
- DB Plan 11 Redirect Planner contract.

Plan 12 makes Postgres `decision: redirect` usable at runtime. It wires the Plan 11 redirect planner into the existing Postgres proxy, forwards rewritten read-only statements when safe, fails closed when unsafe, and records explicit redirect audit metadata.

This plan is runtime integration only. SQL rewrite planning stays owned by Plan 11. If Plan 12 discovers a missing planner contract detail, it may add a narrow adapter seam, but it must not redesign planner behavior.

---

## 1. Goals

- Execute safe redirect plans in Simple Query.
- Execute safe redirect plans in Extended Query `Parse`.
- Cache rewritten prepared-statement classification and redirect metadata without changing client-visible prepared statement names.
- Emit DB events that preserve the original client statement identity and add redirect-specific audit fields.
- Fail closed whenever redirect cannot be executed safely.
- Prove the behavior with focused unit tests and real Postgres CI tests.

External behavior: `decision: redirect` becomes usable for read-only Postgres relation replacement. Clients see normal query results or normal PostgreSQL errors. They do not receive redirect notices by default.

---

## 2. Architecture

Plan 12 adds a thin runtime adapter between the existing proxy policy path and the Plan 11 redirect planner.

Runtime entry points:

- Simple Query: classify and resolve the statement, evaluate DB policy, ask the redirect planner when the winning decision is `redirect`, then forward rewritten SQL upstream.
- Extended Query `Parse`: classify and resolve `Parse.Query`, evaluate DB policy, ask the redirect planner when the winning decision is `redirect`, forward rewritten SQL upstream, and cache rewritten metadata under the client-visible prepared statement name.
- Extended Query `Bind` and `Execute`: use prepared-cache metadata only. They must not inspect SQL or re-plan redirect.
- Audit sink: emit original digest, rewritten digest, redirect rule, source relation, target relation, planner status, and runtime status.
- Error path: synthesize PostgreSQL protocol errors and preserve proxy state when redirect cannot be safely executed.

Invariant: once policy returns `redirect`, the proxy must not forward the original SQL unless the planner returned a valid rewrite that intentionally preserves it. Unsafe redirect means fail closed, not fall back to allow.

---

## 3. Runtime Data Flow

### Simple Query

1. Receive a Simple Query SQL batch.
2. Classify the statement and attach catalog resolution metadata.
3. Evaluate policy.
4. For `deny`, use the existing deny path.
5. For existing non-redirect decisions, use the existing path.
6. For `redirect`, call the Plan 11 planner with the resolved statement, policy action, and current resolver context.
7. If planning succeeds, forward rewritten SQL upstream.
8. Emit a DB event with original digest, rewritten digest, redirect rule, source relation, target relation, and runtime status.
9. If planning fails or returns an unsafe result, synthesize an error and do not forward the original SQL.

Multi-statement redirect candidates fail closed in Plan 12. Future plans can revisit whole-batch redirects after the single-statement runtime path is stable.

### Extended Query

1. On `Parse`, classify and resolve `Parse.Query`.
2. Evaluate policy.
3. For `redirect`, call the Plan 11 planner at `Parse` time only.
4. If planning succeeds, send upstream `Parse` with rewritten SQL while preserving the original client prepared statement name.
5. Store a prepared-cache entry containing original classification, rewritten classification, original digest, rewritten digest, redirect rule, source relation, target relation, and parse-time policy identity.
6. On `Bind` and `Execute`, use the cached rewritten metadata. Do not re-plan.
7. If `Parse` fails closed, do not create a usable prepared-cache entry.

Prepared statements keep their parse-time redirect plan. Policy reload affects new Simple Query statements and new Extended Query `Parse` messages only.

---

## 4. Error Handling

Redirect runtime failures are policy enforcement failures, not upstream database failures.

Rules:

- `deny` always wins before redirect execution.
- If policy returns `redirect` and runtime cannot produce a valid rewritten statement, fail closed.
- Never forward original SQL after a redirect decision unless the planner returned a valid rewrite that intentionally keeps the same SQL.
- Do not emit `NoticeResponse` by default. Redirect is transparent to clients and explicit in audit.

Fail-closed cases:

- Planner rejects the statement form.
- Target relation cannot be resolved.
- Rewritten SQL is empty, unparsable, or reclassifies into an unsafe operation.
- Source or target metadata is stale or inconsistent.
- Multi-statement, write, DDL, COPY, FunctionCall, or another unsupported protocol/query form.
- Prepared-cache lookup disagrees with expected redirect metadata.

Protocol behavior:

- Simple Query: synthesize a PostgreSQL `ErrorResponse`, preserve `ReadyForQuery` state, and emit a DB event with redirect rejection fields.
- Extended Query `Parse`: synthesize `ErrorResponse`, do not forward `Parse` upstream, and do not create a usable prepared-cache entry.
- Extended Query `Bind` and `Execute`: if cached redirect metadata is missing or corrupt, fail closed using the existing extended-protocol error path.
- If rewritten SQL was safely forwarded and upstream Postgres returns an error, pass that error through. The DB event records redirect execution, not guaranteed query success.

---

## 5. Data Model

Plan 12 keeps existing event fields compatible and adds redirect-specific fields beside them.

The runtime adapter consumes a Plan 11 planner result with:

- Rewritten SQL.
- Rewritten statement digest.
- Redirect rule id or name.
- Source relation.
- Target relation.
- Rejection reason when unsupported.

Prepared-cache entries gain redirect metadata:

- Original classification and digest.
- Rewritten classification and digest.
- Redirect rule.
- Source and target relation.
- Parse-time policy identity.

DB events keep the existing statement and digest as the original client statement. Redirect adds explicit fields:

- `redirected`
- `redirect_rule`
- `rewritten_statement_digest`
- `redirect_source_relation`
- `redirect_target_relation`
- `redirect_runtime_status`
- `redirect_rejection_reason`

Plan 12 does not store full rewritten SQL text by default unless existing statement-redaction settings already allow equivalent SQL text exposure. The rewritten digest plus rule/source/target metadata is enough for audit and avoids creating a new leakage path.

---

## 6. Policy And Prepared Statements

Redirect sits after policy evaluation and before forwarding.

- `deny` always wins.
- `redirect` only executes when it is the final winning policy decision.
- `approve`, `audit`, and `allow` keep their existing behavior unless the final winning policy action is explicitly `redirect`.
- The runtime does not add a separate client-visible approval prompt or notice for redirect.
- Redirect remains allow-like for audit semantics: successful redirect is an allowed upstream query with explicit redirect fields.
- Policy reload affects new Simple Query statements and new Extended Query `Parse` messages.
- Existing prepared statements keep their parse-time redirect plan after policy reload.
- Prepared statement names stay client-visible as originally supplied; only upstream SQL and cached metadata use the rewritten target.

This avoids surprising clients and prevents policy reload from retroactively changing already-parsed prepared statements.

---

## 7. Testing

Plan 12 needs focused unit coverage plus real Postgres integration coverage.

Unit coverage:

- Simple Query redirects forward rewritten SQL and emit redirect event fields.
- Simple Query redirect failures synthesize an error and never forward original SQL.
- Extended Query `Parse` stores rewritten classification and redirect metadata.
- `Bind` and `Execute` use cached metadata and never re-plan.
- Deny precedence: deny beats redirect.
- Policy reload affects new statements but not existing prepared entries.
- Event builder preserves original digest and adds redirect fields.

Real Postgres CI gate:

- Simple Query `SELECT ... FROM source` returns rows from target.
- Extended Query prepared statement stays redirected across repeated `Bind`/`Execute`.
- Named prepared statements keep the original client name while upstream uses rewritten SQL.
- Policy reload changes redirect target for new statements without corrupting existing prepared state.
- Unsupported forms fail closed: writes, COPY, multi-statement, and unresolved target.

Plan 12 does not add a separate transaction-behavior suite unless implementation uncovers a concrete transaction-state bug. Existing cross-platform expectations still apply: pure Go unit tests should build everywhere, and platform-specific integration harnesses should skip only when their dependencies are unavailable.

---

## 8. Scope

### In Scope

- Wire the Plan 11 redirect planner into Simple Query.
- Wire the Plan 11 redirect planner into Extended Query `Parse`.
- Extend prepared-cache metadata for rewritten classification and redirect audit data.
- Emit redirect-specific DB event fields.
- Fail closed with correct PostgreSQL protocol behavior.
- Add unit tests and real Postgres integration tests.

### Out of Scope

- Redesigning the redirect planner.
- Re-planning at `Bind` or `Execute`.
- Redirecting writes, DDL, COPY, FunctionCall, or unsupported multi-statement batches.
- Client-facing redirect notices.
- Result-set rewriting or DLP transforms.
- Cross-database or cross-service routing.
- Broad policy language redesign.

---

## 9. Success Criteria

- Redirected Simple Query and Extended Query paths execute rewritten SQL only after a valid planner result.
- Original SQL is never forwarded after an unsafe redirect decision.
- Prepared statements do not mix original and rewritten statement identity.
- DB events identify both original client intent and redirect target.
- Deny precedence and existing non-redirect policy behavior remain unchanged.
- Real Postgres CI proves the supported redirect flows and unsupported fail-closed cases.
