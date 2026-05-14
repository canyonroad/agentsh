# DB Phase 2 Roadmap Design

**Status:** Approved by operator direction on 2026-05-14.
**Owner:** Canyon Road
**Source spec:** `docs/agentsh-db-access-spec.md` v0.8, Phase 2 row.

This document decomposes DB Phase 2 into sequential implementation plans. Phase 1 is now complete: the Postgres proxy, policy evaluator, CancelRequest mapping, unavoidability bundle, lifecycle events, and real-Postgres CI integration have all landed on `main`.

Phase 2 starts from that working proxy and adds three capabilities:

1. Catalog-backed object resolution.
2. Postgres `redirect` decisions implemented as statement rewriting.
3. Policy ergonomics that make resolved-object policies easier to author and debug.

This is a roadmap, not the full product spec for every sub-plan. Each plan still gets its own focused implementation plan before code work starts.

---

## 1. Phase Boundary

### In Scope

- Resolve syntactic Postgres object references against the upstream catalog.
- Resolve relation identity to canonical schema/name/OID metadata.
- Resolve function identity enough to support FunctionCall OID labeling and safer `escalate_unknown_functions` behavior.
- Preserve Phase 1's fail-closed semantics when catalog resolution is unavailable, stale, ambiguous, or unsupported.
- Add policy authoring helpers that explain object coverage and resolution results without weakening strict coverage by default.
- Add `decision: redirect` for Postgres statement rewriting, scoped initially to read-only relation replacement.
- Prove the Phase 2 behavior against real Postgres in CI.

### Out of Scope

- Result-set DLP, row-count caps, and catalog-aware column metadata controls. Those remain Phase 7.
- MySQL, MongoDB, Snowflake, BigQuery, Databricks, ClickHouse, MSSQL, Cassandra, Redis, and Oracle. Those remain later phases.
- Replication protocol classification. That remains future work.
- Credential brokering and SCRAM-SHA-256-PLUS channel-binding support. That remains Phase 4.
- Inspecting arbitrary function bodies for side effects. Phase 2 resolves function identity and volatility metadata, but it does not prove function purity.
- A loose-coverage mode that silently allows uncovered objects. Phase 2 may improve diagnostics and selectors, but strict coverage remains the enforcement default.

---

## 2. Design Constraints

Phase 2 must not regress Phase 1's high-assurance claim. Catalog resolution is an improvement in confidence, not a reason to allow statements when the resolver cannot prove identity.

The proxy already has an upstream authenticated Postgres connection. Phase 2 should use that connection to build and refresh catalog metadata, not introduce a separate privileged side channel. Catalog queries must run under the same effective database identity unless an explicit future plan introduces an admin-side resolver credential.

Resolution metadata should augment existing classified objects rather than replacing the syntactic object set in one step. Phase 1 policy and event consumers expect `effects.ObjectRef` and `effects.Resolution`; Phase 2 can add resolved identity fields and new resolution tags, but the migration must be incremental.

Statement rewriting must be conservative. The first redirect surface should rewrite read-only relation references to configured relation/view targets. It should reject writes, DDL, procedural statements, COPY, multi-statement batches, unknown statements, and any rewrite that would need semantic reasoning beyond relation replacement.

---

## 3. Decomposition

Phase 2 is split into five implementation plans:

```
DB Plan 08 Catalog Resolver Foundation
  -> DB Plan 09 Runtime Resolution Integration
  -> DB Plan 10 Policy Ergonomics
  -> DB Plan 11 Redirect Planner
  -> DB Plan 12 Redirect Runtime And Integration
```

### DB Plan 08 - Catalog Resolver Foundation

Goal: add the catalog package and pure resolver model without changing proxy behavior.

Deliverables:

- `internal/db/catalog/` package with Postgres catalog types, snapshot loading, canonical name lookup, and test fakes.
- Relation metadata: OID, schema, name, relation kind, owner, and columns.
- Function metadata: OID, schema, name, identity args, volatility, strictness, and return type.
- Search-path model that resolves unqualified names using an explicit schema path.
- Safe failure modes: missing catalog row, duplicate candidate, unsupported relation kind, and query failure all return typed unresolved results.
- Unit tests using fake query rows. No Docker or proxy integration in this plan.

External behavior: none. Existing Phase 1 runtime remains unchanged. Plan 08 is implemented and ready for DB Plan 09 runtime integration.

### DB Plan 09 - Runtime Resolution Integration

Goal: feed catalog resolution into existing classification, policy evaluation, and DB events.

Deliverables:

- Per-service catalog snapshot lifecycle in the Postgres proxy.
- Per-connection resolver context derived from StartupMessage database/user and upstream `current_schemas(true)`.
- Resolved object metadata attached to classified effects before policy evaluation.
- Resolution tag upgrade from syntactic tags to catalog-backed tags when every object in an effect resolves cleanly.
- DBEvent fields for canonical object identity and resolution source.
- Fallback behavior: if catalog data cannot be obtained, keep Phase 1 syntactic objects and fail closed under `match_object_resolution` policies.
- Real Postgres integration coverage for schema-qualified, unqualified, temp-shadowed, view, function, and missing-object cases.

External behavior: operators can write stricter policies that require catalog-backed resolution, while existing syntactic policies keep working.

### DB Plan 10 - Policy Ergonomics

Goal: make resolved-object policies usable without weakening enforcement.

Deliverables:

- Policy decode support for canonical selectors such as `relations`, `schemas`, and `functions`, compiled into existing statement-rule matching.
- A DB policy explain command that shows classification, resolution, object coverage, and final decision for a statement under a policy file.
- Config-load warnings for common mistakes: object rules that can never match, redirect rules on unsupported services, and resolution-sensitive rules without catalog-backed services.
- Sample policies that show Phase 1 syntactic rules next to Phase 2 resolved-object rules.
- Documentation updates for operator workflows.

External behavior: policy authoring and debugging improve; default enforcement semantics remain strict.

### DB Plan 11 - Redirect Planner

Goal: define and test safe statement-rewrite planning before proxy runtime changes.

Deliverables:

- `decision: redirect` accepted by DB policy decode with a structured redirect action.
- Redirect validation limited to terminate-mode Postgres services.
- Planner that converts a resolved read-only statement plus redirect rules into a rewrite plan.
- Relation replacement support for table/view references, including alias preservation and schema qualification.
- Rejection reasons for writes, DDL, COPY, procedural statements, FunctionCall frames, unresolved objects, multi-statement batches, and missing redirect targets.
- Pure tests over AST input and expected rewritten SQL.

External behavior: policy files can be validated for redirect support, but the proxy does not execute redirects yet.

### DB Plan 12 - Redirect Runtime And Integration

Goal: execute safe redirect plans in the Postgres proxy and prove them against real Postgres.

Deliverables:

- Simple Query and Extended Query redirect execution paths.
- Statement digest and DBEvent fields for original statement, rewritten statement digest, redirect rule, and target relation.
- Prepared statement cache interaction: redirected Parse caches the rewritten classification and never mixes original and rewritten names.
- Approval/audit interaction: redirect remains an allow-like action with explicit event fields; deny still wins.
- Real Postgres tests for Simple Query, Extended Query, prepared statements, policy reload, and unsupported rewrite forms.

External behavior: `decision: redirect` becomes usable for read-only Postgres relation replacement.

---

## 4. Recommended Next Work

Start with DB Plan 08. It is the dependency for the rest of Phase 2, has no runtime behavior change, and lets the team settle the canonical identity model before touching the proxy.

Success criteria for Plan 08:

- The catalog package builds on every platform.
- Postgres-specific SQL remains isolated behind a small query interface.
- Unit tests prove deterministic resolution for qualified and unqualified names.
- Failures return explicit unresolved reasons, not ad hoc errors.
- No Phase 1 policy or proxy behavior changes.

---

## 5. Open Design Decisions

These should be settled in the relevant implementation plans, not in this roadmap:

- Whether the catalog snapshot refresh is time-based, invalidation-based, or both.
- Whether redirect should support cross-service routing after same-service relation replacement is stable.
- Whether function volatility metadata should feed the default `escalate_unknown_functions` behavior or remain opt-in.
- Whether policy explain should live under `agentsh policy db explain` or extend `cmd/dbclassify-pg`.
- Whether resolved object metadata should be stored directly on `effects.ObjectRef` or in a parallel `ResolvedObjectRef` slice during the transition.

The first Plan 08 implementation should prefer the transition-friendly parallel metadata model unless the code review shows that extending `ObjectRef` is simpler and does not break existing JSON consumers.
