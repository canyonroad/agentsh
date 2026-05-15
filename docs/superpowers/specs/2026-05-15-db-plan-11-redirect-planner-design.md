# DB Plan 11 Redirect Planner Design

## Context

DB Phase 2 introduces catalog-backed policy ergonomics and safe Postgres statement rewriting. DB Plan 10 added canonical relation/function selectors and intentionally kept `decision: redirect` invalid. DB Plan 12 is already scoped as runtime integration, but it depends on a Plan 11 contract that does not exist yet.

Plan 11 fills that gap. It makes redirect a valid statement-level policy decision, defines a structured redirect action, and adds a pure Postgres rewrite planner that can safely replace one catalog-resolved source relation with one configured target relation in a single read-only `SELECT`.

External behavior after this plan: policy files can validate redirect rules, policy evaluation can return a redirect decision, and pure planner tests can prove SQL rewrite behavior. The proxy still does not execute redirects until Plan 12.

## Goals

- Accept `decision: redirect` for `database_rules` with a structured target relation action.
- Keep `decision: redirect` invalid for `database_connection_rules`.
- Preserve strict DB policy coverage and deny precedence.
- Add a pure redirect planner with stable rewrite metadata and stable rejection reasons.
- Support one safe relation replacement in a single-statement read-only Postgres `SELECT`.
- Preserve table aliases and schema-qualify rewritten target relations.
- Keep runtime forwarding, prepared-cache behavior, DB events, and client-visible redirect errors out of Plan 11.

## Non-Goals

- Executing redirects in Simple Query or Extended Query.
- Rewriting prepared-statement cache entries.
- Emitting redirect event fields.
- Rewriting writes, DDL, COPY, procedural statements, FunctionCall protocol frames, or multi-statement batches.
- Supporting SQL templates, arbitrary fragment rewrites, column rewrites, result rewrites, or DLP transforms.
- Doing catalog lookups inside the planner.

## Policy Shape

Plan 11 adds a redirect action to statement rules:

```yaml
database_rules:
  - name: redirect-users
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: redirect
    redirect:
      relation: "public.safe_users"
```

`redirect.relation` is the target relation. It must be a canonical `schema.name` value. The source relation is not repeated in the action; it comes from the actual catalog-resolved relation object covered by the redirect rule's `relations` selector.

Redirect rules must:

- Be statement rules.
- Match at least one terminate-mode Postgres service. Validation fails when a redirect rule has no eligible terminate-mode Postgres service target.
- Use only read operations. `operations: [READ]` is the expected common form; aliases are valid only if they expand exclusively to the read group.
- Constrain `relations`; object-only redirect sources are invalid.
- Use a canonical target relation in `redirect.relation`.

Redirect rules should use `match_object_resolution: catalog_resolved`. Plan 11 should make this fatal for redirect rules rather than a warning, because the planner needs a catalog-resolved source relation to avoid syntactic ambiguity.

Connection rules continue to reject `decision: redirect`.

## Policy Semantics

Plan 11 adds `VerbRedirect` to statement policy evaluation. Redirect joins the existing strict three-pass policy algorithm:

1. Explicit deny wins if any deny rule matches an object in an effect.
2. Every object in the effect must be covered by a non-deny rule.
3. The most-restrictive covered verb becomes the effect-level decision.
4. The most-restrictive effect-level decision becomes the statement decision.

Restrictiveness order:

```text
deny == implicit_deny > approve > redirect > audit > allow
```

This means:

- A matching deny rule blocks redirect.
- Any uncovered object produces implicit deny, which blocks redirect.
- An approve rule that covers the same object set beats redirect and preserves human review semantics.
- Redirect beats audit and allow so the final decision can carry the redirect action when redirect is explicitly configured.
- Existing allow, audit, approve, and deny behavior remains unchanged when no redirect rule covers the statement.

`Decision` gains redirect action metadata only when `Verb == VerbRedirect`. The metadata must include:

- rule name
- source relation canonical name
- target relation canonical name

Audit rule contribution for redirect is not required in Plan 11. Plan 12 may record redirect event fields and treat successful redirect as an allowed upstream query with explicit redirect metadata.

## Planner Contract

Add a pure planner package, likely `internal/db/redirect`.

The planner input should include:

- original SQL text
- the classified/resolved statement for the single statement being planned
- the redirect action from the winning policy decision
- the Postgres parser/deparser backend through the existing classifier backend seam

The planner output should include:

- rewritten SQL
- redirect rule name
- source relation canonical name
- target relation canonical name

Planner failures should be structured rejections with stable reason codes. Initial reason codes:

- `unsupported_statement`
- `multi_statement`
- `non_select_statement`
- `write_statement`
- `ddl_statement`
- `copy_statement`
- `procedural_statement`
- `function_call_protocol`
- `unresolved_object`
- `missing_redirect_target`
- `ambiguous_redirect_source`
- `source_relation_not_found`
- `deparse_failed`

The planner must not perform network I/O or catalog lookup. It trusts the resolver output already attached to the classified statement. If needed metadata is absent, it rejects.

## Rewrite Mechanics

Plan 11 rewrites by mutating the parsed Postgres AST and deparsing it back to SQL. It must not use ad hoc string replacement.

Flow:

1. Parse the original SQL.
2. Require exactly one parsed statement.
3. Require the statement node to be a `SelectStmt`.
4. Reject classified statements with write, DDL, COPY, procedural, FunctionCall, unresolved, or unknown effects.
5. Walk relation-bearing `RangeVar` nodes reachable through:
   - `FROM`
   - joins
   - nested subselects
   - read-only CTE bodies
   - set-operation branches
6. Match the source relation using catalog-resolved object metadata from the classified statement.
7. Replace only `RangeVar.Schemaname` and `RangeVar.Relname`.
8. Preserve aliases, joins, predicates, target lists, parameters, CTE names, and all other AST structure.
9. Deparse the modified AST with the active backend:
   - cgo `pg_query.Deparse` on linux+cgo
   - `wasilibs/go-pgquery.Deparse` otherwise

Deparse may normalize formatting and omit comments. That is acceptable. Plan 12 audit keeps the original statement identity and records the rewritten digest rather than depending on original formatting.

## Safety Boundaries

Plan 11 supports exactly one redirect source occurrence in the first cut. If more than one matching source occurrence is found, reject with `ambiguous_redirect_source`. This keeps CTE shadowing, self-joins, and repeated relation references conservative.

Reject:

- multi-statement SQL
- non-`SELECT` statements
- `SELECT INTO`
- data-modifying CTEs
- `INSERT ... SELECT`, `UPDATE`, `DELETE`, `MERGE`
- DDL
- COPY
- statements with locking clauses such as `FOR UPDATE`
- procedural/function-call effects that policy classified as procedural
- FunctionCall protocol frames
- unresolved or unknown objects
- missing redirect target action
- object-only redirect rules

Plan 11 may support read-only nested subselects, read-only CTEs, joins with one redirected relation, and set operations when the same single-source constraint holds.

## Parser/Deparser Seam

The existing Postgres classifier already splits parser backends by build tag:

- linux+cgo uses `github.com/pganalyze/pg_query_go/v6`
- other builds use `github.com/wasilibs/go-pgquery`

Plan 11 should expose a narrow internal helper from `internal/db/classify/postgres` rather than importing a cgo-only deparser directly from the planner. The helper should parse and deparse through the selected backend, preserving Windows and no-cgo builds.

The acceptance build must include:

```sh
GOOS=windows go build ./...
```

## Tests

Policy tests:

- `decision: redirect` decodes and compiles for valid statement rules.
- Connection-rule redirect still fails validation.
- Redirect without `redirect.relation` fails.
- Redirect with a non-canonical target fails.
- Redirect with object-only source selectors fails.
- Redirect without `match_object_resolution: catalog_resolved` fails.
- Redirect with no eligible terminate-mode Postgres service target fails.
- Deny beats redirect.
- Implicit deny beats redirect.
- Approve beats redirect.
- Redirect beats audit and allow.

Planner tests:

- `SELECT * FROM public.users` rewrites to the configured target relation.
- Unqualified source with catalog resolution rewrites to the qualified target.
- Alias is preserved.
- Join query with one redirected relation rewrites only that relation.
- Nested subselect read-only query rewrites.
- Read-only CTE query rewrites.
- Set operation read-only query rewrites when only one source occurrence matches.
- `SELECT INTO` rejects.
- `INSERT ... SELECT`, `UPDATE`, `DELETE`, DDL, and COPY reject.
- Unresolved object rejects.
- Missing target rejects.
- Multi-statement SQL rejects.
- Procedural/function-call classified cases reject.
- Multiple matching source occurrences reject.

Regression tests:

- Existing non-redirect policy tests still pass unchanged.
- Existing classifier tests still pass unchanged.
- Cross-platform build succeeds.

## Acceptance Criteria

- DB policy accepts valid statement redirect rules with structured target actions.
- DB policy still rejects redirect on connection rules.
- Policy evaluation can return `VerbRedirect` with rule/source/target metadata.
- Existing non-redirect decisions keep their behavior.
- The pure planner returns rewritten SQL and redirect metadata for supported single-`SELECT` cases.
- The pure planner returns stable rejection reasons for unsupported cases.
- Plan 12's dependency gate passes: redirect policy support and planner contract are present.

## Implementation Boundaries

Plan 11 should touch:

- `internal/db/policy`
  - add `VerbRedirect`
  - add `StatementRule.Redirect`
  - validate redirect shape and service scope
  - compile redirect actions
  - return redirect decisions from `Evaluate`
- `internal/db/classify/postgres`
  - expose a narrow parse/deparse helper for planner use while preserving cgo/WASM backend selection
- `internal/db/redirect`
  - pure planning API
  - AST traversal and mutation
  - structured rejection reasons
  - planner unit tests

Plan 11 should not touch:

- Simple Query forwarding
- Extended Query runtime behavior
- prepared statement cache
- DB event schema
- audit sink
- client-visible redirect error handling

Those remain DB Plan 12.

## Open Follow-Ups

- Plan 12 wires this planner into Simple Query and Extended Query `Parse`.
- A later plan may support multiple source occurrences when all occurrences are provably safe to rewrite.
- A later plan may support richer source-to-target maps after the single-target runtime path is stable.
