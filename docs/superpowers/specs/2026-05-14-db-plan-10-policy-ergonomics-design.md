# DB Plan 10 Policy Ergonomics Design

**Status:** Draft approved for implementation planning on 2026-05-14.
**Owner:** Canyon Road
**Source roadmap:** `docs/superpowers/specs/2026-05-14-db-phase-2-roadmap-design.md`
**Depends on:** DB Plan 09 Runtime Resolution Integration

## 1. Goal

Make catalog-resolved DB policies practical to author and debug without
weakening Phase 1 strict coverage or changing existing syntactic policy
semantics.

Plan 09 already attaches catalog-backed `ResolvedObjectRef` metadata to
classified effects at runtime. Plan 10 teaches the policy layer to match that
metadata with canonical selectors, adds an operator explain command, and
surfaces policy authoring mistakes as non-fatal warnings.

## 2. Scope

### In Scope

- Add `relations` and `functions` selectors to statement rules.
- Extend `schemas` so it can match either syntactic object schemas or
  catalog-resolved schemas.
- Keep `objects` syntactic-only for backward compatibility.
- Add evaluator explanation data for rule matches, coverage, uncovered objects,
  and final decision.
- Add `agentsh policy db explain` as the operator-facing explain command.
- Support offline catalog fixtures for explain-mode resolution; no live DB
  connection is required for Plan 10.
- Add config-load warnings for canonical selector misuse, unsupported service
  scopes, and selectors attached to objectless operations.
- Update sample policies and docs to show syntactic and resolved-object rules
  side by side.

### Out of Scope

- Live catalog loading from the CLI.
- Statement rewriting or accepting `decision: redirect`.
- Redirect validation, planning, or runtime execution.
- Changing proxy hot-path policy decisions except where canonical selectors
  intentionally add new coverage.
- Replacing `objects` with canonical matching.
- Loose coverage mode or fallback allow behavior when catalog resolution is
  unavailable.
- Result-set DLP, row-count limits, or Describe metadata filtering.

## 3. Design Decisions

### 3.1 Selector Semantics

`objects` remains the existing syntactic selector. It matches
`effects.ObjectRef` fields exactly as it does today and does not inspect
`ResolvedObjectRef`.

Plan 10 adds canonical selector families:

- `relations`: glob patterns over catalog-resolved relation canonical names,
  formatted as `schema.name`.
- `functions`: glob patterns over catalog-resolved function identity names,
  formatted as `schema.name(identity_args)`.
- `schemas`: glob patterns over schema names. A schema match can come from the
  syntactic object schema or the resolved object schema.

For one effect object slot, a rule covers that slot when all effect-level
filters match and:

1. The schema constraint is absent, or it matches the syntactic schema, or it
   matches the resolved schema.
2. At least one object selector family matches, or no object selector family is
   present.

The object selector families are:

- `objects`, matched against syntactic `ObjectRef`.
- `relations`, matched against a successful resolved relation.
- `functions`, matched against a successful resolved function.

If none of `objects`, `relations`, or `functions` is present, the rule keeps
the current behavior and covers all object slots that pass operation, subtype,
resolution, service, and schema filters.

Canonical selectors only match resolved objects with:

- `source: catalog`
- empty `unresolved_reason`
- the matching resolved kind (`relation` or `function`)

An unresolved, unavailable, or unsupported catalog result does not satisfy a
canonical selector. If no syntactic selector covers that object slot, strict
coverage produces the same implicit deny behavior as Phase 1.

### 3.2 Mixed Selectors

Rules may contain both syntactic and canonical selectors. This is useful during
migration:

```yaml
database_rules:
  - name: app-read-users-during-migration
    db_service: appdb
    operations: [READ]
    objects: ["users"]
    relations: ["public.users"]
    decision: allow
```

The selector families are additive for coverage: either the syntactic object
selector or the canonical relation selector can cover the object slot, subject
to the shared schema filter. This lets operators roll out canonical rules
without duplicating entire policies.

For high-assurance policies, operators should pair canonical selectors with:

```yaml
match_object_resolution: catalog_resolved
```

Plan 10 warns when canonical selectors appear without that guard. It remains a
warning rather than a load error because migration policies may deliberately
allow both syntactic and catalog-resolved coverage.

### 3.3 Function Selector Format

Function selectors match the identity string:

```text
schema.name(identity_args)
```

Examples:

- `pg_catalog.lower(text)`
- `public.safe_fn(integer, text)`
- `public.safe_fn(*)`
- `public.*`

The identity arguments come from Postgres `pg_get_function_identity_arguments`.
Overloaded functions are distinct unless the operator uses a glob. A bare
`schema.name` pattern does not match a function with identity args; operators
who want all overloads use `schema.name(*)`.

### 3.4 Evaluation API

The current `Evaluate` hot path should keep returning `Decision`. Plan 10 adds
an explanation-oriented API in `internal/db/policy` and has `Evaluate` share the
same internal implementation so explain output cannot drift from enforcement.

The explanation API returns:

- Applicable statement rules for the service.
- Per-effect operation, subtype, resolution, and object list.
- Per-object-slot coverage records.
- Matching deny rules and deny-matched object.
- Covering allow/audit/approve rules.
- Uncovered object details for implicit deny.
- Final folded `Decision`.

This API must remain pure and platform-agnostic. It does not read policy files,
open sockets, or query databases.

## 4. Components

### 4.1 `internal/db/policy`

Extend statement-rule decode, validate, compile, and evaluation:

- Add `Relations []string` and `Functions []string` to `StatementRule`.
- Compile relation/function glob patterns beside existing object/schema globs.
- Keep `objectMatches` syntactic-only.
- Add resolved relation/function matchers that operate on
  `effects.ResolvedObjectRef`.
- Refactor per-effect evaluation to build reusable coverage detail.
- Add `ExplainStatement` or an equivalent exported explanation API that returns
  the exact decision plus match details.
- Preserve rule-order tiebreaks and most-restrictive decision ordering.

Existing tests for syntactic `objects`, `schemas`, `match_object_resolution`,
implicit deny, deny precedence, audit/approve coverage, and order independence
must keep passing unchanged.

### 4.2 `internal/db/policy/explain` or Focused Helper Package

Add a small package for CLI explain orchestration if keeping it inside
`internal/db/policy` would make the evaluator package too broad.

Responsibilities:

- Classify SQL using the existing Postgres classifier.
- Optionally apply catalog fixture resolution to the classified statements.
- Call the policy explanation API for each statement.
- Shape stable JSON and text output for the CLI.

This package may depend on `internal/db/catalog` and
`internal/db/classify/postgres`. The lower-level evaluator must not depend on
the classifier or catalog package.

### 4.3 Catalog Fixture Support

Plan 10 explain mode is offline. To demonstrate canonical selectors, the CLI
accepts an optional catalog fixture:

```yaml
search_path: [public, pg_catalog]
relations:
  - oid: 16384
    schema: public
    name: users
    kind: table
  - oid: 16385
    schema: analytics
    name: users_summary
    kind: view
functions:
  - oid: 2200
    schema: public
    name: safe_fn
    identity_args: integer
    volatility: stable
    strict: false
    return_type_oid: 23
```

The fixture loader converts this file into a `catalog.Snapshot` and an explicit
search path, then applies the same catalog resolver rules as runtime resolution:

- Qualified relations resolve by `schema.name`.
- Unqualified relations resolve through `search_path`.
- Missing or ambiguous relations produce `catalog_unresolved`.
- No fixture produces `catalog_unavailable` for explain-mode canonical
  matching.

The fixture is an operator/debugging aid, not a production catalog cache file.
It should be documented as an approximation of what the runtime would see from
the upstream DB identity.

### 4.4 `agentsh policy db explain`

Add a `db` subcommand under the existing `policy` command:

```text
agentsh policy db explain POLICY_OR_PATH --service appdb [--sql "SELECT * FROM users"]
agentsh policy db explain POLICY_OR_PATH --service appdb < statement.sql
```

Flags:

- `--service`: required DB service name used for service-scoped rule matching.
- `--dialect`: optional, defaults to the service dialect when available and
  otherwise to `postgres`.
- `--search-path`: optional comma-separated search path used for syntactic
  classifier session state when no catalog fixture is supplied.
- `--temp-tables`: optional comma-separated temp table names for syntactic
  classifier session state.
- `--catalog-fixture`: optional YAML fixture for offline catalog resolution.
- `--sql`: optional SQL string. When absent, read SQL from stdin.
- `--output`: `json` or `text`, default `json`.

JSON output is the stable automation surface. Text output is a concise human
summary for local debugging.

Minimum JSON shape:

```json
{
  "service": "appdb",
  "dialect": "postgres",
  "catalog_source": "fixture",
  "statements": [
    {
      "index": 0,
      "raw_verb": "SELECT",
      "parser_backend": "libpg_query",
      "effects": [
        {
          "index": 0,
          "operation": "read",
          "subtype": "",
          "resolution": "catalog_resolved",
          "objects": [
            {"kind": "table", "schema": "", "name": "users"}
          ],
          "resolved_objects": [
            {
              "source": "catalog",
              "kind": "relation",
              "oid": 16384,
              "schema": "public",
              "name": "users",
              "relation_kind": "table"
            }
          ],
          "coverage": [
            {
              "object": "users",
              "resolved_object": "public.users",
              "covered": true,
              "covering_rules": ["app-read-users"],
              "selector": "relations"
            }
          ]
        }
      ],
      "decision": {
        "verb": "allow",
        "rule_kind": "statement",
        "rule_name": "app-read-users",
        "matching_effect_index": 0,
        "matching_effect_group": "read",
        "reason": ""
      }
    }
  ],
  "warnings": []
}
```

`warnings` includes policy decode warnings and explain-only warnings such as
missing catalog fixtures for canonical selectors.

### 4.5 Policy Validation And Runtime Warning Surfacing

`dbpolicy.Decode` already returns warnings, but some callers discard them.
Plan 10 should make warnings visible in two places:

- `agentsh policy validate` should run DB policy decode when DB blocks are
  present and print warnings before `ok`.
- Session DB policy compilation should preserve current fatal-error behavior
  and surface warnings through the existing server logging path.

Warning codes are stable strings. Plan 10 adds:

- `canonical_selector_without_resolution_guard`: a rule has `relations` or
  `functions` but does not set `match_object_resolution: catalog_resolved`.
- `canonical_selector_without_catalog_service`: a rule with canonical selectors
  matches no terminate-mode Postgres service.
- `selector_on_objectless_operation`: a rule constrains object selectors but
  all expanded operations are inherently objectless, such as transaction-only
  rules.
- `redirect_not_supported_until_plan_11`: `decision: redirect` remains a load
  error, with an updated message that points to DB Plan 11.

The warning set is intentionally narrow. Plan 10 should not attempt static
proof that every glob matches a real catalog object because that requires a
specific database catalog snapshot and identity.

## 5. Data Flow

### Runtime Policy Evaluation

1. The proxy classifies SQL and Plan 09 attaches resolved metadata.
2. `policy.Evaluate` receives the augmented classified statement.
3. The evaluator filters rules by service, operation, subtype, and resolution.
4. For each effect object slot, it evaluates syntactic and canonical selector
   coverage.
5. Deny still fires on any matching object.
6. Allow/audit/approve still require every object slot to be covered.
7. The most-restrictive decision fold is unchanged.

### Explain Command

1. The CLI loads the root policy and DB policy rule set.
2. The CLI reads SQL from `--sql` or stdin.
3. The Postgres classifier emits syntactic statements.
4. If `--catalog-fixture` is present, explain mode applies offline catalog
   resolution; otherwise it leaves syntactic classification intact and records
   catalog source `none`.
5. The CLI calls the policy explanation API for each statement.
6. The CLI writes JSON or text output with effects, coverage, warnings, and
   final decisions.

## 6. Failure Semantics

- A policy containing `relations` or `functions` decodes successfully when the
  selectors are valid globs.
- Bad relation/function glob patterns are fatal load errors with the existing
  `glob_compile` style.
- A canonical selector never matches unresolved catalog metadata.
- If explain mode has no catalog fixture, canonical selectors can be reported
  as configured but uncovered for the classified statement.
- If a catalog fixture is malformed, `agentsh policy db explain` exits nonzero
  and names the fixture field that failed to parse.
- If policy validation finds warnings only, it exits zero and prints warnings.
- `decision: redirect` remains a fatal load error until Plan 11.

## 7. Testing Strategy

### Unit Tests

- Decode accepts `relations` and `functions`.
- Compile rejects invalid glob patterns in `relations` and `functions`.
- Relation selectors match only successful resolved relations.
- Function selectors match only successful resolved functions.
- `schemas` matches resolved schemas as well as syntactic schemas.
- Mixed syntactic and canonical selectors cover an object slot when either
  selector family matches.
- Canonical selectors do not cover unresolved, unavailable, or unsupported
  resolved objects.
- Existing syntactic-only policies produce identical decisions before and
  after Plan 10.
- Warning codes are emitted for the documented misuse cases.

### Explain Tests

- `agentsh policy db explain` reads SQL from stdin and from `--sql`.
- JSON output includes effects, resolved objects, coverage, uncovered objects,
  warnings, and decision fields.
- Text output includes the statement verb, final decision, matching rule, and
  uncovered object summary.
- Catalog fixture resolution covers qualified and unqualified relation names.
- Missing fixture catalog rows show canonical selectors as uncovered.

### Cross-Platform Verification

Plan 10 touches policy and CLI code that must build on every supported target:

- `go test ./...`
- `GOOS=windows go build ./...`

The explain command must not import Linux-only proxy runtime files. Catalog
fixture resolution should use platform-agnostic catalog and classifier
packages.

## 8. Documentation And Samples

Update the sample DB policy with a resolved-object example:

```yaml
database_rules:
  - name: app-read-users-syntactic
    db_service: appdb
    operations: [READ]
    objects: ["users"]
    decision: allow

  - name: app-read-users-canonical
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: allow
```

Documentation must state:

- `objects` is syntactic.
- `relations` and `functions` require catalog-resolved metadata to match.
- Strict object coverage still applies.
- `match_object_resolution: catalog_resolved` is the recommended guard for
  high-assurance canonical rules.
- `audit` is allow-with-observation, not block-with-observation.
- Plan 10 explain is offline unless a catalog fixture is supplied.

## 9. Acceptance Criteria

- Existing Phase 1 and Plan 09 policies keep their current decisions.
- Operators can author `relations` and `functions` selectors in DB statement
  rules.
- Canonical selectors only match successful catalog-backed resolved objects.
- `agentsh policy db explain` reports classification, resolution, coverage,
  warnings, and final decision for a statement under a policy file.
- Policy validation surfaces Plan 10 warnings without blocking load.
- `decision: redirect` is still rejected and points operators to Plan 11.
- `go test ./...` and `GOOS=windows go build ./...` pass.
