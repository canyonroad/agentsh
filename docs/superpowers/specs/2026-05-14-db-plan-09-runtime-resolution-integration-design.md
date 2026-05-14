# DB Plan 09 Runtime Resolution Integration Design

**Status:** Draft approved for implementation planning on 2026-05-14.
**Owner:** Canyon Road
**Source roadmap:** `docs/superpowers/specs/2026-05-14-db-phase-2-roadmap-design.md`
**Depends on:** DB Plan 08 Catalog Resolver Foundation

## 1. Goal

Feed Postgres catalog resolution into the existing proxy runtime so policy
evaluation and DB events can distinguish syntactic object references from
catalog-backed canonical identities.

Plan 09 is the first Phase 2 runtime change. It must preserve Phase 1 behavior
for existing syntactic policies while enabling stricter policies that require
catalog-backed resolution.

## 2. Scope

### In Scope

- Load and cache Postgres catalog snapshots through the same authenticated
  upstream identity that already serves the proxied connection.
- Derive per-connection resolver context from StartupMessage metadata and
  upstream `current_schemas(true)`.
- Attach resolved canonical relation and function identity to classified
  effects before policy evaluation.
- Add catalog-backed resolution tags while preserving existing syntactic object
  references and JSON compatibility.
- Emit resolved-object metadata in `DBEvent`.
- Cover Simple Query, Extended Query Parse, SQL PREPARE/EXECUTE cache paths,
  approval events, and FunctionCall OID labeling.
- Prove behavior with unit, spine, event, and real Postgres integration tests.

### Out of Scope

- Background TTL refresh or catalog invalidation listeners.
- Redirect planning or statement rewriting.
- Result-set DLP, row-count caps, or Describe metadata filtering.
- Credential brokering or SCRAM-SHA-256-PLUS support.
- Inspecting function bodies for side effects.
- Weakening strict object coverage or adding loose coverage.

## 3. Design Decisions

### 3.1 Snapshot Lifecycle

The proxy does not have a privileged catalog credential and must not introduce
one in Plan 09. Catalog queries therefore run through an already authenticated
upstream connection, under the same effective database identity as the client.

Snapshots are owned by the Postgres proxy and cached in a service-level store,
but each cache entry is keyed by:

- DB service name.
- Database name from StartupMessage.
- DB user from StartupMessage/auth flow.

The first authenticated connection for a key loads the snapshot after upstream
auth reaches `ReadyForQuery`. Later connections for the same key reuse the
snapshot. An explicit refresh hook exists for tests and future policy reload
integration. There is no background polling loop in Plan 09.

If snapshot loading fails, the connection continues in syntactic mode and
records the catalog-unavailable reason for policy/event handling.

### 3.2 Resolution Metadata Shape

Existing `effects.ObjectRef` remains the syntactic object surface. Plan 09 adds
parallel resolved metadata instead of replacing those refs. This keeps existing
event consumers, tests, and Phase 1 policies stable.

Resolved metadata should live at effect scope because policy evaluation is
already effect-local:

- One `ResolvedObjectRef` per syntactic object when resolution was attempted.
- Canonical schema/name/OID/kind fields for resolved relations.
- Canonical schema/name/OID/identity args/volatility for resolved functions.
- Source and unresolved reason fields for diagnostics.

The policy evaluator should continue to match syntactic objects through the
existing object matcher. Catalog-sensitive matching in Plan 09 is limited to
resolution tags. Rich canonical selectors such as `relations`, `schemas`, and
`functions` belong to Plan 10.

### 3.3 Resolution Tags

Plan 09 extends `effects.Resolution` with catalog-backed tags without changing
the meaning of existing Phase 1 tags.

Required new tags:

- `catalog_resolved`: every object that can be catalog-resolved for the effect
  resolved cleanly.
- `catalog_unavailable`: catalog resolution could not run because snapshot or
  connection context was unavailable.
- `catalog_unresolved`: resolution ran, but at least one referenced object was
  missing, ambiguous, or unsupported.

The runtime upgrades an effect to `catalog_resolved` only when every relevant
object resolves cleanly. Otherwise it keeps syntactic object refs intact and
uses the most precise catalog failure tag. Existing `match_object_resolution`
rules fail closed for these tags unless operators explicitly match them.

Plan 09 must decouple resolution confidence from enum append order. The current
`effects.Fold` relies on numeric ordering; adding `catalog_resolved` as an
appended constant would otherwise make the strongest tag look weakest. The
implementation should introduce an explicit confidence-rank table with this
best-to-worst order:

1. `catalog_resolved`
2. `qualified_syntactic`
3. `unqualified_syntactic`
4. `ambiguous_after_search_path`
5. `maybe_temp_shadowed`
6. `unresolved`
7. `catalog_unresolved`
8. `catalog_unavailable`

## 4. Components

### 4.1 `internal/db/effects`

Add the public data structures and resolution tags consumed by policy and
events:

- `ResolvedObjectRef`
- `ResolvedObjectSource`
- `ResolvedObjectKind`
- `UnresolvedReason string`
- `catalog_resolved`, `catalog_unavailable`, `catalog_unresolved`

The resolved fields must have stable JSON names and `omitempty` behavior so
existing fixtures remain valid.

### 4.2 `internal/db/proxy/postgres/catalog_runtime.go`

Owns runtime snapshot loading and refresh:

- Service/database/user cache key.
- Snapshot cache guarded by a mutex.
- `LoadOrGet(ctx, pc)` for first-use loading.
- `Refresh(ctx, key)` hook for tests and future reload integration.
- A small pgproto3 Simple Query helper that runs catalog SQL over the
  authenticated upstream connection, consumes rows through `ReadyForQuery`, and
  adapts those rows to the existing `catalog.Rows` interface.

Snapshot loading must run only while the proxy owns the upstream exchange and
before forwarding the next client statement. It must not interleave with client
traffic.

### 4.3 `internal/db/proxy/postgres/resolve_runtime.go`

Maps classified syntactic effects to catalog lookups:

- Convert relation-like `effects.ObjectRef` values into `catalog.Name`.
- Resolve relation objects against the cached snapshot and connection search
  path.
- Resolve FunctionCall OIDs with `catalog.ResolveFunctionByOID`.
- Preserve unsupported object kinds unchanged.
- Return an augmented copy of `effects.ClassifiedStatement`; callers should not
  mutate classifier-owned slices in place unless they already own the statement.

### 4.4 Proxy Hot Paths

Resolution must run after classification and before policy evaluation in:

- Simple Query `handleQuery`.
- Extended Query `Parse` handling.
- SQL PREPARE cache population and EXECUTE cache reuse.
- Approval wait event generation.
- FunctionCall OID allow/approve/deny path.

The statemachine currently owns part of Extended Query policy evaluation.
Plan 09 should either inject a resolver callback into `TransitionWithParser` or
move the classify-resolve-evaluate boundary into the proxy dispatcher. The plan
should prefer the smallest change that keeps statemachine tests pure.

### 4.5 `internal/db/events`

`DBEvent` should emit resolved-object metadata alongside existing effects.
Events must still include `effects` exactly as Phase 1 consumers expect.

Minimum event additions:

- Per-effect resolved object refs.
- Event-level object resolution source/folded tag.
- Unresolved reason when the runtime stayed syntactic.

The event builder should derive the event-level resolution from the classified
statement after runtime augmentation.

## 5. Data Flow

1. The server accepts a proxy connection and authenticates listener ownership.
2. The proxy forwards StartupMessage/auth to upstream as it does today.
3. After upstream sends `ReadyForQuery`, the connection records database,
   db user, application name, TLS mode, and client identity.
4. The runtime queries `current_schemas(true)` on the authenticated upstream
   connection and stores that ordered search path on `connState`.
5. The snapshot store loads or reuses the catalog snapshot for
   service/database/user.
6. The classifier emits syntactic `effects.ClassifiedStatement` values.
7. Runtime resolution augments each statement with resolved metadata and
   catalog resolution tags.
8. Policy evaluation runs against the augmented statement.
9. The proxy forwards, denies, approves, or handles COPY using existing Phase 1
   behavior.
10. DBEvent emission includes syntactic effects plus resolved metadata.

## 6. Failure Semantics

Plan 09 must fail closed for catalog-sensitive policies without breaking
existing syntactic policies.

- Snapshot load fails: continue in syntactic mode, tag catalog metadata as
  `catalog_unavailable`, and log/emit a diagnostic lifecycle event.
- `current_schemas(true)` fails: use an empty search path, keep syntactic refs,
  and tag catalog metadata as `catalog_unavailable`.
- Object missing: keep syntactic refs and mark the resolved object with reason
  `missing`.
- Ambiguous unqualified object: keep syntactic refs and mark reason
  `ambiguous`.
- Unsupported object kind: keep syntactic refs and mark reason `unsupported`;
  do not block unrelated resolvable objects in other effects.
- Temp schema/shadowing: follow the order returned by `current_schemas(true)`.
  A `pg_temp_*` schema wins only when Postgres reports it in the active search
  path.
- FunctionCall OID missing: preserve existing FunctionCall deny/allow defaults
  and attach unresolved metadata when an event is emitted.
- Snapshot staleness: documented limitation for Plan 09. Operators get explicit
  refresh hooks, not background freshness guarantees.

## 7. Testing Strategy

### Unit Tests

- Resolution tag parsing/string tests for new catalog tags.
- JSON round-trip tests for resolved metadata.
- Runtime augmentation tests for:
  - schema-qualified table.
  - unqualified table via search path.
  - missing table.
  - ambiguous unqualified table.
  - unsupported object kind passthrough.
  - FunctionCall OID.
  - catalog-unavailable fallback.

### Proxy Tests

- Simple Query policy sees `catalog_resolved` before allow/deny.
- Extended Query Parse policy sees `catalog_resolved` before allow/deny.
- SQL PREPARE caches the resolved inner classification.
- EXECUTE reuses the resolved cached classification.
- Approval events include resolved metadata.
- Event builder emits resolved canonical object fields.

### Real Postgres Integration

Extend the existing real Postgres integration suite with cases for:

- Schema-qualified table resolution.
- Unqualified table resolution through default search path.
- Temp table shadowing.
- View references.
- FunctionCall OID labeling when FunctionCall is enabled.
- Missing object fallback.
- Catalog-unavailable fallback, using an injected loader failure or controlled
  upstream catalog-query failure.

### Verification

Required before implementation completion:

```bash
go test ./...
GOOS=windows go build ./...
go test -tags=integration ./internal/integration -run TestDBPostgres
```

The Windows build must keep catalog runtime code behind Linux proxy build tags
or platform-neutral packages. Any platform-specific test must skip when the
feature is unavailable.

## 8. Implementation Plan Notes

The implementation plan should split work into these commits:

1. Effects/events schema additions with unit tests.
2. Catalog runtime cache and query helper with fake upstream tests.
3. Pure statement augmentation adapter with table/function tests.
4. Simple Query runtime integration.
5. Extended Query and prepared-cache integration.
6. Event emission and approval/FunctionCall integration.
7. Real Postgres integration coverage and docs updates.

Each commit should keep `go test` green for the touched packages.

## 9. Open Items For Later Plans

- Background TTL refresh and invalidation strategy.
- Canonical policy selectors (`relations`, `schemas`, `functions`) in Plan 10.
- Redirect policy validation and rewrite planning in Plans 11 and 12.
- Function volatility-driven default escalation behavior.
- Result-set and Describe metadata controls in Phase 7.
