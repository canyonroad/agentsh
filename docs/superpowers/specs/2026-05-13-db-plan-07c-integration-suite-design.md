# DB Plan 07c Integration Suite Design

**Status:** Approved for implementation planning.
**Date:** 2026-05-13
**Source roadmap:** `docs/superpowers/specs/2026-05-13-db-plan-07-split-unavoidability-design.md`
**Source spec:** `docs/agentsh-db-access-spec.md` v0.8, sections 11-14 and 23.4.

## Goal

Close DB Access Plan 07 by adding CI-required integration coverage against a
real Postgres server, then update operator guidance so
`policies.db.unavoidability: enforce` is the high-assurance recommendation for
declared Phase 1 Postgres services.

Plan 07a generated the unavoidability bundle. Plan 07b connected that bundle to
runtime per-session DB proxy startup, listener SessionID authentication, and
normalized bypass lifecycle events. Plan 07c proves those pieces together with
real Postgres instead of fake upstream protocol scripts.

## Requirements

- The required Postgres integration tests run in CI under the existing
  `integration` build tag and existing GitHub Actions integration job.
- Tests use `testcontainers-go` to start a real `postgres` container.
- Tests use `github.com/jackc/pgx/v5` as the client driver.
- Tests exercise the AgentSH Postgres proxy path, not only the classifier or a
  fake upstream harness.
- Required tests fail loudly in CI if Docker, Postgres startup, AgentSH startup,
  SQL execution, or event assertions fail.
- Local developers can run the suite with the same command shape CI uses:
  `go test -v -tags=integration ./internal/integration/...`.
- Aurora Postgres, Redshift, and CockroachDB remain best-effort manual
  validation targets for Phase 1 and are not CI gates.

## Architecture

The 07c suite lives in `internal/integration` beside the existing Docker-backed
AgentSH integration tests. It starts a real Postgres container, starts an
AgentSH server container with a DB policy that declares that Postgres upstream,
creates a session, waits for the per-session DB proxy listener, then connects
to that listener with `pgx`.

The tests should prefer the production API path where practical:

1. Load a policy with `db_services`, `database_connection_rules`,
   `database_rules`, and `policies.db.unavoidability: enforce`.
2. Create an AgentSH session through the API.
3. Let the API layer compile the DB unavoidability bundle and start the
   per-session Postgres proxy.
4. Discover the session DB proxy socket from the session or a narrowly scoped
   test helper.
5. Run `pgx` SQL traffic through the socket to the real Postgres upstream.
6. Query session events through the existing event API when lifecycle events are
   part of the assertion.

Existing unit and spine tests remain the detailed protocol tests. 07c is the
end-to-end integration gate for the real upstream behavior and unavoidability
boundary.

## Test Groups

### Real Proxy SQL Flows

The first group proves normal and denied SQL behavior through a real upstream:

- Simple Query allow path returns rows from Postgres through the proxy.
- Simple Query deny path fails before upstream execution.
- Extended Query allow path works with `pgx` default execution mode.
- Extended Query deny path returns the expected SQLSTATE and does not mutate
  upstream state.
- In-transaction deny behavior leaves the client with the expected error or
  closed-connection behavior and emits a deny event with the in-transaction
  action.

The deny assertions should use an observable upstream side effect, such as
checking that a row count or marker table was not changed after a denied
statement. This makes the test about behavior, not only client-side errors.

### Protocol Features From Earlier DB Plans

The second group proves previous DB plans still work against real Postgres:

- CancelRequest uses the Plan 06 synthetic backend key mapping and cancels a
  real long-running query.
- COPY export/load flows through the proxy, emits the expected DB event shape,
  and applies the configured redaction behavior.

If these require more implementation plumbing than the core 07c gate, they
should remain in the same 07c plan as later tasks on the same branch rather than
becoming a different plan.

### Unavoidability And Bypass

The third group proves the Plan 07 boundary:

- Full bundle plus proxy smoke test creates the session DB proxy listener and
  routes client traffic through it.
- Direct TCP connection attempts to the declared Postgres upstream are denied
  for the governed session and emit `db_bypass_attempt`.
- Direct listener access from a process that does not resolve to the owning
  AgentSH SessionID is rejected and emits `db_listener_auth_fail`.

The bypass tests should use concrete runtime behavior where the current
enforcement machinery can observe it. If a direct kernel-level TCP bypass cannot
be made deterministic in the existing CI container environment, the test must
still verify the production decision path and lifecycle event emission through
the narrowest existing API seam; it must not silently skip the boundary claim in
CI.

### Operator Closeout

The documentation update should make the status explicit:

- Plan 07 is complete only after 07c passes in CI.
- `policies.db.unavoidability: enforce` is the high-assurance recommendation
  for declared Phase 1 Postgres services.
- The recommendation is scoped to processes inside the AgentSH-governed process
  tree, for declared DB services, assuming the AgentSH supervisor and DB proxy
  are not compromised.
- Aurora Postgres, Redshift, CockroachDB, MySQL, and MariaDB do not become
  high-assurance automated claims in Phase 1.

## Test Helper Design

Helpers should stay in the integration package and avoid new production
abstractions unless real Postgres exposes a production bug.

Recommended helpers:

- `startPostgres07c(t, ctx)` starts a `postgres` container, waits for readiness,
  returns host, mapped port, credentials, and a cleanup function.
- `writeDB07cPolicy(t, path, upstream)` writes a policy with one `appdb`
  service, explicit allow rules for permitted reads/session/transaction flows,
  and explicit deny rules for the tested mutations.
- `startAgentSHDB07c(t, ctx, bin, configPath, policiesDir, workspace)` reuses
  the existing server-container pattern and enables the sandbox knobs needed for
  DB unavoidability.
- `sessionDBProxySocket07c(t, cli, sess, serviceName)` finds the per-session DB
  proxy socket. Prefer a public session/API field if available; otherwise use a
  small test-only helper rather than baking internal directory knowledge into
  every test.
- `connectPGXViaProxy07c(t, ctx, socketDir, port, user, database)` builds the
  Unix-socket `pgx` connection string.
- `waitForSessionEvent07c(t, cli, sessionID, predicate)` polls the existing
  event API and fails with observed events on timeout.

Helpers should use `filepath.Join` and `t.TempDir()` for all paths.

## CI Behavior

The existing `.github/workflows/ci.yml` integration job is the target. It
already runs with Docker and `testcontainers-go` support:

```bash
go test -v -tags=integration ./internal/integration/...
```

07c should not add a separate workflow unless the existing integration job
cannot support real Postgres. If a CI dependency is missing, add the smallest
job adjustment needed and keep it local to the integration job.

Timeouts should be explicit:

- Postgres container startup: 60 seconds.
- AgentSH server health: existing server-container health wait, currently 60
  seconds.
- DB proxy listener readiness: 2 seconds after session creation, matching
  existing API-side listener wait behavior.
- SQL operations: 5 to 10 seconds per operation.
- Event assertions: poll up to 2 seconds and fail with observed events.

The required 07c Postgres tests must not skip in CI because Docker or Postgres
is unavailable. A failure to start the required infrastructure is a test
failure.

## Error Handling

Failure messages should identify the 07c boundary being tested. Examples:

- `07c real Postgres proxy did not return rows through appdb`
- `07c deny reached upstream: marker table changed`
- `07c direct TCP bypass unexpectedly succeeded`
- `07c did not emit db_bypass_attempt`
- `07c cross-session listener access was accepted`
- `07c did not emit db_listener_auth_fail`
- `07c cancel request did not cancel pg_sleep`

When a test polls for an event, it should include the observed event types and
fields in the failure output. When a SQL operation fails unexpectedly, include
the SQLSTATE when available.

## Production Change Boundary

Most 07c work should be tests and docs. Production changes are allowed only
when the real Postgres suite exposes a real behavior gap or when an existing
API lacks a clean way to observe a required boundary.

Allowed production changes:

- Small DB proxy fixes discovered by real Postgres behavior.
- Small testability/API additions for session DB proxy socket discovery or
  event assertion, if existing fields are insufficient.
- Minimal CI dependency updates for the existing integration job.

Out of scope:

- MySQL or MariaDB support.
- TCP listener support in enforce mode.
- New DB-specific policy evaluator.
- Catalog-aware object resolution.
- Aurora Postgres, Redshift, or CockroachDB automated CI gates.
- Claims for processes outside the AgentSH-governed process tree.
- Claims when the supervisor or DB proxy is compromised.

## Verification

The implementation plan should finish with:

```bash
go test -v -tags=integration ./internal/integration/...
go test ./internal/db/... ./internal/api/...
go test -p 2 ./...
GOOS=windows go build ./...
git diff --check
```

The first command is the 07c release gate. The remaining commands protect the
existing DB packages, normal unit suite, Windows build, and whitespace hygiene.
