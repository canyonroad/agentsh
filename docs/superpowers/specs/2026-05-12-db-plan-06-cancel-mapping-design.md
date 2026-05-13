# db-access Plan 06 - CancelRequest Mapping Design

Status: design draft 2026-05-12. Brainstormed via `superpowers:brainstorming`.

Cross-references:
- Roadmap: `docs/superpowers/specs/2026-05-08-db-access-phase-1-roadmap-design.md` section 3, Plan 06.
- Spec: `docs/agentsh-db-access-spec.md` v0.8 section 15.
- Predecessor design: `docs/superpowers/specs/2026-05-11-db-plan-05-pg-extended-tx-design.md`.

Plan 06 replaces the temporary un-mapped CancelRequest behavior from Plan 04b2 with protocol-correct `BackendKeyData` translation, a proxy-wide synthetic-to-real cancel mapping table, cancel-rule evaluation against mapped connection metadata, and tests that prove the client never sees upstream cancel credentials.

## 1. Scope

In scope:

- Translate upstream `BackendKeyData(real_pid, real_secret)` into client-facing `BackendKeyData(syn_pid, syn_secret)`.
- Store a proxy-wide mapping from synthetic cancel key to real upstream cancel key and connection metadata.
- Commit the mapping before the synthetic `BackendKeyData` is flushed to the client, closing the side-channel race from spec R20.
- Replace un-mapped CancelRequest forwarding with lookup-first handling.
- Evaluate `database_connection_rules` with `match_kind: cancel` for matched mappings.
- Implement mapping lifecycle with `cancel_grace_window` and `cancel_mapping_max`.
- Emit cancel lifecycle events and cancel `DBEvent` records.
- Add unit, protocol, race, and spine coverage for cancel mapping.

Out of scope:

- Direct-egress bypass enforcement. Plan 07 owns the unavoidability bundle and direct CancelRequest egress blocking.
- SessionID-keyed proxy identity exemption. Plan 07 owns out-of-process proxy identity hardening.
- Per-service cancel-map caps. The map is proxy-wide in Phase 1.
- Persisting mappings across proxy restarts. Cancel mappings are runtime-only and are lost on restart.
- Real PostgreSQL testcontainer coverage. Plan 07 owns the full integration suite; Plan 06 includes fake-upstream spine coverage.

## 2. Architecture

Plan 06 uses a focused Postgres-proxy implementation, not a generic DB abstraction.

`Server` owns one `cancelMap`. Each authenticated upstream connection registers a mapping when `forwardAuth` receives `BackendKeyData` from upstream. Registration generates a synthetic `(pid, secret)` pair, stores the real upstream key plus connection metadata, and returns synthetic values for the client-facing `BackendKeyData`.

The critical ordering is:

1. Upstream sends `BackendKeyData(real_pid, real_secret)`.
2. Proxy registers `(syn_pid, syn_secret) -> real key and metadata`.
3. Proxy sends `BackendKeyData(syn_pid, syn_secret)` to the client.

If registration fails, the proxy does not forward upstream `BackendKeyData`. It fails connection setup and emits an operational lifecycle event.

The normal connection stores a release hook for the registered mapping. On connection teardown, the hook marks the mapping disconnected and starts the grace window. The entry remains lookupable until it is past grace or pruned under cap pressure.

Side-channel CancelRequest handling changes from evaluate-then-forward to lookup-then-evaluate:

1. Parse `CancelRequest(syn_pid, syn_secret)`.
2. Look up the synthetic key in `cancelMap`.
3. If no match or expired, close silently and emit a lifecycle event.
4. If live or within grace, evaluate `match_kind: cancel` against the mapped service and client/startup metadata.
5. Deny closes silently and emits a cancel `DBEvent`.
6. Allow or audit forwards `CancelRequest(real_pid, real_secret)` to upstream and emits a cancel `DBEvent`.

## 3. Components

### 3.1 `cancelmap.go`

Add `internal/db/proxy/postgres/cancelmap.go`.

Primary types:

- `cancelKey`: stable comparable encoding of `(pid uint32, secret []byte)`.
- `cancelEntry`: mapping record containing:
  - service name
  - upstream address
  - real PID and real secret
  - synthetic PID and synthetic secret
  - client identity
  - db user
  - database
  - application name
  - created time
  - disconnected time
  - live/closed state
- `cancelMap`: mutex-protected proxy-wide table with max size, grace window, clock hook, and synthetic-key generator hook for tests.

Primary methods:

- `Register(meta cancelMeta, realPID uint32, realSecret []byte) (cancelRegistration, error)`
- `Lookup(pid uint32, secret []byte) (cancelEntry, cancelLookupStatus)`
- `MarkDisconnected(key cancelKey)`
- `PruneExpired(now time.Time) int`

`Register` returns a `cancelRegistration` containing the synthetic key and a `Release()` function. `Release()` must be idempotent so connection teardown can call it safely from multiple paths.

Errors:

- `errBackendKeyGenerationFailed`: eight synthetic-key collision retries were exhausted.
- `errBackendKeyTableFull`: table cap was reached and no entry past grace could be pruned.

### 3.2 `server.go`

Extend `postgres.Config`:

- `CancelMappingMax int`, default `100000`.
- `CancelGraceWindow time.Duration`, default `5 * time.Minute`.

`New` initializes `Server.cancelMap` for non-sentinel and sentinel servers. The sentinel map is harmless but keeps tests and construction paths uniform.

### 3.3 `authforward.go`

On `*pgproto3.BackendKeyData`:

- Copy the real upstream secret before storing it.
- Call `srv.cancelMap.Register` with service and connection metadata.
- Store the returned registration/release on `proxyConn`.
- Send a new `pgproto3.BackendKeyData` with synthetic PID and synthetic secret.
- Flush only after registration succeeds.

`forwardAuth` must not forward real upstream `BackendKeyData` to the client.

If registration fails:

- `errBackendKeyGenerationFailed` produces `BACKEND_KEY_GENERATION_FAILED`.
- `errBackendKeyTableFull` produces `BACKEND_KEY_TABLE_FULL`.
- The client sees a fatal startup error.
- A lifecycle event captures service, client identity, and error code.

### 3.4 `proxyconn.go`

Store cancel registration state on `proxyConn` or `connState`.

Connection teardown calls the release hook before or during `closeUpstream`. The hook marks the mapping disconnected rather than deleting it immediately.

### 3.5 `handshake.go` and `cancel.go`

`handleCancelRequest` becomes lookup-first:

- no match: emit `db_cancel_unmatched`, close silently
- expired: emit `db_cancel_after_disconnect`, close silently
- live or within grace: evaluate cancel policy with metadata from the mapping

`forwardCancel` keeps the low-level dial/write behavior but receives a packet built from the real upstream key, not the client-supplied synthetic key.

## 4. Data Model

The mapping key is the synthetic `(pid, secret)` pair. Standard PostgreSQL uses a four-byte secret; CockroachDB-compatible flows may use a longer secret. The map stores secret bytes exactly and compares the full byte sequence.

`cancelMeta` captures values needed for later policy evaluation and events:

- `ServiceName`
- `UpstreamAddr`
- `ClientIdentity`
- `DBUser`
- `Database`
- `ApplicationName`
- `PeerUID`

This metadata is copied at registration time. Cancel side-channel connections do not have a startup message for the original session, so the proxy must not rely on the cancel connection itself for db user, database, or application name.

Lookup statuses:

- `cancelLookupMiss`: no mapping for the synthetic key
- `cancelLookupExpired`: mapping existed but is past grace
- `cancelLookupFound`: mapping is live or disconnected within grace

Disconnected-within-grace mappings remain valid for forwarding. This preserves normal client behavior when a cancel races connection shutdown. "Expired" means disconnected and older than `cancel_grace_window`.

## 5. Lifecycle And Capacity

Mappings are created during auth when upstream sends `BackendKeyData`.

Mappings are marked disconnected when the normal connection ends. They are retained for `cancel_grace_window`, default `5m`.

The table is bounded by `cancel_mapping_max`, default `100000`.

When the cap is hit, `Register` prunes only entries whose disconnected time is older than the grace window. Live mappings are never evicted. Disconnected-but-within-grace mappings are not evicted. If no expired entry can be pruned, registration fails with `BACKEND_KEY_TABLE_FULL`.

Collision handling:

- Synthetic PID and secret are generated with a CSPRNG.
- If the generated key already exists, retry.
- Retry at most eight times.
- On exhaustion, fail connection setup with `BACKEND_KEY_GENERATION_FAILED`.

## 6. Policy Semantics

Matched CancelRequests use existing connection-rule evaluation with `MatchCancel`.

The `ConnectionInfo` input is populated from the original mapped connection:

- `Service`: mapped service
- `MatchKind`: cancel
- `DBUser`: original startup `user`, if visible
- `Database`: original startup database, if visible
- `ApplicationName`: original startup application name, if visible
- `ClientIdentity`: original client identity

Config validation already rejects `decision: approve` on `match_kind: cancel`. Plan 06 relies on that rule. Cancel cannot be held for approval because it is a real-time side-channel.

Decision handling:

- `deny`: close silently, emit cancel `DBEvent`
- `allow`: forward real cancel, emit cancel `DBEvent`
- `audit`: forward real cancel, emit cancel `DBEvent` with verb `audit`

If no cancel rule matches, existing evaluator semantics produce implicit deny.

## 7. Events

### 7.1 Lifecycle Events

Add lifecycle event kinds:

- `db_cancel_unmatched`: no synthetic mapping exists. This is suspicious because a normal client should only know proxy-issued keys.
- `db_cancel_after_disconnect`: mapping existed but is past grace. This is a benign client-race diagnostic.
- `db_cancel_forward_failed`: policy allowed or audited the cancel, but upstream dial/write failed.
- `db_cancel_mapping_fail`: normal connection setup could not register a mapping. `ErrorCode` is `BACKEND_KEY_GENERATION_FAILED` or `BACKEND_KEY_TABLE_FULL`.

Lifecycle events include service and client identity when known. For unmatched cancels, service is the listener service that received the cancel side-channel connection, and original mapped metadata is absent.

### 7.2 Cancel DBEvents

For found mappings, emit a `DBEvent` with:

- `decision.rule_kind: "cancel"`
- `decision.verb: "allow"`, `"audit"`, or `"deny"`
- `decision.rule_name`: matched rule name, empty for implicit deny
- `operation_group: "session"`
- `operation_subtype: "cancel_request"`
- one effect: `session/cancel_request`
- service, db user, database, application name, and client identity from the mapping
- no statement text
- no statement digest
- `result.error_code` set when allowed forwarding fails

This keeps cancel governance queryable with statement events while still making no-match and expired-key cases lifecycle events.

## 8. Error Handling

Connection setup failures:

- `BACKEND_KEY_GENERATION_FAILED`: fail closed before exposing any backend key. Emit `db_cancel_mapping_fail`.
- `BACKEND_KEY_TABLE_FULL`: fail closed before exposing any backend key. Emit `db_cancel_mapping_fail`.

Cancel request failures:

- malformed CancelRequest: handled by existing startup parser error paths and connection close
- no mapping: lifecycle event and silent close
- expired mapping: lifecycle event and silent close
- policy deny: cancel DBEvent and silent close
- upstream cancel forward failure: cancel DBEvent with `result.error_code`, lifecycle event, silent close

Postgres cancel side-channel has no response payload. All cancel paths close the cancel connection without synthesizing protocol errors.

## 9. Testing

### 9.1 Unit Tests

`cancelmap_test.go`:

- register returns synthetic keys and stores real metadata
- lookup by synthetic key returns real key and metadata
- real upstream key is never used as the lookup key
- collision retry regenerates keys
- collision retry exhaustion returns `BACKEND_KEY_GENERATION_FAILED`
- cap hit prunes only entries past grace
- live mappings are never evicted
- disconnected-within-grace mappings are never evicted
- cap hit with no expired entries returns `BACKEND_KEY_TABLE_FULL`
- release is idempotent
- disconnected-within-grace remains lookupable
- disconnected-past-grace returns expired

### 9.2 Protocol Tests

`authforward_test.go`:

- `forwardAuth` forwards synthetic `BackendKeyData`, never real upstream key
- mapping is committed before synthetic `BackendKeyData` is visible to the client
- registration failure fails startup and emits `db_cancel_mapping_fail`
- connection teardown marks mapping disconnected

`handshake_test.go` and `cancel_test.go`:

- no-match CancelRequest closes silently and emits `db_cancel_unmatched`
- expired mapping closes silently and emits `db_cancel_after_disconnect`
- deny rule does not dial upstream and emits cancel DBEvent
- allow rule dials upstream with real PID/secret
- audit rule dials upstream with real PID/secret and emits verb `audit`
- forward failure emits cancel DBEvent with error code and lifecycle event

### 9.3 Spine Test

Extend `spine_test.go` with a fake-upstream cancel flow:

1. Fake upstream sends real `BackendKeyData`.
2. Client receives synthetic `BackendKeyData` during startup.
3. Client issues a long-running query or the fake upstream blocks after startup.
4. Client opens a side-channel CancelRequest using synthetic key.
5. Proxy forwards a CancelRequest carrying the real upstream key to fake upstream.
6. Test asserts:
   - client never saw real upstream key
   - upstream received real key
   - cancel DBEvent was emitted
   - mapping remained valid through the side-channel flow

### 9.4 Race And Build Tests

- Race test for R20 commit ordering: a cancel goroutine attempts lookup as soon as client-observable synthetic BKD is read; lookup must already succeed.
- `go test ./internal/db/proxy/postgres/... -race` should pass on Linux.
- `GOOS=windows go build ./...` should remain green through existing stubs.

## 10. Implementation Notes

Keep `cancelMap` small and isolated. Do not introduce a generic proxy session registry.

Prefer value copies for map entries returned from `Lookup`; callers should not mutate internal state.

Use `crypto/rand` in production. Tests can inject deterministic key generation to force collisions and cap behavior.

Use byte-safe comparison for secrets. Do not stringify secrets for logs or events.

When emitting events, never include real or synthetic cancel secrets.

When constructing the upstream CancelRequest packet, preserve the real secret byte length. Standard PostgreSQL secrets are four bytes, but existing code already accommodates longer secrets.

## 11. Done Definition

Plan 06 is done when:

- Clients receive synthetic `BackendKeyData`, never upstream real keys.
- Synthetic mappings are committed before synthetic keys are flushed to clients.
- Side-channel CancelRequests with synthetic keys are translated to real upstream CancelRequests.
- Cancel policies apply after a successful mapping lookup.
- No-match, expired, denied, allowed, audited, forward-failed, collision-exhausted, and table-full paths are covered.
- Live mappings are never evicted under cap pressure.
- Disconnected mappings remain valid through the grace window.
- Linux proxy tests, race-targeted cancel tests, full `go test ./...`, and `GOOS=windows go build ./...` are green.

