# DB Access Plan 07 Split - Unavoidability Design

**Status:** Implemented.
**Date:** 2026-05-13
**Source roadmap:** `docs/superpowers/specs/2026-05-08-db-access-phase-1-roadmap-design.md`
**Source spec:** `docs/agentsh-db-access-spec.md` v0.8, sections 11.1, 12, 17, and 23.4 steps 10-11.

## Goal

Close DB Access Phase 1 by making declared `db_services` unavoidable for processes inside the AgentSH-governed process tree, then prove the end-to-end behavior against a real Postgres server.

The original roadmap Plan 07 is intentionally split into three sequential plans so each PR is reviewable and each phase has a clear security boundary.

## Plan Split

### Plan 07a - Unavoidability Bundle Generator

Build `internal/db/service/bundle.go`.

The generator consumes declared `db_services` plus session/proxy context and emits existing policy primitives:

- `connect_redirects` from declared upstream host/port to the per-session DB proxy Unix socket, including the narrow policy-model extension needed for Unix-socket redirect targets.
- `network_rules` that deny direct egress to declared DB destinations for the agent session.
- DNS/IP expansion metadata for declared upstream hostnames, including CNAME and IPv6 coverage where existing policy supports it.
- `unix_socket_rules` that deny common local Postgres socket paths for non-proxy processes.
- `command_rules` for known bypass tools and patterns.

Generated rules carry minimal DB metadata so later enforcement can map generic policy decisions back to DB bypass events without guessing from names.

### Plan 07b - Listener Session Auth And Bypass Events

Replace Plan 04a's UID-only listener auth with SessionID-based authentication:

- Accept only Unix-socket listeners in Phase 1 enforce mode.
- On accept, read SO_PEERCRED pid/uid/gid.
- Resolve pid to AgentSH SessionID through an injected resolver interface.
- Accept only when the resolved peer SessionID matches the configured agent SessionID.
- Unknown or mismatched SessionID fails closed and emits `db_listener_auth_fail`.

Plan 07b also maps DB-generated deny decisions into normalized `db_bypass_attempt` lifecycle events and deduplicates those events per `(session_id, process_identity, destination_tuple)` for 60 seconds.

### Plan 07c - Integration Suite And Enforce Recommendation

Add integration coverage that exercises the full path:

- Generated bundle.
- DB proxy listener.
- Real Postgres upstream.
- Client traffic through the redirected path.
- Direct bypass attempts.

Plan 07c is the CI closeout gate: it runs `go test -v -tags=integration ./internal/integration/...` against a real `postgres:16-alpine` container, exercises the AgentSH Postgres proxy path through a governed session, and asserts `db_bypass_attempt` plus `db_listener_auth_fail` lifecycle events. Plan 07 is complete only after that suite passes in CI.

## Architecture

Plan 07 should not add a DB-specific policy evaluator. The bundle generator emits existing policy rule families that the current engine can compile and enforce. The one required model extension is a Unix-socket target for `connect_redirects`, because the current `ConnectRedirectRule.RedirectTo` shape redirects TCP host:port to TCP host:port while spec section 12.5 requires redirecting the client's protected DB `connect()` to a per-session Unix socket. DB-specific metadata is carried alongside generated rules and consumed only by DB event mapping.

This keeps the security boundary in existing primitives:

- Destination egress denial catches direct TCP and custom tunnel binaries.
- Connect redirect sends normal client DB connections to the proxy Unix-socket listener.
- Unix socket file rules close common local socket bypass paths.
- Command rules are convenience detection, not the boundary.

## Rule Metadata

Generated DB rules must have stable metadata keyed by rule name. Metadata must survive the handoff from generation to enforcement; it may be carried as an in-memory sidecar in the `Bundle`, and exported policy files should include an equivalent top-level metadata block rather than relying only on rule-name prefixes.

Recommended metadata fields:

```go
type GeneratedRuleMetadata struct {
    RuleName    string
    Source      string // "db_unavoidability"
    DBService   string
    BypassMode  string // tcp_direct, unix_socket, port_forward_tool, dns_alias, custom_tunnel, listener_auth_fail
    Destination string // host:port, CIDR/port, or unix-socket path
}
```

`RuleName` must be deterministic for a given service and rule purpose. Multiple services must not collide. Metadata is not the enforcement mechanism; it is the event-correlation contract between 07a and 07b.

## 07a API

The generator should live in `internal/db/service` rather than generic `internal/policygen`, because it is derived from static `db_services` config rather than from recorded session activity.

Recommended API:

```go
type BundleOptions struct {
    SessionID        string
    ProxySessionID   string
    SocketBaseDir    string
    IncludeToolRules bool
    Mode             Unavoidability // observe or enforce
}

type Bundle struct {
    Policy   policy.Policy
    Metadata []GeneratedRuleMetadata
    Warnings []BundleWarning
}

func GenerateBundle(cfg Config, opts BundleOptions) (Bundle, error)
```

`SessionID` identifies the governed agent session. `ProxySessionID` identifies the DB proxy exemption session. `SocketBaseDir` is used to derive per-session Unix socket listener paths when services do not provide an explicit path.

The output policy must be directly compileable by `internal/policy.NewEngine`.

07a also owns the backward-compatible `connect_redirect` target extension. Existing host:port redirects must keep working unchanged. DB-generated redirects should use an explicit Unix target field or target kind, for example:

```yaml
connect_redirects:
  - name: db-appdb-redirect
    match: '^db\.internal:5432$'
    redirect_to_unix: /run/agentsh/sessions/sess-123/db/appdb.sock
```

The final field spelling can be chosen during implementation planning, but the design requirement is fixed: the target type must be explicit and must not overload `redirect_to` with a Unix path.

## 07a Generated Policy Shape

For each service:

- Add a connect redirect from upstream `host:port` to the service's Unix socket listener path using the Unix-target redirect extension.
- Add direct network deny rules for the declared upstream host/port.
- Add deny rules for resolved IPs when resolution data is available.
- Add Unix socket deny rules for common Postgres paths:
  - `/var/run/postgresql/.s.PGSQL.*`
  - `/tmp/.s.PGSQL.*`
  - service-specific socket path if configured.
- Add command deny/detect rules for known bypass tools when `IncludeToolRules` is true.

Bypass command coverage should include at least:

- `ssh` with local forwarding patterns.
- `socat` TCP listener/forwarder patterns.
- `kubectl port-forward`.
- `cloud-sql-proxy`.
- `gcloud sql connect`.
- `aws rds connect`.
- `chisel`.
- `gost`.
- `frpc`.
- raw `nc` / `ncat` with DB ports.
- container runtime `--net=host` patterns when the command-rule model can express them.

The design must explicitly state that these command rules are non-exhaustive convenience detection. The direct destination deny remains the security boundary.

## 07b Listener Auth API

Listener auth should depend on an interface so tests do not depend on ptrace internals.

```go
type SessionResolver interface {
    ResolveSessionID(pid int32) (sessionID string, ok bool)
}
```

Production wires this to the AgentSH ptrace/session registry. Tests use a fake resolver.

Auth behavior:

- SO_PEERCRED failure: close connection and emit `db_listener_auth_fail`.
- Resolver miss: close connection and emit `db_listener_auth_fail` with `peer_session_id` set to `unknown`.
- Session mismatch: close connection and emit `db_listener_auth_fail`.
- Session match: continue to Postgres startup packet handling.

UID may still be recorded in events, but UID equality must not be the authorization boundary in 07b.

## 07b Bypass Events

07b adds a mapper from generic policy denials to DB lifecycle events:

```go
type BypassAttempt struct {
    SessionID     string
    ProcessID     int
    ProcessIdentity string
    DBService     string
    BypassMode    string
    Destination   string
    RuleName      string
    SuppressedCount int
}
```

When a deny decision has generated DB metadata, emit `db_bypass_attempt`. If a deny does not have DB metadata, keep the normal deny behavior and do not emit a DB bypass event.

Dedup key:

```text
(session_id, process_identity, destination_tuple)
```

The canonical event for a 60-second window carries `suppressed_count`, updated as matching attempts are absorbed. The exact update mechanics can be in-memory for Phase 1.

## 07c Integration Coverage

Plan 07c should use a real Postgres server as the required integration target. The required 07c Postgres tests run through Testcontainers in CI; Docker or Postgres startup failure is a gate failure, not a skip.

Required flows:

- Simple Query allow path.
- Simple Query deny pre-forward.
- Extended Query allow path.
- Extended Query deny path.
- In-transaction deny behavior.
- CancelRequest via Plan 06 mapping.
- COPY bulk export/load event and redaction behavior.
- Direct TCP bypass denied.
- Direct listener cross-session access denied.
- Full bundle plus proxy plus client smoke test.

Aurora PG, Redshift, and CockroachDB remain best-effort for Phase 1. If no reliable container image exists, Plan 07c should document manual validation rather than blocking the core Postgres gate.

## Error Handling

Fail closed where the boundary would otherwise weaken:

- Invalid `db_services` input: return a structured error and generate no partial bundle.
- TCP listener in enforce mode: reject with an error referencing spec section 12.5.
- Session resolver miss or mismatch: close silently at the protocol layer and emit lifecycle event.
- Missing DB metadata on an ordinary deny: deny normally, no DB bypass event.
- DNS expansion failure:
  - `observe`: generate hostname-based denies and return an operational warning.
  - `enforce`: fail bundle generation unless the caller explicitly opts into hostname-only enforcement.

## Tests

### 07a Unit Tests

- Generates redirect, network, Unix socket, command, and metadata entries for one Postgres service.
- Handles multiple services without rule-name collisions.
- Metadata maps back to generated rule names.
- Rejects unsupported TCP listener in enforce mode.
- DNS expansion warning/error behavior differs correctly between observe and enforce.
- Generated policy compiles with `internal/policy.NewEngine`.

### 07b Unit Tests

- Listener accepts matching SessionID.
- Listener rejects mismatched SessionID.
- Listener rejects unknown peer pid/session.
- `db_listener_auth_fail` contains peer pid, uid, peer session when known, and reason.
- DB-generated network deny maps to `db_bypass_attempt`.
- Non-DB deny does not emit DB bypass event.
- Deduper suppresses repeated attempts for 60 seconds and reports `suppressed_count`.

### 07c Integration Tests

- Real Postgres happy path through proxy.
- Policy deny prevents upstream execution.
- Extended Query and transaction state paths still work through generated bundle.
- Cancel mapping still forwards real upstream cancel keys.
- Direct TCP bypass is blocked.
- Direct listener cross-session connection is blocked.

## Non-Goals

- No MySQL/MariaDB unavoidability in Phase 1.
- No TCP listener support in enforce mode.
- No new DB-specific policy evaluator.
- No claim for processes outside the AgentSH-governed process tree.
- No claim when the supervisor or DB proxy is compromised.
- No exhaustive bypass-tool command list; command rules are detection only.

## Rollout

1. Land 07a with bundle generation and compile-only tests.
2. Land 07b with SessionID listener auth and bypass-event mapping.
3. Land 07c with integration tests and documentation updates.

After 07c passes in CI, Plan 07 is complete and DB Access Phase 1 recommends `policies.db.unavoidability: enforce` for declared Postgres services inside the AgentSH-governed process tree. This recommendation assumes an uncompromised AgentSH supervisor and DB proxy.
