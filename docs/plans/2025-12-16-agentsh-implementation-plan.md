# agentsh Implementation Plan (Linux-first, approvals later)

**Date:** 2025-12-16  
**Sources:** `docs/spec.md`, `docs/project-structure.md`, `docs/approval-auth.md`, `docs/cross-platform.md`, `config.yml`, `default-policy.yml`

## Status (this branch)

- ✅ M0–M2 implemented: Go module + server + CLI + policy command pre-check + `sqlite+jsonl` event storage + query APIs/CLI
- ✅ M3 implemented: per-session FUSE loopback mount for workspace monitoring + file policy enforcement (shadow-approve by default)
  - Emits: `file_open`, `file_read`, `file_write`, `file_create`, `file_delete`, `file_rename`, `dir_create`, `dir_delete`, `dir_list`, `file_stat`, `file_chmod`, `symlink_create`, `symlink_read`
- ✅ M4 implemented:
  - Explicit per-session HTTP(S) proxy (works unprivileged) + network policy enforcement
  - Transparent interception (Linux/root-only) via netns + DNAT + SO_ORIGINAL_DST TCP proxy + UDP DNS interceptor
    - DNS answers populate a small in-memory cache so `net_connect` events can include the most recent domain (and domain rules can apply without extra DNS lookups)
- ✅ M5 implemented: approvals manager + local TTY mode + API mode; `approve` decisions block only when approvals are enabled (otherwise shadow-approve)
- ✅ P1 (partial) implemented: resource time limits enforced
  - `resource_limits.command_timeout` caps per-command runtime (request timeout is honored but capped)
  - `resource_limits.session_timeout` + `resource_limits.idle_timeout` reaped by the server (config can further cap via `sessions.default_timeout` / `sessions.default_idle_timeout`)

## Goal

Implement **agentsh** as a daemon + CLI that provides:

- Persistent **sessions** with state (`cwd`, `env`, history)
- **Command execution** with structured JSON output
- Full **file I/O interception** (FUSE) and **network interception** (namespace + proxy/DNS)
- **Policy enforcement** (allow/deny) from day one for intercepted ops
- **Shadow-approve** behavior until approvals are implemented:
  - If policy result is `approve`, we **do not block**; we **allow** but **log/emit** that approval would have been required.
  - Once approvals land, the same `approve` policy result becomes **blocking**.

Non-goal for the initial MVP: cross-platform “native” support outside Linux (Windows/macOS run via Linux strategies as in `docs/cross-platform.md`).

## Key Decisions

### Decision semantics (shadow-approve now, real approvals later)

Keep policy decision stable (`allow|deny|approve`), but make enforcement mode explicit:

- Add `enforcement` metadata to events (and optionally to command response summaries):
  - `policy_decision`: `allow|deny|approve`
  - `effective_decision`: `allow|deny`
  - `approval`: `{ required: bool, mode: "shadow" | "enforced", approval_id?: string }`

This preserves `decision: approve` for future compatibility while making “allowed-but-flagged” unambiguous.

### Event storage + search (local first, pluggable)

Implement a pluggable **event sink** abstraction from the start:

- **JSONL sink**: append-only files (server log + audit log) with rotation. Lowest friction, great for “tail -f”, and easy to ship later.
- **SQLite sink**: local DB for queryable history (session/command/time/type/path/domain/decision filters). Enables search/UI without external dependencies.
- **Composite sink**: fan-out to multiple sinks (e.g., `sqlite + jsonl`).
- Optional: **Webhook sink**: POST batched JSON events to an HTTP endpoint for early-stage “ship to central” workflows.

Search is implemented via SQLite (primary), with JSONL treated as an archival/streaming format. Later, we can add a “shipper” sink that forwards to a central store (SIEM, OpenSearch, Splunk, etc.) without changing the core event model.

**Default for MVP:** `sqlite+jsonl`.

### Query surfaces (API + CLI)

Add a first-class way to query the SQLite event store:

- **API**:
  - Keep the spec endpoint `GET /api/v1/sessions/{id}/history` but implement it as a **query** endpoint with filters (time range, event types, decision, path/domain substring, limit/offset).
  - Add an admin/global query endpoint for cross-session search (e.g., `GET /api/v1/events/search`) with the same filters plus `session_id`.
- **CLI**:
  - `agentsh events query --session <id> --type file_write --since 1h --path-like '%.env%' --decision deny --limit 200`
  - `agentsh events tail --session <id>` (follows SSE stream; optional `--also-jsonl` tail helper for local debugging)
  - Support **both** query modes:
    - Default: query via daemon API (works for remote server, auth-aware)
    - Offline: `agentsh events query --direct-db [--db-path <path>] ...` (reads SQLite locally when server isn’t running)

Implementation detail: treat the query language as **structured filters** (not raw SQL) to avoid exposing arbitrary SQL execution through the API/CLI.

### Repository layout

Adopt the structure in `docs/project-structure.md` (Go module, `cmd/agentsh`, `internal/*`, `pkg/*`, `api/proto/*`, etc.).

### Config + policy sources of truth

- Server config: `config.yml` (to be loaded by server; later we can standardize to `configs/server-config.yaml` and update Docker references).
- Default policy: `default-policy.yml` (to be loadable by the policy engine; later standardize location/name for Docker/docs consistency).

## Architecture (MVP shape)

**Process model**

- `agentsh server`: long-running daemon hosting:
  - HTTP REST API (required)
  - gRPC API (optional milestone; can follow once REST is stable)
  - SSE event stream endpoint (to watch session + I/O + net events)
- `agentsh` CLI: talks to the daemon (HTTP first; gRPC later).

**Execution model**

- Each session owns a **sandbox**:
  - Session state: `cwd`, `env`, history, resource limits, chosen policy
  - Long-lived components: FUSE mount (M3), network namespace/proxy (M4)
  - Per-command lifecycle: spawn command, collect stdout/stderr, attach event correlation (`command_id`)

## Milestones (deliverables + acceptance criteria)

### M0 — Repo bootstrap

Deliverables:
- Go module + skeleton per `docs/project-structure.md`
- Basic `Makefile` targets: `build`, `test`, `lint` (as available)
- Minimal config loader for `config.yml` and policy loader for `default-policy.yml`

Acceptance criteria:
- `go test ./...` runs (even if mostly empty)
- `agentsh --help` works (CLI scaffolding)

### M1 — Sessions + exec + structured responses (no FUSE/network yet)

Deliverables:
- REST endpoints (minimum):
  - `POST /api/v1/sessions`
  - `GET /api/v1/sessions`
  - `GET /api/v1/sessions/{id}`
  - `DELETE /api/v1/sessions/{id}`
  - `POST /api/v1/sessions/{id}/exec`
  - `GET /api/v1/sessions/{id}/events` (SSE; initially command lifecycle only)
- Session state persistence for `cwd` and `env` across exec calls
- Command runner with timeouts + output truncation/pagination metadata (as in `docs/spec.md#10.4`)

Acceptance criteria:
- Create session → run `pwd`/`cd`/`env` builtins → state persists
- `exec` returns JSON response matching the spec’s intent (command_id, stdout/stderr, duration, events arrays present but empty for now)

### M2 — Policy engine + audit log plumbing (enforce “command_rules” now)

Deliverables:
- Policy parser for `default-policy.yml`:
  - `file_rules`, `network_rules`, `command_rules`, `resource_limits`, and decision fields
  - “first match wins” evaluation
  - glob/path/domain matching consistent with spec
- Enforce `command_rules` **before execution**:
  - deny/allow
  - `approve` handled as **shadow** until M5 (logged + returned in response metadata, but command still runs)
- Event/audit sink layer (pluggable) with **default `sqlite+jsonl`**:
  - JSONL writer with rotation
  - SQLite writer (tables + indexes) for queryable history
  - Composite sink to fan-out (same event goes to both)
- Audit/event logging for:
  - session lifecycle
  - command lifecycle
  - policy decisions (including shadow-approve)
- Query path:
  - API handler for `GET /api/v1/sessions/{id}/history` with filters
  - CLI `agentsh events query` that hits the API (not direct DB access by default)

Acceptance criteria:
- Policy denies for `rm -rf` style commands take effect
- Command-rule `approve` decisions are visible in response and audit logs but do not block

### P1 — Basic observability (metrics)

Deliverables:
- Prometheus text-format endpoint (configurable via `metrics.enabled`/`metrics.path`)
- Minimal gauges/counters:
  - `agentsh_up`
  - `agentsh_sessions_active`
  - `agentsh_events_total` + `agentsh_events_by_type_total`

### M3 — FUSE I/O interception (enforce file allow/deny; shadow-approve)

Deliverables:
- Per-session FUSE mount for `/workspace` (real workspace path mapped underneath)
- Intercept and emit events for operations in `docs/spec.md#7.2`
- Policy enforcement for file ops:
  - `allow` → pass through
  - `deny` → return error + emit denied event
  - `approve` → allow + emit shadow-approve metadata
- Event batching knobs aligned with `config.yml` sandbox.fuse settings
- Correct symlink handling to prevent path escapes (spec calls this out as a threat)

Acceptance criteria:
- Reads/writes in workspace generate file events correlated to `command_id`
- Access to denied paths is blocked (when accessed via mounted workspace view)
- `approve` file rules generate “requires approval (shadow)” markers in events

### M4 — Network interception (enforce network allow/deny; shadow-approve)

Deliverables:
- Per-session network namespace wiring + iptables redirect
- DNS interceptor emitting query events + policy checks
- Transparent TCP proxy capturing connect + byte counts
- Policy enforcement:
  - deny private CIDRs and metadata service CIDRs per `default-policy.yml`
  - allow known registries/hosts
  - `approve` unknown 443 as shadow until M5

Acceptance criteria:
- DNS + connect events appear for commands making outbound connections
- Denied CIDRs are blocked
- Unknown HTTPS destinations are labeled “shadow-approve required” but still allowed

### M5 — Approvals (upgrade shadow to enforced)

Deliverables:
- Local TTY approval flow first (hard separation from agent stdin) per `docs/approval-auth.md#4`
- Pluggable notification/remote gateway (webhook) later
- Upgrade `approve` from “allow + shadow” → “block pending approval” + signed token binding

Acceptance criteria:
- File delete operations requiring approval block and surface a pending approval
- Approve/deny unblocks with a verifiable audit record

## Testing strategy (aligned with `docs/project-structure.md`)

- Unit tests: policy matching, config validation, response shaping, truncation/pagination
- Integration tests (Linux, privileged): FUSE behavior, namespace/network proxy behavior, end-to-end session lifecycle
- E2E: create session → exec → verify events emitted and correlated

## Open questions (to resolve before coding)

1. **Response/event compatibility:** resolved by extending the event schema (`types.PolicyInfo`) with `effective_decision` and `approval` metadata, rather than adding a parallel structure.
2. **Config naming/location:** should we standardize to `configs/` now (and update Dockerfile/compose/docs), or keep current names and reconcile later?
3. **gRPC timing:** implement gRPC in parallel with REST (slower) or after REST stabilizes (faster)?
4. **Local event storage default:** use `sqlite+jsonl` (decided).
