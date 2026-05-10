# DB Access Phase 1 — Implementation Roadmap

**Status:** Design approved 2026-05-08. Decomposes implementation of `docs/agentsh-db-access-spec.md` v0.8 (PostgreSQL) into seven sequenced plans.
**Owner:** Canyon Road
**Source spec:** [`docs/agentsh-db-access-spec.md`](../../agentsh-db-access-spec.md) v0.8 (APPROVED FOR PHASE 1 IMPLEMENTATION)

This document is the *roadmap*, not the spec. It commits to plan decomposition, package layout, dependencies, and cross-cutting build/runtime decisions. Each individual plan gets its own brainstorming pass at the time it is started, producing its own per-plan design doc and implementation plan. This avoids spec drift compounding across seven plans built over many weeks.

---

## 1. Decomposition

Seven plans, with Plan 04 split into three sub-plans during 2026-05-10 brainstorming. Plans 01–03 are pure libraries; Plan 04a introduces the first socket (no protocol semantics); Plan 04b adds handshake and TLS; Plan 04c adds the Simple Query path; Plans 05–06 are siblings on top of Plan 04c; Plan 07 closes the loop with unavoidability and integration tests.

```
[01 taxonomy/effects]──┐
                       ├─→[03 pg classifier]─┐
[02 policy evaluator]──┘                     │
                                             ├─→[04a listener]─→[04b handshake+TLS]─→[04c simple+events]─┬─→[05 extended+tx]─┐
                                                                                                         ├─→[06 cancel mapping]─┤
                                                                                                                              └─→[07 unavoidability+listener-hardening+integration]
```

Dependency notes:

- Plan 01 unblocks Plans 02 and 03.
- Plan 02 depends only on Plan 01 — it operates on `ClassifiedStatement`, which Plan 01 defines.
- Plan 03 depends on Plans 01 and 02. The §23.1 golden corpus rows include `expected_decision_under_sample_policy`, so Plan 02's evaluator and `corpus/sample-policy.yaml` must be merged before Plan 03's CI gate can be wired.
- **Plan 04 was split during brainstorming on 2026-05-10** when the unified scope became too large for a single plan. The three sub-plans are sequential: 04a (listener skeleton, no protocol), 04b (handshake + TLS + upstream auth), 04c (Simple Query + DBEvent emission). The shared design doc `2026-05-10-db-plan-04-pg-proxy-skeleton-design.md` covers all three; each sub-plan has its own implementation plan.
- Plan 04a depends on Plans 01–02 only (no classifier needed for an empty listener). Plan 04b depends on 04a. Plan 04c depends on 04b and on Plan 03 (Simple Query path needs the classifier).
- Plans 05 and 06 are siblings on top of Plan 04c. Extended Query / transaction state (Plan 05) and CancelRequest mapping (Plan 06) touch different parts of the proxy and may proceed in parallel after Plan 04c lands.
- Plan 07 depends on Plans 04c–06 — integration tests need a real proxy.

Externally visible behavior:

- Plans 01–03 ship on `main` with no behavior change (types, pure functions, CLI tool only).
- Plans 04a–04c ship behind `policies.db.unavoidability: off` (default). With flag = `off`, no listener is bound and the package is a no-op. With flag = `observe`, listeners bind from Plan 04a, complete handshakes from Plan 04b, and emit `db_statement` events from Plan 04c.
- Plan 04c introduces recognition of `db_services` config end-to-end (declared services intercept queries when flag is `observe`).
- Plan 07 ships the unavoidability bundle and makes `enforce` the recommended high-assurance default.

## 2. Package layout

Single tree under `internal/db/`. Each plan owns one sub-package; cross-package types live at the top.

```
internal/db/
├── effects/                       # plan 01: Effect, ClassifiedStatement, groups, subtypes, aliases, ordering
├── policy/                        # plan 02: RuleSet, Decision, Evaluate(); rule struct types
├── events/                        # plan 01 (skeleton) + plan 04 (emission): DBEvent, redaction levels
├── service/                       # plan 01 (config schema) + plan 07 (bundle generator)
├── classify/
│   └── postgres/
│       ├── parser.go              # plan 03: Parser interface
│       ├── libpgquery.go          # plan 03: //go:build linux && cgo
│       ├── fallback.go            # plan 03: //go:build !linux || !cgo
│       └── corpus/                # plan 03: golden fixtures (yaml per row)
├── proxy/
│   └── postgres/                  # plans 04–06: //go:build linux
│       └── statemachine/          # plan 05: Extended Query / tx state machine
└── listener/                      # plan 07: //go:build linux; SO_PEERCRED, SessionID-keyed identity
cmd/
└── dbclassify-pg/                 # plan 03: CLI; reads SQL on stdin, prints classification
```

Build constraints:

- `effects`, `policy`, `events`, `service` build on every platform — no CGO, no Linux-only syscalls.
- `classify/postgres` builds on every platform via the `Parser` interface split. Consumers see only the interface; the build tags hide which backend is selected.
- `proxy/postgres` and `listener` are Linux-only. Non-Linux gets a stub returning `errors.ErrUnsupported`. The CLAUDE.md `GOOS=windows go build ./...` requirement is preserved.

Boundary calls:

- `internal/proxy/` (HTTP/MCP) and `internal/db/proxy/postgres/` are intentionally separate. Phase 1 does **not** introduce a shared proxy abstraction; that is a Phase 2+ concern when MySQL lands and shared patterns become visible.
- `internal/policy/` is unchanged. The DB rule schema lives in `internal/db/policy/`; `internal/policy/load.go` gains a small registration hook in Plan 02 so YAML files containing `database_rules` / `database_connection_rules` parse and validate without error even before the proxy exists.
- The unavoidability bundle generator (Plan 07) emits standard supervisor inputs (`dest` rules, network rules, file rules over Unix sockets). It does not bypass or reach into the supervisor; it produces config the supervisor already understands.

## 3. Per-plan scope

Plan files land at `docs/superpowers/plans/2026-MM-DD-db-plan-NN-<slug>.md`. The `plan-NN-` prefix matches the existing `external-secrets` decomposition convention so ordering reads off `ls`.

### Plan 01 — `db-plan-01-taxonomy-effects.md`

Spec-§: 5, 6, 8 (skeleton), 9.1; §23.4 steps 1–2.

Deliverables:

- `internal/db/effects/`: risk-tier enum (`safe`, `low`, `medium`, `high`, `critical`), group enum (`read`, `write`, `modify`, `delete`, `bulk_load`, `bulk_export`, `unsafe_io`, `schema_create`, `schema_alter`, `schema_destroy`, `privilege`, `procedural`, `unknown`), subtypes (§5.1), alias table (§5.4 with R23 CREATE-not-INSERT callout), `Effect` and `ClassifiedStatement` structs, canonical effect-ordering function (§5.2 with R5 tie-break order: `unknown > unsafe_io > schema_destroy > bulk_export > privilege` for critical tier).
- `internal/db/service/`: `db_services` config schema parsing only (no bundle generation yet).
- `internal/db/events/`: `DBEvent` struct skeleton; redaction-level enum (§10.3 with R4 enum `none | parameters_redacted | full`); `external_endpoint` value type (§5.2 R8 with `kind`, `host`, `port`).

Tests: exhaustive table-driven tests for ordering, alias resolution, subtype assignment.

External behavior: none.

### Plan 02 — `db-plan-02-policy-evaluator.md`

Spec-§: 9, 10; §23.3, §23.4 step 3.

Deliverables:

- `internal/db/policy/`: `StatementRule`, `ConnectionRule`, `RuleSet` types; glob compilation; `Evaluate(ClassifiedStatement, RuleSet) → Decision`.
- §10.2 implementation: collect-all coverage; any-deny-wins; most-restrictive verb decides; R14 order-independence; R15 approve+audit overlap (`decision.contributing_audit_rules` populated, but verb stays `approve`); R16 multi-glob coverage per-object; `match_object_resolution` per-effect.
- §10.3 statement-text redaction tier (default `parameters_redacted`).
- Config-load validation per §9.4 with R13 audit-on-dangerous warning (silenced by `acknowledge_audit_on_dangerous: true`).
- Registration hook in `internal/policy/load.go` so policy YAML files containing `database_rules` parse without error.
- `corpus/sample-policy.yaml` — single source of truth for Plan 03's golden corpus `expected_decision_under_sample_policy` column.

Tests: §23.3 categories — strict object coverage (allow, audit, approve), implicit deny on uncovered objects, audit-as-coverage, approve does not extend coverage, deny precedence, `match_object_resolution` per-effect, multi-effect mixed decisions, risk-tier-first primary effect ordering.

External behavior: none. Policy YAML referencing `database_rules` no longer fails to load.

### Plan 03 — `db-plan-03-pg-classifier.md`

Spec-§: 7, 20, Appendix B; §23.1, §23.4 step 4.

Deliverables:

- `internal/db/classify/postgres/parser.go`: `Parser` interface — single public surface.
- `libpgquery.go` (`//go:build linux && cgo`): `pganalyze/pg_query_go` bindings.
- `fallback.go` (`//go:build !linux || !cgo`): pure-Go parser (CockroachDB parser fork). Documented divergence policy: when the fallback cannot produce an AST, classify as `unknown` rather than guess.
- AST→effect mapping per §7.3 + Appendix B (Postgres `unsafe_io` and `bulk_export` reference table).
- Multi-statement composition (§5.3), unmapped-form behavior (§7.7), classifier-failure semantics (§7.8).
- `corpus/`: golden fixtures, one `.yaml` per row, schema `(wire_bytes_in, expected_classification, expected_decision_under_sample_policy)`. CI fails on mismatch.
- `parser_backend` field surfaced in `ClassifiedStatement` and propagated to `DBEvent`.
- `cmd/dbclassify-pg`: CLI tool reading SQL on stdin, printing classification + decision under the sample policy. Useful for spec authors and corpus extension.

Tests: corpus-driven; backend cross-validation tests where libpg_query and fallback both succeed and must agree on group/risk-tier.

External behavior: new CLI binary; no runtime change.

### Plan 04 — split into 04a / 04b / 04c during 2026-05-10 brainstorming

The unified Plan 04 was split into three sub-plans during brainstorming when the combined scope (framing + handshake + TLS + simple-query + listener auth + events) became too large for a single plan. The shared design doc `2026-05-10-db-plan-04-pg-proxy-skeleton-design.md` covers all three sub-plans; each has its own implementation plan file. Spec-section coverage and roadmap §23.4 step coverage are unchanged in aggregate.

#### Plan 04a — `db-plan-04a-listener-skeleton.md`

Spec-§: 11.3 (listener part), 12.5 (UID-only listener auth subset); §23.4 step 5 (skeleton work).

Deliverables:

- `internal/db/service/flag.go`: `Unavoidability` enum (`off | observe | enforce`); `internal/policy/load.go` parses `policies.db.unavoidability`.
- `internal/db/proxy/postgres/` package skeleton (`//go:build linux`); non-Linux stub returning `errors.ErrUnsupported`.
- `Server` lifecycle: `New` / `Start` / `Shutdown`; binds Unix-socket listeners per declared `db_service`, accept loop, graceful drain, listener cleanup. Sentinel-server short-circuit when flag = `off`.
- SO_PEERCRED + UID-equality listener auth on Linux; emits `db_listener_auth_fail` event on mismatch and silently closes.
- `internal/db/events/sink.go`: `Sink` interface, `NopSink`, in-memory `SyncSink` test fake.
- `internal/db/policy/validate.go` extension: reject connection rules under `tls_mode: passthrough` that match passthrough-invisible fields (`db_user`, `database`, `application_name`).
- `internal/api` wiring: instantiate `Server` at startup when flag != `off` and `db_services` non-empty.

Tests: bind/unbind, peercred mismatch, peercred match, shutdown drains in-flight, sentinel server is no-op, validate.go rejects passthrough-invisible field rules.

External behavior under flag = `observe`: declared `db_service` listener exists; connections are accepted from the right uid and immediately closed (no protocol code yet).

#### Plan 04b — `db-plan-04b-handshake-tls.md`

Spec-§: 7.1 (framing), 11.1 (startup-packet dispatch), 11.3 (handshake parts), 13 (TLS modes); §23.4 step 5 (handshake/TLS work) + step 7 (degraded-visibility events).

Deliverables:

- pgproto3 dependency (`github.com/jackc/pgx/v5/pgproto3`) and per-connection framing wrappers.
- `internal/db/tlsleaf/`: lazy self-signed CA (load-or-create under StateDir) + per-hostname leaf issuer with in-process LRU cache.
- Startup-packet dispatch: `SSLRequest`, `GSSENCRequest`, `CancelRequest`, `StartupMessage`.
- Three TLS modes: `terminate_reissue`, `terminate_plaintext_upstream` (with config-load loopback/RFC1918 check), `passthrough` (with best-effort SNI extraction and `degraded_visibility_warning` at first connect).
- Replication detection → default-deny; opt-in path enters byte-passthrough and emits `degraded_visibility_warning`.
- `connect`-kind connection-rule evaluation via Plan 02's existing `policy.EvaluateConnection`. `cancel`-kind eval too; CancelRequest forwards un-mapped (Plan 06 owns mapping).
- Upstream TCP connect + auth-byte forwarding; SCRAM-SHA-256-PLUS detection at upstream auth → fail-closed with `db_handshake_fail` event.

Tests: per-mode TLS round-trip with fake upstream, SCRAM fail-closed, replication default-deny, cancel un-mapped forward, degraded_visibility events.

External behavior under flag = `observe`: clients can complete a handshake and reach `ReadyForQuery` through the proxy. The proxy then drops the connection because no statement path exists yet.

#### Plan 04c — `db-plan-04c-simple-query-events.md`

Spec-§: 8 (DBEvent), 11.2 (architecture diagram for simple-query parts), 14.1 / 14.4 (Simple Query semantics, pre-forward); §23.4 step 5 (statement path) + step 7 (DBEvent emission).

Deliverables:

- RFQ status-byte tracker per connection (one byte; updated on observed `ReadyForQuery` from upstream).
- `'Q'` frame classify (Plan 03's `Parser`) + evaluate (Plan 02's `Evaluate`) per-statement; multi-statement parse-all-before-forward.
- Deny synthesis: `ErrorResponse` + `ReadyForQuery('I')` locally when out-of-tx; in-tx terminate (close upstream + client) when `lastUpstreamRFQ ∈ {T, E}`.
- `approve` → `deny + APPROVE_NOT_YET_SUPPORTED` runtime stub + config-load warning when any rule has `decision: approve`.
- Frame budget cap (`MaxQueryBytes`, default 1 MiB) → synthetic `54000` + close.
- Eventbuilder: `ClassifiedStatement` + `Decision` → `DBEvent` with redaction tiers (`full` / `parameters_redacted` / `none`); `statement_digest` = SHA-256 of the normalized form.
- Spine integration test: real `jackc/pgx/v5` client → real `Server` (terminate_reissue) → fake upstream goroutine; assert query result reaches client + one `db_statement` event in `SyncSink`.

Tests: classify+evaluate+forward (allow/audit), deny synth out-of-tx, in-tx terminate, multi-statement deny semantics, approve→deny stub, redaction tiers, statement_digest stability across tiers, spine round-trip.

External behavior under flag = `observe`: declared services intercept `SELECT 1` (allow) and a denied `DELETE` (deny synth); operators see `db_statement` events; `enforce` not yet recommended (unavoidability bundle is Plan 07).

### Plan 05 — `db-plan-05-pg-extended-tx.md`

Spec-§: 7.4, 7.5, 7.6, 14; §23.4 steps 6+9.

Deliverables:

- `internal/db/proxy/postgres/statemachine/`: Extended Query state machine including `upstream_dirty_since_sync` (§14.2 with R7 per-Sync-window scope, R17 in-tx Sync guard, R18 pre-deny upstream response forwarding).
- Parse / Bind / Describe / Execute / Sync handling. Classifier sees concrete bound parameters once Bind completes.
- FunctionCall sub-protocol (§7.5) and optional function-call escalation (§7.6).
- SQL-level prepared statements (§7.4) including DEALLOCATE coverage (§9.2 R1 — `discard_plans`, `discard_all`, `discard_temp`, `discard_sequences` covered by `app-allow-safe-session-settings`).
- Transaction state tracking and `deny_mode_in_tx` flows (§14.3, §14.4).
- Approval timeouts inside transactions (§14.5 with R3 default 60s).
- COPY data-frame handling for the duration of `bulk_load` / `bulk_export` operations.

Tests: state-machine table tests; Extended Query happy/sad paths; in-tx deny modes (rollback, idle, error).

External behavior: Extended Query and transactions now correctly enforced.

### Plan 06 — `db-plan-06-cancel-mapping.md`

Spec-§: 15; §23.4 step 8.

Deliverables:

- `BackendKeyData` translation and proxy-wide mapping table (§15.1, §15.3 R21).
- Cancellation flow (§15.2 with R19 sequencing: mapping lookup → connection-rule eval → forward/deny).
- Mapping lifecycle (§15.3 with R2 eviction rule: live mappings never evicted; new connection setup fails with `BACKEND_KEY_TABLE_FULL` if cap is hit and no entry has been past `cancel_grace_window` since disconnect).
- R20 mapping-commit ordering: mapping committed before forwarding `BackendKeyData(syn_pid, syn_secret)` to client.
- §15.5 cancel governance via connection rules; config-load rejection of `decision: approve` on `match_kind: cancel` (R19).

Tests: race tests on commit ordering; eviction/full-table tests; cancel via mapping vs. direct egress (Plan 07 enforces direct-egress block).

External behavior: cancel requests correctly correlated through the proxy.

### Plan 07 — `db-plan-07-unavoidability-integration.md`

Spec-§: 11.1 deploy, 12, 17; §23.4 steps 10+11.

Deliverables:

- `internal/db/listener/` (`//go:build linux`): SO_PEERCRED-based listener authentication (§12.5).
- SessionID-keyed proxy identity exemption (§12.4 R10) using AgentSH's existing ptrace-attach primitive.
- Bypass-attempt event emission (§12.6) with R11 dedup per `(session_id, process_identity, destination_tuple)` within a 60s window.
- Bypass-tool detection bundle (§12.7) covering R22 enumerated tools: `chisel`, `gost`, `frpc`, raw `nc`, `--net=host` containers, custom-compiled tunnels.
- `internal/db/service/bundle.go`: unavoidability bundle generator (§12.3) emitting `dest` rules, network rules, file rules over Unix sockets — all consumed by the existing supervisor.
- Integration test suite using testcontainers: PostgreSQL (full), Aurora-PG (where a testcontainer image is available; otherwise covered by manual cloud test), Redshift (best-effort), CockroachDB. End-to-end golden flows: simple-query allow, deny pre-forward, deny in-tx with rollback, cancel via mapping, COPY bulk_export with redaction, approve with 60s timeout.
- Recommendation flip: `policies.db.unavoidability: enforce` becomes the high-assurance bundle default.

Tests: integration suite; bypass-attempt detection tests; SessionID-keyed identity tests against ptrace-attach.

External behavior: declared DB services become unavoidable for processes inside the AgentSH-governed process tree, per §1's thesis.

## 4. Cross-cutting decisions

These apply to every plan; locking them here avoids per-plan re-litigation.

**Build matrix.** `effects`, `policy`, `events`, `service` build on every platform with no tags. `classify/postgres` builds on every platform via the `Parser` interface — libpg_query on `linux && cgo`, pure-Go fallback elsewhere. `proxy/postgres` and `listener` are `//go:build linux`; non-Linux gets a stub returning `errors.ErrUnsupported`. CI runs `go test ./...` on Linux + macOS and `GOOS=windows go build ./...` on every PR.

**Parser divergence policy.** When the active parser cannot produce an AST, the classifier emits `effects: [{group: unknown}]` with `parser_backend` set to the active backend. §7.8 failure semantics apply: the evaluator's strict-coverage rule means `unknown` is implicitly denied unless an `unknown`-covering rule exists. Pure-Go fallback's documented gaps live in Plan 03's per-plan open-questions section.

**Sample policy as ground truth.** `corpus/sample-policy.yaml`, committed in Plan 02, is the single source of truth for the `expected_decision_under_sample_policy` column in Plan 03's golden corpus. Modifying the sample policy is a Plan 02 change and forces a corpus regen step in Plan 03. CI fails on drift.

**DBEvent emission point.** Events emit from the proxy (Plan 04+), never from the classifier or evaluator. Plans 01–03 produce types and pure functions only. This keeps Plans 01–03 trivially testable and avoids accidental side effects in library code.

**Feature flag.** `policies.db.unavoidability: enforce | observe | off`. Plan 04 introduces the flag with all three values available; the default remains `off`. Operators may opt up to `observe` for early-adopter visibility. Plan 07 makes `enforce` the high-assurance bundle default once integration tests pass.

**Plan-spec rhythm.** Each plan's *implementation* spec is brainstormed when the plan is about to start, not now. This roadmap commits scope and dependencies; per-plan specs commit interfaces and test plans. Plan 01's spec follows immediately after this roadmap is approved.

**Scope discipline.** Phase 2+ items (catalog-aware resolution, statement rewriting, credential broker, MySQL/Mongo/etc.) are not pre-planned here. Each phase gets its own roadmap when it begins.

## 5. Out of scope for this roadmap

- Per-plan implementation specs (these get their own brainstorming pass when started).
- Phase 2+ planning (catalog-aware redirect, credential broker, additional adapters).
- Watchtower-side control-plane work; this roadmap covers AgentSH OSS only.
- Spec changes to `docs/agentsh-db-access-spec.md` v0.8. The spec is implementation-frozen. If implementation reveals a spec defect, that triggers a redline cycle (the v0.7→v0.8 process), not an inline edit during plan execution.

## 6. Done definition

The roadmap is "done" when Plan 07's integration suite passes and `policies.db.unavoidability: enforce` is the high-assurance bundle default. At that point, Phase 1 is shipped per §2.1 of the source spec.
