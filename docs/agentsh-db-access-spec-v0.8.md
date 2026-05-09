# AgentSH Database Access Control — v0.8

**Status:** APPROVED FOR PHASE 1 IMPLEMENTATION. Supersedes v0.7.
**Implementation target:** PostgreSQL only (Phase 1 of the roadmap in §18).
**Owner:** Canyon Road
**Scope:** AgentSH OSS, Watchtower commercial control plane

---

## 0. Changelog from v0.7

v0.8 incorporates a pressure-test redline. The most consequential edit is **R14**: the rule-evaluation algorithm in §10.2 is now order-independent (collect-all, any-deny-wins). v0.7's prose contained both "first-match-wins" and "collect all" language; the spec now commits to collect-all and removes the contradiction.

The other consequential edit is **R10**: §12.4's "supervisor-issued process token" prose is replaced with a concrete SessionID-keyed mechanism grounded in AgentSH's existing ptrace-attach primitive, plus a new §12.5 covering listener authentication (a gap v0.7 did not address).

All v0.8 changes by R-number:

- **R1 §9.2 sample policy.** `discard_plans, discard_all, discard_temp, discard_sequences` added to `app-allow-safe-session-settings` so prepared-statement-using ORMs are not silently denied at `DEALLOCATE`.
- **R2 §15.3 cancel-mapping eviction.** Live mappings are never evicted. If the cap is hit and no entry has been past `cancel_grace_window` since disconnect, new connection setup fails with `BACKEND_KEY_TABLE_FULL`.
- **R3 §9.2 / §14.5 approval timeout default.** Default reduced from 5 minutes to 60 seconds. Operators with long-form approval workflows opt up explicitly per rule.
- **R4 §10.3 / §8 statement_text redaction.** `policies.db.log_statements` promoted to enum `none | parameters_redacted | full`, default `parameters_redacted`. Event-level redaction independent of approval-preview redaction.
- **R5 §5.2 critical-tier ordering.** Explicit total order on group ties: `unknown > unsafe_io > schema_destroy > bulk_export > privilege` for critical; document order is the canonical tiebreaker within each tier. The `COPY <table> TO '/path'` example becomes a clean rule application.
- **R6 §11.1 replication boundary.** Passthrough begins at StartupMessage acceptance, not at first CopyBoth.
- **R7 §14.2 `upstream_dirty_since_sync` reset wording.** Per-Sync-window scope made explicit.
- **R8 §5.2 / §6 / §8 external_endpoint structure.** Connection-string objects are now `{kind: "external_endpoint", host, port}`. Raw connection strings parsed and discarded at classification time; no embedded credentials in events.
- **R9 §13.2 SNI footnote.** SNI under passthrough is best-effort; many Postgres drivers don't set it.
- **R10 §12.4 / new §12.5 proxy identity and listener authentication.** §12.4's hand-wavy process-token language replaced with SessionID-keyed mechanism. New §12.5 covers Unix-socket listener authentication via SO_PEERCRED. Phase 1 dependency on `NetworkRule` schema work made prominent.
- **R11 §12.6 bypass-attempt rate limiting.** Dedup per `(session_id, process_identity, destination_tuple)` within a 60s window.
- **R12 §6.1 / §6.5 temp-shadow direction.** False-negative-is-unsafe semantics made explicit. `deny CREATE TEMP TABLE` promoted to default in the high-assurance bundle.
- **R13 §9.4 audit-on-dangerous warning.** Config-load emits a non-fatal warning when `decision: audit` is paired with operations of risk tier ≥ high; silenced by `acknowledge_audit_on_dangerous: true`.
- **R14 §10.2 / §10.4 rule ordering.** Algorithm is order-independent. Collect-all coverage; any-deny-wins; most-restrictive verb decides. "First-match-wins" language removed.
- **R15 §10.2 approve+audit overlap.** Final verb is `approve` (most-restrictive); audit-tag rules are recorded in `decision.contributing_audit_rules` but do not change the verb.
- **R16 §9.2 multi-glob coverage.** A rule with `objects: ["a", "b"]` covers any object whose name globs against `a` or `b`. Coverage is per-object.
- **R17 §14.2 in-tx Sync guard.** Sync sub-cases apply only when upstream is in `I` or `E` state; `T` state defers to §14.3.
- **R18 §14.2 pre-deny upstream response forwarding.** Upstream responses for messages forwarded before the deny point are forwarded to the client; only post-deny responses are suppressed.
- **R19 §15.2 / §9.4 cancel-rule sequencing.** Explicit step order: mapping lookup → connection-rule eval → forward/deny. `decision: approve` rejected at config-load on `match_kind: cancel`.
- **R20 §15.1 mapping-commit ordering.** Mapping committed before the proxy forwards `BackendKeyData(syn_pid, syn_secret)` to the client; race-free.
- **R21 §15.3 mapping-table scope.** Mapping table is proxy-wide; `cancel_mapping_max` is a global cap; per-service caps deferred.
- **R22 §12.7 bypass-tool bundle scope.** Known-missing tools enumerated (`chisel`, `gost`, `frpc`, raw `nc`, `--net=host` containers, custom-compiled tunnels). Boundary remains §12.3.
- **R23 §5.4 CREATE alias callout.** Deliberate non-expansion to `INSERT` promoted to its own callout.

Carryover from v0.7 (no changes):

- **§10.1 audit semantics callout** — `audit` is allow-with-observation.
- **§10.2 approve coverage** — approve does not cover otherwise-uncovered objects.
- **§10.2 `match_object_resolution` semantics** — matches per-effect worst-confidence tag.
- **§11.1 + §17 degraded-visibility events** — replication-passthrough and GSSENC-passthrough opt-ins.
- **§12 unavoidability claim scoping** — three explicit clauses.
- **§23 Engineering Handoff** — three required artifacts and Phase 1 implementation order.

---

## 1. Summary

This spec gives AgentSH database-aware runtime enforcement. AgentSH classifies each statement an agent issues into a list of effects, evaluates each effect against policy with strict multi-object semantics, and emits a normalized audit event tied to the agent session and process context.

The thesis:

> AgentSH makes database access agent-aware, policy-governed, and **unavoidable for processes inside the AgentSH-governed process tree, for declared DB services, assuming the AgentSH supervisor and proxy are not compromised.**

Unavoidability rests on AgentSH's existing primitives: process interception, network rules, file rules over Unix sockets, and DNS interception. §12 spells out the threat model in full.

**Spec revision:** v0.8. **Implementation target:** Phase 1 (PostgreSQL).

---

## 2. Scope

### 2.1 Phase 1 implementation scope

- PostgreSQL wire protocol v3, normal frontend/backend mode.
- Dialects: `postgres` (full), `aurora_postgres` (full), `redshift` (beta), `cockroachdb` (beta).
- TLS modes: `terminate_reissue`, `passthrough` (connection-level rules only), `terminate_plaintext_upstream`.
- Decision verbs: `allow`, `deny`, `approve`, `audit`.
- Two rule families: `database_rules` (statement-level), `database_connection_rules` (connection-level).
- Per-effect policy evaluation with strict multi-object semantics.
- CancelRequest correlation (§15).
- Startup-packet handling for SSLRequest / GSSENCRequest / CancelRequest / StartupMessage (§11.1).

### 2.2 Out of scope for Phase 1

- Replication protocol (CopyBoth, `START_REPLICATION`, walsender, logical decoding). Default-deny per §11.1.
- GSSAPI encryption (default-deny per §11.1).
- Column-level masking, row redaction, result-set DLP (Phase 7).
- Statement rewriting (`redirect`, Phase 2).
- Credential brokering (Phase 4).
- Catalog-aware metadata controls (Phase 7).
- ORM-level rules.
- MySQL, MongoDB, MSSQL, Oracle, Cassandra, Redis (Phases 3, 5, 8).
- BigQuery, Databricks, ClickHouse, Snowflake (Phase 6).

### 2.3 Roadmap

| Phase | Adds |
|-------|------|
| Phase 1 | This spec. |
| Phase 2 | Object resolution via upstream catalog. Postgres `redirect` decision (statement rewriting). |
| Phase 3 | MySQL adapter. |
| Phase 4 | Credential broker. |
| Phase 5 | MongoDB adapter. |
| Phase 6 | Snowflake / BigQuery / Databricks / ClickHouse handlers. |
| Phase 7 | Result-set DLP. Row-count caps. Catalog-aware metadata controls (subsumes Describe-leakage). |
| Phase 8 | MSSQL TDS, Cassandra CQL, Redis RESP, Oracle TNS. |
| Future | Logical/physical replication protocol support. |

---

## 3. Goals (Phase 1)

1. Classify every Postgres statement into a list of effects (group + subtype + object set + per-effect resolution tag).
2. Emit a `DBEvent` per statement, suitable for OCSF 1.8.0 mapping into Watchtower as Datastore Activity (6005).
3. Enforce policy per effect with strict multi-object semantics: `allow` requires full coverage; `deny` fires on any match.
4. Make the proxy unavoidable (§12).
5. Three explicit TLS modes; rule matchability constrained per mode.
6. Fail closed on classifier ambiguity, malformed protocol frames, channel-binding ambiguity, unmapped statement forms, prepared-statement cache misses, replication mode, and GSSENC.
7. Translate CancelRequest correctly without leaking real upstream `BackendKeyData`.

---

## 4. Non-Goals (Phase 1)

(See §2.2.)

---

## 5. Operation Taxonomy

| ID | Name | Risk Tier | Description |
|----|------|-----------|-------------|
| 1 | `read` | low | Returns rows or metadata without modifying state and without writing externally. |
| 2 | `write` | medium | Insert new rows. |
| 3 | `modify` | medium | Update existing rows in place. |
| 4 | `delete` | high | Remove rows. |
| 5 | `bulk_load` | high | Mass ingest into a table. |
| 6 | `bulk_export` | critical | Mass export of data through the client/protocol. |
| 7 | `schema_create` | high | Create tables, indexes, views, functions, etc. |
| 8 | `schema_alter` | high | Modify schema definitions in place. |
| 9 | `schema_destroy` | critical | `DROP`, `TRUNCATE`. |
| 10 | `privilege` | critical | Roles, users, grants, ACLs, server config, security labels. |
| 11 | `transaction` | low | `BEGIN`, `COMMIT`, `ROLLBACK`, `SAVEPOINT`, `RELEASE`. |
| 12 | `session` | low | `SET`, `RESET`, `DISCARD`, cancel requests. |
| 13 | `maintenance` | medium | `VACUUM`, `ANALYZE`, `REINDEX`, `CLUSTER`, `CHECKPOINT`. |
| 14 | `lock` | medium | Explicit `LOCK TABLE`. |
| 15 | `notify` | low | `LISTEN`, `NOTIFY`, `UNLISTEN`. |
| 16 | `procedural` | high | Server-side procedures, anonymous code blocks, `CALL`, `DO`, FunctionCall sub-protocol. |
| 17 | `unsafe_io` | critical | DB engine reads/writes filesystem, network, external systems, or configures external connectivity (publications, subscriptions, foreign servers, user mappings, tablespace paths). |
| 18 | `unknown` | critical | Classifier could not determine the group. Default deny. |

**Risk-tier ordering** (most to least): `critical > high > medium > low`. Used by §5.2 to select the primary effect.

### 5.1 Subtypes

(Same as v0.5 §5.1, except subtypes for newly-reclassified DDL move with their groups.)

| Group | Subtypes |
|-------|----------|
| `session` | `set`, `set_search_path`, `set_role`, `set_session_authorization`, `set_local`, `reset`, `reset_all`, `discard`, `discard_all`, `discard_temp`, `discard_plans`, `discard_sequences`, `cancel_request` |
| `schema_create` | `create_table`, `create_index`, `create_view`, `create_schema`, `create_function`, `create_materialized_view`, `create_extension`, `create_database`, `create_publication` |
| `schema_alter` | `alter_publication` (other ALTERs untyped) |
| `schema_destroy` | `drop_table`, `drop_database`, `drop_schema`, `drop_index`, `drop_view`, `drop_function`, `drop_publication`, `truncate` |
| `privilege` | `grant`, `revoke`, `alter_role`, `create_role`, `drop_role`, `alter_system`, `security_label` |
| `bulk_load` | `copy_from_stdin`, `copy_from_s3` |
| `bulk_export` | `copy_to_stdout`, `unload_to_s3` |
| `procedural` | `function_call_protocol`, `call`, `do`, `anonymous_block` |
| `unsafe_io` | `create_subscription`, `alter_subscription`, `drop_subscription`, `create_server`, `alter_server`, `drop_server`, `create_user_mapping`, `alter_user_mapping`, `drop_user_mapping`, `create_tablespace`, `alter_tablespace`, `drop_tablespace`, `copy_to_path`, `copy_from_path`, `copy_to_program`, `copy_from_program`, `large_object_io`, `server_file_read`, `dblink_call`, `fdw_access` |

### 5.2 Per-effect classification and effect ordering

Each statement carries a list of **effects**. An effect is `{group, subtype, objects, object_resolution}`.

**Primary effect selection.** The first entry in the effects list is the primary. Ordering rule:

1. **Highest risk tier first.** If multiple effects have different risk tiers, the one with the highest tier is primary.
2. **Tie-break on tier: fixed group order.** Effects sharing the highest tier are ordered by a canonical group order:
   - Critical: `unknown > unsafe_io > schema_destroy > bulk_export > privilege`
   - High: `delete > schema_create > schema_alter > bulk_load > procedural`
   - Medium: `modify > write > maintenance > lock`
   - Low: `read > transaction > session > notify`
3. **Final tiebreak: stable AST traversal order.** Predictable, repeatable.

The fixed group order makes primary-effect selection deterministic for any pair of implementations and removes judgment calls that v0.7's "syntactic root" rule could not fully resolve.

**Examples** (effect lists shown in canonical order; first entry is primary):

| Statement | Effects |
|-----------|---------|
| `SELECT * FROM users` | `[{read, users, qualified_or_unqualified}]` |
| `INSERT INTO audit_log SELECT * FROM users` | `[{write, audit_log}, {read, users}]` |
| `WITH d AS (DELETE FROM u RETURNING *) SELECT * FROM d` | `[{delete, u}, {read, u}]` |
| `COPY (SELECT * FROM customers) TO STDOUT` | `[{bulk_export(copy_to_stdout), customers}, {read, customers}]` (bulk_export is critical, beats read) |
| `COPY (DELETE FROM u RETURNING *) TO STDOUT` | `[{bulk_export, u}, {delete, u}, {read, u}]` (critical → high → low) |
| `COPY customers TO '/tmp/dump.csv'` | `[{unsafe_io(copy_to_path), customers + /tmp/dump.csv}, {bulk_export, customers}, {read, customers}]` (unsafe_io and bulk_export both tie at critical; canonical group order `unsafe_io > bulk_export` puts unsafe_io first) |
| `CREATE TABLE t AS SELECT * FROM s` | `[{schema_create(create_table), t}, {read, s}]` |
| `CREATE SUBSCRIPTION sub CONNECTION '...' PUBLICATION pub` | `[{unsafe_io(create_subscription), sub + connection_string}, {schema_create, sub}]` (unsafe_io is critical, beats schema_create) |
| `CREATE PUBLICATION pub FOR TABLE t` | `[{schema_create(create_publication), pub + t}]` (publications don't establish outbound connectivity by themselves; subscriptions do) |
| `CREATE SERVER s FOREIGN DATA WRAPPER postgres_fdw OPTIONS (host '...', port '5432')` | `[{unsafe_io(create_server), s + host:port}, {schema_create, s}]` |
| `CREATE USER MAPPING FOR u SERVER s` | `[{unsafe_io(create_user_mapping), u + s}, {privilege, u + s}]` |
| `CREATE TABLESPACE ts LOCATION '/mnt/ssd'` | `[{unsafe_io(create_tablespace), ts + /mnt/ssd}, {schema_create, ts}]` |
| `EXPLAIN ANALYZE INSERT INTO t SELECT * FROM s` | matches inner: `[{write, t}, {read, s}]` |

The risk-tier-first rule has a useful consequence: a SOC analyst filtering events by `operation_group` sees the actually-most-dangerous classification, not the syntactic verb. `CREATE SUBSCRIPTION` shows up as `unsafe_io`, not `schema_create`, which is correct: it establishes outbound connectivity from the database engine.

`schema_create` remains primary for forms like `CREATE TABLE`, `CREATE INDEX`, `CREATE PUBLICATION`, etc. — anything where the highest-tier effect *is* the schema operation itself.

### 5.3 Multi-statement composition

Per-statement classification. Batch decision is most-restrictive across statements (§14).

### 5.4 Aliases

Operators may write rules using aliases that expand to one or more groups at policy load time. Events always emit canonical group names.

| Alias | Expands to |
|-------|------------|
| `READ` | `read` |
| `INSERT` | `write` |
| `UPDATE` | `modify` |
| `DELETE`, `REMOVE` | `delete` |
| `CREATE` | `schema_create` |
| `DROP` | `schema_destroy` |
| `ALTER` | `schema_alter` |
| `TRUNCATE` | `schema_destroy` (subtype `truncate`) |
| `EXPORT` | `bulk_export`, `unsafe_io` |
| `LOAD` | `bulk_load` |
| `MUTATE` | `write`, `modify`, `delete` |
| `SCHEMA` | `schema_create`, `schema_alter`, `schema_destroy` |
| `MAINTENANCE` | `maintenance` |
| `LOCK_TABLES` | `lock` |
| `LISTEN_NOTIFY` | `notify` |
| `DANGEROUS` | `schema_destroy`, `privilege`, `unsafe_io`, `procedural`, `bulk_export`, `lock` |
| `*` | all groups except `unknown` (which must be specified explicitly) |

`CREATE` deliberately does not expand to `write`. An operator who allows `CREATE` should not also implicitly allow `INSERT`. To allow both, write `[CREATE, INSERT]`.

> **Operator callout: alias non-expansion.** `CREATE` does not include `INSERT`; `EXPORT` does not include `READ`; `MUTATE` does not include `READ`. The aliases are deliberately conservative: a sysadmin granting DDL should not implicitly grant DML. To compose effects, list them explicitly: `operations: [CREATE, INSERT]`. Sample policies in §9.2 show this idiom. This is the most common alias misuse; flag it loudly in operator docs.

---

## 6. Object Scoping Model

Phase 1 object names are **syntactic only**. The classifier does not resolve `search_path`, expand views, inspect function bodies, or canonicalize aliases.

### 6.1 Resolution tags (per-effect)

Each effect carries its own `object_resolution`:

| Tag | Meaning |
|-----|---------|
| `qualified_syntactic` | All object references in this effect are schema-qualified. |
| `unqualified_syntactic` | One or more references in this effect are unqualified; their schema field is `null`. |
| `ambiguous_after_search_path` | An unqualified reference appears after `SET search_path` in the session. |
| `maybe_temp_shadowed` | Unqualified reference may be shadowed by a temp table created earlier in the session. Best-effort. |
| `unresolved` | Could not extract object identity for this effect. |

**Failure-direction note for `maybe_temp_shadowed`.** Temp-table tracking is best-effort and the failure direction matters for security. **False negatives are unsafe**: a real temp shadow tagged `qualified_syntactic` lets an allow rule on the production table apply to a temp table the agent created. False positives (tagging `maybe_temp_shadowed` when no real shadowing exists) are noisy but safe — they cause `match_object_resolution` rules to mismatch, falling back to deny. Operators should not rely on `maybe_temp_shadowed` accuracy as a security control; the durable mitigation is the `deny CREATE TEMP TABLE` pattern shipped in the high-assurance bundle (§6.5).

A single statement may have different tags per effect:

```sql
INSERT INTO public.audit_log SELECT * FROM users;
```

After `SET search_path = app, public`:

```json
"effects": [
  {
    "group": "write",
    "objects": [{"kind": "table", "schema": "public", "name": "audit_log"}],
    "object_resolution": "qualified_syntactic"
  },
  {
    "group": "read",
    "objects": [{"kind": "table", "schema": null, "name": "users"}],
    "object_resolution": "ambiguous_after_search_path"
  }
]
```

### 6.2 Top-level resolution summary

The top-level `object_resolution` field is the worst (least-confident) tag across all effects, per this ordering (best to worst):

```
qualified_syntactic > unqualified_syntactic > ambiguous_after_search_path > maybe_temp_shadowed > unresolved
```

Rules with `match_object_resolution:` match against either the per-effect tag (preferred) or the top-level summary; field semantics are spelled out in §9.2.

### 6.3 GUC name normalization

For `session` operations, the "object" is the GUC being set/reset. GUC names are case-folded to Postgres-canonical lowercase before matching.

### 6.4 Non-relational object structure

Effects on objects that are not relations (tables, views, functions) carry kind-specific structured fields. For Phase 1:

- `{kind: "table" | "view" | "function" | "schema" | ..., schema, name}` — relations and namespace-resident objects.
- `{kind: "external_endpoint", host, port}` — destinations referenced by `CREATE SUBSCRIPTION CONNECTION`, `CREATE SERVER OPTIONS (host, port)`, foreign-data-wrapper user mappings. Connection strings are parsed at classification time; the proxy extracts `host` and `port`, **discards** any embedded credentials, dbname, application_name, or other fields, and never persists the raw string into the event payload.
- `{kind: "filesystem_path", path}` — for `COPY ... TO/FROM '/path'`, `lo_import`, `lo_export`, `pg_read_file`, `CREATE TABLESPACE LOCATION`. Path is the literal string; no resolution.
- `{kind: "program", argv0}` — for `COPY ... TO/FROM PROGRAM '<cmd>'`. Only the leading argv element is captured; the full command is not, since it is not a stable identifier for rule matching.
- `{kind: "subscription" | "publication" | "server" | "user_mapping" | "tablespace", name}` — Postgres-cluster-level objects.

Operators write rules using glob patterns against the structured fields (`host: "*.internal"`, `port: 5432`, `path: "/tmp/*"`). Rule schemas in §9.2 reference these fields by name.

### 6.5 Recommended deployment patterns

For object-scoped rules in Phase 1:

- Combine object rules with a deny on `session` subtype `set_search_path`.
- **High-assurance bundle ships with a default `deny CREATE TEMP TABLE` rule** to neutralize `maybe_temp_shadowed` false-negative risk (§6.1). The base bundle does not, since temp tables are common in dev workflows; high-assurance is for production agents.
- Or write object rules that accept any schema (`schemas: ["*"]`) and rely on the verb-level guarantee.
- Or wait for Phase 2, which adds upstream-catalog-backed canonical resolution.

---

## 7. Per-Protocol Classification (PostgreSQL v3)

### 7.1 Wire framing

`pgproto3` for parsing Simple Query (`Q`), Extended Query (`Parse`/`Bind`/`Describe`/`Execute`/`Sync`/`Flush`/`Close`), authentication frames, FunctionCall (`F`), and CancelRequest. CopyData/CopyDone frames tracked for the duration of `COPY` operations.

### 7.2 SQL parsing

`pg_query_go`. Per-effect extraction is the AST walk's primary output; effects are emitted in a deterministic traversal order then re-sorted into canonical order per §5.2.

### 7.3 Mapping

Authoritative table. Most-specific row wins. **Any SQL form not appearing in this table classifies as `unknown` and defaults to deny.**

Effect-list shorthand: `[primary, secondary, secondary, ...]` where each entry is `{group(subtype):object_set}`. When a statement has only one effect, it's shown as a single tuple.

| SQL form | Effects |
|----------|---------|
| `ALTER SYSTEM ...` | `[{privilege(alter_system)}]` |
| `ALTER ROLE`, `ALTER USER` | `[{privilege(alter_role)}]` |
| `ALTER PUBLICATION` | `[{schema_alter(alter_publication)}]` |
| `ALTER SUBSCRIPTION` | `[{unsafe_io(alter_subscription)}, {schema_alter}]` |
| `ALTER SERVER` (foreign) | `[{unsafe_io(alter_server)}, {schema_alter}]` |
| `ALTER USER MAPPING` | `[{unsafe_io(alter_user_mapping)}, {privilege}]` |
| `ALTER TABLESPACE ... SET LOCATION` (Postgres restricts; included for completeness) | `[{unsafe_io(alter_tablespace)}, {schema_alter}]` |
| `ALTER TABLESPACE ... RENAME / OWNER TO` | `[{schema_alter(alter_tablespace)}]` |
| `ALTER ...` (other) | `[{schema_alter}]` |
| `RENAME ...`, `COMMENT ON` | `[{schema_alter}]` |
| `SECURITY LABEL ...` | `[{privilege(security_label)}]` |
| `CREATE ROLE`, `CREATE USER` | `[{privilege(create_role)}]` |
| `CREATE DATABASE` | `[{schema_create(create_database)}]` |
| `CREATE TABLESPACE ts LOCATION '/path'` | `[{unsafe_io(create_tablespace)}, {schema_create}]` |
| `CREATE PUBLICATION` | `[{schema_create(create_publication)}]` |
| `CREATE SUBSCRIPTION` | `[{unsafe_io(create_subscription)}, {schema_create}]` |
| `CREATE SERVER` (foreign) | `[{unsafe_io(create_server)}, {schema_create}]` |
| `CREATE USER MAPPING` | `[{unsafe_io(create_user_mapping)}, {privilege}]` |
| `CREATE TABLE AS SELECT`, `SELECT INTO` | `[{schema_create(create_table)}, {read}]` |
| `CREATE TABLE` | `[{schema_create(create_table)}]` |
| `CREATE INDEX` | `[{schema_create(create_index)}]` |
| `CREATE VIEW`, `CREATE MATERIALIZED VIEW` | `[{schema_create(create_view)}]` (materialized: `create_materialized_view`) |
| `CREATE SCHEMA` | `[{schema_create(create_schema)}]` |
| `CREATE FUNCTION` | `[{schema_create(create_function)}]` |
| `CREATE EXTENSION` | `[{schema_create(create_extension)}]` |
| `CREATE TYPE/DOMAIN/AGGREGATE/SEQUENCE/TRIGGER` | `[{schema_create}]` |
| `DROP ROLE`, `DROP USER` | `[{privilege(drop_role)}]` |
| `DROP DATABASE` | `[{schema_destroy(drop_database)}]` |
| `DROP TABLESPACE` | `[{schema_destroy}]` |
| `DROP PUBLICATION` | `[{schema_destroy(drop_publication)}]` |
| `DROP SUBSCRIPTION` | `[{unsafe_io(drop_subscription)}, {schema_destroy}]` |
| `DROP SERVER` | `[{unsafe_io(drop_server)}, {schema_destroy}]` |
| `DROP USER MAPPING` | `[{unsafe_io(drop_user_mapping)}, {privilege}]` |
| `DROP TABLE` | `[{schema_destroy(drop_table)}]` |
| `DROP SCHEMA` | `[{schema_destroy(drop_schema)}]` |
| `DROP INDEX/VIEW/FUNCTION/TYPE/DOMAIN/AGGREGATE/SEQUENCE/TRIGGER/EXTENSION` | `[{schema_destroy}]` |
| `TRUNCATE` | `[{schema_destroy(truncate)}]` |
| `GRANT`, `REVOKE` | `[{privilege(grant_or_revoke)}]` |
| `BEGIN`, ..., `ROLLBACK TO SAVEPOINT` | `[{transaction}]` |
| `SET search_path = ...` | `[{session(set_search_path)}]` |
| `SET ROLE role` (and `SET ROLE NONE`) | `[{session(set_role)}]` |
| `SET SESSION AUTHORIZATION ...` | `[{session(set_session_authorization)}]` |
| `SET LOCAL ...` | `[{session(set_local)}]` |
| `SET ...` (other) | `[{session(set)}]` |
| `RESET ALL` | `[{session(reset_all)}]` |
| `RESET ...` | `[{session(reset)}]` |
| `DISCARD ALL` | `[{session(discard_all)}]` |
| `DISCARD TEMP` | `[{session(discard_temp)}]` |
| `DISCARD PLANS` | `[{session(discard_plans)}]` |
| `DISCARD SEQUENCES` | `[{session(discard_sequences)}]` |
| `VACUUM`, `ANALYZE`, `REINDEX`, `CLUSTER`, `CHECKPOINT` | `[{maintenance}]` |
| `LOCK TABLE` | `[{lock}]` |
| `LISTEN`, `NOTIFY`, `UNLISTEN` | `[{notify}]` |
| `CALL` | `[{procedural(call)}]` |
| `DO`, anonymous `$$ ... $$` block | `[{procedural(do_or_anon)}]` |
| `EXPLAIN ANALYZE <inner>` | matches inner |
| `EXPLAIN <inner>` (without `ANALYZE`) | `[{read}]` |
| `SHOW`, `WITH ... SELECT` (no data-modifying CTE, no `INTO`) | `[{read}]` |
| `SELECT` | `[{read}]` |
| `WITH ... INSERT` | `[{write}, {read}]` |
| `INSERT`, `INSERT ... ON CONFLICT` | `[{write}]` |
| `WITH ... UPDATE`, `MERGE`, `UPDATE` | `[{modify}]` |
| `WITH ... DELETE RETURNING ...` | `[{delete}, {read}]` |
| `DELETE` | `[{delete}]` |
| `COPY (<query containing DELETE/UPDATE/INSERT>) TO STDOUT` | `[{bulk_export(copy_to_stdout)}, {<inner verb group>}, {read}]` |
| `COPY (<read-only query>) TO STDOUT` | `[{bulk_export(copy_to_stdout)}, {read}]` |
| `COPY <table> TO PROGRAM '<cmd>'` | `[{unsafe_io(copy_to_program)}, {bulk_export}]` |
| `COPY <table> FROM PROGRAM '<cmd>'` | `[{unsafe_io(copy_from_program)}, {bulk_load}]` |
| `COPY <table> TO '<path>'` | `[{unsafe_io(copy_to_path)}, {bulk_export}]` |
| `COPY <table> FROM '<path>'` | `[{unsafe_io(copy_from_path)}, {bulk_load}]` |
| `COPY <table> TO STDOUT` | `[{bulk_export(copy_to_stdout)}, {read}]` |
| `COPY <table> FROM STDIN` | `[{bulk_load(copy_from_stdin)}]` |
| `lo_import('<path>')`, `lo_export(oid, '<path>')` | `[{unsafe_io(large_object_io)}]` |
| `pg_read_file`, `pg_read_binary_file`, `pg_ls_dir`, `pg_ls_logdir`, `pg_ls_waldir`, `pg_stat_file` | `[{unsafe_io(server_file_read)}]` |
| `dblink`, `dblink_exec`, `dblink_open`, `dblink_send_query` | `[{unsafe_io(dblink_call)}]` |
| Foreign-table reference via `postgres_fdw`, `file_fdw` | `[{<verb>}, {unsafe_io(fdw_access)}]` |
| `PREPARE name AS <inner>` | matches inner |
| `EXECUTE name(...)` | matches cached classification |
| `DEALLOCATE name`, `DEALLOCATE ALL` | `[{session(discard_plans)}]` |
| Redshift `UNLOAD <q> TO 's3://...'` | `[{bulk_export(unload_to_s3)}, {unsafe_io}, {read}]` |
| Redshift `COPY <t> FROM 's3://...'` | `[{bulk_load(copy_from_s3)}]` |
| Anything else (parse failure or unmatched form) | `[{unknown}]` |

Effects shown in the table are pre-canonical-ordering. The classifier emits effects in canonical order per §5.2.

### 7.4 SQL-level prepared statements

PostgreSQL supports SQL-level `PREPARE` / `EXECUTE` / `DEALLOCATE` independently of the wire-protocol Extended Query path. Both must be handled.

**At `PREPARE name AS <inner>`:**

1. Classify `<inner>`. PREPARE's effect set is the inner statement's effect set.
2. Evaluate against policy (§10). If denied: synthesize deny `ErrorResponse` and do not forward upstream. Cache not populated.
3. If allowed / audit / approved: forward upstream and cache classification under (connection, prepared statement name).

**At `EXECUTE name(args)`:**

1. Look up cached classification. Cache miss → `unknown`, deny with `result.error_code: SQL_PREPARED_CACHE_MISS`.
2. Re-evaluate against policy (handles hot reload).
3. On allow: forward `EXECUTE`. On deny: synthesize error.

**At `DEALLOCATE name` / `DEALLOCATE ALL`:** evict cache entry/entries. Forward upstream.

**At `DISCARD ALL` / `DISCARD PLANS`:** clear per-connection SQL prepared cache. Forward upstream.

**Unnamed prepared statements:** A `PREPARE` with empty name (rare in SQL form; common in wire form) is cached under the empty key. Subsequent `EXECUTE ''` resolves to it. Empty entry is overwritten on the next unnamed PREPARE, matching server behavior.

Cache size: 4096 LRU per connection. Same cap as the wire-protocol Extended Query cache; the two caches are separate keyspaces.

### 7.5 FunctionCall sub-protocol and Describe leakage

**FunctionCall default behavior.** The proxy synthesizes `ErrorResponse(SQLSTATE 42501, message="FunctionCall sub-protocol denied by AgentSH policy")` followed by `ReadyForQuery(I)`. The FunctionCall message is not forwarded upstream. Event: `operation_group: procedural`, `operation_subtype: function_call_protocol`, `decision: deny`, `result.error_code: FUNCTION_CALL_PROTOCOL_DENIED`.

Per-service opt-in via `allow_function_call_protocol: true`. When enabled, classified as `procedural` subtype `function_call_protocol`; OID resolution is Phase 2.

**Describe leakage.** For allowed prepared statements, Postgres `Describe` returns column-level metadata of the result set. Phase 1 treats this metadata as part of the allowed statement surface — once a `read` is allowed, the proxy does not separately gate the metadata response.

Phase 1 mitigation for operators who need to hide column metadata: **don't grant the agent role access to those relations**. If the agent can `SELECT` from a table, it can prepare statements against it and observe column types via `Describe`. Withholding row-level read access is the only durable Phase 1 defense; column-level metadata filtering and view-based projection enforcement are deferred to Phase 7's catalog-aware policy.

### 7.6 Optional: function-call escalation

`SELECT volatile_function()` is syntactically `read` but may have arbitrary side effects. Phase 1 ships an opt-in mode controlled by `policies.db.escalate_unknown_functions`:

- `false` (default): `SELECT f()` is `read` regardless of `f`.
- `true`: `SELECT f()` is `procedural` unless `f` is in `policies.db.safe_function_allowlist`.

Default is off because the noise level on real workloads is unworkable (every ORM uses `nextval`, `now()`, `to_tsvector`, etc.). Operators who turn it on are expected to maintain the allowlist. The allowlist seeds with a built-in set of immutable Postgres builtins.

Operators who want a hard wall should pair `escalate_unknown_functions: true` with `decision: approve` rather than `deny` to keep the agent unblocked while a human reviews unfamiliar function calls.

### 7.7 Dialect handling and unmapped-form behavior

The classifier dispatches by `db_services.<name>.dialect`:

| Dialect | Behavior |
|---------|----------|
| `postgres` | Full `pg_query_go`. Parse failure → `unknown`. SQL form not in §7.3 → `unknown`. |
| `aurora_postgres` | Identical to `postgres`. |
| `redshift` | `pg_query_go` first; on parse failure, first-keyword classifier with explicit handling for `UNLOAD`, Redshift `COPY`, IAM/credentials clauses, S3 paths. **Beta.** |
| `cockroachdb` | `pg_query_go` first; parse failure → `unknown` (default deny). **Beta.** |

Wire compatibility is not grammar compatibility. The `redshift` and `cockroachdb` classifiers are explicitly best-effort; operators should test with their workloads and consider tighter `decision: deny` defaults.

**Unmapped-form rule.** A parse-tree node type that is not in §7.3 classifies as `unknown`, regardless of whether it parsed cleanly. This protects against future Postgres versions adding new statement types that would otherwise silently default to a permissive primary group. New mappings are added in subsequent spec revisions; the classifier ships with a list of node types it recognizes, and any other type is `unknown`.

### 7.8 Classifier failure semantics

A classifier returns one of:

- Success: `ClassifiedStatement{effects: [...], raw_verb, ...}`.
- Parse failure / unmapped form / ambiguity: `ClassifiedStatement{effects: [{group: unknown, ...}], error: "<reason>"}`.
- Wire-protocol error (malformed wire frame, truncated message): `error` event with `result.error_code: WIRE_PROTOCOL_ERROR`, **connection terminated**.

Group `unknown` is subject to policy. The default catch-all rule denies it.

---

## 8. Normalized DBEvent

```json
{
  "event_id": "uuid-v7",
  "session_id": "...",
  "command_id": "...",
  "ts": "RFC3339Nano",

  "db_service": "appdb",
  "db_family": "postgres",
  "db_dialect": "postgres | aurora_postgres | redshift | cockroachdb",
  "db_user": "string | null",
  "application_name": "string | null",
  "client_identity": "string",

  "operation_group": "...",
  "operation_group_id": 1,
  "operation_subtype": "string | null",

  "effects": [
    {
      "group": "unsafe_io",
      "group_id": 17,
      "subtype": "create_subscription",
      "objects": [
        {"kind": "subscription", "schema": null, "name": "sub_orders"},
        {"kind": "external_endpoint", "host": "upstream.example", "port": 5432}
      ],
      "object_resolution": "qualified_syntactic"
    },
    {
      "group": "schema_create",
      "group_id": 7,
      "subtype": null,
      "objects": [
        {"kind": "subscription", "schema": null, "name": "sub_orders"}
      ],
      "object_resolution": "qualified_syntactic"
    }
  ],

  "raw_verb": "CREATE_SUBSCRIPTION",

  "object_resolution": "qualified_syntactic",

  "statement_digest": "sha256:...",
  "statement_text": "string | null",
  "statement_redaction": "none | parameters_redacted | full",

  "predicates": {"has_filter": true},

  "tls": {
    "mode": "passthrough | terminate_reissue | terminate_plaintext_upstream",
    "client_sni": "string | null",
    "upstream_cert_subject": "string | null"
  },

  "decision": {
    "verb": "allow | deny | approve | audit",
    "rule_kind": "statement | connection | cancel",
    "rule_name": "string",
    "matching_effect_index": 0,
    "matching_effect_group": "unsafe_io",
    "reason": "string"
  },

  "result": {
    "rows_returned": "int | null",
    "rows_affected": "int | null",
    "bytes_in": "int",
    "bytes_out": "int",
    "latency_ms": "int",
    "error_code": "string | null"
  },

  "tx_context": {
    "in_transaction": true,
    "tx_started_at": "RFC3339Nano | null",
    "deny_action": "none | rollback_injected | connection_terminated"
  },

  "context_digest": "sha256:..."
}
```

**Notes:**

- Top-level `operation_group` and `operation_subtype` mirror `effects[0].group` and `effects[0].subtype` (the primary).
- Top-level `object_resolution` is the worst-case across all effects (per §6.2).
- `effects[].objects` is per-effect; do not use the union for enforcement.

OCSF mapping: class **6005 Datastore Activity**. Canyon Road extension fields per v0.4, plus `canyonroad.db.effects` (array).

---

## 9. Policy Schema

### 9.1 Service definitions

```yaml
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: terminate_reissue
    deny_mode_in_tx: terminate
    allow_function_call_protocol: false

  warehouse:
    family: postgres
    dialect: redshift
    upstream: warehouse.cluster.region.redshift.amazonaws.com:5439
    tls_mode: terminate_reissue

  legacy_pg:
    family: postgres
    dialect: postgres
    upstream: legacy.internal:5432
    tls_mode: passthrough           # statement rules cannot attach to this service
```

| Service field | Required | Notes |
|---------------|----------|-------|
| `family` | yes | `postgres` (Phase 1). |
| `dialect` | yes | `postgres`, `aurora_postgres`, `redshift`, `cockroachdb`. |
| `upstream` | yes | `host:port`. |
| `tls_mode` | yes | `passthrough`, `terminate_reissue`, `terminate_plaintext_upstream`. No default. |
| `deny_mode_in_tx` | no | `terminate` (default), `rollback_then_continue`. See §14. |
| `allow_function_call_protocol` | no | Default `false`. See §7.5. |
| `allow_gss_encryption` | no | Default `false`. See §11.1. |
| `upstream_credential_ref` | Phase 4+ | Reserved for credential broker. |
| `trusted_network` | no | Required `true` for `tls_mode: terminate_plaintext_upstream` on non-loopback destinations. |

### 9.2 Statement rules (`database_rules`)

Each rule matches against an individual effect — its `group`, `subtype`, and `objects`.

**Rationale for the `app-deny-mutations` + `app-deny-dangerous` overlap in the sample:** the first rule provides a clear user-facing message tuned to the most common app-DB violations (`DELETE`, `CREATE`, etc.); the second is a backstop covering the broader risk class via the `DANGEROUS` alias. Either alone would work; both together give a clearer error to the agent on common violations and a defense-in-depth backstop for less-common dangerous operations.

```yaml
database_rules:
  - name: app-read-and-update
    db_service: appdb
    operations: [READ, UPDATE]
    decision: allow

  - name: app-allow-tx-control
    db_service: appdb
    operations: [transaction]
    decision: allow

  - name: app-allow-safe-session-settings
    db_service: appdb
    operations: [session]
    subtypes: [set, reset, set_local,
               discard_plans, discard_all, discard_temp, discard_sequences]
    objects: ["application_name", "timezone", "datestyle", "client_encoding",
              "statement_timeout", "lock_timeout",
              "idle_in_transaction_session_timeout",
              "default_transaction_isolation"]
    decision: allow

  - name: app-deny-search-path-and-role-changes
    db_service: appdb
    operations: [session]
    subtypes: [set_search_path, set_role, set_session_authorization]
    decision: deny
    message: "search_path / role manipulation not allowed"

  - name: app-deny-other-session-settings
    db_service: appdb
    operations: [session]
    decision: deny
    message: "Only specific session settings are allowed; requested {{.Object}}"

  - name: app-deny-mutations            # specific user-facing rule for common cases
    db_service: appdb
    operations: [DELETE, CREATE, DROP, ALTER, EXPORT]
    decision: deny
    message: "Agent is read+update only on appdb. Requested: {{.Operation}}"

  - name: app-deny-dangerous            # backstop for the broader risk class
    db_service: appdb
    operations: [DANGEROUS]
    decision: deny

  - name: warehouse-read-only
    db_service: warehouse
    operations: [READ]
    decision: allow

  - name: warehouse-deny-everything-else
    db_service: warehouse
    operations: ["*"]
    decision: deny

  - name: catch-all-unknown
    operations: [unknown]
    decision: deny
    message: "Statement could not be classified. Failing closed."
```

| Statement-rule field | Required | Notes |
|----------------------|----------|-------|
| `name` | yes | Stable identifier. |
| `db_service` | no | If omitted, matches across all services. |
| `db_family` | no | |
| `db_dialect` | no | |
| `schemas` | no | Glob. Matches `objects[].schema` of any object in the effect. |
| `objects` | no | Glob list. Matches `objects[].name` (or kind-specific structured field per §6.4) of any object in the effect. A rule with `objects: ["a", "b"]` covers an object whose name globs against `a` or `b`. Coverage is per-object: with effect objects `{a, c}`, this rule covers `a` only. **Syntactic match only**. For `session` operations, matches GUC name (lowercased). |
| `operations` | yes | Group names or aliases. Rule matches an effect whose `group` is in the list. |
| `subtypes` | no | If specified, rule matches only effects whose `operation_subtype` is in the list. |
| `match_object_resolution` | no | One of the resolution tags or `*`. Matches against the effect's per-effect resolution tag. |
| `decision` | yes | `allow`, `deny`, `approve`, `audit`. |
| `message` | no | Template with `{{.Operation}}, {{.Subtype}}, {{.Schema}}, {{.Object}}, {{.Verb}}, {{.StatementPreview}}`. |
| `timeout` | only for `approve` | Default 60 seconds. Sized to be safe inside open transactions (§14.5). Operators with long-form approval workflows opt up explicitly per rule. |
| `acknowledge_audit_on_dangerous` | no | Required `true` to silence the load-time warning emitted when `decision: audit` is paired with operations of risk tier ≥ high (§9.4, R13). |

### 9.3 Connection rules (`database_connection_rules`)

Connection rules evaluate at connection establishment time. They are the only rule family available for `passthrough` services. Matchable fields are constrained by the service's TLS mode (§13.2); validation is enforced at config-load time.

```yaml
database_connection_rules:
  - name: legacy-connect-readonly-agent-only
    db_service: legacy_pg
    db_user: ["readonly_agent"]
    decision: allow

  - name: legacy-deny-other
    db_service: legacy_pg
    decision: deny
    message: "legacy_pg is restricted to the readonly_agent identity"

  - name: warehouse-connect-allow
    db_service: warehouse
    decision: allow

  - name: appdb-allow-self-cancels
    db_service: appdb
    match_kind: cancel
    decision: allow
```

| Connection-rule field | Required | Notes |
|-----------------------|----------|-------|
| `name` | yes | Stable identifier. |
| `db_service` | no | If omitted, matches all services. |
| `match_kind` | no | One of `connect` (default), `cancel`, `replication`. See §11.1, §15.5. |
| `db_user` | no | List of upstream DB user names extracted from StartupMessage. Requires terminate-mode TLS. |
| `database` | no | DB name from StartupMessage. Requires terminate-mode TLS. |
| `application_name` | no | Glob. Matches StartupMessage `application_name`. Requires terminate-mode TLS. |
| `client_identity` | no | Glob. Matches the AgentSH-internal client identity. Available in all TLS modes. |
| `decision` | yes | `allow`, `deny`, `approve`, `audit`. |
| `message` | no | Returned to client as Postgres `ErrorResponse` with `SQLSTATE 28000` (terminate modes only; passthrough closes TCP). |
| `timeout` | only for `approve` | Default 60 seconds. (See note for statement rules in §9.2.) |

Connection rules evaluate **before** any statement is classified. A connection-level deny prevents any statement from reaching the classifier.

### 9.4 Config-load validation

**Errors (refuse to load):**

- Statement rule referencing a `db_service` whose `tls_mode` is `passthrough` → **load error**.
- Connection rule under a `passthrough` service that matches `db_user`, `database`, or `application_name` → load error. (Those fields are not visible in passthrough; see §13.2.)
- Rule referencing a `db_service` that does not exist → load error.
- Rule with `decision: redirect` in Phase 1 → load error.
- Rule with `subtypes` referencing a non-existent subtype → load error.
- Rule with no `db_service` and no `db_family` and `decision: allow` and `operations: ["*"]` → load error (too broad).
- Service with `tls_mode: terminate_plaintext_upstream` to a non-RFC1918, non-loopback destination without `trusted_network: true` → load error.
- Connection rule with `match_kind: cancel` and `decision: approve` → load error. Cancel is a real-time signal that cannot be held for human approval (§15.2, R19).

**Warnings (load proceeds):**

- A rule with `decision: audit` whose `operations:` resolves to one or more groups with risk tier ≥ `high` (`delete`, `bulk_load`, `bulk_export`, `schema_create`, `schema_alter`, `schema_destroy`, `privilege`, `procedural`, `unsafe_io`, `unknown`) emits a non-fatal warning. `audit` is allow-with-observation (§10.1); pairing it with a dangerous operation is the most common policy misuse. Operators who genuinely intend audit-as-allow on dangerous operations silence the warning by setting `acknowledge_audit_on_dangerous: true` on the rule.

---

## 10. Decision Semantics

### 10.1 Decision verbs

| Decision | Statement-level | Connection-level |
|----------|-----------------|------------------|
| `allow` | Forward unchanged. | Connection established. |
| `deny` | Synthesize `ErrorResponse` (SQLSTATE 42501). See §14. | See §13.3. |
| `approve` | Held; approval flow. On approval, forward. On denial/timeout, behaves as `deny`. | Held until approval. |
| `audit` | Forward, tag event. Functionally equivalent to allow at the wire; differs only in event labeling and downstream alerting/handling. | Connection established with audit tag. |

`redirect` is Phase 2.

> **Operator note: `audit` is allow-with-observation, not block-with-observation.** A statement whose final decision is `audit` is **forwarded to the database**. The agent gets a normal response. The only difference from `allow` is that the event carries `decision.verb: "audit"` and downstream Watchtower alerting policies can treat it differently (e.g., page on-call, send to a dedicated SOC queue). Operators who want "observe but block" should use `approve` (which holds the statement until a human decides) or `deny` (which blocks unconditionally). This is a common point of confusion; repeat it wherever sample policies appear.

### 10.2 Per-effect evaluation with multi-object semantics

**Algorithm:**

```
For statement S with effects = [e_0, e_1, ..., e_n]:
  For each effect e_i:
    decision_i = evaluate_effect(e_i)
  final_decision = most_restrictive(decision_0, ..., decision_n)
```

**`evaluate_effect(e)`** with strict multi-object semantics. The algorithm is **order-independent**: rule position in the policy file does not affect outcomes. Operators may reorder rules for readability without changing semantics.

```
DENY matching:
  e is denied by rule R if:
    - R.group/subtype matches e.group/e.subtype
    - R.match_object_resolution matches e.object_resolution (or R has none)
    - any object in e.objects matches R.objects (or R has no objects: clause)
  → If any deny rule fires for any object in e, decision_i = deny.
  Order-independent: any matching deny anywhere in the policy file produces deny.

ALLOW / AUDIT / APPROVE coverage (strict):
  Collect all allow/audit/approve rules whose group/subtype/resolution match e.
  An object o ∈ e.objects is "covered" if some matching rule's objects glob matches o.
  A rule with no objects: clause covers any object.
  Order-independent: any matching coverage rule contributes regardless of position.

  e is fully covered if every object in e.objects is covered by at least one rule.

  If e is fully covered AND no deny matched:
    The effect-level decision is the most-restrictive verb among the rules that
    cover the object set:
      - If any covering rule has decision: approve → decision_i = approve
      - Else if any covering rule has decision: audit → decision_i = audit
      - Else                                              decision_i = allow

  If at least one object in e is uncovered:
    decision_i = implicit_deny (regardless of approve coverage on other objects).

  If multiple approve rules apply across objects, all approvers are notified;
  first approval allows; any denial denies.
```

**Restrictiveness order (most to least):**

```
deny  ≡  implicit_deny  >  approve  >  audit  >  allow
```

A final decision of `audit` forwards the statement unchanged to upstream. The difference from `allow` is event labeling (`decision.verb: "audit"`) and downstream alerting policies in Watchtower.

A final decision of `approve` holds the statement until a human decides. After approval, the forwarded event carries `decision.verb: "approve"`. Audit-tagged rules that co-cover the object set are recorded in `decision.contributing_audit_rules` (array of rule names) but do not change the verb. Watchtower alerting that targets `decision.verb == audit` does not fire on approved events; alerting that targets `contributing_audit_rules` does.

> **Operator note: `approve` does not cover unrelated uncovered objects.** A common misreading is "approve" = "ask a human for permission for the whole effect." It does not. Each object must independently be covered by `allow`, `audit`, or `approve`. If an effect has objects `{allowed_table, mystery_table}` and a rule says "approve READ on allowed_table" but no rule mentions `mystery_table`, the effect is denied (because `mystery_table` is uncovered → implicit_deny → wins over approve). To get human-in-the-loop on the whole effect, use a rule that matches the broader object set (e.g., `objects: ["*"]` with `decision: approve`), not a narrow rule that happens to match one of the touched objects.

**`match_object_resolution` semantics.** When an effect contains multiple objects with potentially different individual resolution confidences, the effect's resolution tag is the **worst-confidence tag** across all objects in the effect (mirroring §6.2's top-level worst-case computation, applied per-effect). A rule with `match_object_resolution: qualified_syntactic` matches an effect only if every object in that effect is `qualified_syntactic`. This keeps resolution-aware policies conservative.

**Why strict coverage for allow:** an effect that touches multiple objects (`SELECT * FROM allowed_table JOIN sensitive_table`) must have *all* objects covered by an allow rule. A rule that allows reads on `allowed_table` does not automatically allow reads on `sensitive_table`. Operators who want broad allow can still write `objects: ["*"]` or omit `objects:` entirely.

**Why "any object" for deny:** a single sensitive object in an effect's object set is enough to trigger a deny rule, even if other objects in the same effect are uncontroversial. This is the security-conservative posture. The same JOIN above, if a deny rule names `sensitive_table`, denies the whole statement.

The asymmetry is deliberate.

**Concrete examples** under the §9.2 sample policy. Effects shown post-canonical-ordering.

| Statement | Effects (group : objects) | Per-effect decision | Final |
|-----------|---------------------------|---------------------|-------|
| `SELECT * FROM users` | `read:{users}` | read→allow (READ rule, no objects:, covers all) | **allow** |
| `SELECT * FROM users JOIN orders` | `read:{users, orders}` | read→allow (READ rule has no objects:) | **allow** |
| Add: `app-restricted-tables` rule that denies READ on `pii.*` | `read:{users, orders}` | read→allow (no pii table involved) | **allow** |
| `SELECT * FROM users JOIN pii.ssns` | `read:{users, pii.ssns}` | read→deny (`pii.ssns` matches deny) | **deny** |
| `SELECT * FROM uncovered_table JOIN users` (READ allow rule covers `users` only) | `read:{uncovered_table, users}` | read→implicit_deny (uncovered_table not covered) | **deny** |
| `SELECT * FROM allowed JOIN needs_approval` (READ allow on `allowed`, READ approve on `needs_approval`) | `read:{allowed, needs_approval}` | read→approve (both covered, one via approve) | **approve** |
| `SELECT * FROM uncovered JOIN needs_approval` (READ approve on `needs_approval` only) | `read:{uncovered, needs_approval}` | read→implicit_deny (uncovered not covered; approve doesn't extend) | **deny** |
| `SELECT * FROM customers` (audit-on-customers rule) | `read:{customers}` | read→audit (covered by audit rule) | **audit** (forwarded to DB, tagged) |
| `SELECT * FROM customers JOIN orders` (audit-on-customers rule, no allow on orders) | `read:{customers, orders}` | read→implicit_deny (orders uncovered; audit doesn't cover orders) | **deny** |
| `INSERT INTO log SELECT * FROM x` | `write:{log}, read:{x}` | write→implicit_deny (no allow rule), read→allow | **deny** ✓ |
| `WITH d AS (DELETE FROM u RETURNING *) SELECT * FROM d` | `delete:{u}, read:{u}` | delete→deny, read→allow | **deny** ✓ |
| `COPY (DELETE FROM u RETURNING *) TO STDOUT` | `bulk_export:{u}, delete:{u}, read:{u}` | bulk_export→deny, delete→deny, read→allow | **deny** ✓ |
| `CREATE SUBSCRIPTION sub CONNECTION '...' PUBLICATION pub` | `unsafe_io:{sub, host:port}, schema_create:{sub}` | both→deny (DANGEROUS / CREATE rules) | **deny** |
| `UPDATE users SET name='x' WHERE id=1` | `modify:{users}` | modify→allow (UPDATE rule) | **allow** |
| `SET TimeZone='UTC'` | `session(set):{timezone}` | matches `app-allow-safe-session-settings`→allow | **allow** |
| `SET work_mem='64MB'` | `session(set):{work_mem}` | matches `app-deny-other-session-settings`→deny | **deny** |
| `SET search_path = pg_catalog, public` | `session(set_search_path):{pg_catalog, public}` | matches `app-deny-search-path-and-role-changes`→deny | **deny** |

### 10.3 Statement-text redaction

Two independent settings control redaction: one for `DBEvent.statement_text` (event-level), one for the approval-flow preview shown to a human approver. Both default to redacted.

```yaml
policies:
  db:
    log_statements: parameters_redacted        # none | parameters_redacted | full
    approval_statement_preview: redacted       # none | redacted | full
    approval_statement_preview_chars: 200      # max characters shown
```

**Event-level redaction (`log_statements`):**

| Setting | Behavior | `DBEvent.statement_redaction` |
|---------|----------|-------------------------------|
| `none` | `DBEvent.statement_text` is `null`. Operation group, subtype, objects are still emitted. | `full` |
| `parameters_redacted` (default) | `DBEvent.statement_text` is populated with parameter values replaced by `?` and string literals replaced by `<REDACTED>`. | `parameters_redacted` |
| `full` | `DBEvent.statement_text` is populated with the full statement, including parameter values. | `none` |

**Approval-preview redaction (`approval_statement_preview`):**

| Setting | Behavior |
|---------|----------|
| `none` | Approval shows operation group, schema, object only. No statement text at all. |
| `redacted` (default) | Approval shows the statement with parameter values replaced by `?` and string literals replaced by `<REDACTED>`. |
| `full` | Full statement text including parameter values, truncated to `approval_statement_preview_chars`. |

The two settings are independent: an operator may want events redacted (Watchtower retention is long; PII shouldn't accumulate) while approvals are full-text (the approver needs to see the parameter values to decide). Or the inverse, for forensics-heavy environments.

A privacy-sensitive deployment sets `log_statements: parameters_redacted` (or `none`) and `approval_statement_preview: redacted` (or `none`). With both set to redaction-or-stronger, no unredacted statement text exists anywhere in the AgentSH path.

### 10.4 Evaluation order

For each individual effect, rule evaluation is **order-independent**:

- Deny rules trigger on any object match regardless of position in the policy file.
- Allow / audit / approve rules contribute to the per-object coverage set.
- The final effect-level decision is the most-restrictive verb among rules that cover the object set, with `deny ≡ implicit_deny > approve > audit > allow` (§10.2).
- No-match for any object in an effect → `implicit_deny`. Statements are denied unless every object in every effect is covered by at least one allow, audit, or approve rule, and no object is matched by a deny rule.

Two implementations of the policy evaluator that read this section will produce identical decisions for any (rules, statement) pair. Rule order in the policy file does not affect outcomes; operators may reorder rules for readability without changing semantics.

---

## 11. Interception Architecture

### 11.1 Startup-packet handling

A Postgres client begins by sending one of four packet types as the first message after TCP connect:

| Packet | Phase 1 behavior |
|--------|------------------|
| `SSLRequest` | Proxy responds with `S` (SSL supported) and proceeds with TLS handshake per the service's `tls_mode`. After negotiation, expects a normal `StartupMessage`. |
| `GSSENCRequest` | **Default-deny.** Proxy responds with `N` (GSS encryption not supported). Client must fall back to non-GSSENC. Operators who need GSSENC can opt in per service: `allow_gss_encryption: true`. When enabled, proxy treats the connection as `tls_mode: passthrough` after GSSENC negotiation completes (the proxy is not implementing GSS termination in Phase 1). |
| `CancelRequest(syn_pid, syn_secret)` | Translated per §15. |
| Normal `StartupMessage` (after SSL negotiation or directly on plaintext) | Inspected. If `replication` parameter is `true`, see below. Otherwise proceed with connection-rule evaluation. |

**Replication mode.** A `StartupMessage` carrying the `replication` parameter (with values `true`, `database`, `1`, etc.) opens a replication connection rather than a normal SQL connection. The Postgres replication protocol uses CopyBoth and `START_REPLICATION` / `IDENTIFY_SYSTEM` / etc. messages that don't fit the SQL classifier model.

**Phase 1 default:** replication connections are **denied**. The proxy synthesizes an `ErrorResponse(SQLSTATE 28000)` and closes the connection. Event recorded with `decision.rule_kind: connection`, `operation_group: session`, `operation_subtype: replication_request`.

**Opt-in:** operators with legitimate replication needs can write a connection rule:

```yaml
database_connection_rules:
  - name: replicator-allow
    db_service: appdb
    match_kind: replication
    db_user: ["repl_user"]
    decision: allow
```

When a replication connection is allowed, **the connection is treated as effective passthrough for the duration**. The proxy forwards bytes both ways without classification or statement enforcement. The replication protocol is out of Phase 1's classifier scope; statement-level enforcement of replication operations is a future phase.

**Passthrough boundary.** Passthrough begins **at StartupMessage acceptance** for replication-mode connections, not at the first CopyBoth frame. The replication-protocol bootstrap commands (`IDENTIFY_SYSTEM`, `CREATE_REPLICATION_SLOT`, `START_REPLICATION`, `BASE_BACKUP`, etc.) are not classified — they go through unmodified along with the subsequent CopyBoth stream. This is deliberate: classifying the bootstrap would require partial replication-protocol parsing that is explicitly out of Phase 1 scope, and the operator has opted into degraded visibility by allowing the connection.

This means: enabling replication on a service degrades that *connection's* visibility to passthrough. Other connections to the same service with normal StartupMessages remain fully terminated and classified.

**Degraded-visibility events.** Whenever a connection enters a passthrough or passthrough-equivalent state due to an explicit operator opt-in, the proxy emits a `degraded_visibility_warning` event with `reason` field indicating which opt-in was used. This applies to:

- Replication-mode connections allowed via `match_kind: replication` rule. `reason: replication_passthrough`. One event per allowed replication connection at connection start.
- GSSENC connections allowed via `allow_gss_encryption: true` on the service. `reason: gssenc_passthrough`. One event per GSSENC connection at connection start.
- Connections to a service with `tls_mode: passthrough` continue to behave per §13 (no per-connection warning, since visibility was opted-out at the service level).

The degraded-visibility event carries the same session and client identity correlation as other DBEvents and is queryable in Watchtower so SOC analysts can filter on "show me connections where statement-level visibility is reduced." The event payload:

```json
{
  "event_id": "uuid-v7",
  "session_id": "...",
  "ts": "...",
  "db_service": "appdb",
  "db_user": "string | null",
  "client_identity": "string",
  "kind": "degraded_visibility_warning",
  "reason": "replication_passthrough | gssenc_passthrough",
  "context_digest": "sha256:..."
}
```

(Standard DBEvent fields like `operation_group` and `effects` are absent; this is a connection-lifecycle event, not a statement event.)

### 11.2 Architecture diagram

```
agent process (SessionID = agent)
   │  TCP connect
   ▼
[ AgentSH connect_redirect ] — rewrites to per-session Unix socket
   ▼
[ AgentSH DB proxy ] (SessionID = proxy, distinct from agent)
   ├── Unix-socket listener with SO_PEERCRED authentication (§12.5)
   ├── startup-packet handler (SSLRequest / GSSENCRequest / CancelRequest / StartupMessage)
   ├── pgproto3 framer
   ├── classifier (pg_query_go + dialect dispatch)
   ├── wire-protocol Extended Query cache
   ├── SQL-level prepared statement cache
   ├── connection rule evaluator
   ├── statement rule evaluator (per-effect, multi-object, order-independent — §10.2)
   ├── transaction state tracker
   ├── temp-table tracker (best-effort)
   ├── BackendKeyData mapping table
   ├── replication-mode passthrough handler (when allowed)
   ├── event emitter → audit pipeline → Watchtower
   └── upstream connection
   ▼
upstream PostgreSQL
```

### 11.3 Connection lifecycle

1. Agent initiates TCP connect to a declared `db_service` upstream. `connect_redirect` rewrites the connect to the per-session Unix socket where the proxy listens (§12.5).
2. **Listener authentication.** Proxy `accept()`s the connection, calls `getsockopt(SO_PEERCRED)`, resolves peer pid → SessionID via the AgentSH ptrace registry, verifies the SessionID matches the configured agent SessionID. Mismatch → close silently, emit `db_listener_auth_fail`.
3. **Startup-packet handler** (§11.1) classifies the first message: SSLRequest / GSSENCRequest / CancelRequest / StartupMessage. Routes accordingly.
4. For SSLRequest: complete inbound TLS per `tls_mode`. Then expect StartupMessage.
5. For GSSENCRequest: deny by default (respond `N`); under `allow_gss_encryption: true`, enter passthrough mode and emit `degraded_visibility_warning`.
6. For CancelRequest: handle per §15.
7. For StartupMessage: extract `db_user`, `database`, `application_name`. If `replication=true`, evaluate `match_kind: replication` connection rules; if denied (default), close with `ErrorResponse(SQLSTATE 28000)`; if allowed, enter passthrough mode (beginning at this point, not at first CopyBoth — §11.1) and emit `degraded_visibility_warning`.
8. Connection rules (default `match_kind: connect`) evaluated. Deny → close per §13.3.
9. Proxy opens upstream connection. Auth forwarded as-is. SCRAM-SHA-256-PLUS detected at handshake → fail-closed.
10. Proxy receives upstream `BackendKeyData(real_pid, real_secret)`. Commits mapping to the table per §15.1, then sends synthetic `BackendKeyData(syn_pid, syn_secret)` to client.
11. Per-statement loop (Simple Query or Extended Query per §14).
12. On disconnect: emit session-summary event. Drop per-connection caches. Remove BackendKeyData mapping after `cancel_grace_window` (default 5 minutes).

Latency budget: 1ms p50, 5ms p99 for in-line policy evaluation. Approval gates are bounded by `timeout`.

---

## 12. Proxy Unavoidability

The proxy is only useful if the agent cannot reach the database around it. This section defines the requirements.

### 12.1 Scoped claim

The unavoidability claim is:

> **The DB proxy is unavoidable for processes inside the AgentSH-governed process tree, for declared `db_services`, assuming the AgentSH supervisor and proxy are not compromised.**

Three explicit scoping clauses:

1. **AgentSH-governed process tree.** A process running outside AgentSH's interception (e.g., on a different host, in a different namespace not under AgentSH supervision) is out of model.
2. **Declared `db_services`.** A database hosted at a destination the operator has not declared cannot be governed; AgentSH does not know it exists.
3. **Supervisor and proxy not compromised.** Compromise of the AgentSH supervisor process or of the DB proxy itself is out of model.

Inside this scope, the threat model and defenses below apply. Outside this scope, AgentSH makes no claim. Customer-facing material should always pair the unavoidability claim with these scoping clauses.

### 12.2 Threat model

An agent process (or any process in its tree) may attempt to bypass the proxy by:

1. Direct TCP to the DB destination.
2. Custom DNS resolution (custom resolver, hosts-file edit).
3. CNAME chasing, IPv6, private DNS aliases.
4. Unix domain sockets.
5. Port-forward via `ssh -L`, `kubectl port-forward`, `cloud-sql-proxy`, `socat`, `gcloud sql connect`, AWS CLI RDS connect, etc.
6. Sidecar DB proxy (e.g., pgBouncer) reachable inside the network namespace.
7. Loopback redirection through a process the agent itself launches.
8. **Custom tunnel binaries** the agent compiles or downloads (the most important bypass to defend against).

### 12.3 The boundary is destination egress denial

**Command-rule denylists for known bypass tools (`ssh -L`, `socat`, etc.) are convenience detections. They are not the security boundary.** The boundary is destination egress denial to protected DB tuples for all non-proxy processes.

For each `db_service` with upstream `host:port`:

1. **TCP egress** to that destination tuple is denied for every process **except the AgentSH proxy itself**, via existing `network_rules` with process-identity match. This catches custom tunnel binaries the agent might compile.
2. **DNS resolution** of the upstream hostname is intercepted by AgentSH's DNS layer. Resolved IP set is added to the denial set; CNAMEs are followed.
3. **IPv6** is included by default (`::ffff:` mapped, native v6).
4. **Unix domain sockets** at well-known paths (`/var/run/postgresql/.s.PGSQL.*`, `/tmp/.s.PGSQL.*`) are denied at the file layer for non-proxy processes via existing `file_rules`.
5. **Port-forward arithmetic** is handled by denying the *destination* tuple, not the source port. An agent that opens a local listener and forwards to `db.internal:5432` is caught when its forwarding process tries to reach the destination.

### 12.4 Proxy identity: SessionID-keyed exemption

The proxy egress exemption is keyed on **AgentSH SessionID**, the existing process-tracking primitive set at ptrace attach (see `internal/ptrace/attach.go`) and consulted on every network-rule evaluation (see `internal/policy/engine.go` `CheckNetworkCtx`). The mechanism:

1. The AgentSH supervisor launches the DB proxy as a separate process under a **distinct SessionID**, outside the agent's ptrace tree. The proxy is not a child of any agent process.
2. Per-service `network_rules` deny egress to declared DB destinations **for the agent's SessionID**. The proxy's SessionID is not subject to those rules; the proxy's outbound connections to upstream DBs are evaluated under its own (exempt) session.
3. SessionID is supervisor-assigned at session creation. A child process inherits its parent's SessionID via ptrace tracking; an agent process cannot spawn a child with a different SessionID without supervisor cooperation. The unavoidability bundle prevents the agent from escaping its ptrace tree.
4. Forging a SessionID at the rule-evaluation API requires either compromising the supervisor (out of model per §12.1) or escaping the ptrace tree (which the unavoidability primitives prevent). An agent cannot grant itself the exemption by renaming a binary, launching a process named `agentsh-db-proxy`, or any other in-band trick.

> **Phase 1 dependency.** v0.7's `NetworkRule` schema does not carry per-rule SessionID matchability beyond what the existing per-session policy engine provides. Building the SessionID-exempt egress denial — auto-generated from `db_services` config — is part of the Phase 1 deliverable. §23.4 implementation order item 10 ("Unavoidability bundle generation from `db_services` config") includes this work; it is not pre-existing infrastructure that the spec relies on. Operators reading §12 should expect this rule generation to ship in the same release that adds DB awareness.

### 12.5 Listener authentication

The proxy listens on a path that `connect_redirect` rewrites the agent's `connect()` calls toward. Inbound connections must be authenticated to the agent's SessionID before any Postgres protocol is accepted, otherwise a co-resident non-agent process on the same host could connect to the listener directly and use the proxy as an SQL forwarder — bypassing the `connect_redirect` path that gives the proxy its agent-aware audit trail.

**Listener mode: Unix domain socket (required).**

- The proxy creates a Unix domain socket at a per-session path (e.g., `/run/agentsh/<session_id>/db-proxy.sock`). The path is placed in a directory the agent's `file_rules` permit and other tenants do not.
- On `accept()`, the proxy calls `getsockopt(SO_PEERCRED)` to obtain the connecting process's `(pid, uid, gid)`.
- The proxy resolves the peer's `pid` to a TGID, then to a SessionID, via the existing AgentSH ptrace registry. The resolved SessionID must equal the proxy's configured agent SessionID.
- A connection from a process whose SessionID does not match is closed with no protocol response. Event `db_listener_auth_fail` is emitted with `peer_pid`, `peer_uid`, `peer_session_id` (or `unknown` if the pid is not in the registry), and `reason`.

**TCP listener mode: not supported in Phase 1.**

Localhost TCP would in principle allow `getsockopt(TCP_INFO)`/`SO_PEERCRED` for peer-credential extraction on Linux, but coverage is platform-specific and weaker than Unix-socket peer creds (BSD, macOS, and Windows do not provide an equivalent). Phase 1 mandates Unix sockets; if an operator's deployment cannot use Unix sockets, the proxy refuses to start with a structured error referencing this section.

**Discovery.** `connect_redirect` is responsible for rewriting the agent's TCP `connect()` to the per-session socket path. The agent does not see the path and cannot bypass the redirect from inside its session. Cross-session bypass attempts (a process in a different SessionID trying to connect to the socket) are caught by listener authentication.

### 12.6 Bypass-attempt events

Whenever any of the rules in §12.3 fires for a non-proxy process attempting to reach a protected destination, a `db_bypass_attempt` event is emitted with:

- The protected `db_service`.
- The process identity (SessionID + pid) that attempted the bypass.
- The bypass mode (`tcp_direct`, `unix_socket`, `port_forward_tool`, `dns_alias`, `custom_tunnel`, `listener_auth_fail`).
- The attempted destination.
- Correlation to the session.

**Rate limiting.** Bypass-attempt events are deduplicated per `(session_id, process_identity, destination_tuple)` within a 60-second window. The canonical event for the window carries a `suppressed_count` field reflecting how many subsequent matching attempts were absorbed. This prevents a misbehaving process in a tight loop from flooding the event pipeline.

Watchtower can configure session-kill policy on repeated bypass attempts (independent of the rate-limit dedup; the policy operates on the canonical events).

### 12.7 Convenience: bypass-tool detection

`command_rules` for known bypass binaries are still useful for early detection and for distinguishing "agent compiled its own tunnel" from "agent invoked `ssh -L`." They are loud signals, not the boundary.

Default bundle includes deny-with-detect rules for: `ssh` with `-L *:5432` argv pattern, `socat` with TCP listeners on DB ports, `kubectl port-forward` to DB ports, `cloud-sql-proxy`, `gcloud sql connect`, `aws rds connect`.

**Bundle scope.** The bundle is convenience, not boundary. Tools known to be missing as of v0.8: `chisel`, `gost`, `frpc`, raw `nc`/`ncat` with TCP listeners on DB ports, container-runtime escapes (`docker run --net=host` if the agent has docker access), and any custom binary the agent compiles or downloads. The boundary is §12.3 destination egress denial, which catches all of these regardless of binary identity. Operators should not interpret the bundle as exhaustive.

### 12.8 What unavoidability does not cover

- An agent running outside AgentSH's process tree.
- Compromise of the proxy itself.
- Compromise of the AgentSH supervisor.
- A DB hosted at a destination the operator has not declared as a `db_service`.
- Side-channel exfiltration via DNS itself, time-of-check shenanigans, or covert channels.
- A co-resident non-agent process attempting to use the proxy as an SQL forwarder. Mitigated by §12.5 listener authentication; uncaught only if listener authentication itself is misconfigured (not running, wrong path permissions, peer-cred resolution unavailable).

---

## 13. TLS Handling

### 13.1 Modes

Three explicit modes per `db_service`. No default. Operators must choose.

| Mode | Behavior | Visibility |
|------|----------|------------|
| `passthrough` | Opaque after `SSLRequest` exchange. Statement rules cannot attach. | Connection-level only. SNI from ClientHello if available. |
| `terminate_reissue` | Inbound TLS terminated with AgentSH CA leaf. Re-establishes upstream TLS. SCRAM-SHA-256-PLUS detected at handshake → fail-closed with structured error referencing Phase 4 broker. | Full. |
| `terminate_plaintext_upstream` | Inbound TLS terminated. Plaintext upstream. Loopback / RFC1918-only; public destinations produce a load error. | Full. |

### 13.2 Visibility matrix for connection-rule matching

The Postgres StartupMessage (containing `user`, `database`, `application_name`) is sent **after** TLS negotiation. Under passthrough, the proxy cannot see it.

| Field | passthrough | terminate_reissue | terminate_plaintext_upstream |
|-------|-------------|-------------------|------------------------------|
| `db_service` | ✓ | ✓ | ✓ |
| `client_identity` (AgentSH SessionID — see §12.4) | ✓ | ✓ | ✓ |
| destination | ✓ | ✓ | ✓ |
| TLS SNI | △ (best-effort, from ClientHello) | ✓ | ✓ |
| `db_user` | ✗ | ✓ | ✓ |
| `database` | ✗ | ✓ | ✓ |
| `application_name` | ✗ | ✓ | ✓ |

Config-load validation rejects connection rules under passthrough services that try to match passthrough-invisible fields (§9.4).

> **SNI under passthrough is best-effort.** SNI is extracted from the TLS ClientHello when present, but **many Postgres drivers do not set SNI by default**, especially when connecting by IP address. libpq added SNI support relatively recently and not all driver stacks expose it. Connection rules that match SNI under passthrough should be treated as advisory; operators relying on SNI-based routing or access control under passthrough must validate against their specific client stack (driver name + version + connection-string form) and accept that future driver versions may begin or stop sending SNI.

### 13.3 Connection-level deny across modes

- **`terminate_reissue` / `terminate_plaintext_upstream`:** Proxy synthesizes Postgres `ErrorResponse(SQLSTATE 28000, message=<rendered>)` followed by graceful connection close. Client driver surfaces a normal authentication-failed error.
- **`passthrough`:** The proxy is not terminating the encrypted stream and cannot inject Postgres protocol messages inside it. Connection-level deny closes the underlying TCP connection. The client sees a connection reset; some drivers report this as "connection refused" or "server closed connection during startup." Operators are recommended to combine passthrough connection-deny with a clear `db_bypass_attempt`-style event so the audit trail makes the deny visible even though the client gets no protocol-level reason.

A connection-level deny that fires *before* the `SSLRequest` exchange (e.g., `client_identity` rules) closes the TCP connection in all modes; protocol-level error synthesis isn't applicable yet.

---

## 14. Transaction Correctness Model

This section governs what the proxy does when a statement is denied inside a multi-statement batch or an explicit transaction.

### 14.1 Simple Query

The proxy parses every statement in a Simple Query message before forwarding any of them.

- All allowed → forward the full Query message unchanged.
- One or more denied → see §14.4. Upstream sees no partial execution.

### 14.2 Extended Query

Per-message enforcement with explicit upstream-sync state.

**State variable per connection:** `upstream_dirty_since_sync` (boolean). Set to `true` when the proxy forwards `Parse`, `Bind`, `Describe`, `Close`, or `Execute` upstream. **Reset to `false` after observing the next `ReadyForQuery` from upstream in the current Sync window.** The flag is per-Sync-window, not per-connection-lifetime; each Sync window starts fresh.

**Per-message handling:**

- **`Parse(name, sql)`:** Classify `sql`. Evaluate against policy.
  - Denied: synthesize `ErrorResponse` to client. Do not forward upstream. Set `absorbing = true`. Cache not populated.
  - Allowed/audit/approved: forward upstream. Set `upstream_dirty_since_sync = true`. Cache classification under `(connection, name)`.
- **`Bind(portal, name, ...)`:** Look up cached classification by `name`. Cache miss → synthesize `ErrorResponse` to client. Do not forward upstream. Set `absorbing = true`. (Cache miss happens if Parse was denied; the Bind for that statement therefore also denies.) Otherwise forward upstream. Set `upstream_dirty_since_sync = true`.
- **`Describe(target)`:** If `absorbing`, do not forward. Otherwise forward; set `upstream_dirty_since_sync = true`.
- **`Execute(portal, max_rows)`:** If `absorbing`, do not forward (the prior Parse/Bind already errored). Otherwise look up cached classification via portal → prepared statement. Re-evaluate policy (handles hot reload).
  - Denied: synthesize `ErrorResponse` to client. Do not forward upstream. Set `absorbing = true`.
  - Allowed: forward upstream. Set `upstream_dirty_since_sync = true`.
- **`Flush`:** If `absorbing`, do not forward. Otherwise forward.
- **`Close(target)`:** If `absorbing`, do not forward. Otherwise forward; set `upstream_dirty_since_sync = true`. Caches updated client-side regardless.
- **`Sync`:** **Guard:** if upstream is in `T` state, §14.3 governs and this Sync handling does not apply. The sub-cases below assume upstream is in `I` or `E` state. Three sub-cases:
  1. **Not absorbing, not dirty.** Either forward `Sync` upstream and pass `ReadyForQuery` through, or synthesize `ReadyForQuery(I)` locally. Implementation choice; in practice this case is rare and forwarding upstream is simpler.
  2. **Absorbing, dirty.** Forward `Sync` upstream so upstream returns to ready state. **Upstream responses to messages forwarded *before* the deny point** (`ParseComplete`, `BindComplete`, `RowDescription`, `DataRow`, `CommandComplete` for those allowed messages) **are forwarded to the client normally** — the agent expects the protocol responses to its allowed messages. **Once the proxy has synthesized the deny `ErrorResponse` to the client, all subsequent upstream responses are suppressed until upstream's `ReadyForQuery`.** The proxy then forwards upstream's RFQ status to the client. Reset `absorbing`, `upstream_dirty_since_sync`.
  3. **Absorbing, not dirty.** Synthesize `ReadyForQuery(I)` locally; do not forward `Sync` upstream. Reset `absorbing`.

The model: the proxy synthesizes errors locally for denied statements, but always ensures upstream is brought back to `ReadyForQuery` state before the client's next pipeline.

### 14.3 Inside an explicit transaction

Proxy tracks transaction state via observed transaction-control statements and `ReadyForQuery` status flags from upstream (`I` / `T` / `E`).

When a statement is denied inside an explicit transaction (`BEGIN` was forwarded; upstream is in `T` state):

**Default (`deny_mode_in_tx: terminate`):**

1. Synthesize deny `ErrorResponse`.
2. Close upstream connection cleanly. Upstream auto-rollbacks on disconnect.
3. Close client connection.
4. `tx_context.deny_action: "connection_terminated"`.

**Soft (`deny_mode_in_tx: rollback_then_continue`):**

1. Synthesize deny `ErrorResponse`.
2. Inject `ROLLBACK` upstream as if from the client.
3. Drain upstream until `ReadyForQuery(I)`.
4. Send `ReadyForQuery(I)` to client.
5. `tx_context.deny_action: "rollback_injected"`.

Default `terminate` is unambiguous. Soft mode for development environments only.

### 14.4 In-transaction deny overrides pre-forward semantics

When a statement is denied:

1. **Outside an explicit transaction (no `BEGIN` was forwarded):**
   - If `upstream_dirty_since_sync == false`: synthesize `ErrorResponse + ReadyForQuery(I)` locally. Do not touch upstream. `tx_context.deny_action: "none"`.
   - If `upstream_dirty_since_sync == true`: synthesize `ErrorResponse` to client, forward `Sync` upstream, drain to upstream's `ReadyForQuery`, return that to client. `tx_context.deny_action: "none"`.

2. **Inside an explicit transaction (`BEGIN` was forwarded; upstream is in `T` state):**
   - §14.3 always takes precedence.
   - `deny_mode_in_tx: terminate` (default): see §14.3.
   - `deny_mode_in_tx: rollback_then_continue`: see §14.3.

The key invariant: **inside an explicit transaction, the proxy must take action on upstream state regardless of whether the denied statement itself was forwarded**. Otherwise the client thinks the connection is idle (because the proxy returned a local `ReadyForQuery(I)`) while upstream is still inside the transaction holding locks. This applies to Simple Query denies, Parse-time denies, Bind cache-miss denies, and Execute denies.

### 14.5 Approval timeouts inside transactions

A statement awaiting `approve` inside an open transaction holds upstream's transaction state and locks. To prevent indefinite locks:

- Approval `timeout` is enforced strictly.
- On timeout, the statement is treated as denied; `deny_mode_in_tx` applies.
- The default `timeout` is **60 seconds** (§9.2), sized to be safe for the in-tx case. Operators with long-form approval workflows that need more time should opt up explicitly per rule, accepting the lock-hold cost. The previous 5-minute default was unsafe under realistic production lock contention; v0.8 flipped the default to the safe choice.

---

## 15. CancelRequest Handling

Postgres cancellation uses a side-channel TCP connection carrying a `CancelRequest(pid, secret_key)` message. The proxy owns this flow.

### 15.1 BackendKeyData translation

When upstream sends `BackendKeyData(real_pid, real_secret)` during connection startup:

1. Proxy generates a synthetic pair `(syn_pid, syn_secret)` using a CSPRNG. Both are 32-bit values, matching the Postgres wire format.
2. Proxy stores mapping: `(syn_pid, syn_secret) → (upstream_addr, real_pid, real_secret, session_id, timestamp)`.
3. Collision handling: if `(syn_pid, syn_secret)` collides with an existing entry in the per-proxy mapping table, proxy regenerates. Practical collision probability is ~2⁻⁶⁴ per insertion in an empty table; with table size N, ~N · 2⁻⁶⁴ per insertion. At realistic fleet sizes (N < 10⁶), retry rate is negligible. Maximum retry count is 8; on exhaustion, the connection setup fails with `BACKEND_KEY_GENERATION_FAILED` and an operational alert.
4. **The mapping is committed to the table BEFORE the proxy forwards `BackendKeyData(syn_pid, syn_secret)` to the client.** A side-channel `CancelRequest(syn_pid, syn_secret)` cannot reach the proxy with credentials the client has not yet received; race-free by construction.
5. Proxy sends `BackendKeyData(syn_pid, syn_secret)` to client.

The client never sees `real_pid` or `real_secret`. An agent that captures the `BackendKeyData` and tries to send a `CancelRequest` directly to upstream uses synthetic credentials, which upstream rejects.

### 15.2 Cancellation flow

When a client wants to cancel:

1. Client opens a fresh TCP connection (Postgres protocol). `connect_redirect` routes it to the proxy.
2. Client sends `CancelRequest(syn_pid, syn_secret)`.
3. **Proxy mapping lookup.**
   - **No match:** Proxy closes client connection silently. Emits an event flagging the unmatched cancel as a strong signal of forgery or bug. (Real clients never produce unmatched cancels because they always have a real `BackendKeyData` from the original connection.)
   - **Match expired:** Proxy closes client connection. Emits `cancel_after_disconnect` event (benign; queryable for client-bug detection).
   - **Match live:** proceed to step 4.
4. **Connection-rule evaluation.** Evaluate `match_kind: cancel` rules against the matched mapping's `db_service`, `client_identity`, and (if visible per §13.2) `db_user`. `decision: approve` is rejected at config-load time for cancel rules (§9.4), so the verb is `allow` or `deny`.
   - **Allow:** proceed to step 5.
   - **Deny:** Proxy closes client connection. Emits `DBEvent` with `decision.rule_kind: cancel`, `decision.verb: deny`, message rendered from the rule.
5. **Forward.** Proxy opens a fresh TCP connection to `upstream_addr`. Sends `CancelRequest(real_pid, real_secret)`. Closes both connections. Emits `DBEvent` with `decision.rule_kind: cancel`, `operation_group: session`, `operation_subtype: cancel_request`, `decision.verb: allow` (or `audit` if a `match_kind: cancel` audit rule covers).

### 15.3 Mapping lifecycle

- Entry created when upstream's `BackendKeyData` is received. Mapping commit happens **before** the proxy forwards `BackendKeyData(syn_pid, syn_secret)` to the client (§15.1, R20). The client cannot present a synthetic key the proxy has not committed; the side-channel CancelRequest race is closed by construction.
- Retained for connection lifetime + `cancel_grace_window` (default 5 minutes after disconnect, configurable).
- **Eviction policy.** The mapping table is bounded by `cancel_mapping_max` (default 100k). When the cap is hit, eviction considers **only entries whose connection has been closed for ≥ `cancel_grace_window`** — live mappings are never evicted, even if they are the oldest in the table. If the cap is hit and no entry is past its grace window, the proxy fails new connection setup with `BACKEND_KEY_TABLE_FULL` and emits an operational alert. Operators sizing the cap should account for fleet-wide churn under the worst-case scenario where every connection lingers for the full grace window.
- The mapping table is **proxy-wide**, not per-service. A high-churn service can consume capacity that would otherwise serve a low-churn one. Per-service caps are deferred to a future revision; document operator sizing guidance assuming fleet-wide churn (§19 open question).

### 15.4 Direct CancelRequest egress is blocked by §12

Direct TCP connection from agent process to `upstream_addr:port` is denied by destination egress denial regardless of the CancelRequest payload. The proxy is the only process permitted to talk to upstream.

### 15.5 Cancel governance via connection rules

Operators can govern cancellation via an extension to connection rules:

```yaml
database_connection_rules:
  - name: appdb-allow-self-cancels
    db_service: appdb
    match_kind: cancel
    decision: allow

  - name: warehouse-deny-cancels
    db_service: warehouse
    match_kind: cancel
    decision: deny
```

`match_kind` defaults to `connect`. When `cancel`, the rule applies to incoming CancelRequests for that service.

---

## 16. Defense in Depth

The proxy is **not** the only control. Operators are required to provision DB roles that are themselves least-privilege.

Recommended deployment pattern:

- Agent's DB user has no `DROP`, `TRUNCATE`, `CREATE USER`, `GRANT`, `COPY ... FROM PROGRAM`, `lo_import`/`lo_export`, or membership in `pg_read_server_files` / `pg_write_server_files` roles.
- Agent's DB user has no superuser flag.
- Proxy enforces operation-group policy on top.

Either layer alone is insufficient. The proxy provides agent-aware audit, fleet policy, and session correlation. Native DB permissions are the durable last line.

The default config bundle includes a sample `CREATE ROLE` script for Postgres that provisions the recommended least-privilege role.

---

## 17. Failure Modes

| Failure | Behavior |
|---------|----------|
| Classifier parse failure or unmapped form | Effect `{group: unknown}`. Default deny via implicit-deny equivalence. |
| Truncated/malformed wire frame | Connection terminated. `WIRE_PROTOCOL_ERROR`. |
| TLS client-side handshake failure | Connection rejected. Error event emitted. |
| TLS upstream-side handshake failure | Client sees protocol-native error. `UPSTREAM_TLS_FAIL`. |
| SCRAM-SHA-256-PLUS detected under `terminate_reissue` | Connection failed; structured error references Phase 4 broker. |
| FunctionCall sub-protocol message under default config | `ErrorResponse(SQLSTATE 42501) + ReadyForQuery`. `FUNCTION_CALL_PROTOCOL_DENIED`. |
| SQL-level `EXECUTE` of unknown prepared statement | Denied. `SQL_PREPARED_CACHE_MISS`. |
| Wire-level Extended `Bind`/`Execute` of unknown prepared statement | Denied. `PREPARED_CACHE_MISS`. |
| Approval timeout | Denied. `APPROVAL_TIMEOUT`. In-tx behavior per `deny_mode_in_tx`. |
| Denied statement in explicit tx (default `terminate`) | Connection terminated. `tx_context.deny_action: "connection_terminated"`. |
| Denied statement in explicit tx (soft `rollback_then_continue`) | `ROLLBACK` injected, drained, `ReadyForQuery(I)`. `tx_context.deny_action: "rollback_injected"`. |
| Multi-statement Simple Query with one denied | Nothing forwarded. Single `ErrorResponse` referencing index. |
| Bypass attempt detected | `db_bypass_attempt` event. Dedup per `(session_id, process_identity, destination_tuple)` within 60s. Session-kill policy may trigger on canonical events. |
| Inbound listener connection from a process whose SessionID does not match the agent's | Connection closed silently. `db_listener_auth_fail` event with `peer_pid`, `peer_uid`, `peer_session_id`, `reason`. |
| Unmatched CancelRequest | Client connection closed silently; suspicious-event emitted. |
| Expired CancelRequest mapping | Client connection closed. `cancel_after_disconnect` event (benign; queryable for client-bug detection). |
| `BackendKeyData` collision retries exhausted | Connection setup fails. `BACKEND_KEY_GENERATION_FAILED`. Operational alert. |
| `cancel_mapping_max` cap hit with no entries past `cancel_grace_window` | New connection setup fails. `BACKEND_KEY_TABLE_FULL`. Operational alert. Live mappings are never evicted. |
| Connection-level deny under `passthrough` | TCP connection closed. Protocol-level error not synthesized. |
| `GSSENCRequest` under default config | Proxy responds `N`. Client falls back to non-GSSENC. |
| `GSSENCRequest` allowed via `allow_gss_encryption: true` | Connection enters passthrough mode for its lifetime. `degraded_visibility_warning` event emitted with `reason: gssenc_passthrough`. |
| Replication-mode StartupMessage under default config | `ErrorResponse(SQLSTATE 28000)` + connection close. |
| Replication-mode connection allowed via `match_kind: replication` rule | Connection enters passthrough mode for its lifetime. `degraded_visibility_warning` event emitted with `reason: replication_passthrough`. |
| Effect with one or more uncovered objects under allow rules | `implicit_deny` (per strict coverage), final decision deny. |
| Policy file fails integrity check | Server refuses to start. |
| Classifier panic | Connection terminated. Crash logged. Process does not exit. Per-connection isolation. |
| Statement rule attached to passthrough service | Config load error. |
| Connection rule matching invisible field under passthrough | Config load error. |
| `decision: redirect` in Phase 1 policy | Config load error. |

---

## 18. Phased Delivery

| Phase | Scope | Status |
|-------|-------|--------|
| 0 | This spec, reviewed and approved. | done |
| 1 | Postgres adapter. Operation taxonomy with subtypes. Per-effect evaluation with strict object coverage. Two rule families. Event emission. Unavoidability bundle. Transaction correctness. SQL PREPARE/EXECUTE. FunctionCall default-deny. CancelRequest translation. Startup-packet handling. Replication & GSSENC default-deny. | next |
| 2 | Object resolution via upstream catalog. `redirect` decision (statement rewriting). Improved policy ergonomics. | |
| 3 | MySQL adapter. | |
| 4 | Credential broker (resolves SCRAM-SHA-256-PLUS channel binding). | |
| 5 | MongoDB adapter. | |
| 6 | Snowflake / BigQuery / Databricks / ClickHouse handlers via `http_services`. | |
| 7 | Result-set DLP. Row-count caps. Catalog-aware metadata controls (subsumes Describe-leakage). | |
| 8 | MSSQL TDS, Cassandra CQL, Redis RESP, Oracle TNS. | |
| Future | Logical/physical replication protocol support. |

---

## 19. Open Questions

The following are tracked but **none block Phase 1 implementation**. They move into engineering issue tracking after spec freeze.

1. **Prepared-statement cache size** (4096 LRU per connection) needs measurement on representative ORM workloads (Django, SQLAlchemy with prepared-statement caching, Drizzle, Prisma).
2. **Function allowlist seeding** for `escalate_unknown_functions: true` mode. Initial draft: immutable functions in `pg_catalog`. Need a vetted list.
3. **PgBouncer transaction-pool interaction.** `search_path` set in one tx leaks to another in transaction-pool mode. Phase 1 documents the limitation; Phase 2 may add pool-aware tracking.
4. **Bypass-bundle escape hatch** for legitimate operator workflows that need `kubectl port-forward` etc. Likely a separate non-agent identity that can run them. Needs its own small spec.
5. **Approval preview char limit** (default 200) needs validation against approver UX.
6. **`fail_fast_on_parse`** default. Currently `false` to avoid breaking driver retries. May flip with measurement.
7. **Server reset detection accuracy** for clearing prepared-statement caches. Conservative approach (clear on any `BackendKeyData` after the first) may over-evict; alternatives need investigation.
8. **`db_user` matching under IAM/cert auth** (RDS IAM, certificate-based). Apparent user may not match operator's mental model.
9. **CancelRequest grace window** (default 5min) sizing under burst-cancel workloads.
10. **`cancel_mapping_max`** default sizing for multi-tenant proxies.
11. **Sync forwarding implementation choice** when not absorbing and not dirty (forward upstream vs synthesize locally). Should we mandate one for consistency?
12. **`security_label` on shared objects.** Operator mental-model question: "I allowed schema_alter; why is SECURITY LABEL on my column denied?" Worth a note in operator docs.
13. **Strict-coverage allow noise** on broad ad-hoc queries (`SELECT * FROM a JOIN b JOIN c`). Operators may want a `loose_object_coverage: true` mode per service. Track for a future revision; do not ship loose mode in Phase 1.
14. **`match_kind: replication`** rules under terminate-mode services. Replication-allowed connections degrade to passthrough regardless of the service's TLS mode. Document operator expectation.
15. **GSSENC opt-in** treats the connection as passthrough. Flag prominently in deployment docs.

---

## 20. Classifier Test Corpus

The classifier ships with a required golden test corpus. Each entry asserts the expected primary group, secondary groups, subtype, object list, per-effect resolution tag, and final decision under the §9.2 sample policy.

Phase 1 corpus must cover at minimum:

**Simple Query:**

- Single statement (one entry per row in §7.3).
- Multi-statement batches (mixed allowed/denied).

**Extended Query:**

- Parse / Bind / Execute / Sync (with parameters).
- Pipelined Parse / Bind / Execute / Bind / Execute / Sync.
- Denied Parse, subsequent Bind/Execute hit cache miss.
- Allowed Parse, allowed Bind, denied Execute, Sync forwarded with upstream drain.

**SQL-level prepared statements:**

- `PREPARE` / `EXECUTE` / `DEALLOCATE` (named and unnamed).
- Allowed PREPARE then EXECUTE → forwarded.
- Denied PREPARE → not forwarded; subsequent EXECUTE → cache miss + deny.
- `DISCARD ALL` and `DISCARD PLANS` → cache eviction.

**COPY variants:**

- `COPY <table> TO STDOUT`, `COPY <table> FROM STDIN`.
- `COPY <table> TO '/path'`, `COPY <table> FROM '/path'`.
- `COPY <table> TO PROGRAM '<cmd>'`, `COPY <table> FROM PROGRAM '<cmd>'`.
- `COPY (SELECT ...) TO STDOUT`.
- Redshift `UNLOAD <q> TO 's3://...'`.
- Redshift `COPY <t> FROM 's3://...'`.

**DDL forms:**

- `CTAS` and `SELECT INTO` (effect `[schema_create, read]`).
- Data-modifying CTEs with and without `RETURNING`.
- `EXPLAIN ANALYZE` of mutating statements (matches inner).
- `EXPLAIN` (without `ANALYZE`) of mutating statements (`read`).
- `MERGE`.
- `CALL`, `DO`, anonymous `$$ ... $$` blocks.
- `CREATE DATABASE mydb`.
- `CREATE TABLESPACE ts LOCATION '/mnt/ssd'` → primary `unsafe_io`.
- `CREATE PUBLICATION pub FOR TABLE t` → primary `schema_create`.
- `CREATE SUBSCRIPTION sub CONNECTION '...' PUBLICATION pub` → primary `unsafe_io`.
- `CREATE SERVER s FOREIGN DATA WRAPPER postgres_fdw OPTIONS (host '...', port '5432')` → primary `unsafe_io`.
- `CREATE USER MAPPING FOR user SERVER s OPTIONS (user '...', password '...')` → primary `unsafe_io`.
- `SECURITY LABEL FOR provider ON COLUMN tab.col IS 'classified'` → `privilege` (subtype `security_label`).
- `DROP TABLESPACE ts`.

**Session manipulation:**

- `SET search_path`, `SET application_name`, `SET role`, `SET SESSION AUTHORIZATION`, `SET LOCAL`.
- `RESET`, `RESET ALL`.
- `DISCARD ALL`, `DISCARD TEMP`, `DISCARD PLANS`, `DISCARD SEQUENCES`.

**Temp table lifecycle:**

- `CREATE TEMP TABLE` followed by unqualified reference (asserts `maybe_temp_shadowed`).
- `DROP`, `DISCARD TEMP`, `ON COMMIT DROP`.

**Unsafe I/O:**

- All `unsafe_io` function calls listed in Appendix B.
- `dblink` and `postgres_fdw` access.

**Privilege-vs-schema disambiguation:**

- `ALTER SYSTEM` (asserts `privilege` subtype `alter_system`, not `schema_alter`).
- `pg_read_server_files` GRANT (asserts `privilege`, not function call).
- `REINDEX` (asserts `maintenance` only, not `schema_alter`).

**Sub-protocol cases:**

- FunctionCall sub-protocol message (asserts `ErrorResponse + ReadyForQuery`, not `FunctionCallResponse`).
- CancelRequest with valid synthetic mapping → translated and forwarded.
- CancelRequest with unmatched mapping → suspicious event, client closed.
- CancelRequest with expired mapping → benign event, client closed.
- BackendKeyData collision retry exhaustion at connection setup → connection setup fails.

**Effect-set bypass cases (must explicitly fail closed):**

- `COPY (DELETE FROM u RETURNING *) TO STDOUT` with deny-DELETE allow-EXPORT policy → deny.
- `INSERT INTO log SELECT * FROM x` with allow-READ deny-INSERT → deny.
- `WITH d AS (DELETE FROM u RETURNING *) SELECT * FROM d` with allow-READ deny-DELETE → deny.

**Per-effect object attribution:**

- `INSERT INTO audit_log SELECT * FROM users` → effect `[write:audit_log, read:users]`. Policy "allow write to audit_log, allow read to users" → allow.
- `INSERT INTO users SELECT * FROM audit_log` → effect `[write:users, read:audit_log]`. Same policy → deny (write to users uncovered).

**Multi-object coverage cases:**

- `SELECT * FROM allowed JOIN allowed_2` with allow rule covering both → allow.
- `SELECT * FROM allowed JOIN sensitive` with allow rule covering only `allowed` → implicit_deny → deny.
- `SELECT * FROM allowed JOIN sensitive` with deny on `sensitive` → deny.

**Per-effect resolution divergence:**

- `INSERT INTO public.audit_log SELECT * FROM users` after `SET search_path = ...` → write effect `qualified_syntactic`, read effect `ambiguous_after_search_path`. Top-level → `ambiguous_after_search_path`.

**Risk-tier-first primary selection:**

- `CREATE SUBSCRIPTION ...` → primary `unsafe_io`, not `schema_create`.
- `CREATE PUBLICATION ...` → primary `schema_create` (no unsafe_io effect).
- `COPY (SELECT) TO '/tmp/x.csv'` → primary `unsafe_io`, not `bulk_export`.

**In-transaction deny cases:**

- `BEGIN; DELETE FROM users` with deny-DELETE policy under `deny_mode_in_tx: terminate` → upstream connection closed.
- Same with `deny_mode_in_tx: rollback_then_continue` → ROLLBACK injected, ReadyForQuery(I) to client.
- Parse-time deny inside transaction → upstream still terminated/rollback'd.

**Audit semantics:**

- `SELECT * FROM customers` with `audit` rule on customers → forward + tag.
- `SELECT * FROM customers JOIN orders` with audit-on-customers, no rule on orders → deny (orders uncovered).

**Approve semantics:**

- `SELECT * FROM allowed JOIN needs_approval` with allow on allowed, approve on needs_approval → approve.
- `SELECT * FROM uncovered JOIN needs_approval` with approve on needs_approval only → deny (uncovered not covered).

**`match_object_resolution` per-effect:**

- `INSERT INTO public.audit_log SELECT * FROM users` with `match_object_resolution: qualified_syntactic` rule on the read effect → does not match because read effect is `unqualified_syntactic` for `users`.

**GUC normalization:**

- `SET TimeZone='UTC'` matches `objects: ["timezone"]`.
- `SET TIMEZONE='UTC'` matches the same.
- `SET timezone='UTC'` matches the same.

**Startup-packet cases:**

- SSLRequest → SSL handshake → StartupMessage.
- GSSENCRequest → response `N`; client retries with non-GSSENC.
- GSSENCRequest under `allow_gss_encryption: true` → passthrough; emits `degraded_visibility_warning`.
- StartupMessage with `replication=database` → ErrorResponse + close (default).
- StartupMessage with `replication=database` under matching `match_kind: replication` allow rule → passthrough; emits `degraded_visibility_warning`.

**Negative path:**

- Malformed wire frames (truncated Parse, oversized message).
- Parse failures.
- Cockroach-specific syntax (parse-fail expected → `unknown`).
- Redshift first-keyword fallback for `UNLOAD`.

Each entry is a `(wire_bytes_in, expected_classification, expected_decision_under_sample_policy)` tuple. CI fails on any mismatch. Corpus is versioned alongside the spec; new entries are added in subsequent revisions.

---

## 21. Glossary

- **Operation group:** One of the 18 stable categories defined in §5.
- **Operation subtype:** Optional finer-grained label within a group, defined in §5.1.
- **Effect:** A `{group, subtype, objects, object_resolution}` tuple describing one kind of impact a statement has on the database.
- **Effect set / effect list:** The list of all effects on a statement. Always non-empty; first entry is the primary, ordered by risk-tier-first per §5.2.
- **Primary effect:** The effect with the highest risk tier, used as the headline classification.
- **Secondary effects:** Additional effects beyond the primary; participate fully in policy evaluation, not audit-only.
- **Per-effect evaluation:** Policy decision algorithm where each effect is matched independently against the rule list, with the final decision being the most-restrictive across effects.
- **Strict object coverage:** For an effect to be allowed, every object in its object set must be covered by at least one allow / audit / approve rule, and no object may be matched by a deny rule.
- **Asymmetric matching:** Allow / audit / approve use strict coverage; deny uses any-object match.
- **Risk-tier-first ordering:** Primary effect is the effect with the highest risk tier; ties broken by canonical group order then stable AST traversal order (§5.2).
- **Order-independent evaluation:** Rule position in the policy file does not affect outcomes. Deny matches anywhere produce deny; allow / audit / approve rules contribute to coverage; most-restrictive verb wins. Operators may reorder rules for readability without changing semantics. (§10.2, §10.4.)
- **Per-effect resolution:** Confidence tag on object identity, computed and stored independently for each effect.
- **`implicit_deny`:** The effect-level decision when no rule covers the effect (or some object in it is uncovered). Equivalent to `deny` for restrictiveness purposes.
- **Most-restrictive decision:** `deny ≡ implicit_deny > approve > audit > allow`.
- **Audit (as decision):** Allow-with-observation. The statement is forwarded to the database; the event carries `decision.verb: "audit"`. **Not a block.**
- **Coverage (for an object):** An allow / audit / approve rule that matches the effect's group/subtype/resolution and whose `objects:` glob matches that specific object (or whose `objects:` clause is absent, which covers all objects).
- **Classifier:** Per-protocol component that parses a wire frame into a `ClassifiedStatement`.
- **DBEvent:** Normalized per-statement event emitted by the proxy.
- **db_service:** Operator-named upstream database, analogous to `http_services`.
- **Channel binding:** TLS-channel binding for SCRAM-SHA-256-PLUS. Defeats naive MITM.
- **Credential broker (Phase 4):** Component that holds upstream DB credentials and authenticates to upstream on the agent's behalf, so the agent never possesses production DB credentials.
- **Bypass attempt:** A process tries to reach a protected DB outside the proxy path.
- **Object resolution:** Tag indicating confidence of object identity (qualified_syntactic / unqualified_syntactic / ambiguous_after_search_path / maybe_temp_shadowed / unresolved).
- **Sync window:** The Postgres Extended Query messages between two `Sync` frames.
- **`upstream_dirty_since_sync`:** State flag tracking whether forwarded messages have made upstream's state non-idle since the last `Sync`. See §14.2.
- **Statement rule:** A `database_rules` entry. Requires terminate-mode TLS.
- **Connection rule:** A `database_connection_rules` entry. Works under any TLS mode, with field matchability constrained per §13.2.
- **Synthetic BackendKeyData:** Proxy-generated `(pid, secret)` pair issued to the client. Maps to real upstream `BackendKeyData` in a proxy-side table for CancelRequest translation. Mapping is committed before the synthetic value is sent to the client (§15.1).
- **Degraded-visibility event:** Event emitted when a connection enters passthrough or passthrough-equivalent state due to operator opt-in (replication or GSSENC). See §11.1.
- **SessionID:** AgentSH's per-session process-tracking primitive, set at ptrace attach. Network rules and listener authentication are SessionID-keyed (§12.4, §12.5). Inherited by child processes within a session; supervisor-assigned at session creation; not forgeable from inside the agent's session.
- **Listener authentication:** Inbound-connection authentication at the proxy's Unix-socket listener. Uses SO_PEERCRED to resolve peer pid → SessionID and rejects connections from non-agent sessions (§12.5).

---

## 22. References

- AgentSH README and policy model: `https://github.com/canyonroad/agentsh`
- Watchtower Transport Protocol (WTP) v0.4.9 — for `context_digest` semantics and OCSF mapper integration.
- OCSF 1.8.0 schema, class 6005 Datastore Activity.
- PostgreSQL Frontend/Backend Protocol v3 (chapter 54).
  - Message Flow (54.2).
  - Cancellation (54.2.4).
  - SASL Authentication and SCRAM-SHA-256-PLUS channel binding (54.3).
  - FunctionCall sub-protocol (54.2.4).
  - PREPARE / EXECUTE (sql-prepare).
- libpg_query / `pg_query_go`.
- Amazon Redshift `UNLOAD` and `COPY` documentation.

---

## 23. Engineering Handoff

This is the implementation-frozen revision. Phase 1 implementation should produce three artifacts in this order:

### 23.1 Classifier golden corpus (table-driven tests)

Per §20. Build the corpus first; it pins behavior before any code that interprets it. Each entry: `(wire_bytes_in, expected_classification, expected_decision_under_sample_policy)`. CI fails on mismatch. The corpus lives next to the classifier code as test fixtures.

### 23.2 Protocol state machine documentation

A separate engineering doc covering, in detail:

- Startup-packet routing (§11.1).
- Extended Query state machine including `upstream_dirty_since_sync` transitions (§14.2).
- Transaction state tracking and `deny_mode_in_tx` flows (§14.3, §14.4).
- CancelRequest mapping lifecycle (§15).
- COPY data-frame handling for the duration of `bulk_load`/`bulk_export` operations.

This doc is internal-engineering, not customer-facing; it cross-references this spec but goes deeper into implementation invariants.

### 23.3 Policy evaluator tests

Per §20. The policy evaluator should be implementable and testable independently of the wire protocol — given a `ClassifiedStatement` and a `RuleSet`, produce a `Decision`. This isolation lets us nail down the algorithm before the socket-proxying complexity arrives.

Required test categories:

- Strict object coverage (allow, audit, approve cases).
- Implicit deny on uncovered objects.
- `audit` as coverage (forward + tag).
- `approve` does not extend coverage to unrelated objects.
- Deny precedence over allow / audit / approve.
- `match_object_resolution` per-effect.
- Multi-effect statements with mixed decisions.
- Risk-tier-first primary effect ordering.

### 23.4 Recommended implementation order

1. Operation taxonomy as Go types (groups, subtypes, aliases).
2. Effect data model and canonical ordering.
3. Policy evaluator (with the test suite from §23.3).
4. Postgres SQL classifier (libpg_query bindings, with the corpus from §23.1).
5. pgproto3 wire framing and Simple Query path.
6. Extended Query path with `upstream_dirty_since_sync`.
7. Startup-packet routing and TLS modes.
8. CancelRequest mapping.
9. Transaction state tracking and `deny_mode_in_tx`.
10. Unavoidability bundle generation from `db_services` config.
11. Integration tests against real Postgres, Aurora PG, Redshift, CockroachDB.

The first four steps can be built and tested without any socket code. That's the right place to start.

---

## Appendix A: Roadmap protocol mappings (design only)

These mappings are part of v0.7 design scope (so the architecture is coherent), but no code is shipped for them in Phase 1. Each becomes its own implementation spec in later phases.

### A.1 MySQL / MariaDB (Phase 3)

Same operation taxonomy as Postgres. Notable mappings:

- `LOAD DATA INFILE` (server-side path) → `unsafe_io`.
- `LOAD DATA LOCAL INFILE` (client-side path) → `bulk_load`.
- `SELECT ... INTO OUTFILE`, `SELECT ... INTO DUMPFILE` → `unsafe_io` with secondary `bulk_export`.
- `HANDLER` → `read` (read-only cursor API).
- `CALL` → `procedural`.
- `LOAD XML`, `LOAD INDEX INTO CACHE` → `bulk_load`.

Classifier: `pingcap/parser` (TiDB's parser; MySQL-compatible).

### A.2 MongoDB (Phase 5)

- Wire framing: OP_MSG only for data ops. **OP_QUERY remains permitted only for the connection handshake (`hello` and `isMaster`)**; legacy data OP_QUERY/OP_INSERT/OP_UPDATE/OP_DELETE return a structured driver-upgrade error.
- Classification key: first BSON field of the OP_MSG body.
- Mapping highlights:
  - `find`, `count`, `distinct`, `listCollections`, `listIndexes`, `dbStats`, `collStats`, `getMore`, `explain` → `read`.
  - `aggregate` walked end-to-end. Pipelines containing `$out` or `$merge` → `unsafe_io`. Pipelines containing `$function` or `$accumulator` (server-side JS) → `procedural`.
  - `insert` → `write`.
  - `update`, `findAndModify` (with `update` field) → `modify`.
  - `delete`, `findAndModify` with `remove: true` → `delete`.
  - `bulkWrite` classified per sub-op; batch-decision rule applies.
  - `create`, `createIndexes`, `createView`, `createSearchIndex` → `schema_create`.
  - `collMod`, `renameCollection`, `updateSearchIndex` → `schema_alter`.
  - `drop`, `dropDatabase`, `dropIndexes`, `dropSearchIndex` → `schema_destroy`.
  - `createUser`, `updateUser`, `dropUser`, `grantRolesToUser`, `revokeRolesFromUser`, `createRole`, `dropRole` → `privilege`.
  - `eval` (deprecated) → `procedural`.
  - `mapReduce` with `out` to a collection → `unsafe_io`. `mapReduce` inline → `procedural`.

Default-deny on aggregation pipelines unless a rule covers all classification outcomes.

### A.3 Snowflake (Phase 6)

- Reached via existing `http_services` proxy.
- Statement extracted from `request.body.statement`.
- **Classification is keyword/command-family only**, not AST-grade. `EXECUTE IMMEDIATE`, `EXECUTE IMMEDIATE FROM`, `PUT`, `GET`, scripting blocks, `COPY INTO <location>` are Snowflake-specific.
- Default deployment recommendation: read-only allowlist plus deny/approve for everything else.
- `MULTI_STATEMENT_COUNT` parameter must be inspected. Multi-statement requests classified per-statement; batch decision most-restrictive-wins.
- Snowflake-specific:
  - `COPY INTO <table> FROM <stage|s3>` → `bulk_load`.
  - `COPY INTO <location>` → `bulk_export` with secondary `unsafe_io`.
  - `PUT`, `GET` → `unsafe_io`.
  - `CREATE STAGE`, `CREATE STORAGE INTEGRATION`, `CREATE EXTERNAL FUNCTION` → `privilege`.
  - `EXECUTE IMMEDIATE`, `EXECUTE IMMEDIATE FROM` → `procedural`.

The same handler shape extends to BigQuery (`POST /bigquery/v2/projects/{p}/queries`) and Databricks (`POST /api/2.0/sql/statements`) in Phase 6.

---

## Appendix B: Postgres `unsafe_io` and `bulk_export` reference table

Authoritative list of Postgres primitives that escape the database engine, for the Phase 1 classifier implementation. Updated to reflect §7.3's risk-tier-first ordering: external-connectivity DDL (CREATE/ALTER/DROP SUBSCRIPTION/SERVER/USER MAPPING and CREATE TABLESPACE LOCATION) appears with `unsafe_io` as primary.

| Primitive | Primary | Secondary |
|-----------|---------|-----------|
| `COPY <table> TO STDOUT` (or `COPY (<query>) TO STDOUT`) | `bulk_export` | `[read]` |
| `COPY <table> FROM STDIN` | `bulk_load` | |
| `COPY <table> TO '<path>'` | `unsafe_io` | `[bulk_export, read]` |
| `COPY <table> FROM '<path>'` | `unsafe_io` | `[bulk_load]` |
| `COPY <table> TO PROGRAM '<cmd>'` | `unsafe_io` | `[bulk_export]` |
| `COPY <table> FROM PROGRAM '<cmd>'` | `unsafe_io` | `[bulk_load]` |
| `lo_import('<path>')`, `lo_export(oid, '<path>')` | `unsafe_io` | |
| `pg_read_file(...)`, `pg_read_binary_file(...)` | `unsafe_io` | |
| `pg_ls_dir(...)`, `pg_ls_logdir(...)`, `pg_ls_waldir(...)` | `unsafe_io` | |
| `pg_stat_file(...)` | `unsafe_io` | |
| `dblink(...)`, `dblink_exec(...)`, `dblink_open(...)`, `dblink_send_query(...)` | `unsafe_io` | |
| `postgres_fdw` foreign-table access | (verb of statement) | `[unsafe_io]` |
| `file_fdw` foreign-table access | (verb of statement) | `[unsafe_io]` |
| `xml2` / `pgxml` URL-fetching extensions | `unsafe_io` | |
| `CREATE SUBSCRIPTION`, `ALTER SUBSCRIPTION`, `DROP SUBSCRIPTION` | `unsafe_io` | `[schema_create / schema_alter / schema_destroy]` |
| `CREATE SERVER`, `ALTER SERVER`, `DROP SERVER` (foreign data wrappers) | `unsafe_io` | `[schema_create / schema_alter / schema_destroy]` |
| `CREATE USER MAPPING`, `ALTER USER MAPPING`, `DROP USER MAPPING` | `unsafe_io` | `[privilege]` |
| `CREATE TABLESPACE ts LOCATION '/path'` | `unsafe_io` | `[schema_create]` |
| `ALTER TABLESPACE ... SET LOCATION` | `unsafe_io` | `[schema_alter]` |
| Redshift `UNLOAD <q> TO 's3://...'` | `bulk_export` | `[unsafe_io, read]` |
| Redshift `COPY <t> FROM 's3://...'` | `bulk_load` | |
| `ALTER SYSTEM` | `privilege` | |
| `GRANT pg_read_server_files TO ...`, `GRANT pg_write_server_files TO ...` | `privilege` | |

`pg_read_server_files` and `pg_write_server_files` are Postgres roles, not functions. They appear here only as targets of `GRANT`/`REVOKE`, classified as `privilege`. Functions for filesystem access are listed separately above.
