# db-access Plan 03 — PostgreSQL Classifier (design)

Status: design approved 2026-05-09. Implementation plan to follow via writing-plans.

Cross-references:
- Roadmap: `docs/superpowers/specs/2026-05-08-db-access-phase-1-roadmap-design.md` §3 Plan 03.
- Spec: `docs/agentsh-db-access-spec.md` v0.8 §6 (object scoping), §7 (per-protocol classification), §20 (corpus), Appendix B (`unsafe_io` / `bulk_export` reference).
- Predecessors: Plans 01 (`internal/db/effects`, `internal/db/events`, `internal/db/service`) and 02 (`internal/db/policy/`, `MustLoadSample`) already shipped.

This document captures the package-shape and interface decisions the spec leaves to the implementer. The §7.3 mapping table and §20 corpus categories are authoritative upstream and are not re-derived here.

## 1. Scope

In scope:

- `internal/db/classify/postgres/` package: `Parser` interface, `Classify`, `ApplyStatement`, `SessionState`, `Options`, `Dialect`.
- libpg_query bindings via two build paths producing the *same* AST type:
  - `pganalyze/pg_query_go` on `linux && cgo`.
  - `wasilibs/go-pgquery` (libpg_query compiled to WASM, run on `wazero`) elsewhere.
- AST→effect mapping per §7.3 + Appendix B, including object-attribution per §6.
- Multi-statement composition (one `ClassifiedStatement` per top-level `RawStmt`).
- §7.6 escalation knob (`EscalateUnknownFunctions` + safe-function allowlist).
- §7.7 dialect dispatch: `postgres`, `aurora_postgres`, `cockroachdb`, `redshift`, with a minimal first-keyword Redshift fallback for `UNLOAD ... TO 's3://...'` and `COPY ... FROM 's3://...'`.
- §7.8 failure semantics: parse failures, unmapped forms, and empty input all produce `[]ClassifiedStatement` with `err == nil`.
- `cmd/dbclassify-pg`: CLI tool reading SQL on stdin, printing `ClassifiedStatement` JSON + sample-policy decision.
- SQL-text-driven golden corpus under `internal/db/classify/postgres/corpus/`.
- Schema bump: `effects.ClassifiedStatement` gains an `Error string` field.

Out of scope (deferred to later plans):

- pgproto3 wire framing, malformed-frame handling (Plan 04).
- Extended Query state machine, PREPARE/EXECUTE wire-protocol cache, COPY data-frame handling (Plan 05).
- DBEvent emission (Plan 04+).
- CancelRequest mapping (Plan 06).
- Catalog-aware resolution, view rewriting, column-level metadata gating (Phase 2/7).
- FunctionCall sub-protocol OID resolution (Phase 2).

## 2. Architectural decisions

These four decisions were settled during brainstorming and govern the rest of the design.

**D1. Single AST source via dual embedding.** The Linux+CGO build links native libpg_query through `pganalyze/pg_query_go`; every other build embeds the same libpg_query compiled to WASM via `wasilibs/go-pgquery` and runs it through `wazero`. The protobuf AST type is identical on both paths, so `ast_walk.go` is platform-agnostic. The `ParserBackend` enum (already in `effects.ClassifiedStatement`) records which embedding produced a given classification — useful for DBEvent triage but never a semantic difference. Cross-validation collapses to a single CI smoke test that runs the corpus under both build tags and asserts JSON equality.

**D2. Pure-functional classifier with explicit `SessionState` input.** The package exposes `Classify(sql, sess, opts)` and a sibling `ApplyStatement(sess, classified) → sess`. No goroutines, no I/O, no per-connection caches. Plan 04+ owns per-connection state, calls `Classify` first, evaluates against policy (Plan 02), and only invokes `ApplyStatement` after upstream confirms the statement succeeded. This matches Plans 01/02's discipline and lets the corpus express session-aware fixtures (`SET search_path` then unqualified `INSERT`) by synthesizing `SessionState` per row.

**D3. SQL-text-driven corpus.** Each fixture is a YAML file with `{sql, dialect, session?, options?, expected_classification, expected_decision}`. The corpus is the classifier's contract. Wire-byte fixtures (Q-frame body bytes, malformed frames) are a Plan 04 concern — the classifier never sees raw frames. The `corpus/sample-policy.yaml` referenced in `expected_decision` is loaded via `policy.MustLoadSample()` (already shipped in Plan 02); modifying it is a Plan 02 change that triggers a corpus re-pin step.

**D4. `Error string` on `ClassifiedStatement`.** Plan 01 didn't ship this field because Plan 02 didn't need it. Plan 03 adds it so §7.8 failure semantics — parse failure, unmapped form — can carry the reason through to the eventual DBEvent (`result.error_code` in §8). The field is empty for successful classifications. Tests in `internal/db/effects` are extended only to cover the new field's zero value and JSON round-trip; the existing semantics are unchanged.

## 3. Package layout

```
internal/db/classify/postgres/
├── parser.go              # public surface: Parser interface, New, Classify wrapper,
│                          # SessionState, Options, Dialect, ApplyStatement
├── libpgquery.go          # //go:build linux && cgo  — pganalyze/pg_query_go
├── wasm.go                # //go:build !linux || !cgo — wasilibs/go-pgquery on wazero
├── ast_walk.go            # AST → []ClassifiedStatement (shared, takes pg_query AST)
├── object.go              # RangeVar / GUC / role / path / program extraction
├── connstring.go          # libpq keyword-value + URI parser (small, vendored)
├── escalation.go          # §7.6 SELECT volatile_function() escalation
├── redshift.go            # first-keyword fallback for UNLOAD / COPY FROM s3://
├── session.go             # ApplyStatement, SessionState type, SET / DISCARD / RESET handlers
├── corpus/
│   ├── _schema.go         # corpus row struct + loader
│   ├── 0001-select.yaml
│   ├── 0002-insert.yaml
│   ├── ...
│   └── corpus_test.go     # iterates *.yaml, asserts classify + evaluate
└── *_test.go              # unit tests per file (object_test.go, session_test.go, …)

cmd/dbclassify-pg/
└── main.go                # SQL on stdin, JSON on stdout

internal/db/effects/
├── statement.go           # MODIFIED: add Error string field
└── statement_test.go      # MODIFIED: extend table for Error field
```

Build constraints:

- `parser.go`, `ast_walk.go`, `object.go`, `connstring.go`, `escalation.go`, `redshift.go`, `session.go`, `corpus/*.go` build on every platform.
- `libpgquery.go` is `//go:build linux && cgo`.
- `wasm.go` is `//go:build !linux || !cgo`.
- `cmd/dbclassify-pg` builds on every platform (it imports the platform-agnostic `parser.go`).
- `GOOS=windows go build ./...` continues to pass per CLAUDE.md.

## 4. Public surface

```go
package postgres

// Dialect dispatches between Postgres-family parsers per spec §7.7.
type Dialect uint8

const (
    DialectPostgres       Dialect = iota + 1
    DialectAuroraPostgres
    DialectCockroachDB
    DialectRedshift
)

// Options carries per-call tunables. Defaults are zero-valued and safe.
type Options struct {
    EscalateUnknownFunctions bool
    SafeFunctionAllowlist    map[string]struct{} // case-insensitive function name set
}

// SessionState captures the per-connection state that affects resolution
// tagging. Owned by the proxy (Plan 04+); the classifier reads it only.
type SessionState struct {
    SearchPath        []string            // lowercased, ordered
    DefaultSearchPath []string            // restored by RESET search_path / DISCARD ALL
    TempTables        map[string]struct{} // unqualified names
    Role              string              // SET ROLE / SET SESSION AUTHORIZATION
    DefaultRole       string
    InTransaction     bool                // BEGIN/COMMIT/ROLLBACK tracked here as a hint;
                                          // Plan 05 owns authoritative tx state
}

// Parser is the single public surface. Implementations are returned by New.
type Parser interface {
    Classify(sql string, sess SessionState, opts Options) ([]effects.ClassifiedStatement, error)
}

// New returns the parser for the given dialect, using whichever libpg_query
// embedding the active build tag selected.
func New(d Dialect) Parser

// ApplyStatement evolves session state after the proxy has confirmed the
// statement succeeded upstream. Pure function; no I/O.
func ApplyStatement(s SessionState, c effects.ClassifiedStatement) SessionState
```

Everything else in the package is unexported.

## 5. Data flow

For Plan 03 the flow is contained — there is no proxy, no goroutines, no I/O. The lifecycle is captured here so Plan 04 has a clear contract to wire against.

```
caller (Plan 04 proxy / cmd / corpus test)
   │
   │  sql, sess, opts
   ▼
Parser.Classify(sql, sess, opts)
   │
   ├─ backend.parse(sql) ──────────► libpg_query AST  (or parse error)
   │       │
   │       └─ Redshift dialect: on err, redshift.firstKeyword(sql)
   │
   ├─ for each top-level RawStmt in AST (source order):
   │     ast_walk.classify(stmt, sess, opts) →
   │       ├─ extract objects per kind (object.go, connstring.go)
   │       ├─ apply §7.6 escalation if opts.EscalateUnknownFunctions
   │       ├─ tag resolution per §6.1 against sess.SearchPath / sess.TempTables
   │       └─ canonicalize effect order per effects.Order (§5.2)
   │
   ▼
[]ClassifiedStatement, nil

# After Plan 04 forwards and upstream confirms success:
sess = postgres.ApplyStatement(sess, classified)
```

`Classify` returns a Go `error` only on infrastructure failure (e.g. WASM module fails to initialize). SQL-level problems — parse failures, unmapped forms — produce a `ClassifiedStatement` with `Effects: [{Group: GroupUnknown}]` and a non-empty `Error`, with `err == nil`.

## 6. SessionState evolution rules

`ApplyStatement` is the single place this knowledge lives. Each rule implements the corresponding §7.3 row.

| Statement form | Mutation |
|---|---|
| `SET search_path = a, b, c` | Replace `SearchPath` with lowercased identifiers. |
| `SET LOCAL search_path = …` | Tag-only; `SearchPath` unchanged. Plan 05 owns the per-tx revert. |
| `RESET search_path` | `SearchPath = DefaultSearchPath`. |
| `RESET ALL` | `SearchPath = DefaultSearchPath`; `Role = DefaultRole`; clear `TempTables`. |
| `DISCARD ALL` | Same as `RESET ALL` plus clear `TempTables`. |
| `DISCARD TEMP` | Clear `TempTables`. |
| `DISCARD PLANS`, `DISCARD SEQUENCES`, `DEALLOCATE …` | No-op for `SessionState`. Plan 05's PREPARE cache reacts. |
| `SET ROLE r` / `SET SESSION AUTHORIZATION u` | `Role = r` (or `u`). |
| `SET ROLE NONE` / `RESET ROLE` | `Role = DefaultRole`. |
| `CREATE TEMP TABLE foo` | `TempTables[foo] = {}`. |
| `DROP TABLE foo` (unqualified) | `delete(TempTables, foo)` if present. |
| `BEGIN` / `START TRANSACTION` | `InTransaction = true` (hint only). |
| `COMMIT` / `ROLLBACK` | `InTransaction = false`. |

Schema-qualified `DROP TABLE public.foo` does not touch `TempTables` regardless of name overlap — temp-table DROPs are unqualified by spec.

## 7. Object attribution scope

Per §6 + Appendix B. The classifier extracts per-effect objects from the AST.

| Statement family | Extracted objects |
|---|---|
| DML (`SELECT`/`INSERT`/`UPDATE`/`DELETE`/`MERGE`) | `RangeVar` → `(schema, name)` per relation. Resolution per §6.1: qualified→`qualified_syntactic`; unqualified with `SearchPath == [DefaultSearchPath]`→`unqualified_syntactic`; unqualified with mutated `SearchPath`→`ambiguous_after_search_path`; unqualified name in `TempTables`→`maybe_temp_shadowed`. |
| `CREATE/ALTER/DROP TABLE/INDEX/VIEW/SEQUENCE/SCHEMA/FUNCTION/EXTENSION/TYPE/DOMAIN/AGGREGATE/TRIGGER` | `RangeVar` of the target object. |
| `CREATE/ALTER SUBSCRIPTION` | `(subscription, name)` + parsed `external_endpoint{host, port}` from the libpq connection string in `CONNECTION '…'`. |
| `CREATE/ALTER SERVER` | `(server, name)` + parsed `external_endpoint{host, port}` from the FDW `OPTIONS (host '…', port '…')` clause. |
| `CREATE/ALTER USER MAPPING` | `(user_mapping, "role@server")` + `role`. |
| `CREATE/ALTER TABLESPACE` | `(tablespace, name)` + `filesystem_path{path}` from `LOCATION '…'`. |
| `COPY <t> TO/FROM '<path>'` | `(table, …)` + `filesystem_path{path}`. |
| `COPY <t> TO/FROM PROGRAM '<cmd>'` | `(table, …)` + `program{argv0: <first whitespace-split token of cmd>}`. |
| `lo_import('<path>')` / `lo_export(oid, '<path>')` | `filesystem_path{path}`. |
| `pg_read_file(...)` / `pg_read_binary_file(...)` / `pg_ls_dir(...)` / `pg_stat_file(...)` | `filesystem_path{path}` from the literal path argument; if the argument is non-literal (column ref, function call), emit `filesystem_path{path: ""}` with resolution `unknown_dynamic`. |
| `CREATE/DROP/ALTER ROLE`, `GRANT/REVOKE`, `SET ROLE` | `(role, name)`. |
| `SET <var> = …` | `(guc, lowercased.dotted.name)`. |
| Redshift `UNLOAD <q> TO 's3://...'` | inner-`q` relations as `read` + `filesystem_path{path: "s3://..."}`. |
| Redshift `COPY <t> FROM 's3://...'` | `(table, …)` + `filesystem_path{path: "s3://..."}`. |

S3 URIs map to `filesystem_path` rather than `external_endpoint` because the latter is `{host, port}`-shaped and S3 URIs don't fit that schema. Flagged for spec-author confirmation; if the spec author prefers a separate `s3_object` kind, that lands in a v0.9 redline before Plan 04.

Non-literal arguments to `pg_read_file` and friends conservatively emit a path object with empty body and `unknown_dynamic` resolution rather than dropping the object — this lets policies that deny `unsafe_io` still match without depending on argument analysis.

## 8. Dialect dispatch

Per §7.7:

| Dialect | Behavior |
|---|---|
| `postgres` | `parse(sql)` via libpg_query. Parse failure → `unknown` with `Error`. Unmapped AST node → `unknown` with `Error: "unmapped form: <node_type>"`. |
| `aurora_postgres` | Identical to `postgres`. |
| `cockroachdb` | `parse(sql)` via libpg_query. Parse failure → `unknown` (Beta — many Cockroach forms will fail, which is the conservative default). |
| `redshift` | `parse(sql)` via libpg_query first. On parse failure, `redshift.firstKeyword(sql)` recognizes (case-insensitive, leading whitespace stripped): `UNLOAD '...' TO 's3://...'` → §7.3 row; `COPY <t> FROM 's3://...'` → §7.3 row. Anything else → `unknown`. Beta. |

The first-keyword Redshift fallback is intentionally minimal: extract the first keyword, peek at literal positions for the S3 URI, attribute objects, classify per §7.3. Operators who need broader Redshift coverage are expected to pair `dialect: redshift` with `decision: deny` defaults until Phase 2.

## 9. Error handling

Three failure modes, all returned with `err == nil`:

| Failure | Result |
|---|---|
| Parse failure | `ClassifiedStatement{Effects: [{Group: GroupUnknown}], Error: "parse: <msg>", ParserBackend: …, RawVerb: ""}` |
| Parsed cleanly, AST node not in §7.3 | `ClassifiedStatement{Effects: [{Group: GroupUnknown}], Error: "unmapped form: <node_type>", ParserBackend: …, RawVerb: ""}` |
| Empty / whitespace-only input | `[]ClassifiedStatement{}` (caller no-op) |

The only path that returns a Go `error` is **infrastructure failure**: WASM module fails to load at package init, or CGO call returns ENOMEM-class error. These are process-level and are not classifier-level concerns.

`ClassifiedStatement.Error` is empty for successful classifications and is JSON-omitempty so existing consumers see no schema change.

## 10. Cross-validation

Both backends are libpg_query → AST is byte-identical → cross-validation is structural rather than semantic. CI runs the corpus twice on Linux: once with `CGO_ENABLED=1` (selects `libpgquery.go`) and once with `CGO_ENABLED=0` (selects `wasm.go`). The two runs assert JSON equality of the resulting `ClassifiedStatement` slices. Single test, single assertion, no per-row exemptions.

This is a smoke test rather than a divergence ledger. If it ever fails, the failure points at a backend-binding bug (e.g. one path mishandles UTF-8 input), not at a spec-§7.3 ambiguity.

## 11. Testing

Five layers:

1. **Unit tests per file** — table-driven, in-package.
   - `object_test.go`: `RangeVar` matrix (`pg_temp.foo`, `public.foo`, `foo`, dollar-quoted identifiers, double-quoted identifiers).
   - `connstring_test.go`: libpq keyword-value (`host=foo port=5432 user=bar`) and URI (`postgresql://...`) round-trip; corner cases (escaped quotes, `host=foo,bar` multi-host).
   - `session_test.go`: `ApplyStatement` table covering each row in §6 of this doc.
   - `escalation_test.go`: `SELECT vol()` with allowlist on/off; nested function calls; CTE + function call.
   - `redshift_test.go`: first-keyword fallback for `UNLOAD`, `COPY FROM 's3://...'`, garbage input, well-formed-but-unknown forms.

2. **Corpus tests** — `corpus_test.go` iterates `corpus/*.yaml`, runs `Classify` + `policy.Evaluate(_, MustLoadSample(), …)`, asserts both `expected_classification` and `expected_decision` per row. Phase 1 baseline ≥ ~150 rows covering every §20 category. CI fails on any mismatch.

3. **Backend-parity smoke** — single test that classifies a representative subset of the corpus and asserts JSON equality between CGO and WASM outputs. Runs on Linux CI only (the only OS where both backends are available).

4. **Schema-bump regression** — `internal/db/effects/statement_test.go` extended to cover `Error` field zero value, JSON omitempty, and round-trip.

5. **Bench** — `bench_test.go` measures `Classify` throughput on a 50-statement representative workload (`SELECT`/`INSERT`/`EXPLAIN`/`COPY`/`CREATE TABLE` mix). Runs under both backends; informs operators of the perf delta. Not a CI gate.

## 12. CLI: `cmd/dbclassify-pg`

Single-purpose tool for spec authors and corpus extension. Reads SQL on stdin until EOF, prints a JSON object on stdout:

```json
{
  "dialect": "postgres",
  "statements": [
    {
      "raw_verb": "INSERT",
      "parser_backend": "libpg_query",
      "effects": [...],
      "error": "",
      "decision_under_sample_policy": {
        "verb": "deny",
        "matched_rules": ["app-deny-write-to-customers"],
        "reason": "..."
      }
    }
  ]
}
```

Flags:

- `-dialect=<postgres|aurora_postgres|cockroachdb|redshift>` (default `postgres`).
- `-search-path=<comma-separated>` for session-aware tagging.
- `-temp-tables=<comma-separated>` for shadow tagging.
- `-escalate-unknown-functions` to flip the §7.6 knob.
- `-no-evaluate` to print classification only (skip the sample-policy decision).

Useful in two workflows: humans reasoning about a fixture before adding it to the corpus, and scripts regenerating `expected_classification` after a deliberate spec change.

## 13. Cross-cutting

**Build matrix.** `GOOS=windows go build ./...` continues to pass via the WASM path. `GOOS=darwin` hits the WASM path. Native CGO is reserved for `linux && cgo`.

**Dependencies added.** Native libpg_query binding (`pganalyze/pg_query_go`, imported only from the `linux && cgo` file so non-CGO builds never link C) and the wasilibs WASM binding for libpg_query (which transitively pulls a WASM runtime — `wazero`, embedded module). Exact import paths to be confirmed during implementation against the latest tagged releases. Both projects are MIT/Apache-2.0 and actively maintained as of 2026-04. Vendoring policy unchanged.

**Schema bump impact.** `effects.ClassifiedStatement.Error` is JSON omitempty. Plan 02 callers (`policy.Evaluate`) ignore the field. No breaking change for shipped consumers.

**No reverse imports.** `internal/db/classify/postgres` imports `internal/db/effects` and `internal/db/policy`. Nothing in the `effects` or `policy` packages imports the classifier.

**Sample policy as ground truth.** Corpus rows reference decisions computed against `policy.MustLoadSample()`. Modifying `internal/db/policy/testdata/sample-policy.yaml` is a Plan 02 change that forces a corpus repin; CI catches drift.

## 14. Out of scope (re-confirmation)

- COPY data-frame handling (Plan 05).
- Wire-protocol framing, malformed-frame negative-path tests (Plan 04).
- PREPARE/EXECUTE wire-protocol cache (Plan 05).
- DBEvent emission (Plan 04+) — Plan 03 produces `ClassifiedStatement`s only.
- Catalog-aware resolution, view rewriting (Phase 2/7).
- FunctionCall sub-protocol OID resolution (Phase 2).
- Statement-text redaction *operation* — Plan 02 owns the config; Plan 04 owns the redactor (since redaction operates on the SQL string in-flight, not on the classification).

## 15. Done definition

Plan 03 is "done" when:

- `Parser.Classify` and `ApplyStatement` are implemented per §4 with both backends compiling and passing tests.
- The corpus covers every §20 category with ≥ ~150 rows, all green under both backends.
- `cmd/dbclassify-pg` builds on Linux, macOS, and Windows.
- `GOOS=windows go build ./...` passes on CI.
- `effects.ClassifiedStatement.Error` is shipped, documented, and JSON-omitempty.
- The roadmap's `expected_decision_under_sample_policy` column in the corpus is computed against `policy.MustLoadSample()` and CI gates on drift.
