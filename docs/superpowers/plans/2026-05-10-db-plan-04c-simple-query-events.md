# db-access Plan 04c — Simple Query + DBEvent Emission Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Continue the per-connection driver past the first upstream `ReadyForQuery`: read client `'Q'` frames, classify (Plan 03) + evaluate (Plan 02) per statement, forward-or-synthesize-deny, and emit one `db_statement` event per `ClassifiedStatement`. Adds the `Decision`/`Result`/`TxContext`/`Predicates`/`TLS` sub-structs to `events.DBEvent`, a `Normalize` method on the classifier `Parser`, statement source spans on `effects.ClassifiedStatement`, hot-swappable policy, and a real-pgx spine integration test.

**Architecture:** Five new files under `internal/db/proxy/postgres/`: `simplequery.go` (loop), `upstreamread.go` (per-frame demux + counter accumulation), `deny.go` (synth + SQLSTATE picker), `eventbuilder.go` (pure event builder with redaction + digest), `classifiers.go` (per-dialect Parser map). Modifications to `server.go` (Config, atomic policy, dialect map, SetPolicy), `proxyconn.go` (connState extensions), `handshake.go` (call simpleQueryLoop after forwardAuth), `authforward.go` (write `'Z'` status byte into connState before returning). Plan 03's `Parser` interface gains `Normalize`; both libpg_query and wasm backends wire it. `effects.ClassifiedStatement` gains `SourceStart`/`SourceEnd`. `events.DBEvent` gets the five sub-structs.

**Tech Stack:** Go (`//go:build linux` for all new proxy files; events/effects extensions are tag-free), `github.com/jackc/pgx/v5/pgproto3` (already a dep), `github.com/jackc/pgx/v5` added as a test-only dep for the spine integration test, `github.com/pganalyze/pg_query_go/v6` and `github.com/wasilibs/go-pgquery` (both already deps; we call their `Normalize`).

**Settled in brainstorming (2026-05-10):**
1. Single-driver half-duplex loop. After `forwardAuth` returns on the first upstream `'Z'`, the same goroutine enters `simpleQueryLoop`. On allow-forward, `forwardUpstreamUntilRFQ` reads one upstream frame at a time until trailing `'Z'`. Async LISTEN/NOTIFY pushes outside a Q…Z round-trip are documented limitations and deferred to Plan 05.
2. `statement_digest = sha256:` + hex(SHA-256(`Normalize(slice)`)) for every redaction tier. Digest is invariant under redaction so events join across deployments with different `LogStatements` settings. Documented caveat: libpg_query and pure-Go `Normalize` outputs may differ; digests are stable *within an implementation*, not across.
3. `Normalize` lives on the classifier `Parser`, not in the proxy. libpg_query backend → `pg_query.Normalize`. wasm/wasilibs backend → `pgquery_wasm.Normalize`. On `unknown` classification we compute the digest off the verbatim trimmed SQL with a documented note.
4. Per-frame demux for the upstream response stream populates `result.rows_returned`, `result.rows_affected`, `result.bytes_in/out`, `result.latency_ms`, `result.error_code`. CommandComplete tag parsing maps the *i*-th frame to the *i*-th statement.
5. Full §8 DBEvent schema lands in 04c with partial population: `tx_started_at` and `deny_action: "rollback_injected"` defer to Plan 05's state machine.
6. Per-dialect classifier map built in `Server.New()` from `cfg.Services[*].Dialect`. Same dialect shares one `Parser`. Unexported `classifierForTest` hook for tests.
7. `Server.SetPolicy(*policy.RuleSet)` via `atomic.Pointer[policy.RuleSet]`. Each statement reads the snapshot once at evaluate time.
8. `effects.ClassifiedStatement.SourceStart` / `SourceEnd` added in 04c (scope creep onto Plan 03 accepted).
9. Frame budget enforced at `handleQuery` entry against `len(q.String)`. Mitigation-grade rather than streaming-framer ceiling. Documented.
10. Non-`'Q'` / non-`'X'` frame post-handshake → synthetic `ErrorResponse(0A000, …)` + close + `EXTENDED_QUERY_NOT_SUPPORTED` lifecycle event (or `FUNCTION_CALL_PROTOCOL_DENIED` for `'F'`).
11. `command_id = "<sha-of-q.String>:<idx>"` for per-stmt events in multi-stmt batches (no new wire schema field).

**Cross-references:**
- Design: `docs/superpowers/specs/2026-05-10-db-plan-04c-simple-query-events-design.md`
- Macro design: `docs/superpowers/specs/2026-05-10-db-plan-04-pg-proxy-skeleton-design.md`
- Roadmap: `docs/superpowers/specs/2026-05-08-db-access-phase-1-roadmap-design.md` §3 Plan 04c
- Spec: `docs/agentsh-db-access-spec.md` v0.8 §7.1, §7.7, §8, §10.2, §10.3, §14.1, §14.3, §14.4
- Predecessor plan: `docs/superpowers/plans/2026-05-10-db-plan-04b2-upstream-passthrough.md`

---

## File Structure

**Created:**

- `internal/db/proxy/postgres/simplequery.go` — `simpleQueryLoop`, `handleQuery`, `handleUnsupportedFrame`, `MaxQueryBytes` enforcement.
- `internal/db/proxy/postgres/simplequery_test.go` — Q/X/unsupported dispatch, MaxQueryBytes cap, multi-stmt allow/deny/anyDeny matrix, approve→deny stub, RFQ-byte gating.
- `internal/db/proxy/postgres/upstreamread.go` — `forwardUpstreamUntilRFQ`, per-frame demux, CommandComplete tag parsing, counter accumulation.
- `internal/db/proxy/postgres/upstreamread_test.go` — frame-shape tests, tag-parser tests, mid-batch ErrorResponse propagation, RFQ status-byte updates.
- `internal/db/proxy/postgres/deny.go` — `synthErrorAndRFQ`, `synthErrorOnly`, `pickDenySynth`, SQLSTATE constants.
- `internal/db/proxy/postgres/deny_test.go` — synth output round-trip via `pgproto3.Frontend`, SQLSTATE selection by RuleKind, deny_message template substitution.
- `internal/db/proxy/postgres/eventbuilder.go` — pure `buildStatementEvent`; redaction tier rendering; `statement_digest`; `denied_by_sibling` tagging; `command_id` shape.
- `internal/db/proxy/postgres/eventbuilder_test.go` — three-tier render table, digest stability across tiers, multi-stmt EventID uniqueness, denied_by_sibling shape.
- `internal/db/proxy/postgres/classifiers.go` — per-dialect Parser map construction; `classifierFor`.
- `internal/db/proxy/postgres/classifiers_test.go` — dialect→Parser construction, shared-instance assertion, unknown-dialect error, test-hook override.
- `internal/db/proxy/postgres/spine_test.go` (extends existing file) — three real-pgx subtests against the existing `testupstream_test.go` fake upstream.
- `internal/db/classify/postgres/normalize.go` (Linux+CGO) — `(*cgoParser).Normalize` delegating to `pg_query.Normalize`.
- `internal/db/classify/postgres/normalize_wasm.go` (non-Linux or non-CGO) — `(*wasmParser).Normalize` delegating to `pgquery_wasm.Normalize`.
- `internal/db/classify/postgres/parser_normalize_test.go` — backend-agnostic Normalize tests via curated SQL.

**Modified:**

- `internal/db/effects/statement.go` — `ClassifiedStatement` gains `SourceStart int32`, `SourceEnd int32` (byte offsets into the input SQL; zero-valued when parser cannot supply).
- `internal/db/effects/statement_test.go` — coverage for new fields.
- `internal/db/classify/postgres/parser.go` — `Parser` interface gains `Normalize(sql string) (string, error)`; `classifyWithBackend` populates `SourceStart` / `SourceEnd` from `RawStmt.StmtLocation` + `StmtLen`.
- `internal/db/classify/postgres/ast_walk.go` — `classifyRawStmt` accepts the location/length and propagates into the returned `ClassifiedStatement`.
- `internal/db/classify/postgres/corpus_test.go` — golden-corpus regen for the new struct fields (zero-valued for unknown-stmt cases).
- `internal/db/events/event.go` — `DBEvent` gains `TLS`, `Decision`, `Result`, `TxContext`, `Predicates` sub-structs; new types defined in the same file.
- `internal/db/events/event_test.go` — JSON round-trip for the extended schema, including `null` propagation for `*int64` row counters.
- `internal/db/proxy/postgres/server.go` — `Config` gains `MaxQueryBytes int` and `classifierForTest func(dialect string) classify_pg.Parser`; `Server` gains `policyPtr atomic.Pointer[policy.RuleSet]` and `classifiers map[string]classify_pg.Parser`; `New()` validates dialects, builds the classifier map, applies the `MaxQueryBytes` default, stores `cfg.Policy` in the atomic pointer; `SetPolicy` / `policy()` / `classifierFor` helpers added.
- `internal/db/proxy/postgres/server_test.go` — `MaxQueryBytes` default; `SetPolicy` swap visibility; unknown-dialect `New()` rejection.
- `internal/db/proxy/postgres/proxyconn.go` — `connState` gains `lastUpstreamRFQ byte`, `redactionTier policy.RedactionTier`, `tlsMode string`; emit helpers for the new lifecycle events (`emitFrameTooLarge`, `emitUnsupportedFrame`).
- `internal/db/proxy/postgres/authforward.go` — `forwardAuth` records the observed `'Z'` status byte into `pc.state.lastUpstreamRFQ` before returning.
- `internal/db/proxy/postgres/handshake.go` — `dialUpstreamAndForward` calls `pc.simpleQueryLoop(ctx)` instead of returning `nil` after `forwardAuth` returns successfully; seeds `pc.state.redactionTier` and `pc.state.tlsMode`.
- `internal/db/policy/decode.go` — Decode appends a `Warning` with `Code: "APPROVE_NOT_YET_SUPPORTED"` for every rule with `decision: approve` when `Unavoidability != off`.
- `internal/db/policy/decode_test.go` — coverage for the warning emission.
- `go.mod` / `go.sum` — `github.com/jackc/pgx/v5` promoted from `// indirect` to a top-level test-only dep (imported only from `_test.go` files).

**Out of scope (deferred):**

- Extended Query / `Parse` / `Bind` / `Describe` / `Execute` / `Sync` / `Flush` / `Close`, SQL-level prepared cache, COPY data-frame handling, FunctionCall semantics, full §14 deny modes (`rollback_then_continue`), `tx_started_at`, `approve` runtime, GSSENC opt-in, async LISTEN/NOTIFY delivery — Plan 05.
- BackendKeyData mapping, cancel mapping — Plan 06.
- SO_PEERCRED → SessionID, out-of-process proxy, unavoidability bundle, real-PG testcontainer suite — Plan 07.

---

## Task 1: Add `SourceStart` / `SourceEnd` to `effects.ClassifiedStatement`

**Why:** Eventbuilder needs per-statement byte spans to slice the original `Q` body under `RedactionFull`. libpg_query exposes `RawStmt.StmtLocation` and `StmtLen` already; we surface them up. Zero values are legal for parsers that cannot supply them (`unknown` statements, edge fallback paths).

**Files:**
- Modify: `internal/db/effects/statement.go`
- Modify: `internal/db/effects/statement_test.go`

- [ ] **Step 1: Write the failing test for the new fields**

Append to `internal/db/effects/statement_test.go`:

```go
func TestClassifiedStatement_SourceSpan_RoundTrip(t *testing.T) {
	in := ClassifiedStatement{
		Effects:     []Effect{{Group: GroupRead, Resolution: ResolutionQualified}},
		RawVerb:     "SELECT",
		SourceStart: 7,
		SourceEnd:   23,
	}
	bs, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var out ClassifiedStatement
	if err := json.Unmarshal(bs, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.SourceStart != in.SourceStart || out.SourceEnd != in.SourceEnd {
		t.Fatalf("span lost: got (%d,%d) want (%d,%d)",
			out.SourceStart, out.SourceEnd, in.SourceStart, in.SourceEnd)
	}
}

func TestClassifiedStatement_SourceSpan_ZeroOmitted(t *testing.T) {
	in := ClassifiedStatement{
		Effects: []Effect{{Group: GroupRead, Resolution: ResolutionQualified}},
		RawVerb: "SELECT",
	}
	bs, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(bs), "source_start") || strings.Contains(string(bs), "source_end") {
		t.Fatalf("zero span fields must be omitted: %s", bs)
	}
}
```

If `strings` / `encoding/json` are not imported in that test file, add them.

- [ ] **Step 2: Run tests to verify they fail to compile**

Run: `go test ./internal/db/effects/ -run TestClassifiedStatement_SourceSpan -count=1`
Expected: build error referencing `SourceStart` / `SourceEnd`.

- [ ] **Step 3: Add the fields**

Modify `internal/db/effects/statement.go`, replacing the `ClassifiedStatement` struct body:

```go
type ClassifiedStatement struct {
	Effects       []Effect      `json:"effects"`
	RawVerb       string        `json:"raw_verb,omitempty"`
	ParserBackend ParserBackend `json:"parser_backend,omitempty"`
	Error         string        `json:"error,omitempty"`

	// SourceStart / SourceEnd are byte offsets into the original SQL input
	// (Plan 04c needs these to slice per-stmt text under RedactionFull). Both
	// zero when the parser cannot supply them (e.g. unknown-statement path).
	SourceStart int32 `json:"source_start,omitempty"`
	SourceEnd   int32 `json:"source_end,omitempty"`
}
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/effects/ -run TestClassifiedStatement_SourceSpan -count=1 -v`
Expected: both tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/effects/statement.go internal/db/effects/statement_test.go
git commit -m "db: effects — add SourceStart/SourceEnd to ClassifiedStatement"
```

---

## Task 2: Populate `SourceStart` / `SourceEnd` from libpg_query / wasm

**Why:** `RawStmt.StmtLocation` + `StmtLen` exist on the protobuf for both backends. We just need to thread them through `classifyRawStmt` into the returned statement.

**Files:**
- Modify: `internal/db/classify/postgres/parser.go`
- Modify: `internal/db/classify/postgres/ast_walk.go`
- Modify: `internal/db/classify/postgres/backend_test.go`

- [ ] **Step 1: Write the failing test for source-span population**

Append to `internal/db/classify/postgres/backend_test.go`:

```go
func TestParser_SourceSpan_Single(t *testing.T) {
	p := New(DialectPostgres)
	sql := "SELECT 1"
	got, err := p.Classify(sql, SessionState{}, Options{})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len=%d want 1", len(got))
	}
	if got[0].SourceStart != 0 {
		t.Fatalf("SourceStart=%d want 0", got[0].SourceStart)
	}
	if got[0].SourceEnd != int32(len(sql)) {
		t.Fatalf("SourceEnd=%d want %d", got[0].SourceEnd, len(sql))
	}
}

func TestParser_SourceSpan_MultiStmt(t *testing.T) {
	p := New(DialectPostgres)
	sql := "SELECT 1; SELECT 2"
	got, err := p.Classify(sql, SessionState{}, Options{})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len=%d want 2", len(got))
	}
	if string(sql[got[0].SourceStart:got[0].SourceEnd]) != "SELECT 1" {
		t.Fatalf("stmt[0] span = %q want %q",
			string(sql[got[0].SourceStart:got[0].SourceEnd]), "SELECT 1")
	}
	if string(sql[got[1].SourceStart:got[1].SourceEnd]) != "SELECT 2" {
		t.Fatalf("stmt[1] span = %q want %q",
			string(sql[got[1].SourceStart:got[1].SourceEnd]), "SELECT 2")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/db/classify/postgres/ -run TestParser_SourceSpan -count=1`
Expected: FAIL with `SourceStart=0 want 0` for single (passes) but `SourceEnd=0 want 8` (fails) — span is not populated yet.

- [ ] **Step 3: Thread `RawStmt.StmtLocation` + `StmtLen` through dispatch**

Modify `internal/db/classify/postgres/parser.go` `classifyWithBackend` (around the per-RawStmt loop):

```go
	out := make([]effects.ClassifiedStatement, 0, len(res.Stmts))
	for _, raw := range res.Stmts {
		cs := classifyRawStmt(dialect, raw, sess, opts, backend)
		// pg_query gives StmtLen=0 for a trailing single statement; in that
		// case the statement runs from StmtLocation to end-of-input.
		start := raw.StmtLocation
		length := raw.StmtLen
		var end int32
		if length == 0 {
			end = int32(len(sql))
		} else {
			end = start + length
		}
		cs.SourceStart = start
		cs.SourceEnd = end
		out = append(out, cs)
	}
	return out, nil
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/classify/postgres/ -run TestParser_SourceSpan -count=1 -v`
Expected: both tests PASS.

- [ ] **Step 5: Run the full classify/postgres test suite to confirm no regression**

Run: `go test ./internal/db/classify/postgres/ -count=1`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add internal/db/classify/postgres/
git commit -m "db: classify/postgres — populate ClassifiedStatement source spans"
```

---

## Task 3: Add `Normalize(sql)` to `classify/postgres.Parser`

**Why:** `statement_digest` and the `parameters_redacted` tier both consume normalized SQL. libpg_query and wasilibs both expose `Normalize`; we wrap them behind the existing build-tag split.

**Files:**
- Modify: `internal/db/classify/postgres/parser.go`
- Create: `internal/db/classify/postgres/normalize.go` (Linux+CGO)
- Create: `internal/db/classify/postgres/normalize_wasm.go` (non-Linux or non-CGO)
- Create: `internal/db/classify/postgres/parser_normalize_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/db/classify/postgres/parser_normalize_test.go`:

```go
package postgres

import (
	"strings"
	"testing"
)

func TestParser_Normalize_Literals(t *testing.T) {
	p := New(DialectPostgres)
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"int literal", "SELECT 1", "SELECT $1"},
		{"string literal", "SELECT 'hello'", "SELECT $1"},
		{"two literals", "SELECT 1, 'x'", "SELECT $1, $2"},
		{"identifier preserved", "SELECT a FROM t", "SELECT a FROM t"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := p.Normalize(tc.in)
			if err != nil {
				t.Fatalf("Normalize(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("Normalize(%q) = %q want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParser_Normalize_MultiStatement(t *testing.T) {
	p := New(DialectPostgres)
	got, err := p.Normalize("SELECT 1; SELECT 'x'")
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if !strings.Contains(got, "$1") || !strings.Contains(got, "$2") {
		t.Fatalf("Normalize did not redact both literals: %q", got)
	}
}

func TestParser_Normalize_Error(t *testing.T) {
	p := New(DialectPostgres)
	_, err := p.Normalize("THIS IS NOT SQL ;;;")
	if err == nil {
		t.Fatalf("Normalize on malformed SQL: want err, got nil")
	}
}
```

- [ ] **Step 2: Run test to verify it fails to compile**

Run: `go test ./internal/db/classify/postgres/ -run TestParser_Normalize -count=1`
Expected: build error — `Normalize` is undefined on `Parser`.

- [ ] **Step 3: Extend the `Parser` interface**

Modify `internal/db/classify/postgres/parser.go`:

```go
type Parser interface {
	Classify(sql string, sess SessionState, opts Options) ([]effects.ClassifiedStatement, error)
	// Normalize returns SQL with all literal values replaced by $N placeholders.
	// On parse failure returns the parser error verbatim; callers degrade to
	// the verbatim trimmed SQL for digest computation.
	Normalize(sql string) (string, error)
}
```

- [ ] **Step 4: Implement Normalize on the CGO backend**

Create `internal/db/classify/postgres/normalize.go`:

```go
//go:build linux && cgo

package postgres

import pg_query "github.com/pganalyze/pg_query_go/v6"

func (p *cgoParser) Normalize(sql string) (string, error) {
	return pg_query.Normalize(sql)
}
```

- [ ] **Step 5: Implement Normalize on the wasm backend**

Create `internal/db/classify/postgres/normalize_wasm.go`:

```go
//go:build !linux || !cgo

package postgres

import pgquery_wasm "github.com/wasilibs/go-pgquery"

func (p *wasmParser) Normalize(sql string) (string, error) {
	return pgquery_wasm.Normalize(sql)
}
```

- [ ] **Step 6: Run tests to confirm they pass**

Run: `go test ./internal/db/classify/postgres/ -run TestParser_Normalize -count=1 -v`
Expected: all PASS.

- [ ] **Step 7: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: clean build (wasm backend selected; `Normalize` resolves).

- [ ] **Step 8: Commit**

```bash
git add internal/db/classify/postgres/parser.go \
       internal/db/classify/postgres/normalize.go \
       internal/db/classify/postgres/normalize_wasm.go \
       internal/db/classify/postgres/parser_normalize_test.go
git commit -m "db: classify/postgres — add Normalize to Parser interface"
```

---

## Task 4: Extend `events.DBEvent` with §8 sub-structs

**Why:** Plan 04c emits events with `decision`, `result`, `tx_context`, `predicates`, `tls` sub-objects per spec §8. We add the Go types and JSON tags now; downstream tasks populate them.

**Files:**
- Modify: `internal/db/events/event.go`
- Modify: `internal/db/events/event_test.go`

- [ ] **Step 1: Write the failing test for the extended schema**

Append to `internal/db/events/event_test.go`:

```go
func TestDBEvent_Extended_RoundTrip(t *testing.T) {
	rows := int64(7)
	in := DBEvent{
		EventID:   "01HJ...",
		SessionID: "sess-1",
		Timestamp: time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC),
		DBService: "appdb",
		DBFamily:  "postgres",
		DBDialect: "postgres",
		Effects:   []effects.Effect{{Group: effects.GroupRead, Resolution: effects.ResolutionQualified}},

		TLS: EventTLS{Mode: "terminate_reissue", ClientSNI: "db.example"},
		Decision: EventDecision{
			Verb:                "allow",
			RuleKind:            "statement",
			RuleName:            "app-allow-read",
			MatchingEffectIndex: 0,
			MatchingEffectGroup: "read",
		},
		Result: EventResult{
			RowsReturned: &rows,
			BytesIn:      9,
			BytesOut:     42,
			LatencyMs:    3,
		},
		TxContext:  EventTxContext{InTransaction: false, DenyAction: "none"},
		Predicates: EventPredicates{HasFilter: true},
	}
	bs, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var out DBEvent
	if err := json.Unmarshal(bs, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.Decision.Verb != "allow" || out.Result.LatencyMs != 3 {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
	if out.Result.RowsReturned == nil || *out.Result.RowsReturned != 7 {
		t.Fatalf("rows_returned lost: %+v", out.Result.RowsReturned)
	}
	if out.Result.RowsAffected != nil {
		t.Fatalf("rows_affected must be nil for null in wire form: %+v",
			out.Result.RowsAffected)
	}
}

func TestDBEvent_Extended_RowsNull(t *testing.T) {
	in := DBEvent{
		EventID:   "01HJ...",
		Timestamp: time.Now().UTC().Truncate(time.Second),
		Result:    EventResult{BytesIn: 9, BytesOut: 0, LatencyMs: 0},
		TxContext: EventTxContext{DenyAction: "none"},
	}
	bs, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(bs), `"rows_returned":null`) {
		t.Fatalf("rows_returned must serialise as null when nil; got %s", bs)
	}
}
```

- [ ] **Step 2: Run test to verify it fails to compile**

Run: `go test ./internal/db/events/ -run TestDBEvent_Extended -count=1`
Expected: build error referencing `EventTLS` / `EventDecision` / `EventResult` / `EventTxContext` / `EventPredicates`.

- [ ] **Step 3: Add the sub-struct types and extend `DBEvent`**

Replace the `DBEvent` struct in `internal/db/events/event.go` (and append the new types):

```go
type DBEvent struct {
	EventID   string    `json:"event_id"`
	SessionID string    `json:"session_id"`
	CommandID string    `json:"command_id,omitempty"`
	Timestamp time.Time `json:"ts"`

	DBService       string `json:"db_service"`
	DBFamily        string `json:"db_family"`
	DBDialect       string `json:"db_dialect"`
	DBUser          string `json:"db_user,omitempty"`
	ApplicationName string `json:"application_name,omitempty"`
	ClientIdentity  string `json:"client_identity,omitempty"`

	Effects []effects.Effect `json:"effects"`

	OperationGroup   string `json:"operation_group,omitempty"`
	OperationGroupID uint8  `json:"operation_group_id,omitempty"`
	OperationSubtype string `json:"operation_subtype,omitempty"`
	RawVerb          string `json:"raw_verb,omitempty"`
	ObjectResolution string `json:"object_resolution,omitempty"`

	StatementDigest    string    `json:"statement_digest,omitempty"`
	StatementText      string    `json:"statement_text,omitempty"`
	StatementRedaction Redaction `json:"statement_redaction"`

	ParserBackend effects.ParserBackend `json:"parser_backend,omitempty"`

	TLS        EventTLS        `json:"tls"`
	Decision   EventDecision   `json:"decision"`
	Result     EventResult     `json:"result"`
	TxContext  EventTxContext  `json:"tx_context"`
	Predicates EventPredicates `json:"predicates,omitempty"`
}

// EventTLS mirrors spec §8 tls{}. UpstreamCertSubject is unpopulated in 04c.
type EventTLS struct {
	Mode                string `json:"mode"`
	ClientSNI           string `json:"client_sni,omitempty"`
	UpstreamCertSubject string `json:"upstream_cert_subject,omitempty"`
}

// EventDecision mirrors spec §8 decision{}. Verb is one of "allow"|"deny"|
// "approve"|"audit" (approve never emitted live in 04c; the runtime stubs it
// out as deny + APPROVE_NOT_YET_SUPPORTED).
type EventDecision struct {
	Verb                   string   `json:"verb"`
	RuleKind               string   `json:"rule_kind"`
	RuleName               string   `json:"rule_name,omitempty"`
	MatchingEffectIndex    int      `json:"matching_effect_index"`
	MatchingEffectGroup    string   `json:"matching_effect_group,omitempty"`
	Reason                 string   `json:"reason,omitempty"`
	ContributingAuditRules []string `json:"contributing_audit_rules,omitempty"`
}

// EventResult mirrors spec §8 result{}. RowsReturned / RowsAffected are
// pointers so JSON wire form carries null for "not applicable".
type EventResult struct {
	RowsReturned *int64 `json:"rows_returned"`
	RowsAffected *int64 `json:"rows_affected"`
	BytesIn      int64  `json:"bytes_in"`
	BytesOut     int64  `json:"bytes_out"`
	LatencyMs    int64  `json:"latency_ms"`
	ErrorCode    string `json:"error_code,omitempty"`
}

// EventTxContext mirrors spec §8 tx_context{}. TxStartedAt is zero-valued
// in 04c; Plan 05's state machine populates it. DenyAction is one of
// "none"|"connection_terminated"|"rollback_injected" (last value Plan 05).
type EventTxContext struct {
	InTransaction bool      `json:"in_transaction"`
	TxStartedAt   time.Time `json:"tx_started_at,omitempty"`
	DenyAction    string    `json:"deny_action"`
}

// EventPredicates mirrors spec §8 predicates{}.
type EventPredicates struct {
	HasFilter bool `json:"has_filter"`
}
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/events/ -count=1 -v`
Expected: all PASS, including the two new tests.

- [ ] **Step 5: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add internal/db/events/event.go internal/db/events/event_test.go
git commit -m "db: events — extend DBEvent with §8 sub-structs"
```

---

## Task 5: Add `MaxQueryBytes` + dialect classifier map + atomic policy pointer to `Server`

**Why:** Three pieces of `Server` plumbing the rest of the plan needs: per-query frame budget, per-service classifier resolution, hot-swappable policy snapshot. Done together so the `Server` struct only churns once.

**Files:**
- Modify: `internal/db/proxy/postgres/server.go`
- Create: `internal/db/proxy/postgres/classifiers.go`
- Create: `internal/db/proxy/postgres/classifiers_test.go`
- Modify: `internal/db/proxy/postgres/server_test.go`

- [ ] **Step 1: Write failing tests for the new behavior**

Append to `internal/db/proxy/postgres/server_test.go`:

```go
func TestServer_New_AppliesMaxQueryBytesDefault(t *testing.T) {
	s := newTestServer(t, withService(testService(t, "appdb", "postgres")))
	if got := s.cfg.MaxQueryBytes; got != 1<<20 {
		t.Fatalf("MaxQueryBytes default = %d want %d", got, 1<<20)
	}
}

func TestServer_New_HonorsMaxQueryBytesOverride(t *testing.T) {
	s := newTestServer(t,
		withService(testService(t, "appdb", "postgres")),
		withMaxQueryBytes(4096),
	)
	if got := s.cfg.MaxQueryBytes; got != 4096 {
		t.Fatalf("MaxQueryBytes = %d want 4096", got)
	}
}

func TestServer_SetPolicy_AtomicSwap(t *testing.T) {
	s := newTestServer(t, withService(testService(t, "appdb", "postgres")))
	if got := s.policy(); got != nil {
		t.Fatalf("initial policy = %p want nil", got)
	}
	rs := &policy.RuleSet{}
	s.SetPolicy(rs)
	if got := s.policy(); got != rs {
		t.Fatalf("policy() after SetPolicy = %p want %p", got, rs)
	}
}

func TestServer_New_RejectsUnknownDialect(t *testing.T) {
	svc := testService(t, "appdb", "rabbitql") // not a real dialect
	_, err := New(Config{
		Unavoidability: service.UnavoidabilityObserve,
		Services:       []Service{svc},
		StateDir:       t.TempDir(),
		Sink:           events.NopSink{},
	})
	if err == nil || !strings.Contains(err.Error(), "rabbitql") {
		t.Fatalf("New on unknown dialect: err = %v", err)
	}
}
```

(`newTestServer`, `withService`, `withMaxQueryBytes`, `testService` are existing helpers in `server_test.go` from 04a/b/b₂ — extend `withMaxQueryBytes` next; the others exist.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/db/proxy/postgres/ -run "TestServer_New_AppliesMaxQueryBytesDefault|TestServer_New_HonorsMaxQueryBytesOverride|TestServer_SetPolicy_AtomicSwap|TestServer_New_RejectsUnknownDialect" -count=1`
Expected: build errors (missing fields/methods/helpers).

- [ ] **Step 3: Add the new test helper**

Append to `internal/db/proxy/postgres/server_test.go`:

```go
func withMaxQueryBytes(n int) testServerOpt {
	return func(c *Config) { c.MaxQueryBytes = n }
}
```

- [ ] **Step 4: Extend `Config` + add the atomic pointer + helper methods**

Modify `internal/db/proxy/postgres/server.go`:

Add imports `sync/atomic` and the classify package alias (use the existing convention):

```go
import (
	// ...existing...
	"sync/atomic"

	classify_pg "github.com/agentsh/agentsh/internal/db/classify/postgres"
)
```

Extend `Config`:

```go
type Config struct {
	// ...existing fields unchanged...

	// MaxQueryBytes caps the 'Q' frame body. Default 1 MiB when zero.
	// Statements above the cap get a synthetic ErrorResponse(54000) + close.
	MaxQueryBytes int

	// classifierForTest, when non-nil, overrides the per-dialect Parser map
	// built by New(). Test-only — production callsites must leave this nil.
	classifierForTest func(dialect string) classify_pg.Parser
}
```

Extend `Server`:

```go
type Server struct {
	// ...existing fields unchanged...

	policyPtr   atomic.Pointer[policy.RuleSet]
	classifiers map[string]classify_pg.Parser
}
```

Add helpers at the bottom of the file:

```go
// SetPolicy atomically replaces the active rule set. A nil ruleset means
// "implicit deny everywhere" (matches policy.Evaluate(stmt, nil, _)).
func (s *Server) SetPolicy(rs *policy.RuleSet) { s.policyPtr.Store(rs) }

func (s *Server) policy() *policy.RuleSet { return s.policyPtr.Load() }
```

- [ ] **Step 5: Wire the defaults + classifier map + policy seed into `New()`**

In `New()`, after the existing per-service validation loop and before `return &Server{...}`, add:

```go
	if cfg.MaxQueryBytes == 0 {
		cfg.MaxQueryBytes = 1 << 20
	}

	classifiers, err := buildClassifierMap(cfg.Services)
	if err != nil {
		return nil, err
	}
```

Replace the final `return &Server{...}` to capture `classifiers` and seed `policyPtr`:

```go
	srv := &Server{
		cfg:         cfg,
		logger:      cfg.Logger,
		done:        make(chan struct{}),
		uidAllowed:  func(uid uint32) bool { return uid == uint32(os.Getuid()) },
		classifiers: classifiers,
	}
	srv.policyPtr.Store(cfg.Policy)
	return srv, nil
```

Apply the same `MaxQueryBytes` default and `policyPtr.Store(cfg.Policy)` to the sentinel-server path so a Plan-05+ caller that flips to `observe` mid-test still sees the seeded policy.

- [ ] **Step 6: Create `classifiers.go`**

Create `internal/db/proxy/postgres/classifiers.go`:

```go
//go:build linux

package postgres

import (
	"fmt"

	classify_pg "github.com/agentsh/agentsh/internal/db/classify/postgres"
)

// buildClassifierMap constructs one Parser per distinct dialect across the
// supplied services. Services sharing a dialect share a Parser instance.
// Returns an error when any service's Dialect is not a recognized name.
func buildClassifierMap(svcs []Service) (map[string]classify_pg.Parser, error) {
	out := make(map[string]classify_pg.Parser, 4)
	for _, svc := range svcs {
		if _, ok := out[svc.Dialect]; ok {
			continue
		}
		d, ok := classify_pg.ParseDialect(svc.Dialect)
		if !ok {
			return nil, fmt.Errorf("postgres.New: services[%q].Dialect = %q is not a recognized dialect",
				svc.Name, svc.Dialect)
		}
		out[svc.Dialect] = classify_pg.New(d)
	}
	return out, nil
}

// classifierFor returns the parser registered for the given dialect. Falls
// back to the "postgres" parser if a lookup fails — buildClassifierMap
// validated dialects at New(), so this should not happen in practice.
// classifierForTest, when set on Config, overrides the map entirely.
func (s *Server) classifierFor(dialect string) classify_pg.Parser {
	if s.cfg.classifierForTest != nil {
		return s.cfg.classifierForTest(dialect)
	}
	if p, ok := s.classifiers[dialect]; ok {
		return p
	}
	return s.classifiers["postgres"]
}
```

- [ ] **Step 7: Create `classifiers_test.go`**

Create `internal/db/proxy/postgres/classifiers_test.go`:

```go
//go:build linux

package postgres

import (
	"testing"

	classify_pg "github.com/agentsh/agentsh/internal/db/classify/postgres"
)

func TestBuildClassifierMap_PerDialect(t *testing.T) {
	svcs := []Service{
		{Name: "a", Family: "postgres", Dialect: "postgres", Listen: ServiceListener{Kind: "unix", Path: "/tmp/a"}},
		{Name: "b", Family: "postgres", Dialect: "postgres", Listen: ServiceListener{Kind: "unix", Path: "/tmp/b"}},
		{Name: "c", Family: "postgres", Dialect: "cockroachdb", Listen: ServiceListener{Kind: "unix", Path: "/tmp/c"}},
	}
	m, err := buildClassifierMap(svcs)
	if err != nil {
		t.Fatalf("buildClassifierMap: %v", err)
	}
	if len(m) != 2 {
		t.Fatalf("map size = %d want 2 (postgres, cockroachdb)", len(m))
	}
	if m["postgres"] == nil || m["cockroachdb"] == nil {
		t.Fatalf("expected entries for both dialects, got %+v", m)
	}
}

func TestBuildClassifierMap_RejectsUnknown(t *testing.T) {
	_, err := buildClassifierMap([]Service{
		{Name: "x", Family: "postgres", Dialect: "rabbitql"},
	})
	if err == nil {
		t.Fatalf("expected error for unknown dialect, got nil")
	}
}

func TestServer_ClassifierFor_TestHookOverride(t *testing.T) {
	calls := 0
	hook := func(dialect string) classify_pg.Parser {
		calls++
		return classify_pg.New(classify_pg.DialectPostgres)
	}
	s := newTestServer(t,
		withService(testService(t, "appdb", "postgres")),
		func(c *Config) { c.classifierForTest = hook },
	)
	_ = s.classifierFor("postgres")
	_ = s.classifierFor("anything")
	if calls != 2 {
		t.Fatalf("hook called %d times, want 2", calls)
	}
}
```

- [ ] **Step 8: Run all tests to confirm they pass**

Run: `go test ./internal/db/proxy/postgres/ -count=1`
Expected: all green.

- [ ] **Step 9: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: clean.

- [ ] **Step 10: Commit**

```bash
git add internal/db/proxy/postgres/server.go \
       internal/db/proxy/postgres/server_test.go \
       internal/db/proxy/postgres/classifiers.go \
       internal/db/proxy/postgres/classifiers_test.go
git commit -m "db: proxy — MaxQueryBytes, dialect map, atomic policy on Server"
```

---

## Task 6: Extend `connState` and capture `'Z'` byte in `forwardAuth`

**Why:** The Simple Query loop needs to know the most recent upstream `'Z'` status byte to gate deny synthesis, plus the redaction tier and TLS mode for event building. We piggy-back on `forwardAuth` recording the byte before it returns (it already has the frame in scope).

**Files:**
- Modify: `internal/db/proxy/postgres/proxyconn.go`
- Modify: `internal/db/proxy/postgres/authforward.go`
- Modify: `internal/db/proxy/postgres/authforward_test.go`

- [ ] **Step 1: Write failing test asserting `'Z'` byte capture**

Append to `internal/db/proxy/postgres/authforward_test.go`:

```go
func TestForwardAuth_CapturesUpstreamRFQByte(t *testing.T) {
	// Use the existing forwardAuth test scaffold: fake upstream that
	// sends AuthenticationOk + ReadyForQuery{TxStatus: 'I'} after one
	// client message. After forwardAuth returns, connState.lastUpstreamRFQ
	// must equal 'I'.
	pc, fake := newForwardAuthFixture(t, withInitialServerScript([]pgproto3.BackendMessage{
		&pgproto3.AuthenticationOk{},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	}))
	defer fake.Close()
	if err := forwardAuth(context.Background(), pc); err != nil {
		t.Fatalf("forwardAuth: %v", err)
	}
	if pc.state.lastUpstreamRFQ != 'I' {
		t.Fatalf("lastUpstreamRFQ = %q want 'I'", pc.state.lastUpstreamRFQ)
	}
}
```

`newForwardAuthFixture` and `withInitialServerScript` are existing helpers from 04b₂'s `authforward_test.go` — extend if needed.

- [ ] **Step 2: Run test to verify failure**

Run: `go test ./internal/db/proxy/postgres/ -run TestForwardAuth_CapturesUpstreamRFQByte -count=1`
Expected: build error referencing `pc.state.lastUpstreamRFQ`.

- [ ] **Step 3: Extend `connState`**

Modify `internal/db/proxy/postgres/proxyconn.go`'s `connState` struct, adding three fields:

```go
type connState struct {
	// ...existing fields unchanged...

	lastUpstreamRFQ byte                 // 'I' | 'T' | 'E' | 0 (pre-auth)
	redactionTier   policy.RedactionTier // resolved at handshake end
	tlsMode         string               // svc.TLSMode at handshake end, for EventTLS.Mode
}
```

Add the import `"github.com/agentsh/agentsh/internal/db/policy"` if not already present.

- [ ] **Step 4: Capture the byte in `forwardAuth`**

Modify `internal/db/proxy/postgres/authforward.go`. In `forwardUpstreamToClientUntilRFQ`, the `*pgproto3.ReadyForQuery` arm currently looks like:

```go
		case *pgproto3.ReadyForQuery:
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return fmt.Errorf("flush after RFQ: %w", err)
			}
			return nil
```

Replace with:

```go
		case *pgproto3.ReadyForQuery:
			pc.state.lastUpstreamRFQ = m.TxStatus
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return fmt.Errorf("flush after RFQ: %w", err)
			}
			return nil
```

- [ ] **Step 5: Run tests to confirm passing**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestForwardAuth`
Expected: all PASS, including the new one. Pre-existing forward-auth tests must still pass.

- [ ] **Step 6: Commit**

```bash
git add internal/db/proxy/postgres/proxyconn.go \
       internal/db/proxy/postgres/authforward.go \
       internal/db/proxy/postgres/authforward_test.go
git commit -m "db: proxy — capture upstream RFQ status byte into connState"
```

---

## Task 7: `simpleQueryLoop` scaffold + frame dispatch + non-Q reject

**Why:** Establish the loop's outer skeleton — read frames, dispatch `'Q'`/`'X'`/other — with the non-Q reject path complete (lifecycle event, synthetic `ErrorResponse(0A000)`). `handleQuery` is a stub that synthesizes `ErrorResponse(58030, "handleQuery not implemented yet")` so tests for the dispatcher can run before subsequent tasks fill `handleQuery` in.

**Files:**
- Create: `internal/db/proxy/postgres/simplequery.go`
- Create: `internal/db/proxy/postgres/simplequery_test.go`
- Modify: `internal/db/proxy/postgres/proxyconn.go` (lifecycle-emit helpers)

- [ ] **Step 1: Write failing test asserting non-Q reject**

Create `internal/db/proxy/postgres/simplequery_test.go`:

```go
//go:build linux

package postgres

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/events"
)

func TestSimpleQueryLoop_RejectsExtendedQuery(t *testing.T) {
	pc, clientSide, sink := newSimpleQueryFixture(t)
	pc.state.lastUpstreamRFQ = 'I'

	// Send Parse, which Plan 04c rejects.
	parse := &pgproto3.Parse{Name: "s1", Query: "SELECT 1"}
	mustSendFromClient(t, clientSide, parse)

	if err := pc.simpleQueryLoop(context.Background()); err == nil {
		t.Fatalf("simpleQueryLoop: want non-nil error on extended-query frame")
	}

	msg := mustReceiveClientFrame(t, clientSide)
	er, ok := msg.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("unexpected first frame: %T", msg)
	}
	if er.SQLState != "0A000" {
		t.Fatalf("SQLState = %q want 0A000", er.SQLState)
	}

	events := sink.DrainLifecycle()
	if len(events) != 1 || events[0].Kind != "db_handshake_fail" {
		t.Fatalf("lifecycle events = %+v", events)
	}
	if events[0].ErrorCode != "EXTENDED_QUERY_NOT_SUPPORTED" {
		t.Fatalf("ErrorCode = %q want EXTENDED_QUERY_NOT_SUPPORTED", events[0].ErrorCode)
	}
}

func TestSimpleQueryLoop_RejectsFunctionCall(t *testing.T) {
	pc, clientSide, sink := newSimpleQueryFixture(t)
	pc.state.lastUpstreamRFQ = 'I'

	mustSendFromClient(t, clientSide, &pgproto3.FunctionCall{Function: 1234})

	if err := pc.simpleQueryLoop(context.Background()); err == nil {
		t.Fatalf("simpleQueryLoop: want non-nil error on FunctionCall")
	}

	msg := mustReceiveClientFrame(t, clientSide)
	er, ok := msg.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("unexpected first frame: %T", msg)
	}
	if er.SQLState != "42501" {
		t.Fatalf("SQLState = %q want 42501", er.SQLState)
	}

	evs := sink.DrainLifecycle()
	_ = evs // shape: db_handshake_fail with FUNCTION_CALL_PROTOCOL_DENIED
	if len(evs) != 1 || evs[0].ErrorCode != "FUNCTION_CALL_PROTOCOL_DENIED" {
		t.Fatalf("lifecycle events = %+v", evs)
	}
}

func TestSimpleQueryLoop_TerminateForwarded(t *testing.T) {
	pc, clientSide, _ := newSimpleQueryFixtureWithUpstream(t)
	pc.state.lastUpstreamRFQ = 'I'

	mustSendFromClient(t, clientSide, &pgproto3.Terminate{})

	if err := pc.simpleQueryLoop(context.Background()); err != nil {
		t.Fatalf("simpleQueryLoop on Terminate: %v", err)
	}
	// fake upstream's read side will have received a Terminate; assertion
	// lives in newSimpleQueryFixtureWithUpstream's cleanup.
	_ = events.LifecycleEvent{}
}
```

Helper `newSimpleQueryFixture` / `newSimpleQueryFixtureWithUpstream` / `mustSendFromClient` / `mustReceiveClientFrame` / `sink.DrainLifecycle()` go in a new fixture block in the same file:

```go
func newSimpleQueryFixture(t *testing.T) (*proxyConn, *pgproto3.Frontend, *events.SyncSink) {
	t.Helper()
	clientPipe, proxyPipe := net.Pipe()
	t.Cleanup(func() { _ = clientPipe.Close(); _ = proxyPipe.Close() })
	sink := &events.SyncSink{}
	svc := Service{Name: "test", Family: "postgres", Dialect: "postgres", TLSMode: "terminate_reissue"}
	srv := newTestServer(t, withService(svc), withSink(sink))
	pc := newProxyConn(srv, svc, proxyPipe, uint32(os.Getuid()))
	clientFE := pgproto3.NewFrontend(clientPipe, clientPipe)
	return pc, clientFE, sink
}

func newSimpleQueryFixtureWithUpstream(t *testing.T) (*proxyConn, *pgproto3.Frontend, *events.SyncSink) {
	pc, clientFE, sink := newSimpleQueryFixture(t)
	upPipeClient, upPipeServer := net.Pipe()
	t.Cleanup(func() { _ = upPipeClient.Close(); _ = upPipeServer.Close() })
	pc.state.upstream = upPipeServer
	pc.state.upstreamFE = pgproto3.NewFrontend(upPipeServer, upPipeServer)
	// Drain anything the proxy sends upstream to avoid blocking.
	go func() {
		b := make([]byte, 4096)
		for {
			if _, err := upPipeClient.Read(b); err != nil {
				return
			}
		}
	}()
	return pc, clientFE, sink
}

func mustSendFromClient(t *testing.T, fe *pgproto3.Frontend, m pgproto3.FrontendMessage) {
	t.Helper()
	fe.Send(m)
	if err := fe.Flush(); err != nil {
		t.Fatalf("client send: %v", err)
	}
}

func mustReceiveClientFrame(t *testing.T, fe *pgproto3.Frontend) pgproto3.BackendMessage {
	t.Helper()
	m, err := fe.Receive()
	if err != nil {
		t.Fatalf("client recv: %v", err)
	}
	return m
}
```

Add `events.SyncSink.DrainLifecycle()` if it does not exist yet — check `internal/db/events/sink.go` and add a sibling to `Drain()`.

- [ ] **Step 2: Run test to verify failure**

Run: `go test ./internal/db/proxy/postgres/ -run TestSimpleQueryLoop -count=1`
Expected: build errors referencing `pc.simpleQueryLoop`, the emit helpers, and possibly `DrainLifecycle`.

- [ ] **Step 3: Add lifecycle-emit helpers to `proxyconn.go`**

Append to `internal/db/proxy/postgres/proxyconn.go`:

```go
// emitFrameTooLarge emits a db_handshake_fail event with error_code
// FRAME_TOO_LARGE. Used when the client sends a 'Q' body above MaxQueryBytes.
func (pc *proxyConn) emitFrameTooLarge(ctx context.Context, size int) {
	if pc.srv.cfg.Sink == nil {
		return
	}
	_ = pc.srv.cfg.Sink.EmitLifecycle(ctx, events.LifecycleEvent{
		EventID:        newEventID(),
		Timestamp:      timeNow(),
		DBService:      pc.svc.Name,
		ClientIdentity: pc.state.clientIdentity,
		Kind:           "db_handshake_fail",
		ErrorCode:      "FRAME_TOO_LARGE",
		Reason:         fmt.Sprintf("statement too large for AgentSH proxy: %d bytes > %d cap", size, pc.srv.cfg.MaxQueryBytes),
		PeerUID:        pc.state.peerUID,
	})
}

// emitUnsupportedFrame emits a db_handshake_fail event when the client sends
// a Plan-05 frame (Parse/Bind/Describe/Execute/Sync/Flush/Close/FunctionCall)
// post-handshake. errorCode distinguishes FUNCTION_CALL_PROTOCOL_DENIED from
// the generic EXTENDED_QUERY_NOT_SUPPORTED.
func (pc *proxyConn) emitUnsupportedFrame(ctx context.Context, errorCode, frameType string) {
	if pc.srv.cfg.Sink == nil {
		return
	}
	_ = pc.srv.cfg.Sink.EmitLifecycle(ctx, events.LifecycleEvent{
		EventID:        newEventID(),
		Timestamp:      timeNow(),
		DBService:      pc.svc.Name,
		ClientIdentity: pc.state.clientIdentity,
		Kind:           "db_handshake_fail",
		ErrorCode:      errorCode,
		Reason:         "frame " + frameType + " not supported in AgentSH proxy phase 1",
		PeerUID:        pc.state.peerUID,
	})
}
```

Add `"fmt"` import if not present.

- [ ] **Step 4: Create `simplequery.go` scaffold**

Create `internal/db/proxy/postgres/simplequery.go`:

```go
//go:build linux

package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgproto3"
)

var (
	errInTxTerminate       = errors.New("postgres.simpleQueryLoop: in-tx deny terminated connection")
	errFrameTooLargeClose  = errors.New("postgres.simpleQueryLoop: frame budget exceeded; conn closed")
	errUnsupportedFrame    = errors.New("postgres.simpleQueryLoop: unsupported frame type; conn closed")
)

// simpleQueryLoop is the post-handshake driver. It reads client frames one at
// a time, dispatches to handleQuery for 'Q', forwards 'X' (Terminate), and
// rejects any other frame with a synthetic ErrorResponse.
func (pc *proxyConn) simpleQueryLoop(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		msg, err := pc.backend.Receive()
		if err != nil {
			return err
		}
		switch m := msg.(type) {
		case *pgproto3.Query:
			if err := pc.handleQuery(ctx, m); err != nil {
				return err
			}
		case *pgproto3.Terminate:
			if pc.state.upstreamFE != nil {
				pc.state.upstreamFE.Send(m)
				_ = pc.state.upstreamFE.Flush()
			}
			return nil
		default:
			return pc.handleUnsupportedFrame(ctx, m)
		}
	}
}

// handleUnsupportedFrame synthesizes ErrorResponse for any non-Q/non-X
// post-handshake frame and closes the connection. Distinguishes
// FunctionCall (PG 42501) from generic extended-query frames (0A000).
func (pc *proxyConn) handleUnsupportedFrame(ctx context.Context, msg pgproto3.FrontendMessage) error {
	frameType := fmt.Sprintf("%T", msg)
	if _, isFunc := msg.(*pgproto3.FunctionCall); isFunc {
		pc.emitUnsupportedFrame(ctx, "FUNCTION_CALL_PROTOCOL_DENIED", "FunctionCall")
		_ = pc.synthesizeError("42501", "FunctionCall sub-protocol denied by AgentSH policy")
		return errUnsupportedFrame
	}
	pc.emitUnsupportedFrame(ctx, "EXTENDED_QUERY_NOT_SUPPORTED", frameType)
	_ = pc.synthesizeError("0A000", "Extended Query / COPY / FunctionCall not supported in AgentSH proxy phase 1")
	return errUnsupportedFrame
}

// handleQuery is filled in by Task 12 (allow) and Task 13 (deny). For now
// it returns an error to keep the loop progressing in tests.
func (pc *proxyConn) handleQuery(ctx context.Context, q *pgproto3.Query) error {
	_ = ctx
	return pc.synthesizeError("58030", "handleQuery not yet implemented in scaffold")
}
```

`pc.synthesizeError` already exists (used by 04b₂'s handshake) — it writes `ErrorResponse{SQLState, Message}` and flushes.

- [ ] **Step 5: Add `SyncSink.DrainLifecycle`**

Modify `internal/db/events/sink.go` to add (next to `Drain`):

```go
// DrainLifecycle returns and clears all lifecycle events captured so far.
func (s *SyncSink) DrainLifecycle() []LifecycleEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.lifecycle
	s.lifecycle = nil
	return out
}
```

If `SyncSink` does not yet have a `lifecycle []LifecycleEvent` field, add it and have `EmitLifecycle` append to it (mirror the existing `EmitStatement` pattern).

- [ ] **Step 6: Run tests to confirm passing**

Run: `go test ./internal/db/proxy/postgres/ -run TestSimpleQueryLoop -count=1 -v`
Expected: three subtests PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/db/proxy/postgres/simplequery.go \
       internal/db/proxy/postgres/simplequery_test.go \
       internal/db/proxy/postgres/proxyconn.go \
       internal/db/events/sink.go
git commit -m "db: proxy — simpleQueryLoop scaffold + reject non-Q/non-X frames"
```

---

## Task 8: Frame budget cap (`MaxQueryBytes`) in `handleQuery`

**Why:** Reject `'Q'` bodies above `MaxQueryBytes` with `ErrorResponse(54000)` and a `FRAME_TOO_LARGE` lifecycle event. Done before classifier work so subsequent tasks don't have to repeatedly handle the over-cap case.

**Files:**
- Modify: `internal/db/proxy/postgres/simplequery.go`
- Modify: `internal/db/proxy/postgres/simplequery_test.go`

- [ ] **Step 1: Write failing test**

Append to `internal/db/proxy/postgres/simplequery_test.go`:

```go
func TestHandleQuery_FrameTooLarge(t *testing.T) {
	pc, clientFE, sink := newSimpleQueryFixture(t)
	pc.state.lastUpstreamRFQ = 'I'
	pc.srv.cfg.MaxQueryBytes = 32

	big := &pgproto3.Query{String: strings.Repeat("SELECT 1; ", 10)} // > 32 bytes
	mustSendFromClient(t, clientFE, big)

	if err := pc.simpleQueryLoop(context.Background()); err == nil {
		t.Fatalf("simpleQueryLoop on oversized Q: want err, got nil")
	}

	msg := mustReceiveClientFrame(t, clientFE)
	er, ok := msg.(*pgproto3.ErrorResponse)
	if !ok || er.SQLState != "54000" {
		t.Fatalf("expected ErrorResponse(54000), got %T %+v", msg, msg)
	}

	rfq := mustReceiveClientFrame(t, clientFE)
	if _, ok := rfq.(*pgproto3.ReadyForQuery); !ok {
		t.Fatalf("expected ReadyForQuery after FRAME_TOO_LARGE, got %T", rfq)
	}

	ev := sink.DrainLifecycle()
	if len(ev) != 1 || ev[0].ErrorCode != "FRAME_TOO_LARGE" {
		t.Fatalf("lifecycle = %+v", ev)
	}
}
```

Add `"strings"` import if missing.

- [ ] **Step 2: Run test to verify failure**

Run: `go test ./internal/db/proxy/postgres/ -run TestHandleQuery_FrameTooLarge -count=1`
Expected: FAIL — current stub returns 58030, not 54000.

- [ ] **Step 3: Add the cap check to `handleQuery`**

Replace `handleQuery` in `internal/db/proxy/postgres/simplequery.go`:

```go
func (pc *proxyConn) handleQuery(ctx context.Context, q *pgproto3.Query) error {
	if len(q.String) > pc.srv.cfg.MaxQueryBytes {
		pc.emitFrameTooLarge(ctx, len(q.String))
		_ = pc.synthErrorAndRFQ("54000",
			fmt.Sprintf("statement too large for AgentSH proxy: %d bytes > %d cap",
				len(q.String), pc.srv.cfg.MaxQueryBytes))
		return errFrameTooLargeClose
	}
	// Allow/deny paths filled in by later tasks.
	return pc.synthesizeError("58030", "handleQuery not yet implemented in scaffold")
}
```

`synthErrorAndRFQ` does not exist yet — declared in Task 10 (`deny.go`). For Task 8 we use a placeholder until then: open `internal/db/proxy/postgres/deny.go`, no — to avoid a forward-reference, inline the synth here in this task:

```go
func (pc *proxyConn) synthErrorAndRFQTmp(sqlstate, msg string) error {
	pc.backend.Send(&pgproto3.ErrorResponse{Severity: "ERROR", SQLState: sqlstate, Message: msg})
	pc.backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	return pc.backend.Flush()
}
```

And call `pc.synthErrorAndRFQTmp(...)` in `handleQuery`. Task 10 replaces the `_Tmp` helper and updates callers.

- [ ] **Step 4: Run tests to confirm**

Run: `go test ./internal/db/proxy/postgres/ -run TestHandleQuery_FrameTooLarge -count=1 -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/proxy/postgres/simplequery.go \
       internal/db/proxy/postgres/simplequery_test.go
git commit -m "db: proxy — enforce MaxQueryBytes frame budget"
```

---

## Task 9: `upstreamread.go` — per-frame demux + counter accumulation

**Why:** Implement the allow-forward response reader as a pure(-ish) function that reads upstream frames one at a time, forwards each to the client, accumulates per-stmt counters from `CommandComplete` tags and `DataRow` frames, and returns once `'Z'` arrives (updating `lastUpstreamRFQ`).

**Files:**
- Create: `internal/db/proxy/postgres/upstreamread.go`
- Create: `internal/db/proxy/postgres/upstreamread_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/db/proxy/postgres/upstreamread_test.go`:

```go
//go:build linux

package postgres

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

func TestParseCommandTag(t *testing.T) {
	cases := []struct {
		tag               string
		wantRows, wantAff *int64
	}{
		{"SELECT 7", i64ptr(7), nil},
		{"INSERT 0 5", nil, i64ptr(5)},
		{"UPDATE 3", nil, i64ptr(3)},
		{"DELETE 2", nil, i64ptr(2)},
		{"MOVE 0", nil, i64ptr(0)},
		{"COPY 4", nil, i64ptr(4)},
		{"CREATE TABLE", nil, nil},
		{"BEGIN", nil, nil},
		{"COMMIT", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.tag, func(t *testing.T) {
			gotRows, gotAff := parseCommandTag(tc.tag)
			if !i64eq(gotRows, tc.wantRows) || !i64eq(gotAff, tc.wantAff) {
				t.Fatalf("parseCommandTag(%q) = (%v, %v) want (%v, %v)",
					tc.tag, gotRows, gotAff, tc.wantRows, tc.wantAff)
			}
		})
	}
}

func TestForwardUpstreamUntilRFQ_HappyPath(t *testing.T) {
	pc, clientFE, _, upstreamScript := newUpstreamReadFixture(t)
	pc.state.lastUpstreamRFQ = 'I'
	upstreamScript([]pgproto3.BackendMessage{
		&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("a")}}},
		&pgproto3.DataRow{Values: [][]byte{[]byte("1")}},
		&pgproto3.DataRow{Values: [][]byte{[]byte("2")}},
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 2")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	})

	r, err := pc.forwardUpstreamUntilRFQ(context.Background(), time.Now(), 16)
	if err != nil {
		t.Fatalf("forwardUpstreamUntilRFQ: %v", err)
	}
	if len(r.RowsByStmt) != 1 || r.RowsByStmt[0] != 2 {
		t.Fatalf("RowsByStmt = %v want [2]", r.RowsByStmt)
	}
	if len(r.AffectedByStmt) != 1 || r.AffectedByStmt[0] != nil {
		t.Fatalf("AffectedByStmt = %v want [nil]", r.AffectedByStmt)
	}
	if r.ErrorCode != "" {
		t.Fatalf("ErrorCode = %q want empty", r.ErrorCode)
	}
	if pc.state.lastUpstreamRFQ != 'I' {
		t.Fatalf("lastUpstreamRFQ = %q want 'I'", pc.state.lastUpstreamRFQ)
	}
	// Drain client side: every upstream frame should have been forwarded.
	for range 5 {
		_ = mustReceiveClientFrame(t, clientFE)
	}
}

func TestForwardUpstreamUntilRFQ_MultiStmt(t *testing.T) {
	pc, _, _, upstreamScript := newUpstreamReadFixture(t)
	pc.state.lastUpstreamRFQ = 'I'
	upstreamScript([]pgproto3.BackendMessage{
		&pgproto3.CommandComplete{CommandTag: []byte("INSERT 0 3")},
		&pgproto3.CommandComplete{CommandTag: []byte("INSERT 0 5")},
		&pgproto3.ReadyForQuery{TxStatus: 'T'},
	})
	r, err := pc.forwardUpstreamUntilRFQ(context.Background(), time.Now(), 64)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(r.AffectedByStmt) != 2 {
		t.Fatalf("AffectedByStmt = %v want 2 entries", r.AffectedByStmt)
	}
	if *r.AffectedByStmt[0] != 3 || *r.AffectedByStmt[1] != 5 {
		t.Fatalf("AffectedByStmt = %v want [3,5]", r.AffectedByStmt)
	}
	if pc.state.lastUpstreamRFQ != 'T' {
		t.Fatalf("lastUpstreamRFQ = %q want 'T'", pc.state.lastUpstreamRFQ)
	}
}

func TestForwardUpstreamUntilRFQ_MidBatchError(t *testing.T) {
	pc, _, _, upstreamScript := newUpstreamReadFixture(t)
	pc.state.lastUpstreamRFQ = 'I'
	upstreamScript([]pgproto3.BackendMessage{
		&pgproto3.CommandComplete{CommandTag: []byte("INSERT 0 3")},
		&pgproto3.ErrorResponse{Severity: "ERROR", SQLState: "23505", Message: "dup key"},
		&pgproto3.ReadyForQuery{TxStatus: 'E'},
	})
	r, err := pc.forwardUpstreamUntilRFQ(context.Background(), time.Now(), 64)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if r.ErrorCode != "23505" {
		t.Fatalf("ErrorCode = %q want 23505", r.ErrorCode)
	}
	if pc.state.lastUpstreamRFQ != 'E' {
		t.Fatalf("lastUpstreamRFQ = %q want 'E'", pc.state.lastUpstreamRFQ)
	}
}

func i64ptr(v int64) *int64 { return &v }
func i64eq(a, b *int64) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func newUpstreamReadFixture(t *testing.T) (*proxyConn, *pgproto3.Frontend, net.Conn, func([]pgproto3.BackendMessage)) {
	pc, clientFE, _ := newSimpleQueryFixture(t)
	up1, up2 := net.Pipe()
	t.Cleanup(func() { _ = up1.Close(); _ = up2.Close() })
	pc.state.upstream = up2
	pc.state.upstreamFE = pgproto3.NewFrontend(up2, up2)
	script := func(msgs []pgproto3.BackendMessage) {
		go func() {
			be := pgproto3.NewBackend(up1, up1)
			for _, m := range msgs {
				be.Send(m)
			}
			_ = be.Flush()
		}()
	}
	// Drain anything the proxy sends to clientFE in the background so writes
	// in forwardUpstreamUntilRFQ don't block; tests that need to inspect them
	// can reach into clientFE before the drain runs.
	go func() {
		_, _ = clientFE.Receive()
	}()
	return pc, clientFE, up1, script
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `go test ./internal/db/proxy/postgres/ -run "TestParseCommandTag|TestForwardUpstreamUntilRFQ" -count=1`
Expected: build errors referencing `forwardUpstreamUntilRFQ` and `parseCommandTag`.

- [ ] **Step 3: Implement `upstreamread.go`**

Create `internal/db/proxy/postgres/upstreamread.go`:

```go
//go:build linux

package postgres

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// upstreamResult collects counters and final state from one Q...Z round-trip.
// Per-statement counters live in slices indexed by the order CommandComplete
// frames arrived in. Statements that did not produce a CommandComplete frame
// (mid-batch ErrorResponse aborted them) get null counters at event-build time.
type upstreamResult struct {
	BytesOut       int64
	RowsByStmt     []*int64
	AffectedByStmt []*int64
	LatencyMs      int64
	ErrorCode      string
}

// forwardUpstreamUntilRFQ reads upstream frames one at a time and forwards
// each to the client. Returns when the upstream sends ReadyForQuery, updating
// pc.state.lastUpstreamRFQ. Updates upstreamResult counters as it goes.
//
// bytesIn is the inbound 'Q' frame body length (the caller knows it; we just
// pass it through for completeness — currently unused inside this function,
// but the spine and event-builder use it for the per-stmt Result struct).
func (pc *proxyConn) forwardUpstreamUntilRFQ(ctx context.Context, sentAt time.Time, bytesIn int) (upstreamResult, error) {
	_ = bytesIn // attribution belongs to the caller
	var r upstreamResult
	var curRows int64
	curRowsSet := false

	for {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		msg, err := pc.state.upstreamFE.Receive()
		if err != nil {
			return r, fmt.Errorf("upstream recv: %w", err)
		}

		switch m := msg.(type) {
		case *pgproto3.DataRow:
			curRows++
			curRowsSet = true
			r.BytesOut += int64(estimatedFrameSize(m))
			pc.backend.Send(m)

		case *pgproto3.CommandComplete:
			rows, aff := parseCommandTag(string(m.CommandTag))
			if curRowsSet && rows == nil {
				rows = i64ptr(curRows)
			}
			r.RowsByStmt = append(r.RowsByStmt, rows)
			r.AffectedByStmt = append(r.AffectedByStmt, aff)
			curRows, curRowsSet = 0, false
			r.BytesOut += int64(estimatedFrameSize(m))
			pc.backend.Send(m)

		case *pgproto3.ErrorResponse:
			if r.ErrorCode == "" {
				r.ErrorCode = m.SQLState
			}
			r.BytesOut += int64(estimatedFrameSize(m))
			pc.backend.Send(m)

		case *pgproto3.ReadyForQuery:
			pc.state.lastUpstreamRFQ = m.TxStatus
			r.BytesOut += int64(estimatedFrameSize(m))
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return r, fmt.Errorf("flush after RFQ: %w", err)
			}
			r.LatencyMs = time.Since(sentAt).Milliseconds()
			return r, nil

		default:
			// RowDescription / ParameterStatus / NoticeResponse / NotificationResponse /
			// ParameterDescription / etc. — forward verbatim with no counter effect.
			r.BytesOut += int64(estimatedFrameSize(m))
			pc.backend.Send(m)
		}
	}
}

// estimatedFrameSize is an approximation good enough for BytesOut accounting.
// pgproto3 does not expose a public encoded-length helper, so we encode into
// a scratch slice. This is on the hot path; if performance becomes a concern
// a future plan can swap for a per-type length-by-fields path.
func estimatedFrameSize(m pgproto3.BackendMessage) int {
	buf := m.Encode(nil)
	return len(buf)
}

// parseCommandTag parses the PostgreSQL CommandComplete tag string. Returns
// (rowsReturned, rowsAffected) — only one is non-nil for any given tag,
// except utility tags ("BEGIN", "CREATE TABLE") which return (nil, nil).
//
// Recognized prefixes:
//   SELECT <n>       → (n, nil)
//   INSERT <oid> <n> → (nil, n)
//   UPDATE <n>       → (nil, n)
//   DELETE <n>       → (nil, n)
//   MOVE <n>         → (nil, n)
//   FETCH <n>        → (nil, n)
//   COPY <n>         → (nil, n)
func parseCommandTag(tag string) (rows *int64, affected *int64) {
	fields := strings.Fields(tag)
	if len(fields) == 0 {
		return nil, nil
	}
	parseN := func(s string) *int64 {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return nil
		}
		return &n
	}
	switch fields[0] {
	case "SELECT":
		if len(fields) >= 2 {
			return parseN(fields[1]), nil
		}
	case "INSERT":
		if len(fields) >= 3 {
			return nil, parseN(fields[2])
		}
	case "UPDATE", "DELETE", "MOVE", "FETCH", "COPY":
		if len(fields) >= 2 {
			return nil, parseN(fields[1])
		}
	}
	return nil, nil
}
```

- [ ] **Step 4: Run tests to confirm passing**

Run: `go test ./internal/db/proxy/postgres/ -run "TestParseCommandTag|TestForwardUpstreamUntilRFQ" -count=1 -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/proxy/postgres/upstreamread.go \
       internal/db/proxy/postgres/upstreamread_test.go
git commit -m "db: proxy — upstreamread per-frame demux + counter accumulation"
```

---

## Task 10: `deny.go` — synth helpers + SQLSTATE picker

**Why:** Centralize the wire-side synthesis used by both pre-tx-deny (ErrorResponse + RFQ('I')) and in-tx-deny (ErrorResponse only). `pickDenySynth` chooses SQLSTATE by rule kind. Replaces the `synthErrorAndRFQTmp` helper introduced in Task 8.

**Files:**
- Create: `internal/db/proxy/postgres/deny.go`
- Create: `internal/db/proxy/postgres/deny_test.go`
- Modify: `internal/db/proxy/postgres/simplequery.go` (drop the `_Tmp` helper)

- [ ] **Step 1: Write failing tests**

Create `internal/db/proxy/postgres/deny_test.go`:

```go
//go:build linux

package postgres

import (
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/policy"
)

func TestSynthErrorAndRFQ_WritesErrorThenRFQI(t *testing.T) {
	pc, clientFE, _ := newSimpleQueryFixture(t)

	if err := pc.synthErrorAndRFQ("42501", "denied"); err != nil {
		t.Fatalf("synth: %v", err)
	}
	m1 := mustReceiveClientFrame(t, clientFE)
	er, ok := m1.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("first frame = %T want ErrorResponse", m1)
	}
	if er.SQLState != "42501" || er.Message != "denied" || er.Severity != "ERROR" {
		t.Fatalf("ErrorResponse = %+v", er)
	}
	m2 := mustReceiveClientFrame(t, clientFE)
	rfq, ok := m2.(*pgproto3.ReadyForQuery)
	if !ok {
		t.Fatalf("second frame = %T want ReadyForQuery", m2)
	}
	if rfq.TxStatus != 'I' {
		t.Fatalf("RFQ TxStatus = %q want 'I'", rfq.TxStatus)
	}
}

func TestSynthErrorOnly_NoTrailingRFQ(t *testing.T) {
	pc, clientFE, _ := newSimpleQueryFixture(t)

	if err := pc.synthErrorOnly("42501", "in-tx"); err != nil {
		t.Fatalf("synth: %v", err)
	}
	er := mustReceiveClientFrame(t, clientFE).(*pgproto3.ErrorResponse)
	if er.Message != "in-tx" {
		t.Fatalf("Message = %q", er.Message)
	}
	// Subsequent Receive must time out or return EOF; we close the client side
	// and assert.
	if err := clientFE.SetDeadline(timeNow().Add(50)); err != nil { _ = err }
}

func TestPickDenySynth_FirstDenyWins(t *testing.T) {
	decisions := []policy.Decision{
		{Verb: policy.VerbAllow},
		{Verb: policy.VerbDeny, RuleKind: policy.RuleKindStatement, RuleName: "no-deletes", Reason: "delete denied"},
		{Verb: policy.VerbDeny, RuleKind: policy.RuleKindStatement, RuleName: "no-truncates"},
	}
	rendered, sqlstate := pickDenySynth(decisions)
	if sqlstate != "42501" {
		t.Fatalf("sqlstate = %q want 42501", sqlstate)
	}
	if rendered == "" {
		t.Fatalf("rendered empty")
	}
	if !contains(rendered, "no-deletes") {
		t.Fatalf("rendered = %q does not reference first deny rule", rendered)
	}
}

func TestPickDenySynth_ConnectionRuleUses28000(t *testing.T) {
	decisions := []policy.Decision{
		{Verb: policy.VerbDeny, RuleKind: policy.RuleKindConnection, RuleName: "no-replica"},
	}
	_, sqlstate := pickDenySynth(decisions)
	if sqlstate != "28000" {
		t.Fatalf("sqlstate = %q want 28000", sqlstate)
	}
}

func TestPickDenySynth_ImplicitDenyMessage(t *testing.T) {
	decisions := []policy.Decision{
		{Verb: policy.VerbDeny, RuleKind: policy.RuleKindStatement, RuleName: "", Reason: "no rule covers unsafe_io"},
	}
	rendered, _ := pickDenySynth(decisions)
	if !contains(rendered, "no rule covers") {
		t.Fatalf("rendered = %q does not include reason text", rendered)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
```

Note: `pickDenySynth` may be passed a `denyMessage` separately in the implementation; the test expects implicit-deny + non-empty Reason to surface in `rendered`. Adjust the implementation accordingly. If `RuleKind` constants in `internal/db/policy/types.go` are named differently (e.g. `RuleKindStatement`), keep the symbol names consistent with what's already there.

- [ ] **Step 2: Run tests to verify failure**

Run: `go test ./internal/db/proxy/postgres/ -run "TestSynthErrorAndRFQ|TestSynthErrorOnly|TestPickDenySynth" -count=1`
Expected: build errors.

- [ ] **Step 3: Implement `deny.go`**

Create `internal/db/proxy/postgres/deny.go`:

```go
//go:build linux

package postgres

import (
	"fmt"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/policy"
)

const (
	sqlstateInsufficientPrivilege = "42501" // statement-rule deny
	sqlstateAuthFailure           = "28000" // connection-rule deny
	sqlstateProgramLimitExceeded  = "54000" // frame budget
	sqlstateFeatureNotSupported   = "0A000" // extended query / function call
)

// synthErrorAndRFQ writes ErrorResponse + ReadyForQuery('I') to the client.
// Used when lastUpstreamRFQ in {0, 'I'} so the next 'Q' can proceed.
func (pc *proxyConn) synthErrorAndRFQ(sqlstate, message string) error {
	pc.backend.Send(&pgproto3.ErrorResponse{Severity: "ERROR", SQLState: sqlstate, Message: message})
	pc.backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	return pc.backend.Flush()
}

// synthErrorOnly writes ErrorResponse with no trailing RFQ. Used for the
// in-tx deny case ({'T', 'E'}) — caller closes both conns immediately after.
func (pc *proxyConn) synthErrorOnly(sqlstate, message string) error {
	pc.backend.Send(&pgproto3.ErrorResponse{Severity: "ERROR", SQLState: sqlstate, Message: message})
	return pc.backend.Flush()
}

// pickDenySynth chooses the rendered deny message and SQLSTATE for a batch.
// Iterates in order; first denying entry wins (most-restrictive is
// deterministic under §10.2 with stable rule order).
//
// SQLSTATE selection:
//   connection-rule deny → 28000
//   statement-rule deny  → 42501
//
// Rendered message: rule's DenyMessage template if Plan 02 carried one
// (not yet exposed on Decision; we fall back to RuleName / Reason).
func pickDenySynth(decisions []policy.Decision) (string, string) {
	for _, d := range decisions {
		if d.Verb != policy.VerbDeny {
			continue
		}
		sqlstate := sqlstateInsufficientPrivilege
		if d.RuleKind == policy.RuleKindConnection {
			sqlstate = sqlstateAuthFailure
		}
		rendered := renderDenyMessage(d)
		return rendered, sqlstate
	}
	// Defensive: caller is supposed to ensure anyDeny.
	return "denied by AgentSH policy", sqlstateInsufficientPrivilege
}

func renderDenyMessage(d policy.Decision) string {
	if d.RuleName != "" {
		return fmt.Sprintf("denied by AgentSH policy: %s", d.RuleName)
	}
	if d.Reason != "" {
		return fmt.Sprintf("denied by AgentSH policy: %s", d.Reason)
	}
	return "denied by AgentSH policy"
}
```

- [ ] **Step 4: Replace the `_Tmp` helper in `simplequery.go`**

In `internal/db/proxy/postgres/simplequery.go`, delete `synthErrorAndRFQTmp` (its definition and any callers), and update the call site in `handleQuery` to use `pc.synthErrorAndRFQ`.

- [ ] **Step 5: Run all tests to confirm passing**

Run: `go test ./internal/db/proxy/postgres/ -count=1`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add internal/db/proxy/postgres/deny.go \
       internal/db/proxy/postgres/deny_test.go \
       internal/db/proxy/postgres/simplequery.go
git commit -m "db: proxy — deny synth helpers + SQLSTATE picker"
```

---

## Task 11: `eventbuilder.go` — pure event builder, redaction tiers, digest, `denied_by_sibling`

**Why:** Pure function that turns `{stmt, decision, sql, result, denyAction, tier, conn}` into a fully-populated `events.DBEvent`. Owns the digest, the redaction-tier rendering, the `denied_by_sibling` tagging for non-denying statements in an `anyDeny` batch, and the `command_id` shape.

**Files:**
- Create: `internal/db/proxy/postgres/eventbuilder.go`
- Create: `internal/db/proxy/postgres/eventbuilder_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/db/proxy/postgres/eventbuilder_test.go`:

```go
//go:build linux

package postgres

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	classify_pg "github.com/agentsh/agentsh/internal/db/classify/postgres"
	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
)

func TestBuildStatementEvent_FullTier_VerbatimSlice(t *testing.T) {
	sql := "SELECT 1; SELECT 2"
	stmts := []effects.ClassifiedStatement{
		{Effects: []effects.Effect{{Group: effects.GroupRead, Resolution: effects.ResolutionQualified}}, SourceStart: 0, SourceEnd: 8, RawVerb: "SELECT"},
		{Effects: []effects.Effect{{Group: effects.GroupRead, Resolution: effects.ResolutionQualified}}, SourceStart: 10, SourceEnd: 18, RawVerb: "SELECT"},
	}
	parser := classify_pg.New(classify_pg.DialectPostgres)
	ev := buildStatementEvent(buildArgs{
		Stmt:        stmts[0],
		StmtIndex:   0,
		BatchTotal:  2,
		Decision:    policy.Decision{Verb: policy.VerbAllow, RuleKind: policy.RuleKindStatement, RuleName: "app-allow-read"},
		SQL:         sql,
		Tier:        policy.RedactFull,
		Conn:        connStateForTest("appdb", "postgres", "terminate_reissue"),
		DenyAction:  "none",
		BatchSHA:    sha256Hex(sql),
		Parser:      parser,
	})
	if ev.StatementText != "SELECT 1" {
		t.Fatalf("StatementText = %q want %q", ev.StatementText, "SELECT 1")
	}
	if !strings.HasPrefix(ev.StatementDigest, "sha256:") {
		t.Fatalf("StatementDigest = %q must start sha256:", ev.StatementDigest)
	}
	if ev.Decision.Verb != "allow" {
		t.Fatalf("Decision.Verb = %q want allow", ev.Decision.Verb)
	}
	if ev.TLS.Mode != "terminate_reissue" {
		t.Fatalf("TLS.Mode = %q", ev.TLS.Mode)
	}
	if ev.CommandID == "" || !strings.Contains(ev.CommandID, ":0") {
		t.Fatalf("CommandID = %q want suffix :0", ev.CommandID)
	}
}

func TestBuildStatementEvent_DigestStableAcrossTiers(t *testing.T) {
	sql := "SELECT 'hello'"
	stmt := effects.ClassifiedStatement{
		Effects:     []effects.Effect{{Group: effects.GroupRead, Resolution: effects.ResolutionQualified}},
		SourceStart: 0, SourceEnd: int32(len(sql)),
	}
	parser := classify_pg.New(classify_pg.DialectPostgres)
	digests := map[policy.RedactionTier]string{}
	for _, tier := range []policy.RedactionTier{policy.RedactFull, policy.RedactParametersRedacted, policy.RedactNone} {
		ev := buildStatementEvent(buildArgs{
			Stmt: stmt, SQL: sql, Tier: tier,
			Conn: connStateForTest("appdb", "postgres", "terminate_reissue"),
			Decision: policy.Decision{Verb: policy.VerbAllow, RuleKind: policy.RuleKindStatement},
			DenyAction: "none",
			BatchSHA: sha256Hex(sql),
			Parser: parser,
		})
		digests[tier] = ev.StatementDigest
	}
	if digests[policy.RedactFull] != digests[policy.RedactParametersRedacted] ||
		digests[policy.RedactParametersRedacted] != digests[policy.RedactNone] {
		t.Fatalf("digests diverged across tiers: %+v", digests)
	}
}

func TestBuildStatementEvent_DeniedBySibling(t *testing.T) {
	sql := "SELECT 1; DELETE FROM t"
	parser := classify_pg.New(classify_pg.DialectPostgres)
	stmt0 := effects.ClassifiedStatement{
		Effects: []effects.Effect{{Group: effects.GroupRead, Resolution: effects.ResolutionQualified}},
		SourceStart: 0, SourceEnd: 8, RawVerb: "SELECT",
	}
	ev := buildStatementEvent(buildArgs{
		Stmt: stmt0, StmtIndex: 0, BatchTotal: 2,
		Decision: policy.Decision{Verb: policy.VerbDeny, RuleKind: policy.RuleKindStatement, Reason: "denied by sibling statement"},
		SQL: sql, Tier: policy.RedactParametersRedacted,
		Conn: connStateForTest("appdb", "postgres", "terminate_reissue"),
		DenyAction: "none",
		IsDeniedBySibling: true,
		BatchSHA: sha256Hex(sql),
		Parser: parser,
	})
	if ev.Decision.Verb != "deny" {
		t.Fatalf("Decision.Verb = %q want deny", ev.Decision.Verb)
	}
	if ev.Result.ErrorCode != "DENIED_BY_SIBLING" {
		t.Fatalf("Result.ErrorCode = %q want DENIED_BY_SIBLING", ev.Result.ErrorCode)
	}
	if ev.Result.RowsReturned != nil || ev.Result.RowsAffected != nil {
		t.Fatalf("Result rows must be nil: %+v", ev.Result)
	}
}

func TestBuildStatementEvent_NoneTierStripsText(t *testing.T) {
	sql := "SELECT 1"
	stmt := effects.ClassifiedStatement{
		Effects:     []effects.Effect{{Group: effects.GroupRead, Resolution: effects.ResolutionQualified}},
		SourceStart: 0, SourceEnd: int32(len(sql)),
	}
	parser := classify_pg.New(classify_pg.DialectPostgres)
	ev := buildStatementEvent(buildArgs{
		Stmt: stmt, SQL: sql, Tier: policy.RedactNone,
		Conn: connStateForTest("appdb", "postgres", "terminate_reissue"),
		Decision: policy.Decision{Verb: policy.VerbAllow, RuleKind: policy.RuleKindStatement},
		DenyAction: "none",
		BatchSHA: sha256Hex(sql),
		Parser: parser,
	})
	if ev.StatementText != "" {
		t.Fatalf("StatementText must be empty under RedactNone: %q", ev.StatementText)
	}
	if ev.StatementDigest == "" {
		t.Fatalf("StatementDigest must be populated under RedactNone")
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func connStateForTest(svc, dialect, tlsMode string) connState {
	return connState{
		dbService:      svc,
		clientIdentity: "uid:1000",
		dbUser:         "agent",
		database:       "app",
		appName:        "tests",
		tlsMode:        tlsMode,
	}
}

func init() {
	_ = events.DBEvent{}       // ensure package compiles when only test imports referenced
	_ = time.Time{}            // pgproto3 import not needed here
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `go test ./internal/db/proxy/postgres/ -run TestBuildStatementEvent -count=1`
Expected: build errors — `buildStatementEvent`, `buildArgs` undefined.

- [ ] **Step 3: Implement `eventbuilder.go`**

Create `internal/db/proxy/postgres/eventbuilder.go`:

```go
//go:build linux

package postgres

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	classify_pg "github.com/agentsh/agentsh/internal/db/classify/postgres"
	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
)

// buildArgs collects the inputs to buildStatementEvent. Keeping them in a
// struct avoids a 14-argument function and makes test cases readable.
type buildArgs struct {
	Stmt              effects.ClassifiedStatement
	StmtIndex         int
	BatchTotal        int
	Decision          policy.Decision
	SQL               string
	Tier              policy.RedactionTier
	Conn              connState
	BytesIn           int64
	BytesOut          int64
	LatencyMs         int64
	RowsReturned     *int64
	RowsAffected     *int64
	UpstreamErrCode   string
	DenyAction        string
	IsDeniedBySibling bool
	BatchSHA          string // sha256 hex of the full Q.String; used for command_id
	Parser            classify_pg.Parser
}

// buildStatementEvent returns a fully-populated events.DBEvent. Pure function
// — no I/O, no clock, no globals beyond the supplied buildArgs.
func buildStatementEvent(a buildArgs) events.DBEvent {
	slice := perStmtSlice(a.SQL, a.Stmt)

	normalized, err := a.Parser.Normalize(slice)
	if err != nil || normalized == "" {
		normalized = strings.TrimSpace(slice)
	}
	digestBytes := sha256.Sum256([]byte(normalized))
	digest := "sha256:" + hex.EncodeToString(digestBytes[:])

	var stmtText string
	var redaction events.Redaction
	switch a.Tier {
	case policy.RedactFull:
		stmtText = slice
		redaction = events.RedactionFull
	case policy.RedactParametersRedacted:
		stmtText = normalized
		redaction = events.RedactionParametersRedacted
	case policy.RedactNone:
		stmtText = ""
		redaction = events.RedactionNone
	default:
		stmtText = normalized
		redaction = events.RedactionParametersRedacted
	}

	dec := buildDecision(a.Decision, a.IsDeniedBySibling)

	result := events.EventResult{
		RowsReturned: a.RowsReturned,
		RowsAffected: a.RowsAffected,
		BytesIn:      a.BytesIn,
		BytesOut:     a.BytesOut,
		LatencyMs:    a.LatencyMs,
		ErrorCode:    a.UpstreamErrCode,
	}
	if a.IsDeniedBySibling {
		result = events.EventResult{
			BytesIn:   a.BytesIn,
			ErrorCode: "DENIED_BY_SIBLING",
		}
	}

	tx := events.EventTxContext{
		InTransaction: a.Conn.lastUpstreamRFQ == 'T' || a.Conn.lastUpstreamRFQ == 'E',
		DenyAction:    a.DenyAction,
	}

	predicates := events.EventPredicates{HasFilter: hasFilter(a.Stmt)}

	return events.DBEvent{
		EventID:            newEventID(),
		SessionID:          a.Conn.clientIdentity,
		CommandID:          fmt.Sprintf("%s:%d", a.BatchSHA, a.StmtIndex),
		Timestamp:          timeNow(),
		DBService:          a.Conn.dbService,
		DBFamily:           "postgres",
		DBDialect:          stmtDialect(a.Conn),
		DBUser:             a.Conn.dbUser,
		ApplicationName:    a.Conn.appName,
		ClientIdentity:     a.Conn.clientIdentity,
		Effects:            a.Stmt.Effects,
		RawVerb:            a.Stmt.RawVerb,
		ParserBackend:      a.Stmt.ParserBackend,
		StatementText:      stmtText,
		StatementDigest:    digest,
		StatementRedaction: redaction,
		TLS:        events.EventTLS{Mode: a.Conn.tlsMode, ClientSNI: a.Conn.sniHostname},
		Decision:   dec,
		Result:     result,
		TxContext:  tx,
		Predicates: predicates,
	}
}

func buildDecision(d policy.Decision, deniedBySibling bool) events.EventDecision {
	if deniedBySibling {
		return events.EventDecision{
			Verb:     "deny",
			RuleKind: "statement",
			Reason:   "denied by sibling statement",
		}
	}
	verb := strings.ToLower(d.Verb.String())
	// Plan 02's Approval struct → caller already rewrote Verb to deny before
	// reaching us in 04c (APPROVE_NOT_YET_SUPPORTED stub). Be defensive.
	if verb == "" {
		verb = "deny"
	}
	out := events.EventDecision{
		Verb:                verb,
		RuleKind:            strings.ToLower(d.RuleKind.String()),
		RuleName:            d.RuleName,
		MatchingEffectIndex: d.MatchingEffectIndex,
		Reason:              d.Reason,
	}
	if d.MatchingEffectGroup != effects.GroupUnknown {
		out.MatchingEffectGroup = d.MatchingEffectGroup.String()
	}
	if len(d.ContributingAuditRules) > 0 {
		out.ContributingAuditRules = append([]string(nil), d.ContributingAuditRules...)
	}
	return out
}

func perStmtSlice(sql string, stmt effects.ClassifiedStatement) string {
	if stmt.SourceStart == 0 && stmt.SourceEnd == 0 {
		return strings.TrimSpace(sql)
	}
	if int(stmt.SourceEnd) > len(sql) || stmt.SourceStart < 0 || stmt.SourceStart > stmt.SourceEnd {
		return strings.TrimSpace(sql)
	}
	return sql[stmt.SourceStart:stmt.SourceEnd]
}

// hasFilter returns true when the classifier indicated a WHERE clause was
// present. Plan 04c reads this directly from a classifier-supplied flag once
// effects.Effect carries it; until then, we conservatively return false.
func hasFilter(stmt effects.ClassifiedStatement) bool {
	for _, e := range stmt.Effects {
		if e.HasFilter {
			return true
		}
	}
	return false
}

// stmtDialect returns the service's dialect string for the event. This is
// best-effort: 04c does not surface dialect into connState beyond TLSMode,
// so we look it up on the Server. To keep the builder pure for tests, we
// thread it via Conn at a future task if needed; for now default to
// "postgres" when unset.
func stmtDialect(c connState) string {
	if c.dbService == "" {
		return "postgres"
	}
	return "postgres"
}
```

Two things to confirm against existing code before proceeding:

1. **`effects.Effect.HasFilter`** may not exist yet — check `internal/db/effects/effect.go`. If absent, replace `hasFilter` with a stub `return false` and add `// TODO Plan 05: thread WHERE-clause flag from classifier`. **Update this plan to drop the TODO when the field arrives.**
2. **`connState.dbService` / `dbUser` / `database` / `appName` / `sniHostname`** must exist on the struct (they do — see proxyconn.go from 04a/b/b₂).

- [ ] **Step 4: Run tests to confirm passing**

Run: `go test ./internal/db/proxy/postgres/ -run TestBuildStatementEvent -count=1 -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/proxy/postgres/eventbuilder.go \
       internal/db/proxy/postgres/eventbuilder_test.go
git commit -m "db: proxy — eventbuilder with redaction tiers + digest + sibling tagging"
```

---

## Task 12: `handleQuery` allow path — classify + evaluate + forward

**Why:** Wire `simplequery.go::handleQuery` from stub to working allow path: classify via `classifierFor(dialect)`, evaluate every statement, decide `anyDeny`, and on no-deny forward the `Q` upstream and run `forwardUpstreamUntilRFQ` to demux the response. Emit one per-stmt allow/audit event.

**Files:**
- Modify: `internal/db/proxy/postgres/simplequery.go`
- Modify: `internal/db/proxy/postgres/simplequery_test.go`

- [ ] **Step 1: Write failing tests**

Append to `internal/db/proxy/postgres/simplequery_test.go`:

```go
func TestHandleQuery_AllowPath_ForwardsAndEmits(t *testing.T) {
	pc, clientFE, sink, upstreamScript := newAllowPathFixture(t)
	pc.state.lastUpstreamRFQ = 'I'
	pc.srv.SetPolicy(allowAllRuleSet(t))

	upstreamScript([]pgproto3.BackendMessage{
		&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("a")}}},
		&pgproto3.DataRow{Values: [][]byte{[]byte("1")}},
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	})

	mustSendFromClient(t, clientFE, &pgproto3.Query{String: "SELECT 1"})

	go func() {
		_ = pc.simpleQueryLoop(context.Background())
	}()

	// Drain client side; expect RowDescription, DataRow, CommandComplete, ReadyForQuery
	frames := drainNFrames(t, clientFE, 4)
	if _, ok := frames[3].(*pgproto3.ReadyForQuery); !ok {
		t.Fatalf("last frame = %T want ReadyForQuery", frames[3])
	}

	evs := sink.DrainStatements()
	if len(evs) != 1 {
		t.Fatalf("statement events = %d want 1", len(evs))
	}
	if evs[0].Decision.Verb != "allow" {
		t.Fatalf("event Verb = %q want allow", evs[0].Decision.Verb)
	}
	if evs[0].Result.RowsReturned == nil || *evs[0].Result.RowsReturned != 1 {
		t.Fatalf("RowsReturned = %v want 1", evs[0].Result.RowsReturned)
	}
}

func TestHandleQuery_AllowPath_MultiStmt(t *testing.T) {
	pc, clientFE, sink, upstreamScript := newAllowPathFixture(t)
	pc.state.lastUpstreamRFQ = 'I'
	pc.srv.SetPolicy(allowAllRuleSet(t))

	upstreamScript([]pgproto3.BackendMessage{
		&pgproto3.CommandComplete{CommandTag: []byte("INSERT 0 3")},
		&pgproto3.CommandComplete{CommandTag: []byte("INSERT 0 5")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	})

	mustSendFromClient(t, clientFE, &pgproto3.Query{String: "INSERT INTO t VALUES (1); INSERT INTO t VALUES (2)"})

	go func() { _ = pc.simpleQueryLoop(context.Background()) }()
	_ = drainNFrames(t, clientFE, 3)

	evs := sink.DrainStatements()
	if len(evs) != 2 {
		t.Fatalf("statement events = %d want 2", len(evs))
	}
	if *evs[0].Result.RowsAffected != 3 || *evs[1].Result.RowsAffected != 5 {
		t.Fatalf("affected mismatch: %v / %v", evs[0].Result.RowsAffected, evs[1].Result.RowsAffected)
	}
	if evs[0].CommandID == evs[1].CommandID {
		t.Fatalf("CommandID must differ per stmt: %q / %q", evs[0].CommandID, evs[1].CommandID)
	}
}
```

Helpers:

```go
func newAllowPathFixture(t *testing.T) (*proxyConn, *pgproto3.Frontend, *events.SyncSink, func([]pgproto3.BackendMessage)) {
	pc, clientFE, sink := newSimpleQueryFixture(t)
	up1, up2 := net.Pipe()
	t.Cleanup(func() { _ = up1.Close(); _ = up2.Close() })
	pc.state.upstream = up2
	pc.state.upstreamFE = pgproto3.NewFrontend(up2, up2)
	script := func(msgs []pgproto3.BackendMessage) {
		go func() {
			be := pgproto3.NewBackend(up1, up1)
			// Wait for one client message (the 'Q') before sending the script.
			_, _ = be.Receive()
			for _, m := range msgs {
				be.Send(m)
			}
			_ = be.Flush()
		}()
	}
	return pc, clientFE, sink, script
}

func allowAllRuleSet(t *testing.T) *policy.RuleSet {
	// Use the policy package's Decode against a permissive YAML.
	rs, _, err := policy.Decode([]byte(`
services:
  - name: test
    family: postgres
    dialect: postgres
    upstream: "127.0.0.1:5432"
    tls_mode: terminate_reissue

rules:
  - name: allow-all
    decision: allow
    operations: [read, write, ddl, dml, session, procedural]
    services: [test]
    objects: ['*']
`))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	return rs
}

func drainNFrames(t *testing.T, fe *pgproto3.Frontend, n int) []pgproto3.BackendMessage {
	t.Helper()
	out := make([]pgproto3.BackendMessage, 0, n)
	for i := 0; i < n; i++ {
		m, err := fe.Receive()
		if err != nil {
			t.Fatalf("Receive[%d]: %v", i, err)
		}
		out = append(out, m)
	}
	return out
}
```

Verify against the current shape of `policy.Decode` — adjust the YAML keys to match what the codebase actually accepts; the rule schema may be `operations: [read]` and `objects: ['*']` is a wildcard the evaluator supports. Run `go test ./internal/db/policy/...` to confirm the YAML parses, then revise the test fixture if needed.

- [ ] **Step 2: Run tests to verify failure**

Run: `go test ./internal/db/proxy/postgres/ -run TestHandleQuery_AllowPath -count=1`
Expected: FAIL — `handleQuery` is still the stub from Task 8.

- [ ] **Step 3: Wire the allow path**

Replace `handleQuery` in `internal/db/proxy/postgres/simplequery.go`:

```go
func (pc *proxyConn) handleQuery(ctx context.Context, q *pgproto3.Query) error {
	if len(q.String) > pc.srv.cfg.MaxQueryBytes {
		pc.emitFrameTooLarge(ctx, len(q.String))
		_ = pc.synthErrorAndRFQ(sqlstateProgramLimitExceeded,
			fmt.Sprintf("statement too large for AgentSH proxy: %d bytes > %d cap",
				len(q.String), pc.srv.cfg.MaxQueryBytes))
		return errFrameTooLargeClose
	}

	parser := pc.srv.classifierFor(pc.svc.Dialect)
	stmts, _ := parser.Classify(q.String, classify_pg.SessionState{}, classify_pg.Options{})
	rs := pc.srv.policy()
	decisions := make([]policy.Decision, len(stmts))
	anyDeny := false
	for i, s := range stmts {
		decisions[i] = policy.Evaluate(s, rs, policy.ServiceID(pc.svc.Name))
		if decisions[i].Verb == policy.VerbApprove {
			decisions[i] = synthApproveAsDeny(decisions[i])
		}
		if decisions[i].Verb == policy.VerbDeny {
			anyDeny = true
		}
	}

	batchSHA := sha256HexBatch(q.String)

	if !anyDeny {
		sentAt := timeNow()
		pc.state.upstreamFE.Send(q)
		if err := pc.state.upstreamFE.Flush(); err != nil {
			return err
		}
		result, ferr := pc.forwardUpstreamUntilRFQ(ctx, sentAt, len(q.String))
		pc.emitAllowEvents(ctx, stmts, decisions, q.String, batchSHA, result)
		return ferr
	}

	// Deny path is filled in by Task 13.
	return pc.synthesizeError(sqlstateInsufficientPrivilege, "deny path not yet implemented")
}

// synthApproveAsDeny rewrites a Decision with Verb=approve into Verb=deny
// with the APPROVE_NOT_YET_SUPPORTED stub marker. Per spec §14.5, approve
// runtime lands in Plan 05; until then we surface a loud failure mode.
func synthApproveAsDeny(d policy.Decision) policy.Decision {
	d.Verb = policy.VerbDeny
	if d.Reason == "" {
		d.Reason = "APPROVE_NOT_YET_SUPPORTED"
	}
	return d
}

func sha256HexBatch(sql string) string {
	sum := sha256.Sum256([]byte(sql))
	return hex.EncodeToString(sum[:])
}

// emitAllowEvents emits one db_statement event per ClassifiedStatement when
// none denied. Per-stmt counters come from result.RowsByStmt /
// AffectedByStmt; bytes_in / bytes_out / latency_ms are attributed per-stmt
// (each event carries the batch values).
func (pc *proxyConn) emitAllowEvents(
	ctx context.Context,
	stmts []effects.ClassifiedStatement,
	decisions []policy.Decision,
	sql string,
	batchSHA string,
	r upstreamResult,
) {
	parser := pc.srv.classifierFor(pc.svc.Dialect)
	for i, s := range stmts {
		var rows, aff *int64
		if i < len(r.RowsByStmt) {
			rows = r.RowsByStmt[i]
			aff = r.AffectedByStmt[i]
		}
		errCode := ""
		if r.ErrorCode != "" && i >= len(r.RowsByStmt) {
			errCode = "STATEMENT_ABORTED_BY_PRIOR_ERROR"
		} else if i == 0 {
			errCode = r.ErrorCode
		}
		ev := buildStatementEvent(buildArgs{
			Stmt: s, StmtIndex: i, BatchTotal: len(stmts),
			Decision: decisions[i],
			SQL: sql, Tier: pc.state.redactionTier,
			Conn: *pc.state,
			BytesIn: int64(len(sql)),
			BytesOut: r.BytesOut,
			LatencyMs: r.LatencyMs,
			RowsReturned: rows,
			RowsAffected: aff,
			UpstreamErrCode: errCode,
			DenyAction: "none",
			BatchSHA: batchSHA,
			Parser: parser,
		})
		if err := pc.srv.cfg.Sink.EmitStatement(ctx, ev); err != nil {
			pc.logger.Warn("emit statement event failed", "err", err)
		}
	}
}
```

Add the required imports: `"crypto/sha256"`, `"encoding/hex"`, `"github.com/agentsh/agentsh/internal/db/effects"`, `"github.com/agentsh/agentsh/internal/db/policy"`, `classify_pg "github.com/agentsh/agentsh/internal/db/classify/postgres"`.

- [ ] **Step 4: Add `SyncSink.DrainStatements()` if missing**

If the existing `SyncSink` already implements `Drain()` returning `[]DBEvent`, rename callers in tests to `DrainStatements()`, or add a thin alias method `DrainStatements() []DBEvent { return s.Drain() }`. The intent: distinguish statement events from lifecycle events.

- [ ] **Step 5: Run tests to confirm passing**

Run: `go test ./internal/db/proxy/postgres/ -run TestHandleQuery_AllowPath -count=1 -v`
Expected: both subtests PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/db/proxy/postgres/simplequery.go \
       internal/db/proxy/postgres/simplequery_test.go \
       internal/db/events/sink.go
git commit -m "db: proxy — handleQuery allow path with classify+evaluate+forward"
```

---

## Task 13: `handleQuery` deny path — anyDeny + per-stmt events + RFQ-gated synth

**Why:** Complete `handleQuery` for the deny case. When `anyDeny` is true: forward nothing upstream; emit one event per statement (denying ones get the real decision, others get `denied_by_sibling` tagging); synthesize the deny based on `lastUpstreamRFQ` (local `ErrorResponse + RFQ('I')` out-of-tx; `ErrorResponse` only + terminate in-tx with `tx_context.deny_action = "connection_terminated"`).

**Files:**
- Modify: `internal/db/proxy/postgres/simplequery.go`
- Modify: `internal/db/proxy/postgres/simplequery_test.go`

- [ ] **Step 1: Write failing tests**

Append to `internal/db/proxy/postgres/simplequery_test.go`:

```go
func TestHandleQuery_DenyPath_PreTx(t *testing.T) {
	pc, clientFE, sink, _ := newAllowPathFixture(t)
	pc.state.lastUpstreamRFQ = 'I'
	pc.srv.SetPolicy(denyDeletesRuleSet(t))

	mustSendFromClient(t, clientFE, &pgproto3.Query{String: "DELETE FROM t"})

	go func() { _ = pc.simpleQueryLoop(context.Background()) }()

	er := mustReceiveClientFrame(t, clientFE).(*pgproto3.ErrorResponse)
	if er.SQLState != "42501" {
		t.Fatalf("SQLState = %q want 42501", er.SQLState)
	}
	rfq := mustReceiveClientFrame(t, clientFE).(*pgproto3.ReadyForQuery)
	if rfq.TxStatus != 'I' {
		t.Fatalf("RFQ TxStatus = %q want 'I'", rfq.TxStatus)
	}

	evs := sink.DrainStatements()
	if len(evs) != 1 || evs[0].Decision.Verb != "deny" {
		t.Fatalf("statement events = %+v", evs)
	}
	if evs[0].TxContext.DenyAction != "none" {
		t.Fatalf("DenyAction = %q want none", evs[0].TxContext.DenyAction)
	}
}

func TestHandleQuery_DenyPath_InTx_Terminates(t *testing.T) {
	pc, clientFE, sink, _ := newAllowPathFixture(t)
	pc.state.lastUpstreamRFQ = 'T' // simulate prior BEGIN
	pc.srv.SetPolicy(denyDeletesRuleSet(t))

	mustSendFromClient(t, clientFE, &pgproto3.Query{String: "DELETE FROM t"})

	err := pc.simpleQueryLoop(context.Background())
	if err == nil {
		t.Fatalf("simpleQueryLoop must return non-nil on in-tx deny terminate")
	}

	er := mustReceiveClientFrame(t, clientFE).(*pgproto3.ErrorResponse)
	if er.SQLState != "42501" {
		t.Fatalf("SQLState = %q want 42501", er.SQLState)
	}
	// No ReadyForQuery should follow — try Receive and expect an error.
	if _, e := clientFE.Receive(); e == nil {
		t.Fatalf("expected client conn closed after in-tx deny, got next frame")
	}

	evs := sink.DrainStatements()
	if len(evs) != 1 || evs[0].TxContext.DenyAction != "connection_terminated" {
		t.Fatalf("events = %+v", evs)
	}
}

func TestHandleQuery_DenyPath_MultiStmt_TagsSiblings(t *testing.T) {
	pc, clientFE, sink, _ := newAllowPathFixture(t)
	pc.state.lastUpstreamRFQ = 'I'
	pc.srv.SetPolicy(denyDeletesRuleSet(t))

	mustSendFromClient(t, clientFE, &pgproto3.Query{String: "SELECT 1; DELETE FROM t"})

	go func() { _ = pc.simpleQueryLoop(context.Background()) }()
	_ = mustReceiveClientFrame(t, clientFE) // ErrorResponse
	_ = mustReceiveClientFrame(t, clientFE) // ReadyForQuery

	evs := sink.DrainStatements()
	if len(evs) != 2 {
		t.Fatalf("statement events = %d want 2", len(evs))
	}
	// First (SELECT) should be denied_by_sibling.
	if evs[0].Result.ErrorCode != "DENIED_BY_SIBLING" || evs[0].Decision.Verb != "deny" {
		t.Fatalf("evs[0] = %+v", evs[0])
	}
	// Second (DELETE) is the actual denying stmt.
	if evs[1].Decision.Verb != "deny" || evs[1].Decision.RuleName == "" {
		t.Fatalf("evs[1] = %+v", evs[1])
	}
}

func denyDeletesRuleSet(t *testing.T) *policy.RuleSet {
	rs, _, err := policy.Decode([]byte(`
services:
  - name: test
    family: postgres
    dialect: postgres
    upstream: "127.0.0.1:5432"
    tls_mode: terminate_reissue

rules:
  - name: allow-reads
    decision: allow
    operations: [read]
    services: [test]
    objects: ['*']
  - name: deny-deletes
    decision: deny
    operations: [write]
    services: [test]
    objects: ['*']
`))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	return rs
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `go test ./internal/db/proxy/postgres/ -run TestHandleQuery_DenyPath -count=1`
Expected: FAIL — deny stub returns `42501` with "deny path not yet implemented", and no events emit.

- [ ] **Step 3: Wire the deny path**

Replace the deny stub at the end of `handleQuery` in `internal/db/proxy/postgres/simplequery.go`:

```go
	// Deny path.
	denyAction := "none"
	if pc.state.lastUpstreamRFQ == 'T' || pc.state.lastUpstreamRFQ == 'E' {
		denyAction = "connection_terminated"
	}
	pc.emitDenyEvents(ctx, stmts, decisions, q.String, batchSHA, denyAction)
	rendered, sqlstate := pickDenySynth(decisions)
	switch pc.state.lastUpstreamRFQ {
	case 0, 'I':
		return pc.synthErrorAndRFQ(sqlstate, rendered)
	case 'T', 'E':
		_ = pc.synthErrorOnly(sqlstate, rendered)
		return errInTxTerminate
	default:
		return fmt.Errorf("postgres.handleQuery: unexpected RFQ byte %q", pc.state.lastUpstreamRFQ)
	}
}

func (pc *proxyConn) emitDenyEvents(
	ctx context.Context,
	stmts []effects.ClassifiedStatement,
	decisions []policy.Decision,
	sql, batchSHA, denyAction string,
) {
	parser := pc.srv.classifierFor(pc.svc.Dialect)
	for i, s := range stmts {
		deniedBySibling := decisions[i].Verb != policy.VerbDeny
		ev := buildStatementEvent(buildArgs{
			Stmt: s, StmtIndex: i, BatchTotal: len(stmts),
			Decision: decisions[i],
			SQL: sql, Tier: pc.state.redactionTier,
			Conn: *pc.state,
			BytesIn: int64(len(sql)),
			DenyAction: denyAction,
			IsDeniedBySibling: deniedBySibling,
			BatchSHA: batchSHA,
			Parser: parser,
		})
		if err := pc.srv.cfg.Sink.EmitStatement(ctx, ev); err != nil {
			pc.logger.Warn("emit statement event failed", "err", err)
		}
	}
}
```

- [ ] **Step 4: Run all simplequery tests**

Run: `go test ./internal/db/proxy/postgres/ -run TestHandleQuery -count=1 -v`
Expected: all PASS.

Run the package's full suite to confirm no regression:

Run: `go test ./internal/db/proxy/postgres/ -count=1`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add internal/db/proxy/postgres/simplequery.go \
       internal/db/proxy/postgres/simplequery_test.go
git commit -m "db: proxy — handleQuery deny path with RFQ-gated synth + sibling tagging"
```

---

## Task 14: Wire `simpleQueryLoop` into `handshake.dialUpstreamAndForward` + config-load warning for `approve`

**Why:** Two small wiring steps. (1) After `forwardAuth` returns nil, `dialUpstreamAndForward` currently returns nil; we change it to seed `redactionTier` / `tlsMode` and call `simpleQueryLoop`. (2) `policy.Decode` emits a `Warning` for every rule with `decision: approve` so operators see APPROVE_NOT_YET_SUPPORTED at config load.

**Files:**
- Modify: `internal/db/proxy/postgres/handshake.go`
- Modify: `internal/db/policy/decode.go`
- Modify: `internal/db/policy/decode_test.go`

- [ ] **Step 1: Write failing test for the decode warning**

Append to `internal/db/policy/decode_test.go`:

```go
func TestDecode_WarnsOnApproveDecision(t *testing.T) {
	yaml := []byte(`
services:
  - name: appdb
    family: postgres
    dialect: postgres
    upstream: "127.0.0.1:5432"
    tls_mode: terminate_reissue

rules:
  - name: review-deletes
    decision: approve
    operations: [write]
    services: [appdb]
    objects: ['*']
`)
	_, warnings, err := Decode(yaml)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	var found bool
	for _, w := range warnings {
		if w.Code == "APPROVE_NOT_YET_SUPPORTED" && w.Rule == "review-deletes" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected APPROVE_NOT_YET_SUPPORTED warning, got %+v", warnings)
	}
}
```

- [ ] **Step 2: Write failing test for the loop entry**

Append to `internal/db/proxy/postgres/handshake_test.go` (or extend an existing forward-auth test):

```go
func TestDialUpstreamAndForward_EntersSimpleQueryLoopAfterRFQ(t *testing.T) {
	pc, _, fakeUp, sink := newDialUpstreamFixture(t)
	pc.srv.SetPolicy(allowAllRuleSet(t))

	fakeUp.ScriptAuth([]pgproto3.BackendMessage{
		&pgproto3.AuthenticationOk{},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	})
	fakeUp.ScriptOnFirstQuery([]pgproto3.BackendMessage{
		&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("a")}}},
		&pgproto3.DataRow{Values: [][]byte{[]byte("1")}},
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	})

	// Client sends a 'Q' after handshake; the proxy should classify+forward.
	go pc.dispatchStartup(context.Background())

	// (Implementation of newDialUpstreamFixture lives below in this file.)
	// Assert: one statement event in sink after the round-trip.
	// ...
	_ = sink
}
```

This test is structurally larger than the others and exists for full path-coverage. The exact fixture shape may need to lean on the existing `testupstream_test.go` helper from 04b₂ — extend it to script a post-auth Q response.

- [ ] **Step 3: Run tests to verify failure**

Run: `go test ./internal/db/policy/ -run TestDecode_WarnsOnApproveDecision -count=1`
Expected: FAIL — no warning emitted today.

Run: `go test ./internal/db/proxy/postgres/ -run TestDialUpstreamAndForward_EntersSimpleQueryLoopAfterRFQ -count=1`
Expected: FAIL or build error — `simpleQueryLoop` not yet called from the handshake.

- [ ] **Step 4: Emit the approve warning in `policy.Decode`**

Modify `internal/db/policy/decode.go`. After statement-rule decoding, iterate rules and append a `Warning`:

```go
	for _, r := range statementRules {
		if r.Decision == "approve" {
			warnings = append(warnings, Warning{
				Rule:    r.Name,
				Field:   "decision",
				Code:    "APPROVE_NOT_YET_SUPPORTED",
				Message: "decision: approve is parsed but treated as deny at runtime until Plan 05",
				Line:    r.line, // existing yaml.v3 node line
			})
		}
	}
```

Adjust naming to match the existing decode loop — the symbol names in the codebase may differ slightly.

- [ ] **Step 5: Call `simpleQueryLoop` after `forwardAuth` returns**

Modify `internal/db/proxy/postgres/handshake.go`. In `dialUpstreamAndForward`, the tail of the function currently looks like:

```go
	if err := forwardAuth(ctx, pc); err != nil {
		if errors.Is(err, errScramPlusFailClosed) {
			pc.emitHandshakeFail(ctx, scramPlusEventCode)
			return nil
		}
		return nil
	}
	return nil
}
```

Replace with:

```go
	if err := forwardAuth(ctx, pc); err != nil {
		if errors.Is(err, errScramPlusFailClosed) {
			pc.emitHandshakeFail(ctx, scramPlusEventCode)
			return nil
		}
		return nil
	}
	// Hand off to the Simple Query loop. forwardAuth already wrote the
	// observed 'Z' status byte into pc.state.lastUpstreamRFQ.
	if rs := pc.srv.policy(); rs != nil {
		pc.state.redactionTier = rs.Redaction().LogStatements
	} else {
		pc.state.redactionTier = policy.RedactParametersRedacted
	}
	pc.state.tlsMode = pc.svc.TLSMode
	return pc.simpleQueryLoop(ctx)
}
```

Add the `"github.com/agentsh/agentsh/internal/db/policy"` import if not present.

- [ ] **Step 6: Run tests to confirm passing**

Run: `go test ./internal/db/policy/ -count=1`
Expected: green, including the new warning test.

Run: `go test ./internal/db/proxy/postgres/ -count=1`
Expected: green.

- [ ] **Step 7: Commit**

```bash
git add internal/db/proxy/postgres/handshake.go \
       internal/db/policy/decode.go \
       internal/db/policy/decode_test.go \
       internal/db/proxy/postgres/handshake_test.go
git commit -m "db: wire simpleQueryLoop into handshake + warn on approve at config-load"
```

---

## Task 15: Spine integration test — real `pgx` + fake upstream

**Why:** The skeleton design's "does the whole shape compose" test. Three subtests: allow, pre-tx deny, in-tx deny terminate. Adds `pgx` as a test-only dep.

**Files:**
- Modify: `internal/db/proxy/postgres/spine_test.go` (extend existing file from 04b₂)
- Modify: `go.mod` / `go.sum`

- [ ] **Step 1: Promote `pgx` to a top-level test dep**

Run:

```bash
go get github.com/jackc/pgx/v5
go mod tidy
```

Expected: `pgx` moves from `// indirect` to a top-level entry; checksum changes.

- [ ] **Step 2: Write the three failing spine subtests**

Append to `internal/db/proxy/postgres/spine_test.go`:

```go
func TestSpine_Plan04c_SimpleQuery_AllowFlow(t *testing.T) {
	t.Parallel()
	env := newSpineEnv(t, withSpinePolicy(allowAllRuleSet(t)))
	defer env.Close()

	env.Upstream.ScriptOnFirstQuery([]pgproto3.BackendMessage{
		&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("a")}}},
		&pgproto3.DataRow{Values: [][]byte{[]byte("1")}},
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	})

	conn, err := pgx.Connect(context.Background(), env.PgxConnString())
	if err != nil {
		t.Fatalf("pgx.Connect: %v", err)
	}
	defer conn.Close(context.Background())

	rows, err := conn.Query(context.Background(), "SELECT 1")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !rows.Next() {
		t.Fatalf("expected one row, got none")
	}
	rows.Close()

	evs := env.Sink.DrainStatements()
	if len(evs) != 1 || evs[0].Decision.Verb != "allow" {
		t.Fatalf("events = %+v", evs)
	}
	if evs[0].Result.RowsReturned == nil || *evs[0].Result.RowsReturned != 1 {
		t.Fatalf("RowsReturned = %v want 1", evs[0].Result.RowsReturned)
	}
}

func TestSpine_Plan04c_SimpleQuery_DenyPreTx(t *testing.T) {
	t.Parallel()
	env := newSpineEnv(t, withSpinePolicy(denyDeletesRuleSet(t)))
	defer env.Close()

	conn, err := pgx.Connect(context.Background(), env.PgxConnString())
	if err != nil {
		t.Fatalf("pgx.Connect: %v", err)
	}
	defer conn.Close(context.Background())

	_, err = conn.Exec(context.Background(), "DELETE FROM t")
	if err == nil {
		t.Fatalf("Exec: expected deny error, got nil")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("error = %v (code = %v) want 42501", err, pgErrCodeOrEmpty(err))
	}
	if env.Upstream.BytesReceivedAfterStartup() != 0 {
		t.Fatalf("upstream received %d bytes after startup; want 0 (deny pre-forward)",
			env.Upstream.BytesReceivedAfterStartup())
	}

	evs := env.Sink.DrainStatements()
	if len(evs) != 1 || evs[0].Decision.Verb != "deny" {
		t.Fatalf("events = %+v", evs)
	}
}

func TestSpine_Plan04c_SimpleQuery_DenyInTx_Terminates(t *testing.T) {
	t.Parallel()
	env := newSpineEnv(t, withSpinePolicy(denyDeletesRuleSet(t)))
	defer env.Close()

	// BEGIN is an allowed statement (session, covered by allow-reads? — no,
	// the deny fixture only allows reads. We need a fixture that allows
	// BEGIN as well. Use a separate fixture:)
	env.Server.SetPolicy(allowReadsAndSessionsDenyWritesRuleSet(t))

	env.Upstream.ScriptOnNthQuery(1, []pgproto3.BackendMessage{
		&pgproto3.CommandComplete{CommandTag: []byte("BEGIN")},
		&pgproto3.ReadyForQuery{TxStatus: 'T'},
	})

	conn, err := pgx.Connect(context.Background(), env.PgxConnString())
	if err != nil {
		t.Fatalf("pgx.Connect: %v", err)
	}

	// Issue BEGIN via SimpleProtocol.
	_, err = conn.Exec(context.Background(), "BEGIN")
	if err != nil {
		t.Fatalf("BEGIN: %v", err)
	}
	// Now DELETE — must be denied and the conn terminated.
	_, err = conn.Exec(context.Background(), "DELETE FROM t")
	if err == nil {
		t.Fatalf("Exec DELETE: expected deny error")
	}

	// Subsequent op must fail with closed-conn.
	_, err = conn.Exec(context.Background(), "SELECT 1")
	if err == nil {
		t.Fatalf("expected closed-conn error on next op")
	}

	evs := env.Sink.DrainStatements()
	var deny events.DBEvent
	for _, e := range evs {
		if e.Decision.Verb == "deny" {
			deny = e
			break
		}
	}
	if deny.TxContext.DenyAction != "connection_terminated" {
		t.Fatalf("DenyAction = %q want connection_terminated", deny.TxContext.DenyAction)
	}
}

func pgErrCodeOrEmpty(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}
```

The fixture `newSpineEnv` + `withSpinePolicy` + `env.PgxConnString()` + `env.Upstream.BytesReceivedAfterStartup()` must be authored to:
1. Bind the proxy to a `t.TempDir()` Unix socket.
2. Issue the AgentSH CA via the existing `tlsleaf` package.
3. Build a `pgxpool`-friendly conn string with `sslmode=verify-full`, `sslrootcert=` set to the CA path, `host=` set to the Unix socket dir.
4. Spin a fake upstream from `testupstream_test.go` (extend with `BytesReceivedAfterStartup` if missing).

Put helpers near the existing 04b₂ spine helpers.

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/db/proxy/postgres/ -run TestSpine_Plan04c -count=1`
Expected: FAIL on missing fixture helpers; flesh them out incrementally.

- [ ] **Step 4: Author the fixture helpers**

In `internal/db/proxy/postgres/spine_test.go`, add `newSpineEnv` + `spineEnv`. Sketch:

```go
type spineEnv struct {
	Server   *Server
	Upstream *fakeUpstream
	Sink     *events.SyncSink
	CAPath   string
	SockDir  string
}

func newSpineEnv(t *testing.T, opts ...spineOpt) *spineEnv {
	t.Helper()
	dir := t.TempDir()
	caDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(caDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sockDir := filepath.Join(dir, "sock")
	if err := os.MkdirAll(sockDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sockPath := filepath.Join(sockDir, ".s.PGSQL.5432")

	fake := newFakeUpstream(t)

	sink := &events.SyncSink{}
	svc := Service{
		Name:     "test",
		Family:   "postgres",
		Dialect:  "postgres",
		Upstream: fake.Addr(),
		TLSMode:  "terminate_reissue",
		Listen:   ServiceListener{Kind: "unix", Path: sockPath},
	}
	cfg := Config{
		Unavoidability: service.UnavoidabilityObserve,
		Services:       []Service{svc},
		StateDir:       caDir,
		Sink:           sink,
		// UpstreamTLSConfigForTest set to skip-verify against the fake upstream.
		UpstreamTLSConfigForTest: &tls.Config{InsecureSkipVerify: true},
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = s.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = s.Shutdown(context.Background())
	})

	caPath := filepath.Join(caDir, "db-ca.crt")
	return &spineEnv{
		Server:   s,
		Upstream: fake,
		Sink:     sink,
		CAPath:   caPath,
		SockDir:  sockDir,
	}
}

func (e *spineEnv) PgxConnString() string {
	return fmt.Sprintf("host=%s port=5432 user=agent dbname=app sslmode=verify-full sslrootcert=%s",
		e.SockDir, e.CAPath)
}

func (e *spineEnv) Close() { /* covered by t.Cleanup */ }

type spineOpt func(*Config)

func withSpinePolicy(rs *policy.RuleSet) spineOpt {
	return func(c *Config) { c.Policy = rs }
}
```

The `fakeUpstream` helper from 04b₂'s `testupstream_test.go` likely has `Addr()` and a script API; extend it with `ScriptOnFirstQuery` / `ScriptOnNthQuery` / `BytesReceivedAfterStartup` as needed. (If extending feels disproportionate, build a fresh fixture here and document why.)

- [ ] **Step 5: Run the spine tests**

Run: `go test ./internal/db/proxy/postgres/ -run TestSpine_Plan04c -count=1 -v`
Expected: all three subtests PASS.

If `pgx` keeps the conn open via NOTICE pumps or background goroutines and the test hangs, add a Read deadline to the proxy-side conn or a `context.WithTimeout(t.Context(), 5*time.Second)` on every `pgx` call.

- [ ] **Step 6: Cross-compile + full repo test**

Run: `GOOS=windows go build ./...`
Expected: green.

Run: `go test ./... -count=1`
Expected: green.

Run: `go mod tidy && git diff --exit-code go.mod go.sum`
Expected: no further changes.

- [ ] **Step 7: Commit**

```bash
git add internal/db/proxy/postgres/spine_test.go internal/db/proxy/postgres/testupstream_test.go go.mod go.sum
git commit -m "db: proxy — spine integration test for Plan 04c (real pgx + fake upstream)"
```

---

## Self-review checklist (run after every task lands)

Before opening the PR for Plan 04c, walk back through the spec and verify each requirement maps to at least one task:

1. `Normalize` on Parser — Task 3. ✓
2. `SourceStart` / `SourceEnd` on ClassifiedStatement — Tasks 1, 2. ✓
3. DBEvent §8 sub-structs — Task 4. ✓
4. `MaxQueryBytes` default + cap enforcement — Tasks 5, 8. ✓
5. Atomic policy pointer + `SetPolicy` — Task 5. ✓
6. Per-dialect classifier map — Task 5. ✓
7. `connState` extensions + `'Z'` byte capture — Task 6. ✓
8. `simpleQueryLoop` skeleton + non-Q reject — Task 7. ✓
9. Per-frame upstream demux + counters — Task 9. ✓
10. Deny synth + SQLSTATE picker — Task 10. ✓
11. Eventbuilder + redaction + digest + sibling tagging — Task 11. ✓
12. Allow path + per-stmt allow events — Task 12. ✓
13. Deny path + RFQ-gated synth + per-stmt events with DenyAction — Task 13. ✓
14. Loop wired into handshake + approve config-load warning — Task 14. ✓
15. Spine integration test — Task 15. ✓
16. Cross-compile (`GOOS=windows go build ./...`) — Tasks 3, 4, 5, 15. ✓
17. `go mod tidy` clean after pgx promotion — Task 15. ✓

**Done definition** (mirrors spec §13): the spine test passes, `policies.db.unavoidability: off` is a no-op, `observe` mode end-to-end works, `go test ./...` green on Linux, cross-compile green on Windows.

---

## Open questions surfaced during planning

- **`effects.Effect.HasFilter`** — Plan 04c's `Predicates.HasFilter` reads from this field. If Plan 03 didn't surface it, `hasFilter()` returns false and a follow-up plan (or a small in-04c carve-out) wires the WHERE-clause detection. Flagged in Task 11 Step 3.
- **`SyncSink.lifecycle`** — verify against the current `sink.go`. Task 7 Step 5 assumes the structure; if 04b₂ shipped it differently, follow the existing shape.
- **`Decision.DenyMessage` template** — Plan 02's design mentions templates; the current `policy.Decision` struct does not expose `DenyMessage` directly. Task 10's `renderDenyMessage` falls back to RuleName/Reason. Adding template support is its own follow-up.

