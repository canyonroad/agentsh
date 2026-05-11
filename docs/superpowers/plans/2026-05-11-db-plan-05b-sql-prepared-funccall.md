# db-access Plan 05b — SQL Prepared Cache + FunctionCall Opt-in + Escalation Wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recognize SQL-level `PREPARE` / `EXECUTE` / `DEALLOCATE` / `DISCARD ALL` / `DISCARD PLANS` inside `'Q'` frames and wire a per-connection cache; flip 04c's `42501` FunctionCall stub into a real per-service opt-in path that classifies and evaluates `procedural` / `function_call_protocol`; thread the existing-but-unwired classifier escalation knobs (`EscalateUnknownFunctions`, `SafeFunctionAllowlist`) through from `policies.db` config to the classifier call sites in the proxy.

**Architecture:** Three orthogonal slices. (a) The classifier already implements function-call escalation (`internal/db/classify/postgres/escalation.go` exists in 04c); this plan adds `policies.db.escalate_unknown_functions` + `safe_function_allowlist` config fields and a seed list of immutable PG builtins, and threads them at every proxy classify call. (b) The classifier already classifies `PREPARE`/`EXECUTE`/`DEALLOCATE`/`DISCARD` per §7.3; this plan extends `effects.ClassifiedStatement` with a `PreparedName string` field, populates it from the existing AST handlers, and adds an `Intercept` helper that runs in `handleQuery` before forwarding to populate/lookup/evict `pc.sqlCache` (the second LRU instance 05a wired up). (c) FunctionCall `'F'` frame: when `service.AllowFunctionCallProtocol == true`, classify as `procedural`/`function_call_protocol` with `function_oid` populated and route through `Evaluate` + `DenyRoute`; otherwise keep 04c's `42501` stub.

**Tech Stack:** Go (`//go:build linux` for all new proxy files; events/effects/classify extensions are tag-free). No new external dependencies. Re-uses `statemachine.DenyRoute` from 05a so the deny path is unified.

**Cross-references:**
- Shared design: `docs/superpowers/specs/2026-05-11-db-plan-05-pg-extended-tx-design.md`
- Predecessor plan: `docs/superpowers/plans/2026-05-11-db-plan-05a-pg-extended-tx-statemachine.md`
- Spec: `docs/agentsh-db-access-spec.md` v0.8 §7.4, §7.5, §7.6, §9.2 R1, §10.3

**Settled in brainstorming (2026-05-11):**

1. The classifier's escalation logic ships in 04c. This plan only adds the config wiring + builtin seed list + proxy call-site threading.
2. SQL-prepared cache uses the second `preparedcache.Cache` instance 05a created (`pc.sqlCache`). Separate keyspace from the wire-protocol cache per §7.4 last paragraph.
3. `PrepareName` / `ExecuteName` / `DeallocateName` are carried on a single new `effects.ClassifiedStatement.PreparedName string` field, populated only for those verbs. Avoids the proxy re-parsing the SQL.
4. `DEALLOCATE ALL` is signaled by `PreparedName == ""` and `RawVerb == "DEALLOCATE"`. Tests confirm.
5. FunctionCall events carry `Effect.FunctionOID *int32` (omitempty). `function_name` resolution deferred to Phase 2 per §7.5.
6. `policies.db.escalate_unknown_functions` and `policies.db.safe_function_allowlist` go on `RedactionConfig` (already the catch-all for the policies.db block; renaming is out of scope).
7. The `Approve` runtime is NOT in 05b — `decision: approve` continues to deny as `APPROVE_NOT_YET_SUPPORTED` until 05c lands.

---

## File Structure

**Created:**

- `internal/db/proxy/postgres/sqlprepared.go` — `Intercept(stmts, sqlCache) → (Handled bool, Actions []statemachine.Action)`. Recognizes PREPARE/EXECUTE/DEALLOCATE/DISCARD by `RawVerb` prefix on the first classified statement; mutates `sqlCache`; returns `Handled=true` with `Actions` populated when the proxy should NOT call `policy.Evaluate` on the original statement (e.g., EXECUTE cache-miss synthesis).
- `internal/db/proxy/postgres/sqlprepared_test.go` — table coverage of §7.4 forms.
- `internal/db/proxy/postgres/funccall.go` — `handleFunctionCall(ctx, msg)` replaces 04c's `42501`-stub branch in `handleUnsupportedFrame`. Checks `pc.svc.Service.AllowFunctionCallProtocol`; if true, classifies as `procedural`/`function_call_protocol` and routes through `Evaluate`+`DenyRoute`+forward.
- `internal/db/proxy/postgres/funccall_test.go` — default → 42501; opt-in + allow → Forward; opt-in + deny → DenyRoute.
- `internal/db/classify/postgres/builtin_immutable.go` — `DefaultSafeFunctionAllowlist()` returning a curated set of immutable PG builtins (lowercase canonical names).
- `internal/db/classify/postgres/builtin_immutable_test.go` — sanity asserts that common builtins are present (`now`, `nextval`, `to_tsvector`, `count`, `coalesce`, `abs`, `length`, `lower`, `upper`, `pg_typeof`).

**Modified:**

- `internal/db/effects/statement.go` — add `PreparedName string \`json:"prepared_name,omitempty\"\`` field.
- `internal/db/effects/statement_test.go` — JSON round-trip with `omitempty` for zero value.
- `internal/db/classify/postgres/ast_dml.go` — `classifyPrepare`, `classifyExecute` populate `cs.PreparedName`; deallocate uses `classifyDeallocate` which already lives in this file.
- `internal/db/classify/postgres/ast_dml_test.go` — coverage for `PreparedName` on PREPARE/EXECUTE.
- `internal/db/classify/postgres/ast_walk.go` — already dispatches PREPARE/EXECUTE/DEALLOCATE; no change beyond the AST handler tweaks above.
- `internal/db/policy/redaction.go` — add `EscalateUnknownFunctions bool` and `SafeFunctionAllowlist []string` to `RedactionConfig`.
- `internal/db/policy/decode.go` — parse the new fields from `policies.db.escalate_unknown_functions` and `policies.db.safe_function_allowlist`; default the allowlist to `classify_pg.DefaultSafeFunctionAllowlist()` when omitted.
- `internal/db/policy/decode_test.go` — coverage for the new YAML keys.
- `internal/db/proxy/postgres/simplequery.go` — `handleQuery` calls `sqlprepared.Intercept` after classify but before evaluate; threads `Options{EscalateUnknownFunctions, SafeFunctionAllowlist}` into the classifier call from the active policy snapshot.
- `internal/db/proxy/postgres/statemachine/transition.go` — `handleQuery` and `handleParse` thread the same `Options` into `parser.Classify`. (Tests inject a fake parser; production uses the new helper.)
- `internal/db/proxy/postgres/extquery.go` — `handleUnsupportedFrame` no longer special-cases `*pgproto3.FunctionCall`; it delegates to `funccall.go`.
- `internal/db/proxy/postgres/simplequery.go` — same delegation (Q-frame dispatch loop already routes FunctionCall through `handleUnsupportedFrame`).
- `internal/db/events/event.go` — `Effect.FunctionOID *int32 \`json:"function_oid,omitempty"\`` added (the existing `effects.Effect` type also needs this — see note in Task 8).
- `internal/db/effects/effect.go` — `Effect` struct gains `FunctionOID *int32` (omitempty).
- `internal/db/proxy/postgres/eventbuilder.go` — propagate `FunctionOID` from classified effects into the emitted event.

**Out of scope (deferred to 05c):**

- COPY data-frame handling.
- Approver interface, approval-timeout runtime, removal of `APPROVE_NOT_YET_SUPPORTED` warning.

---

## Task 1: `effects.ClassifiedStatement.PreparedName` field

**Why:** The proxy's SQL prepared cache needs the statement name, but the classifier currently doesn't expose it. Add a single string field rather than 3-4 verb-specific fields.

**Files:**
- Modify: `internal/db/effects/statement.go`
- Modify: `internal/db/effects/statement_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/db/effects/statement_test.go`:

```go
func TestClassifiedStatement_PreparedName_JSON_RoundTrip(t *testing.T) {
	in := ClassifiedStatement{
		Effects:      []Effect{{Group: GroupSession, Subtype: SubtypeDiscardPlans}},
		RawVerb:      "DEALLOCATE",
		PreparedName: "s1",
	}
	bs, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(bs), `"prepared_name":"s1"`) {
		t.Fatalf("missing prepared_name in JSON: %s", bs)
	}
	var out ClassifiedStatement
	if err := json.Unmarshal(bs, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.PreparedName != "s1" {
		t.Fatalf("PreparedName=%q", out.PreparedName)
	}
}

func TestClassifiedStatement_PreparedName_OmitEmpty(t *testing.T) {
	in := ClassifiedStatement{
		Effects: []Effect{{Group: GroupRead}},
		RawVerb: "SELECT",
	}
	bs, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(bs), "prepared_name") {
		t.Fatalf("prepared_name should be omitted; got: %s", bs)
	}
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `go test ./internal/db/effects/ -run TestClassifiedStatement_PreparedName -count=1`
Expected: build error — `PreparedName` undefined.

- [ ] **Step 3: Add the field**

Open `internal/db/effects/statement.go`. Append `PreparedName` to the struct:

```go
type ClassifiedStatement struct {
	Effects       []Effect      `json:"effects"`
	RawVerb       string        `json:"raw_verb,omitempty"`
	ParserBackend ParserBackend `json:"parser_backend,omitempty"`
	Error         string        `json:"error,omitempty"`
	SourceStart   int32         `json:"source_start,omitempty"`
	SourceEnd     int32         `json:"source_end,omitempty"`

	// PreparedName is populated for PREPARE / EXECUTE / DEALLOCATE classifications.
	// Empty for any other verb. For DEALLOCATE ALL, PreparedName is "" (the
	// proxy's sqlprepared.Intercept distinguishes by RawVerb).
	PreparedName string `json:"prepared_name,omitempty"`
}
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/effects/ -run TestClassifiedStatement_PreparedName -count=1 -v`
Expected: both PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/effects/statement.go internal/db/effects/statement_test.go
git commit -m "db: effects — add PreparedName to ClassifiedStatement for §7.4 cache wiring"
```

---

## Task 2: Populate `PreparedName` from classifier handlers

**Why:** The classifier's PREPARE / EXECUTE / DEALLOCATE handlers see the pg_query node with the name in it but discard the value. Capture it onto `cs.PreparedName`.

**Files:**
- Modify: `internal/db/classify/postgres/ast_dml.go`
- Modify: `internal/db/classify/postgres/ast_dml_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/db/classify/postgres/ast_dml_test.go`:

```go
func TestClassifyPrepare_PopulatesPreparedName(t *testing.T) {
	p := New(DialectPostgres)
	got, err := p.Classify("PREPARE s1 AS SELECT 1", SessionState{}, Options{})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0].PreparedName != "s1" {
		t.Fatalf("PreparedName=%q want s1", got[0].PreparedName)
	}
}

func TestClassifyExecute_PopulatesPreparedName(t *testing.T) {
	p := New(DialectPostgres)
	got, err := p.Classify("EXECUTE s1(42)", SessionState{}, Options{})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got[0].PreparedName != "s1" {
		t.Fatalf("PreparedName=%q want s1", got[0].PreparedName)
	}
}

func TestClassifyDeallocate_Named(t *testing.T) {
	p := New(DialectPostgres)
	got, err := p.Classify("DEALLOCATE s1", SessionState{}, Options{})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got[0].RawVerb != "DEALLOCATE" {
		t.Fatalf("RawVerb=%q", got[0].RawVerb)
	}
	if got[0].PreparedName != "s1" {
		t.Fatalf("PreparedName=%q want s1", got[0].PreparedName)
	}
}

func TestClassifyDeallocate_All(t *testing.T) {
	p := New(DialectPostgres)
	got, err := p.Classify("DEALLOCATE ALL", SessionState{}, Options{})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got[0].PreparedName != "" {
		t.Fatalf("PreparedName=%q want \"\" for DEALLOCATE ALL", got[0].PreparedName)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/db/classify/postgres/ -run TestClassify(Prepare|Execute|Deallocate) -count=1`
Expected: FAIL — `PreparedName=""` for the named cases.

- [ ] **Step 3: Update the handlers**

Open `internal/db/classify/postgres/ast_dml.go`. Update `classifyPrepare`:

```go
func classifyPrepare(cs *effects.ClassifiedStatement, s *pg_query.PrepareStmt, sess SessionState, opts Options) {
	cs.RawVerb = "PREPARE"
	if s == nil || s.Query == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: PREPARE without query"
		return
	}
	cs.PreparedName = s.Name // pg_query.PrepareStmt.Name is the prepared statement name
	inner := classifyRawStmt(DialectPostgres, &pg_query.RawStmt{Stmt: s.Query}, sess, opts, cs.ParserBackend)
	cs.Effects = inner.Effects
	if inner.RawVerb != "" {
		cs.RawVerb = "PREPARE_" + inner.RawVerb
	}
	if inner.Error != "" {
		cs.Error = inner.Error
	}
}
```

Update `classifyExecute`:

```go
func classifyExecute(cs *effects.ClassifiedStatement, s *pg_query.ExecuteStmt, _ SessionState, _ Options) {
	// Cache lookup is owned by Plan 05 (proxy). Plan 03 returns unknown so the
	// proxy can synthesize the cache-miss deny path per spec §7.4. Plan 05b
	// captures the prepared-statement name here so the proxy can index into
	// its cache without re-parsing.
	cs.RawVerb = "EXECUTE"
	if s != nil {
		cs.PreparedName = s.Name
	}
	cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
	cs.Error = "execute: cache lookup deferred to proxy (Plan 05)"
}
```

Update `classifyDeallocate`:

```go
func classifyDeallocate(cs *effects.ClassifiedStatement, s *pg_query.DeallocateStmt) {
	cs.RawVerb = "DEALLOCATE"
	if s != nil {
		cs.PreparedName = s.Name // empty string means DEALLOCATE ALL
	}
	cs.Effects = []effects.Effect{{
		Group:   effects.GroupSession,
		Subtype: effects.SubtypeDiscardPlans,
	}}
}
```

Note: `pg_query.DeallocateStmt.Name == ""` is precisely how pg_query represents `DEALLOCATE ALL`. Sanity-check by inspecting the v6 generated proto definition if behavior differs.

The function signature for `classifyDeallocate` does not currently take `s` (per the 04c grep — the second param was `*pg_query.DeallocateStmt` per call site but the function ignored it with `_`). Update the function signature to use the parameter, and verify the caller in `ast_walk.go` passes it.

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/classify/postgres/ -run TestClassify(Prepare|Execute|Deallocate) -count=1 -v`
Expected: all four PASS.

Run also: `go test ./internal/db/classify/postgres/ -count=1`
Expected: all existing classifier tests still PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/classify/postgres/ast_dml.go internal/db/classify/postgres/ast_dml_test.go
git commit -m "db: classify/postgres — populate PreparedName for PREPARE/EXECUTE/DEALLOCATE"
```

---

## Task 3: Builtin immutable seed list

**Why:** Operators turning on `escalate_unknown_functions` need a sensible default `safe_function_allowlist` so common workloads (ORM-issued `now()`, `nextval()`, `count()`, …) don't trip the escalation. Ship a curated set of immutable PG builtins.

**Files:**
- Create: `internal/db/classify/postgres/builtin_immutable.go`
- Create: `internal/db/classify/postgres/builtin_immutable_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/db/classify/postgres/builtin_immutable_test.go`:

```go
package postgres

import "testing"

func TestDefaultSafeFunctionAllowlist_ContainsCommonBuiltins(t *testing.T) {
	allow := DefaultSafeFunctionAllowlist()
	want := []string{
		"now", "nextval", "currval", "lastval",
		"to_tsvector", "to_tsquery", "plainto_tsquery",
		"count", "sum", "avg", "min", "max",
		"coalesce", "nullif", "greatest", "least",
		"abs", "length", "char_length", "octet_length",
		"lower", "upper", "trim", "btrim", "ltrim", "rtrim",
		"substring", "substr", "left", "right", "position",
		"replace", "split_part", "string_agg", "array_agg",
		"pg_typeof", "version", "current_timestamp",
		"current_date", "current_time", "localtimestamp", "localtime",
		"current_user", "session_user", "user",
	}
	for _, name := range want {
		if _, ok := allow[name]; !ok {
			t.Errorf("default allowlist missing %q", name)
		}
	}
}

func TestDefaultSafeFunctionAllowlist_LowercaseKeys(t *testing.T) {
	allow := DefaultSafeFunctionAllowlist()
	for k := range allow {
		for _, r := range k {
			if r >= 'A' && r <= 'Z' {
				t.Errorf("allowlist key %q has uppercase rune", k)
			}
		}
	}
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `go test ./internal/db/classify/postgres/ -run TestDefaultSafeFunctionAllowlist -count=1`
Expected: build error — `DefaultSafeFunctionAllowlist` undefined.

- [ ] **Step 3: Implement the seed list**

Create `internal/db/classify/postgres/builtin_immutable.go`:

```go
package postgres

// DefaultSafeFunctionAllowlist returns the curated set of immutable PostgreSQL
// builtin function names safe to treat as `read` when
// policies.db.escalate_unknown_functions is enabled.
//
// All keys are lowercase canonical names. Schema-qualified variants are not
// included; the canonicalFuncName walker matches bare names against the
// shorter form. Operators with custom search_path setups that prefer
// "pg_catalog.*" should add those keys explicitly via
// policies.db.safe_function_allowlist.
//
// This list is best-effort and conservative. It excludes anything stable but
// not provably immutable (e.g., functions that depend on timezone settings)
// and anything user-replaceable via search_path shadowing. When in doubt,
// operators should extend the allowlist via config rather than expect this
// list to be exhaustive.
func DefaultSafeFunctionAllowlist() map[string]struct{} {
	names := []string{
		// time / sequence
		"now", "current_timestamp", "current_date", "current_time",
		"localtimestamp", "localtime", "statement_timestamp", "transaction_timestamp",
		"clock_timestamp", "timeofday",
		"nextval", "currval", "lastval", "setval",
		"extract", "date_part", "date_trunc", "age",
		"to_date", "to_timestamp", "to_char", "to_number",
		// text search
		"to_tsvector", "to_tsquery", "plainto_tsquery", "phraseto_tsquery",
		"websearch_to_tsquery", "ts_rank", "ts_rank_cd", "ts_headline",
		// aggregates (read-only)
		"count", "sum", "avg", "min", "max", "stddev", "variance",
		"string_agg", "array_agg", "json_agg", "jsonb_agg",
		"bit_and", "bit_or", "bool_and", "bool_or", "every",
		// numeric / general
		"abs", "ceil", "ceiling", "floor", "round", "trunc", "sign",
		"power", "sqrt", "exp", "ln", "log", "mod", "div",
		"sin", "cos", "tan", "asin", "acos", "atan", "atan2",
		"degrees", "radians", "pi", "random",
		// string
		"length", "char_length", "character_length", "octet_length", "bit_length",
		"lower", "upper", "initcap",
		"trim", "btrim", "ltrim", "rtrim",
		"substring", "substr", "left", "right", "position", "strpos",
		"replace", "translate", "overlay",
		"split_part", "regexp_replace", "regexp_split_to_array", "regexp_split_to_table",
		"regexp_matches", "concat", "concat_ws", "format",
		"chr", "ascii", "to_hex", "md5",
		// general
		"coalesce", "nullif", "greatest", "least",
		"pg_typeof", "version", "current_schema", "current_schemas",
		"current_database", "current_user", "session_user", "user",
		"current_setting", "inet_client_addr", "inet_server_addr",
		// json / jsonb (selectors only — constructors are stable but cheap)
		"json_extract_path", "json_extract_path_text",
		"jsonb_extract_path", "jsonb_extract_path_text",
		"jsonb_typeof", "json_typeof",
		"json_array_elements", "jsonb_array_elements",
		"json_object_keys", "jsonb_object_keys",
		// array
		"array_length", "array_lower", "array_upper", "cardinality",
		"unnest", "array_to_string", "string_to_array", "array_position",
	}
	out := make(map[string]struct{}, len(names))
	for _, n := range names {
		out[n] = struct{}{}
	}
	return out
}
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/classify/postgres/ -run TestDefaultSafeFunctionAllowlist -count=1 -v`
Expected: both PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/classify/postgres/builtin_immutable.go internal/db/classify/postgres/builtin_immutable_test.go
git commit -m "db: classify/postgres — DefaultSafeFunctionAllowlist seed for §7.6 escalation"
```

---

## Task 4: `RedactionConfig` gains escalation knobs + decode

**Why:** `policies.db.escalate_unknown_functions: bool` and `policies.db.safe_function_allowlist: [<func>, ...]` must reach the classifier. They live on `RedactionConfig` (the existing `policies.db` block).

**Files:**
- Modify: `internal/db/policy/redaction.go`
- Modify: `internal/db/policy/decode.go`
- Modify: `internal/db/policy/decode_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/db/policy/decode_test.go`:

```go
func TestDecode_EscalateUnknownFunctions_DefaultFalse(t *testing.T) {
	rs, _, err := Decode([]byte(`
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue}
`))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if rs.Redaction().EscalateUnknownFunctions {
		t.Error("default EscalateUnknownFunctions should be false")
	}
}

func TestDecode_EscalateUnknownFunctions_True(t *testing.T) {
	rs, _, err := Decode([]byte(`
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue}
policies:
  db:
    escalate_unknown_functions: true
`))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !rs.Redaction().EscalateUnknownFunctions {
		t.Error("expected EscalateUnknownFunctions to be true")
	}
	if len(rs.Redaction().SafeFunctionAllowlist) == 0 {
		t.Error("default allowlist should be populated when escalate is true and allowlist omitted")
	}
}

func TestDecode_SafeFunctionAllowlist_Custom(t *testing.T) {
	rs, _, err := Decode([]byte(`
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue}
policies:
  db:
    escalate_unknown_functions: true
    safe_function_allowlist: ["my_func", "schema.fn"]
`))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	want := []string{"my_func", "schema.fn"}
	got := rs.Redaction().SafeFunctionAllowlist
	if len(got) != len(want) {
		t.Fatalf("len(got)=%d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d]=%q want %q", i, got[i], want[i])
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/db/policy/ -run TestDecode_(EscalateUnknownFunctions|SafeFunctionAllowlist) -count=1`
Expected: build error — fields undefined.

- [ ] **Step 3: Add the fields**

Open `internal/db/policy/redaction.go`. Extend `RedactionConfig`:

```go
type RedactionConfig struct {
	LogStatements            RedactionTier
	ApprovalStatementPreview RedactionTier
	ApprovalStatementChars   int

	// EscalateUnknownFunctions reflects policies.db.escalate_unknown_functions.
	// When true, classifier reclassifies SELECT calling a function NOT in
	// SafeFunctionAllowlist as procedural rather than read.
	EscalateUnknownFunctions bool

	// SafeFunctionAllowlist is the lowercase canonical function names that
	// stay classified as `read` when EscalateUnknownFunctions is on. When
	// the config omits the key but escalate is on, Decode populates this
	// with classify/postgres.DefaultSafeFunctionAllowlist() keys.
	SafeFunctionAllowlist []string
}
```

- [ ] **Step 4: Wire decode**

Open `internal/db/policy/decode.go`. Locate `decodeRedaction` (it parses the `policies.db` block). Add the new fields to the YAML target struct (likely `redactionYAML` per the existing layout) and populate `RedactionConfig`:

```go
type redactionYAML struct {
	// existing fields ...
	EscalateUnknownFunctions bool     `yaml:"escalate_unknown_functions"`
	SafeFunctionAllowlist    []string `yaml:"safe_function_allowlist"`
}
```

After populating the existing fields, append:

```go
	out.EscalateUnknownFunctions = w.DB.EscalateUnknownFunctions
	if len(w.DB.SafeFunctionAllowlist) > 0 {
		out.SafeFunctionAllowlist = append([]string(nil), w.DB.SafeFunctionAllowlist...)
	} else if out.EscalateUnknownFunctions {
		// Default to the curated builtin list when operator turned escalate
		// on without specifying their own allowlist.
		out.SafeFunctionAllowlist = defaultAllowlistKeys()
	}
```

Add a small helper in `decode.go`:

```go
// defaultAllowlistKeys returns the keys of DefaultSafeFunctionAllowlist as a
// sorted slice (for deterministic config round-trip). Lives in this package
// (not classify/postgres) to avoid an import cycle — the classifier reads
// the allowlist as a map[string]struct{}; this function converts.
func defaultAllowlistKeys() []string {
	src := classify_pg.DefaultSafeFunctionAllowlist()
	out := make([]string, 0, len(src))
	for k := range src {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
```

Add the imports `classify_pg "github.com/agentsh/agentsh/internal/db/classify/postgres"` and `"sort"` if not already present.

Watch for an import cycle: `internal/db/policy` may already import `classify/postgres` transitively via `effects`. If a cycle appears, the easiest fix is to move `DefaultSafeFunctionAllowlist` from `classify/postgres` to a new tag-free package `internal/db/classify/postgres/builtins` and have both `classify/postgres` and `policy` import that. The plan's preference is the direct import; only refactor if Go errors.

- [ ] **Step 5: Run tests to confirm they pass**

Run: `go test ./internal/db/policy/ -count=1 -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/db/policy/redaction.go internal/db/policy/decode.go internal/db/policy/decode_test.go
git commit -m "db: policy — decode policies.db.escalate_unknown_functions and safe_function_allowlist"
```

---

## Task 5: Thread escalation `Options` at proxy classify call sites

**Why:** Every `parser.Classify(sql, sess, opts)` call in the proxy must populate `Options.EscalateUnknownFunctions` + `SafeFunctionAllowlist` from the active policy snapshot. Two call sites today: `handleQuery` (Simple Query) and `statemachine.handleParse` + `statemachine.handleQuery` (Plan 05a).

**Files:**
- Modify: `internal/db/proxy/postgres/simplequery.go`
- Modify: `internal/db/proxy/postgres/statemachine/transition.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/db/proxy/postgres/simplequery_test.go`:

```go
func TestHandleQuery_Escalation_AppliesPolicyOptions(t *testing.T) {
	yaml := `
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue}
policies:
  db:
    escalate_unknown_functions: true
    safe_function_allowlist: ["now"]
database_rules:
  - name: block-procedural
    db_service: appdb
    operations: [procedural]
    decision: deny
  - name: allow-read
    db_service: appdb
    operations: [read]
    decision: allow
`
	srv := mustNewServerWithYAML(t, yaml)
	pc := mustPCFromSrv(t, srv)
	// SELECT calling an unknown function should be reclassified as procedural
	// and denied by the rule above.
	err := pc.handleQuery(context.Background(), &pgproto3.Query{String: "SELECT do_thing()"})
	if err == nil && !pc.upstreamFake.SawSyntheticErrorResponse() {
		t.Error("expected deny path: synthetic error or terminate")
	}
}
```

Mirror in `statemachine/transition_test.go` if a Parse-equivalent assertion fits.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestHandleQuery_Escalation`
Expected: FAIL — `SELECT do_thing()` is still classified as `read` (Options not threaded).

- [ ] **Step 3: Add the threading helper**

Add a small helper in `internal/db/proxy/postgres/simplequery.go` near the top:

```go
// classifierOptionsFromPolicy materializes a classify_pg.Options from the
// active policy snapshot. Captures the escalation knobs (§7.6) and converts
// the allowlist slice to a map for the walker.
func classifierOptionsFromPolicy(rs *policy.RuleSet) classify_pg.Options {
	if rs == nil {
		return classify_pg.Options{}
	}
	r := rs.Redaction()
	if !r.EscalateUnknownFunctions {
		return classify_pg.Options{}
	}
	allow := make(map[string]struct{}, len(r.SafeFunctionAllowlist))
	for _, n := range r.SafeFunctionAllowlist {
		allow[n] = struct{}{}
	}
	return classify_pg.Options{
		EscalateUnknownFunctions: true,
		SafeFunctionAllowlist:    allow,
	}
}
```

Update `handleQuery`'s classify call. Replace:

```go
	stmts, _ := parser.Classify(q.String, classify_pg.SessionState{}, classify_pg.Options{})
```

with:

```go
	rs := pc.srv.policy()
	opts := classifierOptionsFromPolicy(rs)
	stmts, _ := parser.Classify(q.String, classify_pg.SessionState{}, opts)
	// Note: the original `rs := pc.srv.policy()` below this line in 04c
	// becomes redundant — remove it if present, since `rs` is now defined
	// above.
```

- [ ] **Step 4: Thread the same options into the state machine**

Open `internal/db/proxy/postgres/statemachine/transition.go`. The pure `Transition` function currently constructs a parser via `classify_pg.New(classify_pg.DialectPostgres)` and calls `parser.Classify(sql, sess, Options{})`. Extend the helper functions `handleParse` and `handleQuery` (inside the state machine) to accept an `opts classify_pg.Options` argument:

```go
func handleParse(
	s ConnState, f *ParseFrame, cache CacheView,
	rules *policy.RuleSet, svc policy.ServiceID,
	parser PolicyClassifier, opts classify_pg.Options,
) (ConnState, []Action) {
	// ... unchanged guards ...
	stmts, err := parser.Classify(f.SQL, classify_pg.SessionState{}, opts)
	// ... rest unchanged ...
}
```

Add a parallel update to `handleQuery`. The top-level `Transition` and `TransitionWithParser` functions need a new parameter `opts classify_pg.Options`:

```go
func TransitionWithParser(
	s ConnState, frame Frame, cache CacheView,
	rules *policy.RuleSet, svc policy.ServiceID,
	parser PolicyClassifier, opts classify_pg.Options,
) (ConnState, []Action) {
	// switch unchanged; pass opts through to handleParse and handleQuery
}

func Transition(
	s ConnState, frame Frame, cache CacheView,
	rules *policy.RuleSet, svc policy.ServiceID,
) (ConnState, []Action) {
	parser := classify_pg.New(classify_pg.DialectPostgres)
	return TransitionWithParser(s, frame, cache, rules, svc, parser, classify_pg.Options{})
}
```

The dispatcher in `extquery.go` (from 05a) must thread `opts` through:

```go
parser := pc.srv.classifierFor(pc.svc.Dialect)
opts := classifierOptionsFromPolicy(pc.srv.policy())
next, actions := statemachine.TransitionWithParser(
	*pc.state.smState, frame, wireCacheView,
	pc.srv.policy(), policy.ServiceID(pc.svc.Name),
	parser, opts,
)
```

Tests built in 05a that call `Transition` (without opts) continue to work because the no-opts variant defaults to zero-valued Options (escalation off).

- [ ] **Step 5: Run tests to confirm they pass**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestHandleQuery_Escalation -v`
Expected: PASS.

Run: `go test ./internal/db/proxy/postgres/... -count=1`
Expected: all green (the no-opts `Transition` keeps 05a's tests working).

- [ ] **Step 6: Commit**

```bash
git add internal/db/proxy/postgres/simplequery.go internal/db/proxy/postgres/simplequery_test.go internal/db/proxy/postgres/statemachine/transition.go internal/db/proxy/postgres/extquery.go
git commit -m "db: proxy — thread escalation Options from policy through to classifier at call sites"
```

---

## Task 6: `sqlprepared.Intercept` helper

**Why:** Centralize the §7.4 SQL-prepared logic. `handleQuery` calls this *after* classify but *before* evaluate; on `Handled=true`, the caller skips its own evaluate/forward and executes the returned actions directly.

**Files:**
- Create: `internal/db/proxy/postgres/sqlprepared.go`
- Create: `internal/db/proxy/postgres/sqlprepared_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/db/proxy/postgres/sqlprepared_test.go`:

```go
//go:build linux

package postgres

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/preparedcache"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/statemachine"
)

func TestSQLPrepared_Prepare_Allow_PopulatesCacheAndReturnsNotHandled(t *testing.T) {
	cache := preparedcache.New(0)
	stmts := []effects.ClassifiedStatement{{
		RawVerb:      "PREPARE_SELECT",
		PreparedName: "s1",
		Effects:      []effects.Effect{{Group: effects.GroupRead}},
	}}
	decisions := []policy.Decision{{Verb: policy.VerbAllow}}
	handled, _ := Intercept(stmts, decisions, cache, statemachine.ConnState{})
	if handled {
		t.Fatal("PREPARE allow should return Handled=false; caller forwards normally")
	}
	if _, ok := cache.Get("s1"); !ok {
		t.Fatal("cache should contain s1 after PREPARE allow")
	}
}

func TestSQLPrepared_Prepare_Deny_HandledAndDoesNotCache(t *testing.T) {
	cache := preparedcache.New(0)
	stmts := []effects.ClassifiedStatement{{
		RawVerb:      "PREPARE_DELETE",
		PreparedName: "delstmt",
		Effects:      []effects.Effect{{Group: effects.GroupDelete}},
	}}
	decisions := []policy.Decision{{Verb: policy.VerbDeny, RuleName: "block-delete"}}
	handled, acts := Intercept(stmts, decisions, cache, statemachine.ConnState{LastUpstreamRFQ: 'I'})
	if !handled {
		t.Fatal("PREPARE deny should be handled by Intercept")
	}
	if len(acts) == 0 {
		t.Fatal("expected DenyRoute actions")
	}
	if _, ok := cache.Get("delstmt"); ok {
		t.Fatal("denied PREPARE must not populate cache")
	}
}

func TestSQLPrepared_Execute_CacheHit_AllowNotHandled(t *testing.T) {
	cache := preparedcache.New(0)
	cache.Put("s1", preparedcache.Entry{
		Classification: effects.ClassifiedStatement{
			Effects: []effects.Effect{{Group: effects.GroupRead}},
		},
	})
	stmts := []effects.ClassifiedStatement{{
		RawVerb:      "EXECUTE",
		PreparedName: "s1",
		Effects:      []effects.Effect{{Group: effects.GroupUnknown}}, // classifier marks Unknown for EXECUTE
	}}
	// Note: Intercept rewrites stmts[0] to the cached classification before
	// the caller evaluates. The current Decisions slice is empty until then.
	handled, acts := Intercept(stmts, nil, cache, statemachine.ConnState{})
	if handled {
		t.Fatalf("EXECUTE with cache hit should return Handled=false; caller evaluates rewritten stmts. acts=%v", acts)
	}
	if stmts[0].Effects[0].Group != effects.GroupRead {
		t.Fatalf("stmts[0] not rewritten; Group=%v", stmts[0].Effects[0].Group)
	}
}

func TestSQLPrepared_Execute_CacheMiss_HandledWithDenyRoute(t *testing.T) {
	cache := preparedcache.New(0)
	stmts := []effects.ClassifiedStatement{{
		RawVerb:      "EXECUTE",
		PreparedName: "missing",
	}}
	handled, acts := Intercept(stmts, nil, cache, statemachine.ConnState{LastUpstreamRFQ: 'I'})
	if !handled {
		t.Fatal("EXECUTE cache miss must be handled by Intercept")
	}
	if len(acts) < 2 {
		t.Fatalf("expected SynthError + RFQ; got %d actions", len(acts))
	}
	se, ok := acts[0].(*statemachine.ActionSynthError)
	if !ok {
		t.Fatalf("acts[0]=%T want SynthError", acts[0])
	}
	if !contains(se.Message, "SQL_PREPARED_CACHE_MISS") && !contains(se.Message, "prepared statement") {
		t.Errorf("error message lacks cache-miss indication: %q", se.Message)
	}
}

func TestSQLPrepared_DeallocateNamed_EvictsAndNotHandled(t *testing.T) {
	cache := preparedcache.New(0)
	cache.Put("s1", preparedcache.Entry{Classification: effects.ClassifiedStatement{RawVerb: "SELECT"}})
	stmts := []effects.ClassifiedStatement{{
		RawVerb:      "DEALLOCATE",
		PreparedName: "s1",
	}}
	handled, _ := Intercept(stmts, []policy.Decision{{Verb: policy.VerbAllow}}, cache, statemachine.ConnState{})
	if handled {
		t.Error("DEALLOCATE should return Handled=false so caller forwards Q to upstream")
	}
	if _, ok := cache.Get("s1"); ok {
		t.Error("cache must not retain s1 after DEALLOCATE")
	}
}

func TestSQLPrepared_DeallocateAll_ClearsAndNotHandled(t *testing.T) {
	cache := preparedcache.New(0)
	cache.Put("a", preparedcache.Entry{})
	cache.Put("b", preparedcache.Entry{})
	stmts := []effects.ClassifiedStatement{{RawVerb: "DEALLOCATE", PreparedName: ""}}
	handled, _ := Intercept(stmts, []policy.Decision{{Verb: policy.VerbAllow}}, cache, statemachine.ConnState{})
	if handled {
		t.Error("DEALLOCATE ALL should not be handled (forward Q to upstream)")
	}
	if cache.Len() != 0 {
		t.Errorf("cache.Len()=%d after DEALLOCATE ALL; want 0", cache.Len())
	}
}

func TestSQLPrepared_DiscardAll_ClearsAndNotHandled(t *testing.T) {
	cache := preparedcache.New(0)
	cache.Put("a", preparedcache.Entry{})
	stmts := []effects.ClassifiedStatement{{
		RawVerb: "DISCARD",
		Effects: []effects.Effect{{Group: effects.GroupSession, Subtype: effects.SubtypeDiscardAll}},
	}}
	handled, _ := Intercept(stmts, []policy.Decision{{Verb: policy.VerbAllow}}, cache, statemachine.ConnState{})
	if handled {
		t.Error("DISCARD ALL should not be handled (forward Q to upstream)")
	}
	if cache.Len() != 0 {
		t.Errorf("cache.Len()=%d after DISCARD ALL; want 0", cache.Len())
	}
}

func TestSQLPrepared_DiscardPlans_ClearsAndNotHandled(t *testing.T) {
	cache := preparedcache.New(0)
	cache.Put("a", preparedcache.Entry{})
	stmts := []effects.ClassifiedStatement{{
		RawVerb: "DISCARD",
		Effects: []effects.Effect{{Group: effects.GroupSession, Subtype: effects.SubtypeDiscardPlans}},
	}}
	handled, _ := Intercept(stmts, []policy.Decision{{Verb: policy.VerbAllow}}, cache, statemachine.ConnState{})
	if handled {
		t.Error("DISCARD PLANS should not be handled")
	}
	if cache.Len() != 0 {
		t.Errorf("cache.Len()=%d; want 0", cache.Len())
	}
}

func TestSQLPrepared_DiscardTemp_DoesNotTouchCache(t *testing.T) {
	cache := preparedcache.New(0)
	cache.Put("a", preparedcache.Entry{})
	stmts := []effects.ClassifiedStatement{{
		RawVerb: "DISCARD",
		Effects: []effects.Effect{{Group: effects.GroupSession, Subtype: effects.SubtypeDiscardTemp}},
	}}
	handled, _ := Intercept(stmts, []policy.Decision{{Verb: policy.VerbAllow}}, cache, statemachine.ConnState{})
	if handled {
		t.Error("DISCARD TEMP should not be handled")
	}
	if cache.Len() != 1 {
		t.Errorf("cache.Len()=%d after DISCARD TEMP; want 1 (untouched)", cache.Len())
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestSQLPrepared_ExpectedActionShape_DenyRouteMatch(t *testing.T) {
	cache := preparedcache.New(0)
	stmts := []effects.ClassifiedStatement{{RawVerb: "PREPARE_DELETE", PreparedName: "x", Effects: []effects.Effect{{Group: effects.GroupDelete}}}}
	decisions := []policy.Decision{{Verb: policy.VerbDeny, RuleName: "rule1"}}
	_, acts := Intercept(stmts, decisions, cache, statemachine.ConnState{LastUpstreamRFQ: 'I'})
	want := []statemachine.Action{
		&statemachine.ActionSynthError{SQLState: "42501", Message: "denied by AgentSH policy: rule1"},
		&statemachine.ActionSynthReadyForQuery{Status: 'I'},
	}
	if diff := cmp.Diff(want, acts); diff != "" {
		t.Errorf("acts diff: %s", diff)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestSQLPrepared`
Expected: build error — `Intercept` undefined.

- [ ] **Step 3: Implement `Intercept`**

Create `internal/db/proxy/postgres/sqlprepared.go`:

```go
//go:build linux

package postgres

import (
	"strings"

	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/preparedcache"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/statemachine"
)

// Intercept implements the spec §7.4 SQL-level prepared statement plus
// §9.2 R1 DISCARD coverage on the Simple Query path. Called from handleQuery
// after classify and evaluate; mutates the cache, may rewrite stmts[0] in
// place (for EXECUTE cache hits), and signals whether the caller still
// needs to forward the Q frame.
//
// Returns Handled=true with an Action sequence when the proxy must NOT
// forward to upstream — currently:
//   - PREPARE deny: cache untouched; emit DenyRoute.
//   - EXECUTE cache miss: emit SynthError + RFQ.
//
// Returns Handled=false when the caller should continue with its normal
// forward path. In that case, stmts[0] may have been rewritten:
//   - PREPARE allow/audit: cache populated; stmts unchanged.
//   - EXECUTE cache hit: stmts[0] replaced with cached classification so the
//     caller's subsequent Evaluate sees the right effect set.
//   - DEALLOCATE: cache entry removed (or cleared); stmts unchanged.
//   - DISCARD ALL / DISCARD PLANS: cache cleared; stmts unchanged.
//   - DISCARD TEMP / DISCARD SEQUENCES: no cache change; stmts unchanged.
//   - Any other RawVerb: no-op.
//
// `decisions` is allowed to be nil for verbs that don't require a prior
// evaluation (EXECUTE — the cached classification is the source of truth
// for re-eval inside the caller).
func Intercept(
	stmts []effects.ClassifiedStatement,
	decisions []policy.Decision,
	cache *preparedcache.Cache,
	s statemachine.ConnState,
) (handled bool, actions []statemachine.Action) {
	if len(stmts) == 0 {
		return false, nil
	}
	first := &stmts[0]

	switch {
	case strings.HasPrefix(first.RawVerb, "PREPARE"):
		// PREPARE name AS <inner>. RawVerb is "PREPARE" (no inner) or
		// "PREPARE_<INNER_VERB>". Decisions[0] should have been computed
		// against the inner classification (Effects already reflect inner).
		if len(decisions) > 0 && decisions[0].Verb == policy.VerbDeny {
			rule := lookupStatementRuleByName(nil, decisions[0].RuleName) // caller will pass rules; see handleQuery wiring
			msg := "denied by AgentSH policy: " + decisions[0].RuleName
			return true, statemachine.DenyRoute(s, rule, msg, "42501")
		}
		// Allow path: populate cache with the inner classification.
		// We stash a copy of the inner classification (sans the PREPARE_
		// prefix) so EXECUTE-time re-eval gets a clean ClassifiedStatement.
		inner := *first
		inner.RawVerb = strings.TrimPrefix(first.RawVerb, "PREPARE_")
		inner.PreparedName = ""
		cache.Put(first.PreparedName, preparedcache.Entry{Classification: inner})
		return false, nil

	case first.RawVerb == "EXECUTE":
		e, ok := cache.Get(first.PreparedName)
		if !ok {
			return true, []statemachine.Action{
				&statemachine.ActionSynthError{
					SQLState: "26000",
					Message:  "SQL_PREPARED_CACHE_MISS: prepared statement \"" + first.PreparedName + "\" does not exist in AgentSH proxy cache",
				},
				&statemachine.ActionSynthReadyForQuery{Status: 'I'},
			}
		}
		// Rewrite stmts[0] with the cached classification so the caller's
		// downstream Evaluate sees the inner statement's effects, not the
		// classifier's Unknown placeholder. RawVerb stays "EXECUTE" so
		// event emission shows the right action; the Effects come from
		// the cache.
		first.Effects = e.Classification.Effects
		first.Error = ""
		return false, nil

	case first.RawVerb == "DEALLOCATE":
		if first.PreparedName == "" {
			cache.Clear()
		} else {
			cache.Delete(first.PreparedName)
		}
		return false, nil

	case first.RawVerb == "DISCARD":
		// DISCARD ALL / DISCARD PLANS clear; DISCARD TEMP / SEQUENCES don't.
		if len(first.Effects) > 0 {
			switch first.Effects[0].Subtype {
			case effects.SubtypeDiscardAll, effects.SubtypeDiscardPlans:
				cache.Clear()
			}
		}
		return false, nil
	}

	return false, nil
}
```

Note: the PREPARE deny branch references `lookupStatementRuleByName(nil, ...)` for `rs` — that's wrong inside this self-contained helper because Intercept doesn't take a RuleSet. Fix in Step 4.

- [ ] **Step 4: Refactor Intercept to take a RuleSet**

Update the signature:

```go
func Intercept(
	stmts []effects.ClassifiedStatement,
	decisions []policy.Decision,
	cache *preparedcache.Cache,
	s statemachine.ConnState,
	rs *policy.RuleSet,
) (handled bool, actions []statemachine.Action) {
	// ... use rs in the PREPARE deny branch:
	if len(decisions) > 0 && decisions[0].Verb == policy.VerbDeny {
		rule := lookupStatementRuleByName(rs, decisions[0].RuleName)
		// ...
	}
```

Update the test calls in `sqlprepared_test.go` to pass `nil` for `rs` (deny tests use a rule named in the decision; `lookupStatementRuleByName(nil, name)` returns the zero `StatementRule`, which has `DenyModeInTx == ""` — out-of-tx deny path is correct).

- [ ] **Step 5: Run tests to confirm they pass**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestSQLPrepared -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/db/proxy/postgres/sqlprepared.go internal/db/proxy/postgres/sqlprepared_test.go
git commit -m "db: proxy — sqlprepared.Intercept implements §7.4 PREPARE/EXECUTE/DEALLOCATE/DISCARD"
```

---

## Task 7: Wire `Intercept` into `handleQuery`

**Why:** The interception must run on the Simple Query path after classify and after evaluate (so PREPARE has its inner-stmt decision) but before forward.

**Files:**
- Modify: `internal/db/proxy/postgres/simplequery.go`
- Modify: `internal/db/proxy/postgres/simplequery_test.go`

- [ ] **Step 1: Write the failing spine-shaped test**

Append to `internal/db/proxy/postgres/simplequery_test.go`:

```go
func TestHandleQuery_SQLPrepare_Deny_HandledByIntercept(t *testing.T) {
	srv := mustNewServerWithYAML(t, denyDeletePolicyYAML())
	pc := mustPCFromSrv(t, srv)
	pc.state.smState = &statemachine.ConnState{LastUpstreamRFQ: 'I'}
	err := pc.handleQuery(context.Background(), &pgproto3.Query{String: "PREPARE x AS DELETE FROM users"})
	if err != nil && !errors.Is(err, errInTxTerminate) {
		t.Fatalf("handleQuery: %v", err)
	}
	if pc.upstreamFake.SawQuery("PREPARE x AS DELETE FROM users") {
		t.Error("denied PREPARE should NOT be forwarded upstream")
	}
	if _, ok := pc.sqlCache.Get("x"); ok {
		t.Error("denied PREPARE must not populate sqlCache")
	}
}

func TestHandleQuery_SQLPrepare_Allow_PopulatesCacheAndForwards(t *testing.T) {
	srv := mustNewServerWithYAML(t, allowAllPolicyYAML())
	pc := mustPCFromSrv(t, srv)
	pc.state.smState = &statemachine.ConnState{LastUpstreamRFQ: 'I'}
	err := pc.handleQuery(context.Background(), &pgproto3.Query{String: "PREPARE s1 AS SELECT 1"})
	if err != nil {
		t.Fatalf("handleQuery: %v", err)
	}
	if !pc.upstreamFake.SawQuery("PREPARE s1 AS SELECT 1") {
		t.Error("allowed PREPARE should be forwarded upstream")
	}
	if _, ok := pc.sqlCache.Get("s1"); !ok {
		t.Error("allowed PREPARE should populate sqlCache")
	}
}

func TestHandleQuery_SQLExecute_CacheMiss(t *testing.T) {
	srv := mustNewServerWithYAML(t, allowAllPolicyYAML())
	pc := mustPCFromSrv(t, srv)
	pc.state.smState = &statemachine.ConnState{LastUpstreamRFQ: 'I'}
	err := pc.handleQuery(context.Background(), &pgproto3.Query{String: "EXECUTE missing(1)"})
	if err != nil {
		t.Fatalf("handleQuery: %v", err)
	}
	if !pc.clientFake.SawSQLState("26000") {
		t.Error("EXECUTE cache miss should synthesize SQLSTATE 26000")
	}
	if pc.upstreamFake.SawQuery("EXECUTE missing(1)") {
		t.Error("EXECUTE cache-miss must not be forwarded upstream")
	}
}
```

`pc.upstreamFake.SawQuery(s)` / `pc.clientFake.SawSQLState(code)` are test-helpers the 04c spine harness already provides (or extends in this task — straightforward additions to `testupstream_test.go`).

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestHandleQuery_SQL`
Expected: FAIL — Intercept not wired.

- [ ] **Step 3: Wire `Intercept` into `handleQuery`**

Open `internal/db/proxy/postgres/simplequery.go`. Insert the Intercept call after `stmts, _ := parser.Classify(...)` and `rs := pc.srv.policy()`, and before computing decisions. The updated `handleQuery` body should look like:

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
	rs := pc.srv.policy()
	opts := classifierOptionsFromPolicy(rs)
	stmts, _ := parser.Classify(q.String, classify_pg.SessionState{}, opts)

	// SQL-prepared cache mutations and EXECUTE rewriting happen BEFORE we
	// compute decisions, so cache-rewritten stmts feed into Evaluate cleanly.
	// PREPARE-deny still needs decisions to know which rule denied — handle
	// PREPARE / EXECUTE / DEALLOCATE / DISCARD via a pre-pass and a post-pass.

	// Pre-pass: rewrite EXECUTE classification from cache; clear cache on
	// DEALLOCATE / DISCARD.
	preHandled, preActions := Intercept(stmts, nil, pc.sqlCache, *pc.state.smState, rs)
	if preHandled {
		return pc.executeActions(ctx, q, preActions)
	}

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

	// Post-pass: PREPARE-deny needs decisions to know the denying rule;
	// PREPARE-allow populates the cache.
	postHandled, postActions := Intercept(stmts, decisions, pc.sqlCache, *pc.state.smState, rs)
	if postHandled {
		batchSHA := sha256HexBatch(q.String)
		pc.emitDenyEvents(ctx, stmts, decisions, q.String, batchSHA, denyActionForState(pc.state.smState))
		return pc.executeActions(ctx, q, postActions)
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

	// 04c's existing in-band deny path (now via statemachine.DenyRoute per 05a):
	var denyIdx int
	for i, d := range decisions {
		if d.Verb == policy.VerbDeny {
			denyIdx = i
			break
		}
	}
	denyDecision := decisions[denyIdx]
	denyRule := lookupStatementRuleByName(rs, denyDecision.RuleName)
	pc.emitDenyEvents(ctx, stmts, decisions, q.String, batchSHA, denyActionForState(pc.state.smState))
	msg, sqlstate := pickDenySynth(decisions)
	actions := statemachine.DenyRoute(*pc.state.smState, denyRule, msg, sqlstate)
	return pc.executeActions(ctx, q, actions)
}

func denyActionForState(s *statemachine.ConnState) string {
	if s == nil {
		return "none"
	}
	switch s.LastUpstreamRFQ {
	case 'T', 'E':
		return "connection_terminated"
	}
	return "none"
}
```

This is a larger refactor than typical — the `handleQuery` body changes substantially. The two `Intercept` calls implement the pre/post split: pre-pass rewrites EXECUTE and clears caches; post-pass receives the decisions vector so PREPARE-deny can route through `DenyRoute`.

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestHandleQuery_SQL -v`
Expected: all three PASS.

Run: `go test ./internal/db/proxy/postgres/ -count=1`
Expected: all 04c + 05a tests still PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/proxy/postgres/simplequery.go internal/db/proxy/postgres/simplequery_test.go internal/db/proxy/postgres/testupstream_test.go
git commit -m "db: proxy — wire sqlprepared.Intercept into handleQuery pre+post passes"
```

---

## Task 8: `Effect.FunctionOID` field

**Why:** FunctionCall events and escalated-function events need to carry the function OID for operators auditing FunctionCall traffic. Phase 1 ships OID-only; Phase 2 resolves to names.

**Files:**
- Modify: `internal/db/effects/effect.go`
- Modify: `internal/db/effects/effect_test.go` (if it exists; otherwise create) or `internal/db/effects/statement_test.go`

- [ ] **Step 1: Write the failing test**

Append a test asserting JSON round-trip for `Effect.FunctionOID` to `internal/db/effects/statement_test.go` (or `effect_test.go` if that exists):

```go
func TestEffect_FunctionOID_RoundTrip(t *testing.T) {
	oid := int32(12345)
	in := Effect{
		Group:       GroupProcedural,
		Subtype:     SubtypeFunctionCallProtocol, // see Note in Step 3 about adding this subtype
		FunctionOID: &oid,
	}
	bs, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(bs), `"function_oid":12345`) {
		t.Fatalf("missing function_oid: %s", bs)
	}
	var out Effect
	if err := json.Unmarshal(bs, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.FunctionOID == nil || *out.FunctionOID != 12345 {
		t.Fatalf("FunctionOID round-trip lost value: %v", out.FunctionOID)
	}
}

func TestEffect_FunctionOID_OmitEmpty(t *testing.T) {
	in := Effect{Group: GroupRead}
	bs, _ := json.Marshal(in)
	if strings.Contains(string(bs), "function_oid") {
		t.Fatalf("function_oid should be omitted; got %s", bs)
	}
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `go test ./internal/db/effects/ -run TestEffect_FunctionOID -count=1`
Expected: build error — `FunctionOID` and likely `SubtypeFunctionCallProtocol` undefined.

- [ ] **Step 3: Add the field and subtype**

Open `internal/db/effects/effect.go`. Add `FunctionOID *int32` to `Effect`:

```go
type Effect struct {
	Group       Group     `json:"group"`
	GroupID     uint8     `json:"group_id,omitempty"`
	Subtype     Subtype   `json:"subtype,omitempty"`
	Objects     []Object  `json:"objects,omitempty"`
	Resolution  Resolution `json:"object_resolution,omitempty"`

	// FunctionOID is populated for procedural effects with Subtype
	// SubtypeFunctionCallProtocol (FunctionCall `'F'` frame) or
	// SubtypeEscalatedFunctionCall (when classifier escalation produced
	// the effect). Pointer so JSON omits zero.
	FunctionOID *int32 `json:"function_oid,omitempty"`
}
```

Then locate the `Subtype` constants in the same file (or wherever they're defined) and add:

```go
const (
	// ... existing subtypes ...
	SubtypeFunctionCallProtocol  Subtype = "function_call_protocol"
	SubtypeEscalatedFunctionCall Subtype = "escalated_function_call"
)
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/effects/ -run TestEffect_FunctionOID -count=1 -v`
Expected: both PASS.

Run full effects test to confirm no regression:
```bash
go test ./internal/db/effects/ -count=1
```

- [ ] **Step 5: Commit**

```bash
git add internal/db/effects/effect.go internal/db/effects/effect_test.go internal/db/effects/statement_test.go
git commit -m "db: effects — add Effect.FunctionOID and function_call_protocol/escalated_function_call subtypes"
```

---

## Task 9: FunctionCall (`'F'`) opt-in path

**Why:** Flip 04c's `42501`-or-`0A000` stub into a real path when `service.AllowFunctionCallProtocol == true`. Classify as `procedural` + `function_call_protocol`; evaluate; forward-or-deny.

**Files:**
- Create: `internal/db/proxy/postgres/funccall.go`
- Create: `internal/db/proxy/postgres/funccall_test.go`
- Modify: `internal/db/proxy/postgres/simplequery.go` (`handleUnsupportedFrame`)

- [ ] **Step 1: Write the failing tests**

Create `internal/db/proxy/postgres/funccall_test.go`:

```go
//go:build linux

package postgres

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

func TestFunctionCall_Default_42501(t *testing.T) {
	srv := mustNewServerWithYAML(t, allowAllPolicyYAML())
	pc := mustPCFromSrv(t, srv)
	// svc.AllowFunctionCallProtocol defaults to false.
	err := pc.handleFunctionCall(context.Background(), &pgproto3.FunctionCall{Function: 12345})
	if err == nil {
		t.Fatal("expected stub error")
	}
	if !pc.clientFake.SawSQLState("42501") {
		t.Error("default FunctionCall should synthesize 42501")
	}
}

func TestFunctionCall_OptIn_Allow_Forwards(t *testing.T) {
	yaml := `
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: "127.0.0.1:5432"
    tls_mode: terminate_reissue
    allow_function_call_protocol: true
database_rules:
  - name: allow-procedural
    db_service: appdb
    operations: [procedural]
    decision: allow
`
	srv := mustNewServerWithYAML(t, yaml)
	pc := mustPCFromSrv(t, srv)
	err := pc.handleFunctionCall(context.Background(), &pgproto3.FunctionCall{Function: 12345})
	if err != nil {
		t.Fatalf("handleFunctionCall: %v", err)
	}
	if !pc.upstreamFake.SawFunctionCall(12345) {
		t.Error("FunctionCall should be forwarded upstream when opt-in + allow")
	}
}

func TestFunctionCall_OptIn_Deny_DenyRoute(t *testing.T) {
	yaml := `
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: "127.0.0.1:5432"
    tls_mode: terminate_reissue
    allow_function_call_protocol: true
database_rules:
  - name: deny-procedural
    db_service: appdb
    operations: [procedural]
    decision: deny
`
	srv := mustNewServerWithYAML(t, yaml)
	pc := mustPCFromSrv(t, srv)
	err := pc.handleFunctionCall(context.Background(), &pgproto3.FunctionCall{Function: 12345})
	if err != nil {
		t.Fatalf("handleFunctionCall returned err %v; deny is in-band", err)
	}
	if pc.upstreamFake.SawFunctionCall(12345) {
		t.Error("denied FunctionCall must NOT be forwarded")
	}
	if !pc.clientFake.SawSQLState("42501") {
		t.Error("denied FunctionCall should synthesize 42501")
	}
}
```

`pc.upstreamFake.SawFunctionCall(oid)` is a new method on the fake — add to `testupstream_test.go`:

```go
func (u *testUpstream) SawFunctionCall(oid uint32) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, o := range u.functionCallsSeen {
		if o == oid {
			return true
		}
	}
	return false
}
```

And the response goroutine in the fake records each `*pgproto3.FunctionCall` it receives into `u.functionCallsSeen`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestFunctionCall`
Expected: build error — `handleFunctionCall` undefined.

- [ ] **Step 3: Implement `handleFunctionCall`**

Create `internal/db/proxy/postgres/funccall.go`:

```go
//go:build linux

package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/statemachine"
)

// handleFunctionCall handles a `'F'` FunctionCall frame. Default behavior
// (when service.AllowFunctionCallProtocol == false) preserves 04c's
// `42501` stub: synth error, lifecycle event, close. Opt-in behavior
// classifies as procedural/function_call_protocol, evaluates, and forwards
// or denies via DenyRoute.
func (pc *proxyConn) handleFunctionCall(ctx context.Context, msg *pgproto3.FunctionCall) error {
	if !pc.svc.Service.AllowFunctionCallProtocol {
		// 04c default: stub deny + close.
		pc.emitUnsupportedFrame(ctx, "FUNCTION_CALL_PROTOCOL_DENIED", "FunctionCall")
		_ = pc.synthErrorAndRFQ(sqlstateInsufficientPrivilege,
			"FunctionCall sub-protocol denied by AgentSH policy")
		return errUnsupportedFrame
	}

	// Opt-in: classify + evaluate.
	oid := int32(msg.Function)
	cs := effects.ClassifiedStatement{
		RawVerb: "FUNCTION_CALL",
		Effects: []effects.Effect{{
			Group:       effects.GroupProcedural,
			Subtype:     effects.SubtypeFunctionCallProtocol,
			FunctionOID: &oid,
		}},
	}
	rs := pc.srv.policy()
	d := policy.Evaluate(cs, rs, policy.ServiceID(pc.svc.Name))
	if d.Verb == policy.VerbApprove {
		d = synthApproveAsDeny(d)
	}

	if d.Verb == policy.VerbDeny {
		denyRule := lookupStatementRuleByName(rs, d.RuleName)
		batchSHA := sha256HexBatchFunctionCall(oid)
		pc.emitFunctionCallEvent(ctx, cs, d, denyActionForState(pc.state.smState), batchSHA)
		msg2 := renderDenyMsgFromRule(d)
		actions := statemachine.DenyRoute(*pc.state.smState, denyRule, msg2, "42501")
		return pc.executeActions(ctx, msg, actions)
	}

	// Allow: forward.
	pc.state.upstreamFE.Send(msg)
	if err := pc.state.upstreamFE.Flush(); err != nil {
		return err
	}
	// Drain upstream until RFQ; emit the allow event afterward with the
	// per-FunctionCall counters.
	result, ferr := pc.forwardUpstreamUntilRFQ(ctx, timeNow(), 0)
	batchSHA := sha256HexBatchFunctionCall(oid)
	pc.emitFunctionCallEvent(ctx, cs, d, "none", batchSHA)
	_ = result
	return ferr
}

// emitFunctionCallEvent emits a db_statement event for a FunctionCall.
func (pc *proxyConn) emitFunctionCallEvent(
	ctx context.Context,
	cs effects.ClassifiedStatement,
	d policy.Decision,
	denyAction, batchSHA string,
) {
	if pc.srv.cfg.Sink == nil {
		return
	}
	ev := buildStatementEvent(buildArgs{
		Stmt:       cs,
		StmtIndex:  0,
		BatchTotal: 1,
		Decision:   d,
		SQL:        "FUNCTION_CALL", // never logged; placeholder for digest
		Tier:       pc.state.redactionTier,
		Conn:       *pc.state,
		BytesIn:    0,
		DenyAction: denyAction,
		BatchSHA:   batchSHA,
		Parser:     pc.srv.classifierFor(pc.svc.Dialect),
	})
	_ = pc.srv.cfg.Sink.EmitStatement(ctx, ev)
}

// renderDenyMsgFromRule mirrors the existing rendered deny pattern but for
// the FunctionCall path (no rule template lookup yet — RuleName-prefixed
// "denied by AgentSH policy" is sufficient for the spine).
func renderDenyMsgFromRule(d policy.Decision) string {
	if d.RuleName != "" {
		return "denied by AgentSH policy: " + d.RuleName
	}
	return "denied by AgentSH policy"
}

func sha256HexBatchFunctionCall(oid int32) string {
	// Stable digest input so the event's batch_sha groups all events from
	// one FunctionCall together. SHA-256 of "F:<oid>".
	return sha256HexBatch("F:" + intToString(int64(oid)))
}

// intToString is local to avoid importing strconv into this file just for
// one place; remove when adding a broader util.
func intToString(n int64) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
```

Where `intToString` already exists in the package (likely via `strconv.FormatInt`), use that and drop the local helper. The version above is a fallback to avoid cycles.

- [ ] **Step 4: Delegate from `handleUnsupportedFrame`**

Open `internal/db/proxy/postgres/simplequery.go`. Replace the FunctionCall branch in `handleUnsupportedFrame`:

```go
func (pc *proxyConn) handleUnsupportedFrame(ctx context.Context, msg pgproto3.FrontendMessage) error {
	frameType := fmt.Sprintf("%T", msg)
	if fc, isFunc := msg.(*pgproto3.FunctionCall); isFunc {
		return pc.handleFunctionCall(ctx, fc)
	}
	pc.emitUnsupportedFrame(ctx, "EXTENDED_QUERY_NOT_SUPPORTED", frameType)
	_ = pc.synthesizeError(sqlstateFeatureNotSupported, "Extended Query / COPY / FunctionCall not supported in AgentSH proxy phase 1")
	return errUnsupportedFrame
}
```

`handleFunctionCall` decides whether to deny-and-close (errUnsupportedFrame default) or to deny-in-band (return nil for the dispatcher loop to read the next frame) based on the rule's `deny_mode_in_tx`.

- [ ] **Step 5: Run tests to confirm they pass**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestFunctionCall -v`
Expected: all three PASS.

Run also: `go test ./internal/db/proxy/postgres/ -count=1`
Expected: full PASS — the existing 04c `42501` stub test still passes (default path is unchanged).

- [ ] **Step 6: Commit**

```bash
git add internal/db/proxy/postgres/funccall.go internal/db/proxy/postgres/funccall_test.go internal/db/proxy/postgres/simplequery.go internal/db/proxy/postgres/testupstream_test.go
git commit -m "db: proxy — FunctionCall (F) opt-in path via allow_function_call_protocol"
```

---

## Task 10: Event-builder surfaces `function_oid`

**Why:** The event builder currently does not pass `FunctionOID` from the classified effects into the emitted `events.DBEvent`. Plug it in.

**Files:**
- Modify: `internal/db/proxy/postgres/eventbuilder.go`
- Modify: `internal/db/proxy/postgres/eventbuilder_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/db/proxy/postgres/eventbuilder_test.go`:

```go
func TestBuildEvent_PropagatesFunctionOID(t *testing.T) {
	oid := int32(99)
	args := buildArgs{
		Stmt: effects.ClassifiedStatement{
			RawVerb: "FUNCTION_CALL",
			Effects: []effects.Effect{{
				Group:       effects.GroupProcedural,
				Subtype:     effects.SubtypeFunctionCallProtocol,
				FunctionOID: &oid,
			}},
		},
		Decision: policy.Decision{Verb: policy.VerbAllow},
		Tier:     policy.RedactionParametersRedacted,
		Conn:     connState{},
		Parser:   classify_pg.New(classify_pg.DialectPostgres),
	}
	ev := buildStatementEvent(args)
	if len(ev.Effects) != 1 {
		t.Fatalf("len(Effects)=%d", len(ev.Effects))
	}
	if ev.Effects[0].FunctionOID == nil || *ev.Effects[0].FunctionOID != 99 {
		t.Errorf("FunctionOID=%v want 99", ev.Effects[0].FunctionOID)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestBuildEvent_PropagatesFunctionOID`
Expected: FAIL — `ev.Effects[0].FunctionOID` is nil.

- [ ] **Step 3: Update `buildStatementEvent`**

Open `internal/db/proxy/postgres/eventbuilder.go`. Locate the effects copy (the loop that converts `effects.Effect` to `events.DBEvent.Effects[i]`). The builder may either copy the field directly (if `events.DBEvent.Effects` is `[]effects.Effect`) or convert. From `event.go` we know `Effects []effects.Effect` — so this is just a single-field include.

If the builder currently does `out := append([]effects.Effect(nil), src...)` then `FunctionOID` already round-trips. If it does field-by-field copy, add:

```go
		out.FunctionOID = src.FunctionOID
```

Identify the exact location via:
```bash
git grep -n 'Effects\[' internal/db/proxy/postgres/eventbuilder.go
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestBuildEvent_PropagatesFunctionOID -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/proxy/postgres/eventbuilder.go internal/db/proxy/postgres/eventbuilder_test.go
git commit -m "db: proxy/eventbuilder — propagate Effect.FunctionOID into DBEvent.Effects"
```

---

## Task 11: Spine tests — SQL PREPARE deny + FunctionCall opt-in

**Why:** End-to-end verification through a real pgx driver: SQL PREPARE flows through the Q-path; FunctionCall flows through the opt-in path.

**Files:**
- Modify: `internal/db/proxy/postgres/spine_test.go`
- Modify: `internal/db/proxy/postgres/testupstream_test.go`

- [ ] **Step 1: Extend the fake upstream**

Open `internal/db/proxy/postgres/testupstream_test.go`. Add the `FunctionCall` response branch:

```go
case *pgproto3.FunctionCall:
	u.functionCallsSeen = append(u.functionCallsSeen, m.Function)
	u.send(&pgproto3.FunctionCallResponse{Result: nil})
	u.send(&pgproto3.ReadyForQuery{TxStatus: u.currentStatus})
```

And add `functionCallsSeen []uint32` to the fake struct.

- [ ] **Step 2: Add spine tests**

Append to `internal/db/proxy/postgres/spine_test.go`:

```go
func TestSpine_SQLPrepare_DenyOverPGX(t *testing.T) {
	yaml := `
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue, listener: {unix: "/tmp/agentsh-appdb.sock"}}
database_rules:
  - name: block-delete
    db_service: appdb
    operations: [delete]
    decision: deny
`
	srv, sink := mustStartSpineServer(t, yaml)
	defer srv.Shutdown(context.Background())
	cfg, _ := pgx.ParseConfig("postgres:///?host=" + srv.cfg.Services[0].Listen.Path + "&sslrootcert=" + filepath.Join(srv.cfg.StateDir, "db-ca.crt"))
	conn, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.Close(context.Background())
	// SQL-level PREPARE goes via Q-frame in pgx when using Exec with a raw
	// SQL string.
	_, err = conn.Exec(context.Background(), "PREPARE delx AS DELETE FROM users")
	if err == nil {
		t.Fatal("expected deny error")
	}
	gotDeny := false
	for _, ev := range sink.StatementEvents() {
		if ev.Decision.Verb == "deny" {
			gotDeny = true
			break
		}
	}
	if !gotDeny {
		t.Error("expected deny event for PREPARE DELETE")
	}
}

func TestSpine_FunctionCall_OptInForwards(t *testing.T) {
	yaml := `
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: "127.0.0.1:5432"
    tls_mode: terminate_reissue
    listener: {unix: "/tmp/agentsh-appdb.sock"}
    allow_function_call_protocol: true
database_rules:
  - name: allow-procedural
    db_service: appdb
    operations: [procedural]
    decision: allow
`
	srv, sink := mustStartSpineServer(t, yaml)
	defer srv.Shutdown(context.Background())
	// pgx v5 does not emit raw FunctionCall frames in normal usage; this
	// test drives it manually through pgproto3.Frontend connected via the
	// proxy's Unix socket. Use the existing rawClient helper from 04c's
	// handshake_test.go to dial through TLS termination.
	client := newRawTLSClient(t, srv) // existing helper
	defer client.Close()
	client.SendStartupAndAuth("postgres") // existing helper that completes auth
	client.Send(&pgproto3.FunctionCall{Function: 12345})
	if err := client.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	// Expect FunctionCallResponse followed by ReadyForQuery.
	got, err := client.Receive()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if _, ok := got.(*pgproto3.FunctionCallResponse); !ok {
		t.Fatalf("got %T; want *pgproto3.FunctionCallResponse", got)
	}
	gotAllow := false
	for _, ev := range sink.StatementEvents() {
		if ev.Decision.Verb == "allow" && hasFunctionOID(ev, 12345) {
			gotAllow = true
			break
		}
	}
	if !gotAllow {
		t.Error("expected allow event for FunctionCall(12345)")
	}
}

func hasFunctionOID(ev events.DBEvent, want int32) bool {
	for _, e := range ev.Effects {
		if e.FunctionOID != nil && *e.FunctionOID == want {
			return true
		}
	}
	return false
}
```

The helper `newRawTLSClient(t, srv)` is the 04c handshake test's raw-client wrapper. Reuse it; it speaks pgproto3 directly through the proxy's TLS termination so we can emit handcrafted FunctionCall frames that pgx never produces.

- [ ] **Step 3: Run tests to verify they fail / iterate to pass**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestSpine_(SQLPrepare|FunctionCall) -v -timeout 120s`
Expected: FAIL initially; iterate until both pass.

Common iteration items:
- pgx may classify "PREPARE delx AS DELETE FROM users" client-side — in that case the test's deny depends on the rule covering `delete`. The classifier's PREPARE handler classifies inner effects, so the deny rule fires.
- FunctionCallResponse encoding: the upstream fake must send a valid `FunctionCallResponse` (empty result is fine).

- [ ] **Step 4: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: green.

- [ ] **Step 5: Commit**

```bash
git add internal/db/proxy/postgres/spine_test.go internal/db/proxy/postgres/testupstream_test.go
git commit -m "db: proxy — spine tests for SQL PREPARE deny and FunctionCall opt-in"
```

---

## Final verification

- [ ] **Step 1: Full test suite**

Run: `go test ./... -count=1 -timeout 180s`
Expected: PASS.

- [ ] **Step 2: Race detector on the package**

Run: `go test -race ./internal/db/... -count=1 -timeout 180s`
Expected: PASS.

- [ ] **Step 3: Cross-compile**

Run: `GOOS=windows go build ./...`
Expected: PASS.

- [ ] **Step 4: Verify the new files exist**

Run:
```bash
test -f internal/db/proxy/postgres/sqlprepared.go
test -f internal/db/proxy/postgres/funccall.go
test -f internal/db/classify/postgres/builtin_immutable.go
```
Expected: all present.
