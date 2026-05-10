# db-access Plan 03 — PostgreSQL Classifier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `internal/db/classify/postgres/` (the PostgreSQL classifier) and `cmd/dbclassify-pg` (the operator CLI), per spec §7 / §20 / Appendix B and the Plan 03 design doc.

**Architecture:** Two libpg_query embeddings — native CGO via `pg_query_go` on `linux && cgo`, WASM via `wasilibs/go-pgquery` everywhere else — produce the same protobuf AST. A platform-agnostic AST walker maps RawStmt nodes to `effects.ClassifiedStatement`s with per-effect object attribution per §6. A pure-functional `ApplyStatement` evolves `SessionState` so corpus rows can express session-aware fixtures (`SET search_path` then unqualified ref). A SQL-text-driven golden corpus under `corpus/*.yaml` is the classifier's contract; `cmd/dbclassify-pg` reads SQL on stdin and prints classification + sample-policy decision.

**Tech Stack:** Go 1.25, `pganalyze/pg_query_go/v6` (CGO, build-tag-gated), `wasilibs/go-pgquery` + `tetratelabs/wazero` (WASM, default), `gopkg.in/yaml.v3`, `gobwas/glob` (already deps).

---

## File Structure

**Created in `internal/db/classify/postgres/`:**

- `parser.go` — public surface: `Parser`, `New`, `Dialect`, `Options`, `SessionState`, `ApplyStatement`.
- `libpgquery.go` — `//go:build linux && cgo`; native libpg_query backend.
- `wasm.go` — `//go:build !linux || !cgo`; WASM libpg_query backend.
- `ast_walk.go` — RawStmt → ClassifiedStatement dispatcher and shared helpers.
- `ast_dml.go` — SELECT / INSERT / UPDATE / DELETE / MERGE / WITH-CTE / EXPLAIN / PREPARE / EXECUTE / DEALLOCATE.
- `ast_session.go` — SET / RESET / DISCARD / SET ROLE / SET SESSION AUTHORIZATION / BEGIN / COMMIT / ROLLBACK.
- `ast_ddl.go` — CREATE / ALTER / DROP / TRUNCATE for tables, indexes, views, schemas, functions, sequences, types, extensions, publications.
- `ast_privilege.go` — GRANT / REVOKE / CREATE-ALTER-DROP ROLE / ALTER SYSTEM / SECURITY LABEL.
- `ast_copy.go` — COPY variants including inner-query composition.
- `ast_external.go` — CREATE/ALTER/DROP SUBSCRIPTION / SERVER / USER MAPPING / TABLESPACE LOCATION; libpq connection-string parser.
- `ast_unsafe_io.go` — `pg_read_file`, `lo_import`, `lo_export`, `dblink`, FDW access detection.
- `ast_misc.go` — CALL / DO / anonymous block / VACUUM / ANALYZE / REINDEX / CLUSTER / CHECKPOINT / LOCK / LISTEN / NOTIFY / UNLISTEN.
- `connstring.go` — libpq keyword-value + URI parser.
- `escalation.go` — §7.6 SELECT volatile_function() escalation knob.
- `redshift.go` — first-keyword fallback for UNLOAD / COPY FROM s3.
- `corpus/_schema.go` — corpus row Go struct + loader.
- `corpus/*.yaml` — golden fixtures, ≥150 rows covering every §20 category.
- `corpus_test.go` — iterates `corpus/*.yaml`, asserts classification + decision.
- Per-file `*_test.go` companions for unit-level tests.

**Created in `cmd/dbclassify-pg/`:**

- `main.go` — SQL on stdin, JSON on stdout.

**Modified:**

- `internal/db/effects/statement.go` — add `Error string` field to `ClassifiedStatement`.
- `internal/db/effects/statement_test.go` — extend table for `Error` field zero value + JSON omitempty.
- `go.mod` / `go.sum` — add `pg_query_go`, `go-pgquery`, transitive `wazero`.

---

## Task 1: Preflight — add `Error string` to `effects.ClassifiedStatement`

**Why:** §7.8 failure semantics need a place to record parse-failure / unmapped-form reasons. The field is JSON-omitempty so no shipped consumer sees a schema break.

**Files:**
- Modify: `internal/db/effects/statement.go`
- Modify: `internal/db/effects/statement_test.go`

- [ ] **Step 1: Write the failing test for the new field**

Append to `internal/db/effects/statement_test.go`:

```go
func TestClassifiedStatement_ErrorField(t *testing.T) {
	t.Run("zero value is empty string", func(t *testing.T) {
		var cs ClassifiedStatement
		if cs.Error != "" {
			t.Fatalf("zero value Error = %q, want \"\"", cs.Error)
		}
	})

	t.Run("JSON omits empty Error", func(t *testing.T) {
		cs := ClassifiedStatement{Effects: []Effect{{Group: GroupRead}}}
		b, err := json.Marshal(cs)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if bytes.Contains(b, []byte(`"error"`)) {
			t.Fatalf("empty Error leaked into JSON: %s", b)
		}
	})

	t.Run("JSON round-trips populated Error", func(t *testing.T) {
		in := ClassifiedStatement{
			Effects: []Effect{{Group: GroupUnknown}},
			Error:   "parse: syntax error at end of input",
		}
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		var out ClassifiedStatement
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if out.Error != in.Error {
			t.Fatalf("Error round-trip: got %q want %q", out.Error, in.Error)
		}
	})
}
```

Add `import` lines for `bytes` and `encoding/json` at the top of `statement_test.go` if not already present.

- [ ] **Step 2: Run the test to verify it fails**

```bash
go test ./internal/db/effects/ -run TestClassifiedStatement_ErrorField -v
```

Expected: FAIL — `cs.Error undefined`.

- [ ] **Step 3: Add the field**

Edit `internal/db/effects/statement.go`. Update the struct and its JSON shape:

```go
type ClassifiedStatement struct {
	Effects       []Effect      `json:"effects"`
	RawVerb       string        `json:"raw_verb,omitempty"`
	ParserBackend ParserBackend `json:"parser_backend,omitempty"`
	Error         string        `json:"error,omitempty"`
}
```

If the existing struct uses no JSON tags, add them in this same edit so omitempty works. Keep the `Primary` and `FoldResolution` methods unchanged.

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/db/effects/ -v
```

Expected: PASS for the new test plus all existing tests.

- [ ] **Step 5: Cross-compile check**

```bash
GOOS=windows go build ./...
```

Expected: clean build.

- [ ] **Step 6: Commit**

```bash
git add internal/db/effects/statement.go internal/db/effects/statement_test.go
git commit -m "effects: add Error field to ClassifiedStatement (Plan 03 prep)"
```

---

## Task 2: Skeleton — package, public types, dependency wiring

**Why:** Lock down the public surface from the design doc §4 before wiring backends. Stubs let later tasks call `Classify` without a circular dependency on backend selection.

**Files:**
- Create: `internal/db/classify/postgres/parser.go`
- Create: `internal/db/classify/postgres/parser_test.go`
- Modify: `go.mod`, `go.sum`

- [ ] **Step 1: Write the failing test for the public surface**

Create `internal/db/classify/postgres/parser_test.go`:

```go
package postgres

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestNew_ReturnsParserPerDialect(t *testing.T) {
	for _, d := range []Dialect{DialectPostgres, DialectAuroraPostgres, DialectCockroachDB, DialectRedshift} {
		p := New(d)
		if p == nil {
			t.Fatalf("New(%v) returned nil", d)
		}
	}
}

func TestNew_PanicsOnUnknownDialect(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on unknown dialect")
		}
	}()
	New(Dialect(99))
}

func TestApplyStatement_NoOpOnEmptyEffects(t *testing.T) {
	in := SessionState{SearchPath: []string{"public"}}
	got := ApplyStatement(in, effects.ClassifiedStatement{})
	if len(got.SearchPath) != 1 || got.SearchPath[0] != "public" {
		t.Fatalf("ApplyStatement mutated state on empty input: %+v", got)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
go test ./internal/db/classify/postgres/ -v
```

Expected: FAIL — package does not exist.

- [ ] **Step 3: Add dependencies**

```bash
go get github.com/pganalyze/pg_query_go/v6@latest
go get github.com/wasilibs/go-pgquery@latest
go mod tidy
```

If a dependency add fails (network, version skew), pin a known-good version and proceed; the team can update later. Note the resolved version in the commit message.

- [ ] **Step 4: Implement the public surface**

Create `internal/db/classify/postgres/parser.go`:

```go
// Package postgres classifies PostgreSQL-family SQL into effects.ClassifiedStatement
// per docs/agentsh-db-access-spec.md §7. The package exposes a Parser interface
// (one implementation per build-tag-selected backend) plus pure helpers for
// session-state evolution. No I/O, no goroutines.
package postgres

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// Dialect dispatches between Postgres-family parsers per spec §7.7.
type Dialect uint8

const (
	DialectPostgres Dialect = iota + 1
	DialectAuroraPostgres
	DialectCockroachDB
	DialectRedshift
)

func (d Dialect) String() string {
	switch d {
	case DialectPostgres:
		return "postgres"
	case DialectAuroraPostgres:
		return "aurora_postgres"
	case DialectCockroachDB:
		return "cockroachdb"
	case DialectRedshift:
		return "redshift"
	default:
		return ""
	}
}

// ParseDialect resolves the spec's lowercase dialect name. Returns ok=false on
// unknown input.
func ParseDialect(s string) (Dialect, bool) {
	switch s {
	case "postgres":
		return DialectPostgres, true
	case "aurora_postgres":
		return DialectAuroraPostgres, true
	case "cockroachdb":
		return DialectCockroachDB, true
	case "redshift":
		return DialectRedshift, true
	default:
		return 0, false
	}
}

// Options carries per-call tunables. Defaults are zero-valued and safe.
type Options struct {
	// EscalateUnknownFunctions toggles §7.6: when true, SELECT calling a
	// function NOT in SafeFunctionAllowlist classifies as procedural rather
	// than read.
	EscalateUnknownFunctions bool
	// SafeFunctionAllowlist is consulted only when EscalateUnknownFunctions
	// is true. Lookup is case-insensitive on the canonical lowercase name
	// (e.g. "now", "to_tsvector"). Schema-qualified names use "schema.name".
	SafeFunctionAllowlist map[string]struct{}
}

// SessionState is the per-connection state the classifier consults to assign
// resolution tags per §6.1. Owned by Plan 04+ proxies; the classifier reads it
// only — ApplyStatement (a free function) evolves it after upstream success.
type SessionState struct {
	SearchPath        []string            // lowercased identifiers, in order
	DefaultSearchPath []string            // restored by RESET search_path / DISCARD ALL
	TempTables        map[string]struct{} // unqualified names
	Role              string              // SET ROLE / SET SESSION AUTHORIZATION; "" = default
	DefaultRole       string
	InTransaction     bool // hint only; Plan 05 owns authoritative tx state
}

// Clone returns a deep copy of s — call this before applying mutations if the
// caller needs to retain the pre-mutation state (corpus harness uses this).
func (s SessionState) Clone() SessionState {
	cp := SessionState{
		SearchPath:        append([]string(nil), s.SearchPath...),
		DefaultSearchPath: append([]string(nil), s.DefaultSearchPath...),
		Role:              s.Role,
		DefaultRole:       s.DefaultRole,
		InTransaction:     s.InTransaction,
	}
	if len(s.TempTables) > 0 {
		cp.TempTables = make(map[string]struct{}, len(s.TempTables))
		for k := range s.TempTables {
			cp.TempTables[k] = struct{}{}
		}
	}
	return cp
}

// Parser is the single public surface. Implementations are returned by New.
type Parser interface {
	Classify(sql string, sess SessionState, opts Options) ([]effects.ClassifiedStatement, error)
}

// New returns the parser for the given dialect, using whichever libpg_query
// embedding the active build tag selected. Panics on unknown dialect; the
// dialect set is closed and a typo at construction time is a programmer error.
func New(d Dialect) Parser {
	if d.String() == "" {
		panic(fmt.Sprintf("postgres.New: unknown dialect %d", d))
	}
	return newParser(d)
}

// ApplyStatement evolves session state after the proxy has confirmed the
// statement succeeded upstream. Pure function; see ast_session.go for the
// per-statement rules.
func ApplyStatement(s SessionState, c effects.ClassifiedStatement) SessionState {
	if len(c.Effects) == 0 {
		return s
	}
	return applySession(s, c)
}
```

`newParser` and `applySession` are package-private and live in build-tag-gated files (Tasks 3-4) and `ast_session.go` (Task 9) respectively. Until those tasks land, add a temporary stub at the bottom of `parser.go`:

```go
// Temporary stubs until Tasks 3-4 (backends) and Task 9 (session) ship.
func newParser(d Dialect) Parser            { panic("not implemented: backend not yet wired (Task 3/4)") }
func applySession(s SessionState, c effects.ClassifiedStatement) SessionState {
	return s
}
```

- [ ] **Step 5: Run tests to verify the surface compiles**

```bash
go test ./internal/db/classify/postgres/ -run TestNew_ -v
```

Expected: `TestNew_ReturnsParserPerDialect` panics (stub); `TestNew_PanicsOnUnknownDialect` PASS; `TestApplyStatement_NoOpOnEmptyEffects` PASS. The first failure is expected and removed in Task 3. Update the test to expect the panic temporarily, OR skip with `t.Skip("backend wired in Task 3")`. Use skip — it's clearer.

Update `TestNew_ReturnsParserPerDialect` to:

```go
func TestNew_ReturnsParserPerDialect(t *testing.T) {
	t.Skip("re-enabled in Task 3 once backends are wired")
	for _, d := range []Dialect{DialectPostgres, DialectAuroraPostgres, DialectCockroachDB, DialectRedshift} {
		p := New(d)
		if p == nil {
			t.Fatalf("New(%v) returned nil", d)
		}
	}
}
```

Re-run; expected: all pass / skipped.

- [ ] **Step 6: Cross-compile check**

```bash
GOOS=windows go build ./...
GOOS=darwin go build ./...
```

Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add internal/db/classify/postgres/parser.go internal/db/classify/postgres/parser_test.go go.mod go.sum
git commit -m "classify/postgres: package skeleton, public types, dependencies"
```

---

## Task 3: Backend bindings — both libpg_query embeddings

**Why:** Both backends produce the same protobuf AST type from `github.com/pganalyze/pg_query_go/v6`. The CGO file links libpg_query natively; the WASM file uses `wasilibs/go-pgquery` which loads libpg_query into wazero and exposes the same `Parse` entry point returning the same `*pg_query.ParseResult`. Wiring both at once keeps the AST-walker callers symmetric.

**Files:**
- Create: `internal/db/classify/postgres/libpgquery.go`
- Create: `internal/db/classify/postgres/wasm.go`
- Create: `internal/db/classify/postgres/backend_test.go`

**Note on import paths:** the design doc §13 commits to confirming exact import paths during implementation. As of writing, the canonical paths are `github.com/pganalyze/pg_query_go/v6` (Parse → `*pg_query.ParseResult`, Stmts is `[]*pg_query.RawStmt`) and `github.com/wasilibs/go-pgquery` (drop-in API-compatible). If the wasilibs API differs from pg_query_go (e.g. exposes a `pgquery.Parse` instead of `pg_query.Parse`), wrap it in `wasm.go` so the rest of the package sees the pg_query_go shape.

- [ ] **Step 1: Write the failing test**

Create `internal/db/classify/postgres/backend_test.go`:

```go
package postgres

import (
	"strings"
	"testing"
)

func TestBackend_ParsesSimpleSelect(t *testing.T) {
	p := New(DialectPostgres)
	got, err := p.Classify("SELECT 1", SessionState{}, Options{})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(got))
	}
	if got[0].Error != "" {
		t.Fatalf("unexpected Error: %q", got[0].Error)
	}
}

func TestBackend_ParseFailureProducesUnknown(t *testing.T) {
	p := New(DialectPostgres)
	got, err := p.Classify("SELECT FROM WHERE", SessionState{}, Options{})
	if err != nil {
		t.Fatalf("Classify returned err for SQL-level failure: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 statement on parse failure, got %d", len(got))
	}
	if !strings.HasPrefix(got[0].Error, "parse:") {
		t.Fatalf("Error = %q, want prefix \"parse:\"", got[0].Error)
	}
}

func TestBackend_EmptyInputReturnsEmpty(t *testing.T) {
	p := New(DialectPostgres)
	got, err := p.Classify("   \n\t  ", SessionState{}, Options{})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty SQL should produce no statements, got %d", len(got))
	}
}
```

Also unskip `TestNew_ReturnsParserPerDialect` from Task 2.

- [ ] **Step 2: Run the test to verify it fails**

```bash
go test ./internal/db/classify/postgres/ -v
```

Expected: PANIC from the temporary stub.

- [ ] **Step 3: Implement the CGO backend**

Create `internal/db/classify/postgres/libpgquery.go`:

```go
//go:build linux && cgo

package postgres

import (
	pg_query "github.com/pganalyze/pg_query_go/v6"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func newParser(d Dialect) Parser {
	return &cgoParser{dialect: d}
}

type cgoParser struct {
	dialect Dialect
}

func (p *cgoParser) Classify(sql string, sess SessionState, opts Options) ([]effects.ClassifiedStatement, error) {
	return classifyWithBackend(p.dialect, sql, sess, opts, parseCGO, effects.ParserBackendLibPgQuery)
}

func parseCGO(sql string) (*pg_query.ParseResult, error) {
	return pg_query.Parse(sql)
}
```

- [ ] **Step 4: Implement the WASM backend**

Create `internal/db/classify/postgres/wasm.go`:

```go
//go:build !linux || !cgo

package postgres

import (
	pg_query "github.com/pganalyze/pg_query_go/v6"
	pgquery_wasm "github.com/wasilibs/go-pgquery"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func newParser(d Dialect) Parser {
	return &wasmParser{dialect: d}
}

type wasmParser struct {
	dialect Dialect
}

func (p *wasmParser) Classify(sql string, sess SessionState, opts Options) ([]effects.ClassifiedStatement, error) {
	return classifyWithBackend(p.dialect, sql, sess, opts, parseWASM, effects.ParserBackendPureGo)
}

func parseWASM(sql string) (*pg_query.ParseResult, error) {
	return pgquery_wasm.Parse(sql)
}
```

If `wasilibs/go-pgquery` returns a different protobuf type than `pg_query_go/v6`, add a thin shim that converts (the protobuf schema is the same). Document the conversion in a `wasm_shim.go` comment.

- [ ] **Step 5: Implement the shared dispatcher**

Append to `internal/db/classify/postgres/parser.go` (or create `dispatch.go` — keep it in `parser.go` for proximity):

```go
import (
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// classifyWithBackend is shared between libpgquery.go and wasm.go.
func classifyWithBackend(
	dialect Dialect,
	sql string,
	sess SessionState,
	opts Options,
	parse func(string) (*pg_query.ParseResult, error),
	backend effects.ParserBackend,
) ([]effects.ClassifiedStatement, error) {
	if strings.TrimSpace(sql) == "" {
		return nil, nil
	}

	res, err := parse(sql)
	if err != nil {
		// SQL-level parse failure for postgres / aurora / cockroachdb dialects:
		// produce a single unknown statement carrying the parser message.
		// Redshift dialect attempts the first-keyword fallback (Task 16).
		if dialect == DialectRedshift {
			if cs, ok := redshiftFirstKeyword(sql, backend); ok {
				return []effects.ClassifiedStatement{cs}, nil
			}
		}
		return []effects.ClassifiedStatement{
			unknownStatement(backend, "parse: "+err.Error()),
		}, nil
	}

	if res == nil || len(res.Stmts) == 0 {
		return nil, nil
	}

	out := make([]effects.ClassifiedStatement, 0, len(res.Stmts))
	for _, raw := range res.Stmts {
		cs := classifyRawStmt(dialect, raw, sess, opts, backend)
		out = append(out, cs)
	}
	return out, nil
}

// unknownStatement returns the spec §7.8 unknown-classification value with the
// given message.
func unknownStatement(backend effects.ParserBackend, msg string) effects.ClassifiedStatement {
	return effects.ClassifiedStatement{
		Effects: []effects.Effect{{
			Group:      effects.GroupUnknown,
			Resolution: effects.ResolutionUnresolved,
		}},
		ParserBackend: backend,
		Error:         msg,
	}
}

// classifyRawStmt and redshiftFirstKeyword are stubbed here; they're filled in
// by Task 5 (ast_walk.go) and Task 16 (redshift.go) respectively.
func classifyRawStmt(d Dialect, raw *pg_query.RawStmt, sess SessionState, opts Options, backend effects.ParserBackend) effects.ClassifiedStatement {
	return unknownStatement(backend, "unmapped form: <classifier not yet implemented>")
}

func redshiftFirstKeyword(sql string, backend effects.ParserBackend) (effects.ClassifiedStatement, bool) {
	return effects.ClassifiedStatement{}, false
}
```

Remove the temporary `newParser` and `applySession` stubs at the bottom of `parser.go` from Task 2; both real definitions now exist (`newParser` in the build-tag files; `applySession` still gets a real impl in Task 9 — leave that stub in place but move it to its own file `ast_session_stub.go` or keep as-is until Task 9 replaces it).

- [ ] **Step 6: Run tests to verify both backends parse SELECT 1**

```bash
go test ./internal/db/classify/postgres/ -run TestBackend_ -v
```

Expected: PASS for `TestBackend_ParseFailureProducesUnknown` and `TestBackend_EmptyInputReturnsEmpty`. `TestBackend_ParsesSimpleSelect` returns 1 statement (the dispatcher's `unknown` placeholder) — its assertion that `Error == ""` will FAIL. Mark it `t.Skip("re-enabled in Task 5 once ast_walk lands")` and re-run.

- [ ] **Step 7: Cross-platform compile**

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build ./...   # libpgquery.go path
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...   # wasm.go path
GOOS=darwin go build ./...                              # wasm.go path
GOOS=windows go build ./...                             # wasm.go path
```

Expected: all four clean.

- [ ] **Step 8: Commit**

```bash
git add internal/db/classify/postgres/libpgquery.go internal/db/classify/postgres/wasm.go internal/db/classify/postgres/parser.go internal/db/classify/postgres/parser_test.go internal/db/classify/postgres/backend_test.go
git commit -m "classify/postgres: wire libpg_query backends (CGO + WASM)"
```

---

## Task 4: Corpus harness — loader + empty `corpus_test.go`

**Why:** Stand up the test harness before any AST mapping ships. Each subsequent AST-walk task can add corpus rows that immediately CI-gate the new code.

**Files:**
- Create: `internal/db/classify/postgres/corpus/_schema.go`
- Create: `internal/db/classify/postgres/corpus_test.go`
- Create: `internal/db/classify/postgres/corpus/0001-select-literal.yaml` (smallest possible smoke fixture)

- [ ] **Step 1: Write the corpus row schema**

Create `internal/db/classify/postgres/corpus/_schema.go`:

```go
// Package corpus declares the on-disk shape of classifier golden fixtures.
// The harness in corpus_test.go loads every *.yaml in this directory and
// asserts (Classify, Evaluate) against each row.
package corpus

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// Row is one corpus fixture. Each .yaml file contains exactly one Row.
type Row struct {
	// Authoring metadata.
	Name        string `yaml:"name"`        // human-readable handle, used in test names
	SpecRef     string `yaml:"spec_ref"`    // §7.3 row reference, optional
	Description string `yaml:"description"` // freeform note

	// Classifier inputs.
	SQL     string `yaml:"sql"`
	Dialect string `yaml:"dialect"` // postgres | aurora_postgres | cockroachdb | redshift; default postgres
	Session struct {
		SearchPath        []string `yaml:"search_path,omitempty"`
		DefaultSearchPath []string `yaml:"default_search_path,omitempty"`
		TempTables        []string `yaml:"temp_tables,omitempty"`
		Role              string   `yaml:"role,omitempty"`
		InTransaction     bool     `yaml:"in_transaction,omitempty"`
	} `yaml:"session,omitempty"`
	Options struct {
		EscalateUnknownFunctions bool     `yaml:"escalate_unknown_functions,omitempty"`
		SafeFunctionAllowlist    []string `yaml:"safe_function_allowlist,omitempty"`
	} `yaml:"options,omitempty"`

	// Expected outputs.
	ExpectedClassification []ExpectedStatement `yaml:"expected_classification"`
	ExpectedDecision       *ExpectedDecision   `yaml:"expected_decision_under_sample_policy,omitempty"`
}

type ExpectedStatement struct {
	RawVerb         string           `yaml:"raw_verb,omitempty"`
	PrimaryGroup    string           `yaml:"primary_group"`
	PrimarySubtype  string           `yaml:"primary_subtype,omitempty"`
	Effects         []ExpectedEffect `yaml:"effects"`
	ErrorPrefix     string           `yaml:"error_prefix,omitempty"`     // matches Error.HasPrefix
	TopResolution   string           `yaml:"top_resolution,omitempty"`   // FoldResolution String
}

type ExpectedEffect struct {
	Group      string           `yaml:"group"`
	Subtype    string           `yaml:"subtype,omitempty"`
	Objects    []ExpectedObject `yaml:"objects,omitempty"`
	Resolution string           `yaml:"resolution,omitempty"`
}

type ExpectedObject struct {
	Kind   string `yaml:"kind"`
	Schema string `yaml:"schema,omitempty"`
	Name   string `yaml:"name,omitempty"`
	Host   string `yaml:"host,omitempty"`
	Port   int    `yaml:"port,omitempty"`
	Path   string `yaml:"path,omitempty"`
	Argv0  string `yaml:"argv0,omitempty"`
}

type ExpectedDecision struct {
	Verb     string `yaml:"verb"`               // allow | audit | approve | deny
	RuleName string `yaml:"rule_name,omitempty"` // empty for implicit deny
	Reason   string `yaml:"reason_contains,omitempty"`
}

// LoadAll reads every *.yaml under dir and returns the rows in filename order.
func LoadAll(dir string) ([]Row, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	out := make([]Row, 0, len(matches))
	for _, p := range matches {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		var r Row
		dec := yaml.NewDecoder(bytesReader(b))
		dec.KnownFields(true)
		if err := dec.Decode(&r); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if r.Name == "" {
			r.Name = filepath.Base(p)
		}
		out = append(out, r)
	}
	return out, nil
}

// bytesReader is a tiny adapter so the schema package doesn't import bytes
// just to wrap a slice.
func bytesReader(b []byte) *yamlBytesReader { return &yamlBytesReader{b: b} }

type yamlBytesReader struct {
	b []byte
	i int
}

func (r *yamlBytesReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, fmt.Errorf("EOF")
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}
```

Note: the EOF return from `yamlBytesReader` should be `io.EOF`. Replace the `fmt.Errorf("EOF")` with `io.EOF` and add `"io"` to the imports.

- [ ] **Step 2: Write the harness**

Create `internal/db/classify/postgres/corpus_test.go`:

```go
package postgres

import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/db/classify/postgres/corpus"
	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
)

func TestCorpus(t *testing.T) {
	rows, err := corpus.LoadAll("corpus")
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("no corpus rows loaded — corpus/*.yaml missing?")
	}

	rs := policy.MustLoadSample()

	for _, row := range rows {
		row := row
		t.Run(row.Name, func(t *testing.T) {
			d := DialectPostgres
			if row.Dialect != "" {
				if got, ok := ParseDialect(row.Dialect); ok {
					d = got
				} else {
					t.Fatalf("unknown dialect: %q", row.Dialect)
				}
			}

			sess := SessionState{
				SearchPath:        row.Session.SearchPath,
				DefaultSearchPath: row.Session.DefaultSearchPath,
				Role:              row.Session.Role,
				InTransaction:     row.Session.InTransaction,
			}
			if len(row.Session.TempTables) > 0 {
				sess.TempTables = make(map[string]struct{}, len(row.Session.TempTables))
				for _, n := range row.Session.TempTables {
					sess.TempTables[n] = struct{}{}
				}
			}

			opts := Options{EscalateUnknownFunctions: row.Options.EscalateUnknownFunctions}
			if len(row.Options.SafeFunctionAllowlist) > 0 {
				opts.SafeFunctionAllowlist = make(map[string]struct{}, len(row.Options.SafeFunctionAllowlist))
				for _, n := range row.Options.SafeFunctionAllowlist {
					opts.SafeFunctionAllowlist[strings.ToLower(n)] = struct{}{}
				}
			}

			got, err := New(d).Classify(row.SQL, sess, opts)
			if err != nil {
				t.Fatalf("Classify: %v", err)
			}
			if len(got) != len(row.ExpectedClassification) {
				t.Fatalf("statement count: got %d want %d", len(got), len(row.ExpectedClassification))
			}
			for i, exp := range row.ExpectedClassification {
				assertStatement(t, i, got[i], exp)
			}

			if row.ExpectedDecision != nil {
				if len(got) != 1 {
					t.Fatalf("expected_decision requires single-statement fixture; got %d statements", len(got))
				}
				dec := policy.Evaluate(got[0], rs, "appdb")
				if dec.Verb.String() != row.ExpectedDecision.Verb {
					t.Fatalf("decision verb: got %q want %q", dec.Verb.String(), row.ExpectedDecision.Verb)
				}
				if row.ExpectedDecision.RuleName != "" && dec.RuleName != row.ExpectedDecision.RuleName {
					t.Fatalf("decision rule: got %q want %q", dec.RuleName, row.ExpectedDecision.RuleName)
				}
				if c := row.ExpectedDecision.Reason; c != "" && !strings.Contains(dec.Reason, c) {
					t.Fatalf("decision reason: got %q want substring %q", dec.Reason, c)
				}
			}
		})
	}
}

func assertStatement(t *testing.T, idx int, got effects.ClassifiedStatement, exp corpus.ExpectedStatement) {
	t.Helper()
	if exp.ErrorPrefix != "" {
		if !strings.HasPrefix(got.Error, exp.ErrorPrefix) {
			t.Fatalf("stmt[%d] error: got %q want prefix %q", idx, got.Error, exp.ErrorPrefix)
		}
	}
	if exp.RawVerb != "" && got.RawVerb != exp.RawVerb {
		t.Fatalf("stmt[%d] raw_verb: got %q want %q", idx, got.RawVerb, exp.RawVerb)
	}
	if got.Primary, primaryOk := got.Primary(); primaryOk {
		if exp.PrimaryGroup != "" && got.Primary.Group.String() != exp.PrimaryGroup {
			t.Fatalf("stmt[%d] primary group: got %q want %q", idx, got.Primary.Group.String(), exp.PrimaryGroup)
		}
		if exp.PrimarySubtype != "" && got.Primary.Subtype.String() != exp.PrimarySubtype {
			t.Fatalf("stmt[%d] primary subtype: got %q want %q", idx, got.Primary.Subtype.String(), exp.PrimarySubtype)
		}
		_ = primaryOk
	} else if exp.PrimaryGroup != "" {
		t.Fatalf("stmt[%d] no primary effect; expected %q", idx, exp.PrimaryGroup)
	}
	if exp.TopResolution != "" && got.FoldResolution().String() != exp.TopResolution {
		t.Fatalf("stmt[%d] fold resolution: got %q want %q", idx, got.FoldResolution().String(), exp.TopResolution)
	}
	if len(exp.Effects) != 0 {
		if len(got.Effects) != len(exp.Effects) {
			t.Fatalf("stmt[%d] effect count: got %d want %d", idx, len(got.Effects), len(exp.Effects))
		}
		for i, ee := range exp.Effects {
			ge := got.Effects[i]
			if ee.Group != "" && ge.Group.String() != ee.Group {
				t.Fatalf("stmt[%d].effect[%d] group: got %q want %q", idx, i, ge.Group.String(), ee.Group)
			}
			if ee.Subtype != "" && ge.Subtype.String() != ee.Subtype {
				t.Fatalf("stmt[%d].effect[%d] subtype: got %q want %q", idx, i, ge.Subtype.String(), ee.Subtype)
			}
			if ee.Resolution != "" && ge.Resolution.String() != ee.Resolution {
				t.Fatalf("stmt[%d].effect[%d] resolution: got %q want %q", idx, i, ge.Resolution.String(), ee.Resolution)
			}
			if len(ee.Objects) != 0 {
				assertObjects(t, idx, i, ge.Objects, ee.Objects)
			}
		}
	}
}

func assertObjects(t *testing.T, sIdx, eIdx int, got []effects.ObjectRef, exp []corpus.ExpectedObject) {
	t.Helper()
	if len(got) != len(exp) {
		t.Fatalf("stmt[%d].effect[%d] object count: got %d want %d", sIdx, eIdx, len(got), len(exp))
	}
	for i, e := range exp {
		g := got[i]
		if e.Kind != "" && g.Kind.String() != e.Kind {
			t.Fatalf("stmt[%d].effect[%d].obj[%d] kind: got %q want %q", sIdx, eIdx, i, g.Kind.String(), e.Kind)
		}
		if e.Schema != "" && g.Schema != e.Schema {
			t.Fatalf("stmt[%d].effect[%d].obj[%d] schema: got %q want %q", sIdx, eIdx, i, g.Schema, e.Schema)
		}
		if e.Name != "" && g.Name != e.Name {
			t.Fatalf("stmt[%d].effect[%d].obj[%d] name: got %q want %q", sIdx, eIdx, i, g.Name, e.Name)
		}
		if e.Host != "" && g.Host != e.Host {
			t.Fatalf("stmt[%d].effect[%d].obj[%d] host: got %q want %q", sIdx, eIdx, i, g.Host, e.Host)
		}
		if e.Port != 0 && g.Port != e.Port {
			t.Fatalf("stmt[%d].effect[%d].obj[%d] port: got %d want %d", sIdx, eIdx, i, g.Port, e.Port)
		}
		if e.Path != "" && g.Path != e.Path {
			t.Fatalf("stmt[%d].effect[%d].obj[%d] path: got %q want %q", sIdx, eIdx, i, g.Path, e.Path)
		}
		if e.Argv0 != "" && g.Argv0 != e.Argv0 {
			t.Fatalf("stmt[%d].effect[%d].obj[%d] argv0: got %q want %q", sIdx, eIdx, i, g.Argv0, e.Argv0)
		}
	}
}
```

Note: the local variable `got.Primary` shadow in `assertStatement` is wrong — `Primary()` is a method. Replace with:

```go
prim, primaryOk := got.Primary()
if primaryOk {
    if exp.PrimaryGroup != "" && prim.Group.String() != exp.PrimaryGroup {
        t.Fatalf("stmt[%d] primary group: got %q want %q", idx, prim.Group.String(), exp.PrimaryGroup)
    }
    if exp.PrimarySubtype != "" && prim.Subtype.String() != exp.PrimarySubtype {
        t.Fatalf("stmt[%d] primary subtype: got %q want %q", idx, prim.Subtype.String(), exp.PrimarySubtype)
    }
} else if exp.PrimaryGroup != "" {
    t.Fatalf("stmt[%d] no primary effect; expected %q", idx, exp.PrimaryGroup)
}
```

- [ ] **Step 3: Write the smallest viable corpus row**

Create `internal/db/classify/postgres/corpus/0001-select-literal.yaml`:

```yaml
name: select-literal-1
spec_ref: §7.3 SELECT
description: Trivial SELECT to smoke-test the harness.
sql: "SELECT 1"
dialect: postgres
expected_classification:
  - raw_verb: SELECT
    primary_group: read
    effects:
      - group: read
```

This row will fail until Task 5 ships the SELECT handler. Mark `TestCorpus` `t.Skip("re-enabled in Task 5 once ast_walk lands")` if you want a green CI between tasks; otherwise expect it to fail and re-enable in Task 5.

- [ ] **Step 4: Cross-compile + commit**

```bash
go vet ./internal/db/classify/postgres/...
GOOS=windows go build ./...
git add internal/db/classify/postgres/corpus internal/db/classify/postgres/corpus_test.go
git commit -m "classify/postgres: corpus harness + first smoke fixture"
```

---

## Task 5: AST walk — DML + composition (`ast_dml.go`)

**Why:** SELECT, INSERT, UPDATE, DELETE, MERGE, WITH-CTE, EXPLAIN, PREPARE, EXECUTE, DEALLOCATE — the largest single chunk of §7.3. Sharing one file because they share the relation-extraction helper and the CTE-composition rule.

**Files:**
- Create: `internal/db/classify/postgres/ast_walk.go`
- Create: `internal/db/classify/postgres/ast_dml.go`
- Create: `internal/db/classify/postgres/ast_dml_test.go`
- Create: `internal/db/classify/postgres/object.go`
- Create: `internal/db/classify/postgres/object_test.go`
- Add corpus rows: SELECT, INSERT, UPDATE, DELETE, MERGE, INSERT...SELECT, WITH...DELETE RETURNING, EXPLAIN, EXPLAIN ANALYZE, PREPARE, EXECUTE, DEALLOCATE.

- [ ] **Step 1: Write the failing unit test for RangeVar extraction**

Create `internal/db/classify/postgres/object_test.go`:

```go
package postgres

import (
	"testing"

	pg_query "github.com/pganalyze/pg_query_go/v6"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestExtractRelation_QualifiedAndUnqualified(t *testing.T) {
	cases := []struct {
		sql  string
		sess SessionState
		want effects.ObjectRef
		res  effects.Resolution
	}{
		{"SELECT * FROM public.users", SessionState{}, effects.ObjectRef{Kind: effects.ObjectTable, Schema: "public", Name: "users"}, effects.ResolutionQualified},
		{"SELECT * FROM users", SessionState{SearchPath: []string{"public"}, DefaultSearchPath: []string{"public"}}, effects.ObjectRef{Kind: effects.ObjectTable, Name: "users"}, effects.ResolutionUnqualified},
		{"SELECT * FROM users", SessionState{SearchPath: []string{"app", "public"}, DefaultSearchPath: []string{"public"}}, effects.ObjectRef{Kind: effects.ObjectTable, Name: "users"}, effects.ResolutionAmbiguousAfterSearchPath},
		{"SELECT * FROM users", SessionState{TempTables: map[string]struct{}{"users": {}}, DefaultSearchPath: []string{"public"}}, effects.ObjectRef{Kind: effects.ObjectTable, Name: "users"}, effects.ResolutionMaybeTempShadowed},
	}
	for _, tc := range cases {
		t.Run(tc.sql, func(t *testing.T) {
			res, err := pg_query.Parse(tc.sql)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			rel := firstFromRelation(res.Stmts[0].Stmt)
			if rel == nil {
				t.Fatalf("no relation found in %q", tc.sql)
			}
			obj, resn := extractRelation(rel, tc.sess, effects.ObjectTable)
			if obj.Kind != tc.want.Kind || obj.Schema != tc.want.Schema || obj.Name != tc.want.Name {
				t.Fatalf("ObjectRef mismatch: got %+v want %+v", obj, tc.want)
			}
			if resn != tc.res {
				t.Fatalf("Resolution: got %v want %v", resn, tc.res)
			}
		})
	}
}
```

`firstFromRelation` is a test helper that pulls the first FROM-clause RangeVar out of a SELECT — define it in `object_test.go` for clarity.

- [ ] **Step 2: Run to verify failure**

```bash
go test ./internal/db/classify/postgres/ -run TestExtractRelation -v
```

Expected: FAIL — `extractRelation` undefined.

- [ ] **Step 3: Implement `object.go`**

Create `internal/db/classify/postgres/object.go`:

```go
package postgres

import (
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// extractRelation maps a pg_query RangeVar to an ObjectRef + Resolution per §6.
// Caller specifies the target ObjectKind (table, view, sequence, etc.).
func extractRelation(rv *pg_query.RangeVar, sess SessionState, kind effects.ObjectKind) (effects.ObjectRef, effects.Resolution) {
	if rv == nil {
		return effects.ObjectRef{Kind: kind}, effects.ResolutionUnresolved
	}
	obj := effects.ObjectRef{
		Kind:   kind,
		Schema: strings.ToLower(rv.Schemaname),
		Name:   strings.ToLower(rv.Relname),
	}
	res := resolutionFor(obj, sess)
	return obj, res
}

func resolutionFor(obj effects.ObjectRef, sess SessionState) effects.Resolution {
	if obj.Schema != "" {
		return effects.ResolutionQualified
	}
	if _, isTemp := sess.TempTables[obj.Name]; isTemp {
		return effects.ResolutionMaybeTempShadowed
	}
	if !equalStringSlice(sess.SearchPath, sess.DefaultSearchPath) {
		// Empty SearchPath with empty DefaultSearchPath is "no info" → unqualified_syntactic.
		if len(sess.SearchPath) == 0 && len(sess.DefaultSearchPath) == 0 {
			return effects.ResolutionUnqualified
		}
		return effects.ResolutionAmbiguousAfterSearchPath
	}
	return effects.ResolutionUnqualified
}

func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
```

- [ ] **Step 4: Implement the dispatcher in `ast_walk.go`**

Create `internal/db/classify/postgres/ast_walk.go`:

```go
package postgres

import (
	pg_query "github.com/pganalyze/pg_query_go/v6"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// classifyRawStmt dispatches a single RawStmt to the per-family handler.
// It is the central switch over pg_query.Node one-of variants.
func classifyRawStmt(d Dialect, raw *pg_query.RawStmt, sess SessionState, opts Options, backend effects.ParserBackend) effects.ClassifiedStatement {
	if raw == nil || raw.Stmt == nil {
		return unknownStatement(backend, "unmapped form: nil RawStmt")
	}

	cs := effects.ClassifiedStatement{ParserBackend: backend}

	switch n := raw.Stmt.Node.(type) {
	case *pg_query.Node_SelectStmt:
		classifySelect(&cs, n.SelectStmt, sess, opts)
	case *pg_query.Node_InsertStmt:
		classifyInsert(&cs, n.InsertStmt, sess, opts)
	case *pg_query.Node_UpdateStmt:
		classifyUpdate(&cs, n.UpdateStmt, sess, opts)
	case *pg_query.Node_DeleteStmt:
		classifyDelete(&cs, n.DeleteStmt, sess, opts)
	case *pg_query.Node_MergeStmt:
		classifyMerge(&cs, n.MergeStmt, sess, opts)
	case *pg_query.Node_ExplainStmt:
		classifyExplain(&cs, n.ExplainStmt, sess, opts)
	case *pg_query.Node_PrepareStmt:
		classifyPrepare(&cs, n.PrepareStmt, sess, opts)
	case *pg_query.Node_ExecuteStmt:
		classifyExecute(&cs, n.ExecuteStmt, sess, opts)
	case *pg_query.Node_DeallocateStmt:
		classifyDeallocate(&cs, n.DeallocateStmt)
	// Session
	case *pg_query.Node_VariableSetStmt:
		classifySet(&cs, n.VariableSetStmt)
	case *pg_query.Node_VariableShowStmt:
		classifyShow(&cs)
	case *pg_query.Node_DiscardStmt:
		classifyDiscard(&cs, n.DiscardStmt)
	case *pg_query.Node_TransactionStmt:
		classifyTransaction(&cs, n.TransactionStmt)
	// DDL
	case *pg_query.Node_CreateStmt:
		classifyCreateTable(&cs, n.CreateStmt, sess)
	case *pg_query.Node_AlterTableStmt:
		classifyAlter(&cs, n.AlterTableStmt, sess)
	case *pg_query.Node_DropStmt:
		classifyDrop(&cs, n.DropStmt, sess)
	case *pg_query.Node_TruncateStmt:
		classifyTruncate(&cs, n.TruncateStmt, sess)
	case *pg_query.Node_IndexStmt:
		classifyCreateIndex(&cs, n.IndexStmt, sess)
	case *pg_query.Node_ViewStmt:
		classifyCreateView(&cs, n.ViewStmt, sess)
	case *pg_query.Node_CreateSchemaStmt:
		classifyCreateSchema(&cs, n.CreateSchemaStmt)
	case *pg_query.Node_CreateFunctionStmt:
		classifyCreateFunction(&cs, n.CreateFunctionStmt)
	case *pg_query.Node_CreateExtensionStmt:
		classifyCreateExtension(&cs, n.CreateExtensionStmt)
	case *pg_query.Node_CreatedbStmt:
		classifyCreateDatabase(&cs, n.CreatedbStmt)
	case *pg_query.Node_DropdbStmt:
		classifyDropDatabase(&cs, n.DropdbStmt)
	case *pg_query.Node_CreatePublicationStmt:
		classifyCreatePublication(&cs, n.CreatePublicationStmt)
	case *pg_query.Node_AlterPublicationStmt:
		classifyAlterPublication(&cs, n.AlterPublicationStmt)
	// Privilege
	case *pg_query.Node_GrantStmt:
		classifyGrant(&cs, n.GrantStmt)
	case *pg_query.Node_GrantRoleStmt:
		classifyGrantRole(&cs, n.GrantRoleStmt)
	case *pg_query.Node_CreateRoleStmt:
		classifyCreateRole(&cs, n.CreateRoleStmt)
	case *pg_query.Node_AlterRoleStmt:
		classifyAlterRole(&cs, n.AlterRoleStmt)
	case *pg_query.Node_DropRoleStmt:
		classifyDropRole(&cs, n.DropRoleStmt)
	case *pg_query.Node_AlterSystemStmt:
		classifyAlterSystem(&cs, n.AlterSystemStmt)
	case *pg_query.Node_SecLabelStmt:
		classifySecurityLabel(&cs, n.SecLabelStmt)
	// COPY
	case *pg_query.Node_CopyStmt:
		classifyCopy(&cs, n.CopyStmt, sess, opts)
	// External-IO DDL
	case *pg_query.Node_CreateSubscriptionStmt:
		classifyCreateSubscription(&cs, n.CreateSubscriptionStmt)
	case *pg_query.Node_AlterSubscriptionStmt:
		classifyAlterSubscription(&cs, n.AlterSubscriptionStmt)
	case *pg_query.Node_DropSubscriptionStmt:
		classifyDropSubscription(&cs, n.DropSubscriptionStmt)
	case *pg_query.Node_CreateForeignServerStmt:
		classifyCreateServer(&cs, n.CreateForeignServerStmt)
	case *pg_query.Node_AlterForeignServerStmt:
		classifyAlterServer(&cs, n.AlterForeignServerStmt)
	case *pg_query.Node_CreateUserMappingStmt:
		classifyCreateUserMapping(&cs, n.CreateUserMappingStmt)
	case *pg_query.Node_AlterUserMappingStmt:
		classifyAlterUserMapping(&cs, n.AlterUserMappingStmt)
	case *pg_query.Node_DropUserMappingStmt:
		classifyDropUserMapping(&cs, n.DropUserMappingStmt)
	case *pg_query.Node_CreateTableSpaceStmt:
		classifyCreateTablespace(&cs, n.CreateTableSpaceStmt)
	case *pg_query.Node_AlterTableSpaceOptionsStmt:
		classifyAlterTablespace(&cs, n.AlterTableSpaceOptionsStmt)
	// Procedural / misc
	case *pg_query.Node_CallStmt:
		classifyCall(&cs, n.CallStmt)
	case *pg_query.Node_DoStmt:
		classifyDo(&cs, n.DoStmt)
	case *pg_query.Node_VacuumStmt:
		classifyMaintenance(&cs, n.VacuumStmt)
	case *pg_query.Node_ReindexStmt:
		classifyReindex(&cs, n.ReindexStmt)
	case *pg_query.Node_ClusterStmt:
		classifyCluster(&cs, n.ClusterStmt)
	case *pg_query.Node_CheckPointStmt:
		classifyCheckpoint(&cs)
	case *pg_query.Node_LockStmt:
		classifyLock(&cs, n.LockStmt, sess)
	case *pg_query.Node_ListenStmt, *pg_query.Node_NotifyStmt, *pg_query.Node_UnlistenStmt:
		classifyNotify(&cs, raw.Stmt)
	default:
		cs.Error = unmappedFormError(raw.Stmt)
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		return cs
	}

	// Empty Effects after dispatch indicates a handler bug; surface as unknown.
	if len(cs.Effects) == 0 {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		if cs.Error == "" {
			cs.Error = "unmapped form: handler produced no effects"
		}
	}
	effects.Order(cs.Effects)
	return cs
}

func unmappedFormError(stmt *pg_query.Node) string {
	if stmt == nil || stmt.Node == nil {
		return "unmapped form: nil statement"
	}
	// %T renders the Go type name, e.g. "*pg_query.Node_AlterEnumStmt".
	return "unmapped form: " + nodeTypeName(stmt)
}

func nodeTypeName(n *pg_query.Node) string {
	if n == nil {
		return "nil"
	}
	return strings.TrimPrefix(strings.TrimPrefix(fmt.Sprintf("%T", n.Node), "*pg_query."), "Node_")
}
```

Add `import` lines for `fmt` and `strings` at the top of `ast_walk.go`.

Note: this dispatcher references handler functions for every SQL family covered in Tasks 5–13. Until those tasks ship, each handler not yet implemented should exist as a no-op stub returning an unknown effect with `cs.Error = "unmapped form: <family> not yet implemented"`. Add a single file `ast_stubs.go` with all stubs initially; subsequent tasks delete a stub when they ship the real handler.

Concretely for Task 5, leave only the DML/composition handlers as stubs to be replaced in this task, and keep the rest as unknown-stubs.

Create `internal/db/classify/postgres/ast_stubs.go` (build-tag-free, all platforms):

```go
package postgres

import (
	pg_query "github.com/pganalyze/pg_query_go/v6"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// Stubs replaced in Tasks 5–13. Each writes an unknown effect with a
// "not yet implemented" error so the dispatcher's invariant (len(Effects) > 0)
// holds. Remove a stub once its real implementation lands.

func classifyMerge(cs *effects.ClassifiedStatement, _ *pg_query.MergeStmt, _ SessionState, _ Options) {
	stub(cs, "merge")
}
func classifyExplain(cs *effects.ClassifiedStatement, _ *pg_query.ExplainStmt, _ SessionState, _ Options) {
	stub(cs, "explain")
}
// … one stub per handler enumerated in ast_walk.go's switch

func stub(cs *effects.ClassifiedStatement, family string) {
	cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
	cs.Error = "unmapped form: " + family + " not yet implemented"
}
```

For brevity the stub list isn't enumerated here; the engineer follows the pattern: one no-op per handler the dispatcher references.

- [ ] **Step 5: Implement DML handlers**

Create `internal/db/classify/postgres/ast_dml.go`:

```go
package postgres

import (
	pg_query "github.com/pganalyze/pg_query_go/v6"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func classifySelect(cs *effects.ClassifiedStatement, s *pg_query.SelectStmt, sess SessionState, opts Options) {
	cs.RawVerb = "SELECT"

	// CTAS — SELECT ... INTO is parsed as SelectStmt with IntoClause.
	if s.IntoClause != nil {
		cs.RawVerb = "SELECT_INTO"
		target, res := extractRelation(s.IntoClause.Rel, sess, effects.ObjectTable)
		cs.Effects = append(cs.Effects, effects.Effect{
			Group:      effects.GroupSchemaCreate,
			Subtype:    effects.SubtypeCreateTable,
			Objects:    []effects.ObjectRef{target},
			Resolution: res,
		})
	}

	// Read effect from FROM-clause and joins; recurse into sub-selects via
	// walkRelations.
	relations, res := walkSelectRelations(s, sess)
	if len(relations) > 0 || cs.IntoClauseEffect() == false {
		cs.Effects = append(cs.Effects, effects.Effect{
			Group:      effects.GroupRead,
			Objects:    relations,
			Resolution: res,
		})
	}

	// §7.6 escalation: if any function call in the projection / WHERE is not
	// in the safe-allowlist, escalate to procedural.
	if opts.EscalateUnknownFunctions && containsUnknownFunctionCall(s, opts.SafeFunctionAllowlist) {
		cs.Effects = append(cs.Effects, effects.Effect{Group: effects.GroupProcedural})
	}

	// Detect unsafe-IO function calls (pg_read_file, lo_*, dblink) anywhere
	// inside the statement — handled by ast_unsafe_io.go's appendUnsafeIO.
	appendUnsafeIO(cs, s, sess)

	if len(cs.Effects) == 0 {
		// SELECT 1 with no relations and no escalation — still classify as read.
		cs.Effects = []effects.Effect{{Group: effects.GroupRead, Resolution: effects.ResolutionQualified}}
	}
}

// ClassifiedStatement.IntoClauseEffect is a tiny method on the host struct;
// since we cannot add methods to a foreign struct, replace with a local helper.
// Inline equivalent:
func hasSchemaCreateEffect(cs *effects.ClassifiedStatement) bool {
	for _, e := range cs.Effects {
		if e.Group == effects.GroupSchemaCreate {
			return true
		}
	}
	return false
}
```

Note: the line `if len(relations) > 0 || cs.IntoClauseEffect() == false` references a method that does not exist. Use the local `hasSchemaCreateEffect(cs)` helper:

```go
if len(relations) > 0 || !hasSchemaCreateEffect(cs) {
    cs.Effects = append(cs.Effects, effects.Effect{
        Group:      effects.GroupRead,
        Objects:    relations,
        Resolution: res,
    })
}
```

Continue with the other DML handlers in the same file:

```go
func classifyInsert(cs *effects.ClassifiedStatement, s *pg_query.InsertStmt, sess SessionState, opts Options) {
	cs.RawVerb = "INSERT"
	tgt, tgtRes := extractRelation(s.Relation, sess, effects.ObjectTable)
	writeEff := effects.Effect{
		Group:      effects.GroupWrite,
		Objects:    []effects.ObjectRef{tgt},
		Resolution: tgtRes,
	}
	cs.Effects = append(cs.Effects, writeEff)
	// INSERT ... SELECT — read effect for the inner SELECT relations.
	if s.SelectStmt != nil {
		if sel, ok := s.SelectStmt.Node.(*pg_query.Node_SelectStmt); ok {
			rels, res := walkSelectRelations(sel.SelectStmt, sess)
			if len(rels) > 0 {
				cs.Effects = append(cs.Effects, effects.Effect{
					Group:      effects.GroupRead,
					Objects:    rels,
					Resolution: res,
				})
			}
		}
	}
	// WITH-CTE composition: data-modifying CTEs add their own effects.
	if s.WithClause != nil {
		appendCTEEffects(cs, s.WithClause, sess, opts)
	}
}

func classifyUpdate(cs *effects.ClassifiedStatement, s *pg_query.UpdateStmt, sess SessionState, opts Options) {
	cs.RawVerb = "UPDATE"
	tgt, tgtRes := extractRelation(s.Relation, sess, effects.ObjectTable)
	cs.Effects = append(cs.Effects, effects.Effect{
		Group:      effects.GroupModify,
		Objects:    []effects.ObjectRef{tgt},
		Resolution: tgtRes,
	})
	// FROM-clause references add a read effect.
	rels, res := walkRangeRelations(s.FromClause, sess)
	if len(rels) > 0 {
		cs.Effects = append(cs.Effects, effects.Effect{
			Group:      effects.GroupRead,
			Objects:    rels,
			Resolution: res,
		})
	}
	if s.WithClause != nil {
		appendCTEEffects(cs, s.WithClause, sess, opts)
	}
}

func classifyDelete(cs *effects.ClassifiedStatement, s *pg_query.DeleteStmt, sess SessionState, opts Options) {
	cs.RawVerb = "DELETE"
	tgt, tgtRes := extractRelation(s.Relation, sess, effects.ObjectTable)
	cs.Effects = append(cs.Effects, effects.Effect{
		Group:      effects.GroupDelete,
		Objects:    []effects.ObjectRef{tgt},
		Resolution: tgtRes,
	})
	// DELETE … RETURNING with a RETURNING list adds a read effect on the
	// target table (already covered by GroupDelete's Objects, but the spec
	// distinguishes RETURNING as a read).
	if hasReturningList(s.ReturningList) {
		cs.Effects = append(cs.Effects, effects.Effect{
			Group:      effects.GroupRead,
			Objects:    []effects.ObjectRef{tgt},
			Resolution: tgtRes,
		})
	}
	// USING clause adds a read effect for additional relations.
	rels, res := walkRangeRelations(s.UsingClause, sess)
	if len(rels) > 0 {
		cs.Effects = append(cs.Effects, effects.Effect{
			Group:      effects.GroupRead,
			Objects:    rels,
			Resolution: res,
		})
	}
	if s.WithClause != nil {
		appendCTEEffects(cs, s.WithClause, sess, opts)
	}
}

func classifyMerge(cs *effects.ClassifiedStatement, s *pg_query.MergeStmt, sess SessionState, opts Options) {
	cs.RawVerb = "MERGE"
	tgt, tgtRes := extractRelation(s.Relation, sess, effects.ObjectTable)
	cs.Effects = append(cs.Effects, effects.Effect{
		Group:      effects.GroupModify,
		Objects:    []effects.ObjectRef{tgt},
		Resolution: tgtRes,
	})
	// Source side is read.
	if s.SourceRelation != nil {
		if rv, ok := s.SourceRelation.Node.(*pg_query.Node_RangeVar); ok {
			obj, res := extractRelation(rv.RangeVar, sess, effects.ObjectTable)
			cs.Effects = append(cs.Effects, effects.Effect{
				Group:      effects.GroupRead,
				Objects:    []effects.ObjectRef{obj},
				Resolution: res,
			})
		}
	}
}

func classifyExplain(cs *effects.ClassifiedStatement, s *pg_query.ExplainStmt, sess SessionState, opts Options) {
	cs.RawVerb = "EXPLAIN"
	analyze := false
	for _, opt := range s.Options {
		if dn, ok := opt.Node.(*pg_query.Node_DefElem); ok && dn.DefElem != nil {
			if dn.DefElem.Defname == "analyze" {
				analyze = true
				break
			}
		}
	}
	if analyze && s.Query != nil {
		// EXPLAIN ANALYZE <inner> matches inner statement.
		inner := classifyRawStmt(DialectPostgres, &pg_query.RawStmt{Stmt: s.Query}, sess, opts, cs.ParserBackend)
		cs.RawVerb = "EXPLAIN_ANALYZE"
		cs.Effects = inner.Effects
		return
	}
	// Plain EXPLAIN — read.
	cs.Effects = []effects.Effect{{Group: effects.GroupRead, Resolution: effects.ResolutionQualified}}
}

func classifyPrepare(cs *effects.ClassifiedStatement, s *pg_query.PrepareStmt, sess SessionState, opts Options) {
	cs.RawVerb = "PREPARE"
	if s.Query == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
		cs.Error = "unmapped form: PREPARE without query"
		return
	}
	inner := classifyRawStmt(DialectPostgres, &pg_query.RawStmt{Stmt: s.Query}, sess, opts, cs.ParserBackend)
	cs.Effects = inner.Effects
	if cs.RawVerb == "" && inner.RawVerb != "" {
		cs.RawVerb = "PREPARE_" + inner.RawVerb
	}
}

func classifyExecute(cs *effects.ClassifiedStatement, s *pg_query.ExecuteStmt, sess SessionState, opts Options) {
	// Cache lookup is owned by Plan 05 (proxy). Plan 03 returns unknown so the
	// proxy can synthesize the cache-miss deny path per spec §7.4.
	cs.RawVerb = "EXECUTE"
	cs.Effects = []effects.Effect{{Group: effects.GroupUnknown, Resolution: effects.ResolutionUnresolved}}
	cs.Error = "execute: cache lookup deferred to proxy (Plan 05)"
}

func classifyDeallocate(cs *effects.ClassifiedStatement, s *pg_query.DeallocateStmt) {
	cs.RawVerb = "DEALLOCATE"
	cs.Effects = []effects.Effect{{
		Group:   effects.GroupSession,
		Subtype: effects.SubtypeDiscardPlans, // §7.3 maps DEALLOCATE → discard_plans
	}}
}

// ---- helpers ----

// walkSelectRelations enumerates relations referenced anywhere in a SelectStmt
// (FROM, JOINs, sub-selects, set-ops). Returns a single Resolution folded
// across all returned relations.
func walkSelectRelations(s *pg_query.SelectStmt, sess SessionState) ([]effects.ObjectRef, effects.Resolution) {
	if s == nil {
		return nil, effects.ResolutionQualified
	}
	objs, ress := []effects.ObjectRef{}, []effects.Resolution{}
	collectRangeRefs(s.FromClause, sess, &objs, &ress)
	if s.WithClause != nil {
		// CTE relations themselves are not added; their bodies' relations are
		// reached via the CTE's SubSelect.
		for _, c := range s.WithClause.Ctes {
			if cn, ok := c.Node.(*pg_query.Node_CommonTableExpr); ok && cn.CommonTableExpr.Ctequery != nil {
				if inner, ok := cn.CommonTableExpr.Ctequery.Node.(*pg_query.Node_SelectStmt); ok {
					more, _ := walkSelectRelations(inner.SelectStmt, sess)
					objs = append(objs, more...)
				}
			}
		}
	}
	if s.Larg != nil {
		more, _ := walkSelectRelations(s.Larg, sess)
		objs = append(objs, more...)
	}
	if s.Rarg != nil {
		more, _ := walkSelectRelations(s.Rarg, sess)
		objs = append(objs, more...)
	}
	return objs, effects.Fold(ress)
}

// walkRangeRelations enumerates RangeVar nodes inside a list of *pg_query.Node
// (used for FROM lists, USING lists, etc.).
func walkRangeRelations(list []*pg_query.Node, sess SessionState) ([]effects.ObjectRef, effects.Resolution) {
	objs, ress := []effects.ObjectRef{}, []effects.Resolution{}
	collectRangeRefs(list, sess, &objs, &ress)
	return objs, effects.Fold(ress)
}

func collectRangeRefs(list []*pg_query.Node, sess SessionState, objs *[]effects.ObjectRef, ress *[]effects.Resolution) {
	for _, n := range list {
		if n == nil {
			continue
		}
		switch v := n.Node.(type) {
		case *pg_query.Node_RangeVar:
			obj, res := extractRelation(v.RangeVar, sess, effects.ObjectTable)
			*objs = append(*objs, obj)
			*ress = append(*ress, res)
		case *pg_query.Node_JoinExpr:
			if v.JoinExpr != nil {
				collectRangeRefs([]*pg_query.Node{v.JoinExpr.Larg, v.JoinExpr.Rarg}, sess, objs, ress)
			}
		case *pg_query.Node_RangeSubselect:
			if v.RangeSubselect != nil && v.RangeSubselect.Subquery != nil {
				if sel, ok := v.RangeSubselect.Subquery.Node.(*pg_query.Node_SelectStmt); ok {
					more, _ := walkSelectRelations(sel.SelectStmt, sess)
					*objs = append(*objs, more...)
				}
			}
		}
	}
}

// appendCTEEffects walks WITH-clause CTEs and appends effects for any CTEs
// whose body is a data-modifying statement (INSERT/UPDATE/DELETE).
func appendCTEEffects(cs *effects.ClassifiedStatement, with *pg_query.WithClause, sess SessionState, opts Options) {
	if with == nil {
		return
	}
	for _, c := range with.Ctes {
		cn, ok := c.Node.(*pg_query.Node_CommonTableExpr)
		if !ok || cn.CommonTableExpr.Ctequery == nil {
			continue
		}
		inner := classifyRawStmt(DialectPostgres, &pg_query.RawStmt{Stmt: cn.CommonTableExpr.Ctequery}, sess, opts, cs.ParserBackend)
		for _, e := range inner.Effects {
			// CTE-as-RETURNING delete/insert/update propagates to outer.
			cs.Effects = append(cs.Effects, e)
		}
	}
}

func hasReturningList(list []*pg_query.Node) bool {
	return len(list) > 0
}

func containsUnknownFunctionCall(s *pg_query.SelectStmt, allow map[string]struct{}) bool {
	// Walk the projection list; for any FuncCall, check the canonical lowercase
	// name against the allowlist. Conservatively returns true on any non-allowlisted
	// function — the operator opted into noise per §7.6 by setting EscalateUnknownFunctions.
	// Implementation walks via collectFuncCalls (a sibling helper); details in escalation.go.
	return collectFuncCallsAny(s, allow)
}
```

`collectFuncCallsAny` is implemented in `escalation.go` (Task 14). Until then, define it in `ast_dml.go` as a stub that returns `false` so DML tests don't depend on Task 14:

```go
func collectFuncCallsAny(s *pg_query.SelectStmt, allow map[string]struct{}) bool { return false }
```

Delete this stub when Task 14 ships the real `collectFuncCallsAny`.

`appendUnsafeIO` is from Task 12 (unsafe-IO functions). For Task 5, define a stub:

```go
func appendUnsafeIO(cs *effects.ClassifiedStatement, s *pg_query.SelectStmt, sess SessionState) {}
```

Delete this stub when Task 12 ships the real walker.

- [ ] **Step 6: Run unit tests**

```bash
go test ./internal/db/classify/postgres/ -run "TestExtractRelation|TestBackend_" -v
```

Expected: PASS for `TestExtractRelation_*` and `TestBackend_ParsesSimpleSelect` (now that the SELECT handler is real).

- [ ] **Step 7: Add corpus rows**

Each fixture is its own YAML file under `internal/db/classify/postgres/corpus/`. Replace the placeholder `0001-select-literal.yaml` content if needed and add at least the following rows. Use the existing schema; primary group is the first effect after canonical ordering.

- `0010-select-table.yaml`:

```yaml
name: select-table
spec_ref: §7.3 SELECT
sql: "SELECT * FROM customers"
session: { search_path: ["public"], default_search_path: ["public"] }
expected_classification:
  - raw_verb: SELECT
    primary_group: read
    effects:
      - group: read
        objects:
          - { kind: table, name: customers }
        resolution: unqualified_syntactic
```

- `0011-select-qualified.yaml`:

```yaml
name: select-qualified
sql: "SELECT * FROM public.customers"
expected_classification:
  - raw_verb: SELECT
    primary_group: read
    effects:
      - group: read
        objects:
          - { kind: table, schema: public, name: customers }
        resolution: qualified_syntactic
```

- `0012-insert.yaml`:

```yaml
name: insert
sql: "INSERT INTO audit_log VALUES (1, 'note')"
expected_classification:
  - raw_verb: INSERT
    primary_group: write
    effects:
      - group: write
        objects: [{ kind: table, name: audit_log }]
```

- `0013-insert-select.yaml` (per-effect attribution from §20):

```yaml
name: insert-select
sql: "INSERT INTO audit_log SELECT * FROM users"
expected_classification:
  - raw_verb: INSERT
    primary_group: write
    effects:
      - group: write
        objects: [{ kind: table, name: audit_log }]
      - group: read
        objects: [{ kind: table, name: users }]
```

- `0014-update.yaml`, `0015-delete.yaml`, `0016-merge.yaml`, `0017-explain.yaml`, `0018-explain-analyze.yaml`, `0019-prepare-select.yaml`, `0020-with-delete-returning.yaml`, `0021-deallocate.yaml`, `0022-select-into.yaml`, `0023-select-after-search-path-change.yaml` (resolution: ambiguous_after_search_path), `0024-select-temp-shadowed.yaml`.

For each row that has a §9.2 sample-policy decision (allow/deny) per §20, add `expected_decision_under_sample_policy` per the schema. For example, `0013-insert-select.yaml` with sample policy "allow write to audit_log, allow read to users" should produce `verb: allow`. Include at least one allow and one deny in this batch.

- [ ] **Step 8: Run corpus**

```bash
go test ./internal/db/classify/postgres/ -run TestCorpus -v
```

Expected: PASS for all DML rows added in Step 7.

- [ ] **Step 9: Commit**

```bash
git add internal/db/classify/postgres/
git commit -m "classify/postgres: DML / composition AST mapping + corpus seed"
```

---

## Task 6: AST walk — session statements (`ast_session.go`) + ApplyStatement

**Why:** SET / RESET / DISCARD / SET ROLE / SET SESSION AUTHORIZATION / BEGIN / COMMIT / ROLLBACK. These are also where `ApplyStatement` lives — a single file owns the per-statement state-evolution rules.

**Files:**
- Create: `internal/db/classify/postgres/ast_session.go`
- Create: `internal/db/classify/postgres/ast_session_test.go`
- Add corpus rows for SET search_path, SET role, RESET, RESET ALL, DISCARD ALL, DISCARD TEMP, DISCARD PLANS, BEGIN, COMMIT, ROLLBACK, SET LOCAL.

- [ ] **Step 1: Failing test for `ApplyStatement`**

Create `internal/db/classify/postgres/ast_session_test.go`:

```go
package postgres

import (
	"reflect"
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestApplyStatement_SetSearchPath(t *testing.T) {
	in := SessionState{SearchPath: []string{"public"}, DefaultSearchPath: []string{"public"}}
	cs := effects.ClassifiedStatement{
		Effects: []effects.Effect{{
			Group:   effects.GroupSession,
			Subtype: effects.SubtypeSetSearchPath,
			Objects: []effects.ObjectRef{
				{Kind: effects.ObjectGUC, Name: "search_path"},
			},
		}},
		RawVerb: "SET_SEARCH_PATH=app,public",
	}
	got := ApplyStatement(in, cs)
	want := []string{"app", "public"}
	if !reflect.DeepEqual(got.SearchPath, want) {
		t.Fatalf("SearchPath: got %v want %v", got.SearchPath, want)
	}
}

func TestApplyStatement_DiscardAll(t *testing.T) {
	in := SessionState{
		SearchPath:        []string{"app", "public"},
		DefaultSearchPath: []string{"public"},
		TempTables:        map[string]struct{}{"foo": {}},
		Role:              "alice",
		DefaultRole:       "",
	}
	cs := effects.ClassifiedStatement{Effects: []effects.Effect{{Group: effects.GroupSession, Subtype: effects.SubtypeDiscardAll}}}
	got := ApplyStatement(in, cs)
	if !reflect.DeepEqual(got.SearchPath, in.DefaultSearchPath) {
		t.Fatalf("DiscardAll search_path not reset: %v", got.SearchPath)
	}
	if len(got.TempTables) != 0 {
		t.Fatalf("DiscardAll temp_tables not cleared: %v", got.TempTables)
	}
	if got.Role != "" {
		t.Fatalf("DiscardAll role not reset: %q", got.Role)
	}
}
```

Add similar small tests for: `SetLocal` (no mutation), `Reset search_path`, `ResetAll`, `DiscardTemp`, `SetRole "r"`, `ResetRole`, `BEGIN`, `COMMIT`.

- [ ] **Step 2: Run failing**

```bash
go test ./internal/db/classify/postgres/ -run TestApplyStatement_ -v
```

Expected: FAIL — current `applySession` is the no-op stub from Task 2.

- [ ] **Step 3: Implement classifiers + ApplyStatement**

Create `internal/db/classify/postgres/ast_session.go`:

```go
package postgres

import (
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// classifySet maps SET / SET LOCAL / SET SESSION AUTHORIZATION / SET ROLE.
func classifySet(cs *effects.ClassifiedStatement, s *pg_query.VariableSetStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown}}
		cs.Error = "unmapped form: nil VariableSetStmt"
		return
	}
	name := strings.ToLower(s.Name)
	subtype, raw := mapSetSubtype(s.Kind, name)
	cs.RawVerb = raw + valueSummary(s)
	cs.Effects = []effects.Effect{{
		Group:   effects.GroupSession,
		Subtype: subtype,
		Objects: []effects.ObjectRef{{Kind: effects.ObjectGUC, Name: name}},
	}}
}

func mapSetSubtype(k pg_query.VariableSetKind, name string) (effects.Subtype, string) {
	switch k {
	case pg_query.VariableSetKind_VAR_SET_VALUE, pg_query.VariableSetKind_VAR_SET_DEFAULT, pg_query.VariableSetKind_VAR_SET_CURRENT:
		switch name {
		case "search_path":
			return effects.SubtypeSetSearchPath, "SET_SEARCH_PATH="
		case "role":
			return effects.SubtypeSetRole, "SET_ROLE="
		case "session_authorization":
			return effects.SubtypeSetSessionAuthorization, "SET_SESSION_AUTHORIZATION="
		default:
			return effects.SubtypeSet, "SET="
		}
	case pg_query.VariableSetKind_VAR_SET_MULTI:
		return effects.SubtypeSet, "SET="
	case pg_query.VariableSetKind_VAR_RESET:
		if name == "all" {
			return effects.SubtypeResetAll, "RESET_ALL"
		}
		return effects.SubtypeReset, "RESET=" + name
	case pg_query.VariableSetKind_VAR_RESET_ALL:
		return effects.SubtypeResetAll, "RESET_ALL"
	}
	return effects.SubtypeSet, "SET="
}

// classifyShow — read.
func classifyShow(cs *effects.ClassifiedStatement) {
	cs.RawVerb = "SHOW"
	cs.Effects = []effects.Effect{{Group: effects.GroupRead, Resolution: effects.ResolutionQualified}}
}

func classifyDiscard(cs *effects.ClassifiedStatement, s *pg_query.DiscardStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown}}
		cs.Error = "unmapped form: nil DiscardStmt"
		return
	}
	switch s.Target {
	case pg_query.DiscardMode_DISCARD_ALL:
		cs.RawVerb = "DISCARD_ALL"
		cs.Effects = []effects.Effect{{Group: effects.GroupSession, Subtype: effects.SubtypeDiscardAll}}
	case pg_query.DiscardMode_DISCARD_PLANS:
		cs.RawVerb = "DISCARD_PLANS"
		cs.Effects = []effects.Effect{{Group: effects.GroupSession, Subtype: effects.SubtypeDiscardPlans}}
	case pg_query.DiscardMode_DISCARD_TEMP:
		cs.RawVerb = "DISCARD_TEMP"
		cs.Effects = []effects.Effect{{Group: effects.GroupSession, Subtype: effects.SubtypeDiscardTemp}}
	case pg_query.DiscardMode_DISCARD_SEQUENCES:
		cs.RawVerb = "DISCARD_SEQUENCES"
		cs.Effects = []effects.Effect{{Group: effects.GroupSession, Subtype: effects.SubtypeDiscardSequences}}
	default:
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown}}
		cs.Error = "unmapped form: discard target"
	}
}

func classifyTransaction(cs *effects.ClassifiedStatement, s *pg_query.TransactionStmt) {
	if s == nil {
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown}}
		cs.Error = "unmapped form: nil TransactionStmt"
		return
	}
	cs.RawVerb = strings.ToUpper(s.Kind.String())
	cs.Effects = []effects.Effect{{Group: effects.GroupTransaction}}
}

// valueSummary renders a compact representation of a SET's value list, used
// for RawVerb introspection. Best-effort — only covers literal, identifier,
// and list-of-strings cases; falls back to "?" for complex expressions.
func valueSummary(s *pg_query.VariableSetStmt) string {
	if len(s.Args) == 0 {
		return ""
	}
	parts := make([]string, 0, len(s.Args))
	for _, arg := range s.Args {
		parts = append(parts, summarizeArg(arg))
	}
	return strings.Join(parts, ",")
}

func summarizeArg(n *pg_query.Node) string {
	if n == nil {
		return ""
	}
	switch v := n.Node.(type) {
	case *pg_query.Node_AConst:
		if v.AConst == nil || v.AConst.Val == nil {
			return ""
		}
		switch c := v.AConst.Val.(type) {
		case *pg_query.A_Const_Sval:
			return c.Sval.Sval
		case *pg_query.A_Const_Ival:
			return formatInt(c.Ival.Ival)
		}
	case *pg_query.Node_String_:
		return v.String_.Sval
	}
	return "?"
}

func formatInt(n int32) string {
	// Keep allocations minimal; SET values are rarely huge ints.
	return strings.TrimSpace(strconv.FormatInt(int64(n), 10))
}
```

Add `import "strconv"` at the top of `ast_session.go`.

- [ ] **Step 4: Implement `applySession`**

Replace the `applySession` stub in `parser.go` with this in `ast_session.go`:

```go
func applySession(s SessionState, c effects.ClassifiedStatement) SessionState {
	out := s.Clone()
	for _, e := range c.Effects {
		if e.Group != effects.GroupSession && e.Group != effects.GroupTransaction {
			// Non-session effects: only CREATE TEMP TABLE / DROP TABLE mutate session state.
			applyTempLifecycle(&out, e, c.RawVerb)
			continue
		}
		applySessionEffect(&out, e, c.RawVerb)
	}
	return out
}

func applySessionEffect(s *SessionState, e effects.Effect, rawVerb string) {
	switch e.Subtype {
	case effects.SubtypeSetSearchPath:
		s.SearchPath = parseSearchPath(rawVerb)
	case effects.SubtypeSetRole:
		s.Role = parseAfterEqual(rawVerb)
	case effects.SubtypeSetSessionAuthorization:
		s.Role = parseAfterEqual(rawVerb)
	case effects.SubtypeReset:
		// Specific GUC reset: only search_path resets affect tracked state.
		if hasGUC(e.Objects, "search_path") {
			s.SearchPath = append([]string(nil), s.DefaultSearchPath...)
		}
	case effects.SubtypeResetAll, effects.SubtypeDiscardAll:
		s.SearchPath = append([]string(nil), s.DefaultSearchPath...)
		s.Role = s.DefaultRole
		s.TempTables = nil
	case effects.SubtypeDiscardTemp:
		s.TempTables = nil
	case effects.SubtypeSetLocal:
		// Tag-only; no mutation.
	}

	// Transaction tracking (hint only — see SessionState comment).
	switch rawVerb {
	case "BEGIN", "START", "BEGIN_TRANSACTION":
		s.InTransaction = true
	case "COMMIT", "ROLLBACK", "END":
		s.InTransaction = false
	}
}

func applyTempLifecycle(s *SessionState, e effects.Effect, rawVerb string) {
	if e.Subtype == effects.SubtypeCreateTable && strings.Contains(rawVerb, "TEMP") {
		for _, o := range e.Objects {
			if o.Kind == effects.ObjectTable && o.Schema == "" {
				if s.TempTables == nil {
					s.TempTables = make(map[string]struct{})
				}
				s.TempTables[o.Name] = struct{}{}
			}
		}
	}
	if e.Subtype == effects.SubtypeDropTable {
		for _, o := range e.Objects {
			if o.Kind == effects.ObjectTable && o.Schema == "" {
				delete(s.TempTables, o.Name)
			}
		}
	}
}

func parseSearchPath(rawVerb string) []string {
	const prefix = "SET_SEARCH_PATH="
	if !strings.HasPrefix(rawVerb, prefix) {
		return nil
	}
	parts := strings.Split(rawVerb[len(prefix):], ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"`)
		p = strings.ToLower(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseAfterEqual(rawVerb string) string {
	if i := strings.Index(rawVerb, "="); i >= 0 {
		return strings.ToLower(strings.TrimSpace(rawVerb[i+1:]))
	}
	return ""
}

func hasGUC(objs []effects.ObjectRef, name string) bool {
	for _, o := range objs {
		if o.Kind == effects.ObjectGUC && o.Name == name {
			return true
		}
	}
	return false
}
```

- [ ] **Step 5: Run tests**

```bash
go test ./internal/db/classify/postgres/ -run "TestApplyStatement|TestCorpus" -v
```

Expected: PASS for the new ApplyStatement tests and the session corpus rows.

- [ ] **Step 6: Add corpus rows**

Files: `0030-set-search-path.yaml`, `0031-set-role.yaml`, `0032-set-local.yaml`, `0033-reset.yaml`, `0034-reset-all.yaml`, `0035-discard-all.yaml`, `0036-discard-temp.yaml`, `0037-discard-plans.yaml`, `0038-begin.yaml`, `0039-commit.yaml`, `0040-rollback.yaml`. One example, the rest follow the same shape:

```yaml
name: set-search-path
sql: "SET search_path = app, public"
expected_classification:
  - raw_verb: SET_SEARCH_PATH=app,public
    primary_group: session
    primary_subtype: set_search_path
    effects:
      - group: session
        subtype: set_search_path
        objects: [{ kind: guc, name: search_path }]
```

- [ ] **Step 7: Commit**

```bash
git add internal/db/classify/postgres/
git commit -m "classify/postgres: session/transaction AST mapping + ApplyStatement"
```

---

## Task 7: AST walk — DDL CREATE / ALTER / DROP / TRUNCATE (`ast_ddl.go`)

**Why:** §7.3's largest taxonomy block: the schema_create / schema_alter / schema_destroy verbs. The handler delegates per-target-kind so future spec additions slot in cleanly.

**Files:**
- Create: `internal/db/classify/postgres/ast_ddl.go`
- Create: `internal/db/classify/postgres/ast_ddl_test.go`
- Add corpus rows: CREATE TABLE / INDEX / VIEW / MATERIALIZED VIEW / SCHEMA / FUNCTION / EXTENSION / SEQUENCE / TYPE / DOMAIN / AGGREGATE / TRIGGER / DATABASE / PUBLICATION; ALTER TABLE / RENAME / COMMENT ON / ALTER PUBLICATION; DROP TABLE / SCHEMA / INDEX / VIEW / FUNCTION / SEQUENCE / TYPE / DOMAIN / AGGREGATE / TRIGGER / EXTENSION / DATABASE / PUBLICATION; TRUNCATE.

- [ ] **Step 1: Tests, in the same TDD pattern as Task 5/6 — write 4-6 representative cases first (`CREATE TABLE`, `CREATE INDEX`, `CREATE VIEW`, `ALTER TABLE`, `DROP TABLE`, `TRUNCATE`).**

- [ ] **Step 2: Implement handlers in `ast_ddl.go`.** Each handler follows the pattern:

```go
func classifyCreateTable(cs *effects.ClassifiedStatement, s *pg_query.CreateStmt, sess SessionState) {
	cs.RawVerb = "CREATE_TABLE"
	tgt, res := extractRelation(s.Relation, sess, effects.ObjectTable)
	cs.Effects = []effects.Effect{{
		Group:      effects.GroupSchemaCreate,
		Subtype:    effects.SubtypeCreateTable,
		Objects:    []effects.ObjectRef{tgt},
		Resolution: res,
	}}
}
```

Handlers needed (one per dispatcher case):

- `classifyCreateTable`, `classifyCreateIndex`, `classifyCreateView` (also handles materialized views via `s.WithCheck` / `s.View.Relpersistence`), `classifyCreateSchema`, `classifyCreateFunction`, `classifyCreateExtension`, `classifyCreateDatabase`, `classifyCreatePublication`.
- `classifyAlter` — dispatches on `AlterTableStmt.Objtype` (table / view / sequence / index) → schema_alter. RENAME and COMMENT ON map to `schema_alter` per §7.3.
- `classifyAlterPublication` → schema_alter, subtype `alter_publication`.
- `classifyDrop` — dispatches on `DropStmt.RemoveType` → schema_destroy with the right subtype (drop_table / drop_index / drop_view / drop_function / drop_schema / drop_publication / etc.). Subscriptions / servers / user mappings / tablespaces are handled in Task 9 (external).
- `classifyDropDatabase` → schema_destroy, subtype `drop_database`.
- `classifyTruncate` → schema_destroy, subtype `truncate`, with one ObjectRef per relation in `s.Relations`.

- [ ] **Step 3: Run unit tests + corpus.**

- [ ] **Step 4: Add ≥ 25 corpus rows covering the §7.3 DDL block** — file naming `0050-create-table.yaml` … `0080-truncate.yaml`. Each has the same shape as Task 5's examples.

- [ ] **Step 5: Cross-compile + commit.**

```bash
GOOS=windows go build ./...
git add internal/db/classify/postgres/
git commit -m "classify/postgres: DDL CREATE/ALTER/DROP/TRUNCATE mapping + corpus"
```

---

## Task 8: AST walk — privilege (`ast_privilege.go`)

**Why:** §7.3's privilege block. Disambiguates from `schema_alter` per §20 ("ALTER SYSTEM asserts privilege subtype alter_system, not schema_alter").

**Files:**
- Create: `internal/db/classify/postgres/ast_privilege.go`
- Create: `internal/db/classify/postgres/ast_privilege_test.go`
- Add corpus rows: `GRANT`, `REVOKE`, `CREATE ROLE`, `ALTER ROLE`, `DROP ROLE`, `ALTER SYSTEM SET …`, `SECURITY LABEL FOR provider ON COLUMN tab.col IS 'classified'`.

- [ ] **Steps 1-3: TDD per Task 5 pattern.**

Handlers:

```go
func classifyGrant(cs *effects.ClassifiedStatement, s *pg_query.GrantStmt) {
	cs.RawVerb = "GRANT"
	if !s.IsGrant {
		cs.RawVerb = "REVOKE"
	}
	cs.Effects = []effects.Effect{{
		Group:   effects.GroupPrivilege,
		Subtype: effects.SubtypeGrant, // SubtypeRevoke when !IsGrant — both map to spec subtype "grant_or_revoke"; use SubtypeGrant for now and tighten when subtype taxonomy supports it
	}}
}
func classifyGrantRole(cs *effects.ClassifiedStatement, s *pg_query.GrantRoleStmt) {
	cs.RawVerb = "GRANT_ROLE"
	cs.Effects = []effects.Effect{{Group: effects.GroupPrivilege, Subtype: effects.SubtypeGrant}}
}
func classifyCreateRole(cs *effects.ClassifiedStatement, s *pg_query.CreateRoleStmt) {
	cs.RawVerb = "CREATE_ROLE"
	cs.Effects = []effects.Effect{{
		Group:   effects.GroupPrivilege,
		Subtype: effects.SubtypeCreateRole,
		Objects: []effects.ObjectRef{{Kind: effects.ObjectRole, Name: strings.ToLower(s.Role)}},
	}}
}
func classifyAlterRole(cs *effects.ClassifiedStatement, s *pg_query.AlterRoleStmt) { … }
func classifyDropRole(cs *effects.ClassifiedStatement, s *pg_query.DropRoleStmt) { … }
func classifyAlterSystem(cs *effects.ClassifiedStatement, s *pg_query.AlterSystemStmt) {
	cs.RawVerb = "ALTER_SYSTEM"
	cs.Effects = []effects.Effect{{
		Group:   effects.GroupPrivilege,
		Subtype: effects.SubtypeAlterSystem,
	}}
}
func classifySecurityLabel(cs *effects.ClassifiedStatement, s *pg_query.SecLabelStmt) {
	cs.RawVerb = "SECURITY_LABEL"
	cs.Effects = []effects.Effect{{Group: effects.GroupPrivilege, Subtype: effects.SubtypeSecurityLabel}}
}
```

If `effects.SubtypeRevoke` doesn't exist, add it to `internal/db/effects/subtype.go` in this task and update `subtype_test.go` to recognize it.

- [ ] **Step 4: Add ≥ 8 corpus rows**, including the §20 disambiguation cases.

- [ ] **Step 5: Commit.**

```bash
git add internal/db/effects internal/db/classify/postgres/
git commit -m "classify/postgres: privilege AST mapping + corpus"
```

---

## Task 9: AST walk — COPY variants (`ast_copy.go`)

**Why:** COPY is the most effect-rich §7.3 family — `unsafe_io` + `bulk_load`/`bulk_export` + inner read on `COPY (SELECT) TO`. Per-row attribution is non-trivial.

**Files:**
- Create: `internal/db/classify/postgres/ast_copy.go`
- Create: `internal/db/classify/postgres/ast_copy_test.go`
- Add corpus rows: `COPY t TO STDOUT`, `COPY t FROM STDIN`, `COPY t TO '/path'`, `COPY t FROM '/path'`, `COPY t TO PROGRAM 'cmd'`, `COPY t FROM PROGRAM 'cmd'`, `COPY (SELECT) TO STDOUT`, `COPY (DELETE FROM u RETURNING *) TO STDOUT` (effect-set bypass case).

- [ ] **Steps 1-3: TDD per Task 5 pattern.**

Handler outline:

```go
func classifyCopy(cs *effects.ClassifiedStatement, s *pg_query.CopyStmt, sess SessionState, opts Options) {
	cs.RawVerb = "COPY"
	isFrom := s.IsFrom
	hasFile := s.Filename != "" && !s.IsProgram
	hasProgram := s.Filename != "" && s.IsProgram

	switch {
	case s.Relation != nil && hasProgram && !isFrom:
		// COPY t TO PROGRAM 'cmd'
		appendCopyEffects(cs, s, sess, effects.SubtypeCopyToProgram, effects.GroupBulkExport, "TO_PROGRAM")
	case s.Relation != nil && hasProgram && isFrom:
		appendCopyEffects(cs, s, sess, effects.SubtypeCopyFromProgram, effects.GroupBulkLoad, "FROM_PROGRAM")
	case s.Relation != nil && hasFile && !isFrom:
		appendCopyEffects(cs, s, sess, effects.SubtypeCopyToPath, effects.GroupBulkExport, "TO_PATH")
	case s.Relation != nil && hasFile && isFrom:
		appendCopyEffects(cs, s, sess, effects.SubtypeCopyFromPath, effects.GroupBulkLoad, "FROM_PATH")
	case s.Relation != nil && !isFrom:
		appendCopyStdoutEffects(cs, s, sess)
	case s.Relation != nil && isFrom:
		// COPY t FROM STDIN
		obj, res := extractRelation(s.Relation, sess, effects.ObjectTable)
		cs.RawVerb = "COPY_FROM_STDIN"
		cs.Effects = []effects.Effect{{
			Group:      effects.GroupBulkLoad,
			Subtype:    effects.SubtypeCopyFromStdin,
			Objects:    []effects.ObjectRef{obj},
			Resolution: res,
		}}
	case s.Query != nil:
		// COPY (<query>) TO STDOUT
		appendCopyQueryEffects(cs, s, sess, opts)
	default:
		cs.Effects = []effects.Effect{{Group: effects.GroupUnknown}}
		cs.Error = "unmapped form: COPY shape not recognized"
	}
}

func appendCopyEffects(cs *effects.ClassifiedStatement, s *pg_query.CopyStmt, sess SessionState, sub effects.Subtype, sec effects.Group, suffix string) {
	cs.RawVerb = "COPY_" + suffix
	tgt, tgtRes := extractRelation(s.Relation, sess, effects.ObjectTable)
	pathObj := effects.ObjectRef{Kind: effects.ObjectFilesystemPath, Path: s.Filename}
	progObj := effects.ObjectRef{Kind: effects.ObjectProgram, Argv0: firstWhitespaceToken(s.Filename)}
	primaryObjs := []effects.ObjectRef{tgt}
	if sub == effects.SubtypeCopyToPath || sub == effects.SubtypeCopyFromPath {
		primaryObjs = append(primaryObjs, pathObj)
	}
	if sub == effects.SubtypeCopyToProgram || sub == effects.SubtypeCopyFromProgram {
		primaryObjs = append(primaryObjs, progObj)
	}
	cs.Effects = append(cs.Effects, effects.Effect{
		Group:      effects.GroupUnsafeIO,
		Subtype:    sub,
		Objects:    primaryObjs,
		Resolution: tgtRes,
	})
	cs.Effects = append(cs.Effects, effects.Effect{
		Group:      sec,
		Objects:    []effects.ObjectRef{tgt},
		Resolution: tgtRes,
	})
	if sec == effects.GroupBulkExport {
		// TO PATH / TO PROGRAM also produces a read of the target table per Appendix B.
		cs.Effects = append(cs.Effects, effects.Effect{
			Group:      effects.GroupRead,
			Objects:    []effects.ObjectRef{tgt},
			Resolution: tgtRes,
		})
	}
}

func appendCopyStdoutEffects(cs *effects.ClassifiedStatement, s *pg_query.CopyStmt, sess SessionState) {
	cs.RawVerb = "COPY_TO_STDOUT"
	tgt, res := extractRelation(s.Relation, sess, effects.ObjectTable)
	cs.Effects = []effects.Effect{
		{Group: effects.GroupBulkExport, Subtype: effects.SubtypeCopyToStdout, Objects: []effects.ObjectRef{tgt}, Resolution: res},
		{Group: effects.GroupRead, Objects: []effects.ObjectRef{tgt}, Resolution: res},
	}
}

func appendCopyQueryEffects(cs *effects.ClassifiedStatement, s *pg_query.CopyStmt, sess SessionState, opts Options) {
	cs.RawVerb = "COPY_QUERY_TO_STDOUT"
	cs.Effects = append(cs.Effects, effects.Effect{
		Group:   effects.GroupBulkExport,
		Subtype: effects.SubtypeCopyToStdout,
	})
	if s.Query == nil {
		return
	}
	inner := classifyRawStmt(DialectPostgres, &pg_query.RawStmt{Stmt: s.Query}, sess, opts, cs.ParserBackend)
	for _, e := range inner.Effects {
		// Inner DELETE/UPDATE/INSERT inside COPY (...) TO STDOUT keeps its
		// effect — this is the §20 effect-set bypass case.
		cs.Effects = append(cs.Effects, e)
	}
}

func firstWhitespaceToken(s string) string {
	for i, r := range s {
		if r == ' ' || r == '\t' || r == '\n' {
			return s[:i]
		}
	}
	return s
}
```

If `effects.SubtypeCopyToPath` / `SubtypeCopyFromPath` / `SubtypeCopyToProgram` / `SubtypeCopyFromProgram` are not yet defined in `internal/db/effects/subtype.go`, add them in this task and extend `subtype_test.go`.

- [ ] **Step 4: Add corpus rows** — including the §20 effect-set bypass case `COPY (DELETE FROM u RETURNING *) TO STDOUT` and verifying its expected_decision under the sample policy is `deny` per §20.

- [ ] **Step 5: Commit.**

---

## Task 10: AST walk — external-IO DDL + libpq connstring parser (`ast_external.go`, `connstring.go`)

**Why:** SUBSCRIPTION / SERVER / USER MAPPING / TABLESPACE LOCATION are the §5.4 R23 "CREATE-not-INSERT" callout and Appendix B's external-connectivity DDL. Connection-string parsing surfaces the `external_endpoint{host, port}` object the policy engine matches on.

**Files:**
- Create: `internal/db/classify/postgres/ast_external.go`
- Create: `internal/db/classify/postgres/connstring.go`
- Create: `internal/db/classify/postgres/connstring_test.go`
- Create: `internal/db/classify/postgres/ast_external_test.go`
- Add corpus rows: CREATE/ALTER/DROP SUBSCRIPTION; CREATE/ALTER SERVER; CREATE/ALTER/DROP USER MAPPING; CREATE TABLESPACE LOCATION; ALTER TABLESPACE … SET LOCATION.

- [ ] **Step 1-3: connstring.go**

```go
package postgres

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// libpqConn extracts host and port from a libpq connection string.
// Accepts both keyword-value ("host=foo port=5432") and URI ("postgresql://...")
// forms per spec §7.3 CREATE SUBSCRIPTION row. Returns ("", 0) on failure
// rather than an error — partial extraction is acceptable; the policy engine
// matches on whatever fields are populated.
func libpqConn(s string) (host string, port int) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0
	}
	if strings.HasPrefix(s, "postgresql://") || strings.HasPrefix(s, "postgres://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", 0
		}
		host = u.Hostname()
		if p := u.Port(); p != "" {
			if n, err := strconv.Atoi(p); err == nil {
				port = n
			}
		}
		return
	}
	// Keyword-value. Split on whitespace except inside single-quoted values.
	for _, kv := range splitKeywordValue(s) {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(kv[:eq]))
		val := strings.TrimSpace(kv[eq+1:])
		val = strings.Trim(val, `'`)
		switch key {
		case "host":
			host = val
		case "port":
			if n, err := strconv.Atoi(val); err == nil {
				port = n
			}
		}
	}
	return
}

// splitKeywordValue splits a libpq keyword-value string into space-separated
// tokens, respecting single quotes around values.
func splitKeywordValue(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && (i == 0 || s[i-1] != '\\'):
			inQuote = !inQuote
			cur.WriteByte(c)
		case (c == ' ' || c == '\t') && !inQuote:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// _ ensures `fmt` is used (helpful when extending with debug logging).
var _ = fmt.Sprintf
```

Tests cover both forms with edge cases (escaped quotes, multi-host `host=a,b`, missing port).

- [ ] **Step 4: ast_external.go** handlers — each pulls the connection string from the relevant DefElem and builds an `external_endpoint` object alongside the named subscription/server/user_mapping/tablespace.

- [ ] **Step 5: Add corpus rows** including §20's `CREATE SUBSCRIPTION` row that asserts primary `unsafe_io`, secondary `schema_create`, and the external_endpoint object populated from the conn string.

- [ ] **Step 6: Commit.**

---

## Task 11: AST walk — unsafe-IO function calls (`ast_unsafe_io.go`)

**Why:** Appendix B's function-call surface: `pg_read_file`, `pg_read_binary_file`, `pg_ls_*`, `pg_stat_file`, `lo_import`, `lo_export`, `dblink*`, `xml2`/`pgxml` URL-fetch, FDW relation access. These appear in any expression position — projection, WHERE, COPY query, CTE — so the walker is recursive and additive (calls `appendUnsafeIO` from DML / COPY / SELECT_INTO handlers).

**Files:**
- Create: `internal/db/classify/postgres/ast_unsafe_io.go`
- Create: `internal/db/classify/postgres/ast_unsafe_io_test.go`
- Replace the stub `appendUnsafeIO` from Task 5.
- Add corpus rows: every Appendix B function family.

- [ ] **Step 1: TDD per Task 5 pattern.** Tests confirm a `SELECT pg_read_file('/etc/passwd')` adds an `unsafe_io` effect with `filesystem_path{path: "/etc/passwd"}`.

- [ ] **Step 2: Handler:**

```go
package postgres

import (
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"

	"github.com/agentsh/agentsh/internal/db/effects"
)

var unsafeIOFunctions = map[string]effects.Subtype{
	"pg_read_file":         effects.SubtypeServerFileRead,
	"pg_read_binary_file":  effects.SubtypeServerFileRead,
	"pg_ls_dir":            effects.SubtypeServerFileRead,
	"pg_ls_logdir":         effects.SubtypeServerFileRead,
	"pg_ls_waldir":         effects.SubtypeServerFileRead,
	"pg_stat_file":         effects.SubtypeServerFileRead,
	"lo_import":            effects.SubtypeLargeObjectIO,
	"lo_export":            effects.SubtypeLargeObjectIO,
	"dblink":               effects.SubtypeDBLinkCall,
	"dblink_exec":          effects.SubtypeDBLinkCall,
	"dblink_open":          effects.SubtypeDBLinkCall,
	"dblink_send_query":    effects.SubtypeDBLinkCall,
}

func appendUnsafeIO(cs *effects.ClassifiedStatement, n interface{}, sess SessionState) {
	walkUnsafe(n, func(name string, args []*pg_query.Node) {
		sub, ok := unsafeIOFunctions[strings.ToLower(name)]
		if !ok {
			return
		}
		obj := pathFromFirstStringArg(args)
		cs.Effects = append(cs.Effects, effects.Effect{
			Group:   effects.GroupUnsafeIO,
			Subtype: sub,
			Objects: []effects.ObjectRef{obj},
		})
	})
}

func walkUnsafe(n interface{}, visit func(string, []*pg_query.Node)) {
	// Reflective walk over the protobuf AST is impractical; instead, dispatch
	// over the SelectStmt / SubLink / FuncCall / etc. nodes the parser emits.
	// Implement breadth-first using a stack of *pg_query.Node, expanding
	// one-of variants as encountered. Helper at end of file.
}

func pathFromFirstStringArg(args []*pg_query.Node) effects.ObjectRef {
	if len(args) == 0 {
		return effects.ObjectRef{Kind: effects.ObjectFilesystemPath}
	}
	if a, ok := args[0].Node.(*pg_query.Node_AConst); ok && a.AConst != nil {
		if sval, ok := a.AConst.Val.(*pg_query.A_Const_Sval); ok {
			return effects.ObjectRef{Kind: effects.ObjectFilesystemPath, Path: sval.Sval.Sval}
		}
	}
	return effects.ObjectRef{Kind: effects.ObjectFilesystemPath} // unknown_dynamic — empty path
}

// walkUnsafe stack-based recursion expanded:
// (full implementation: walk each Node variant we know about — SelectStmt,
// FuncCall, A_Expr, RangeFunction, ResTarget, etc. — pushing children onto
// a worklist. Stop at leaf types.)
```

The walker implementation enumerates pg_query Node variants explicitly. If you find this list grows quickly, switch to `pg_query.Walk` (provided by pg_query_go) which visits all nodes via reflection — call `Walk` with a visitor that filters for `FuncCall` and forwards to `visit`.

If `effects.SubtypeServerFileRead`, `SubtypeLargeObjectIO`, `SubtypeDBLinkCall` don't already exist in subtype.go, add them in this task.

- [ ] **Step 3: Wire the FDW detection.** Foreign-table reference in a FROM clause (relation backed by a `FOREIGN DATA WRAPPER`) classifies the verb's primary group as the original verb plus `unsafe_io` secondary per Appendix B. Phase 1 implementation: skip — Phase 1 has no catalog access. Document this gap inline as a `// TODO Phase 2: catalog-aware FDW detection` and let corpus rows that need it stay in the open-questions list. (This is consistent with the spec's "best-effort" framing.)

- [ ] **Step 4: Add corpus rows** for each function family in Appendix B.

- [ ] **Step 5: Commit.**

---

## Task 12: AST walk — misc (`ast_misc.go`)

**Why:** CALL / DO / anonymous block; VACUUM / ANALYZE / REINDEX / CLUSTER / CHECKPOINT (maintenance); LOCK; LISTEN / NOTIFY / UNLISTEN.

**Files:**
- Create: `internal/db/classify/postgres/ast_misc.go`
- Create: `internal/db/classify/postgres/ast_misc_test.go`
- Add corpus rows: CALL, DO $$ block $$, VACUUM, ANALYZE, REINDEX, CLUSTER, CHECKPOINT, LOCK TABLE, LISTEN, NOTIFY, UNLISTEN.

Per Task 5 pattern. Handlers are direct: each maps to a single Effect with the right Group/Subtype.

```go
func classifyCall(cs *effects.ClassifiedStatement, s *pg_query.CallStmt) {
	cs.RawVerb = "CALL"
	cs.Effects = []effects.Effect{{Group: effects.GroupProcedural, Subtype: effects.SubtypeCall}}
}
func classifyDo(cs *effects.ClassifiedStatement, s *pg_query.DoStmt) {
	cs.RawVerb = "DO"
	cs.Effects = []effects.Effect{{Group: effects.GroupProcedural, Subtype: effects.SubtypeDoOrAnon}}
}
func classifyMaintenance(cs *effects.ClassifiedStatement, s *pg_query.VacuumStmt) {
	cs.RawVerb = "VACUUM_OR_ANALYZE"
	cs.Effects = []effects.Effect{{Group: effects.GroupMaintenance}}
}
func classifyReindex(cs *effects.ClassifiedStatement, s *pg_query.ReindexStmt) {
	cs.RawVerb = "REINDEX"
	cs.Effects = []effects.Effect{{Group: effects.GroupMaintenance}}
}
func classifyCluster(cs *effects.ClassifiedStatement, s *pg_query.ClusterStmt) {
	cs.RawVerb = "CLUSTER"
	cs.Effects = []effects.Effect{{Group: effects.GroupMaintenance}}
}
func classifyCheckpoint(cs *effects.ClassifiedStatement) {
	cs.RawVerb = "CHECKPOINT"
	cs.Effects = []effects.Effect{{Group: effects.GroupMaintenance}}
}
func classifyLock(cs *effects.ClassifiedStatement, s *pg_query.LockStmt, sess SessionState) {
	cs.RawVerb = "LOCK"
	objs, _ := walkRangeRelations(s.Relations, sess)
	cs.Effects = []effects.Effect{{Group: effects.GroupLock, Objects: objs}}
}
func classifyNotify(cs *effects.ClassifiedStatement, n *pg_query.Node) {
	cs.RawVerb = "LISTEN_OR_NOTIFY"
	cs.Effects = []effects.Effect{{Group: effects.GroupNotify}}
}
```

- [ ] **Steps and commit per the established pattern.**

---

## Task 13: §7.6 escalation knob (`escalation.go`)

**Why:** Operators who set `EscalateUnknownFunctions: true` opt into reclassifying `SELECT volatile_function()` as `procedural`. The allowlist controls noise level. Plan 03 owns the classifier-side knob; runtime config wiring is Plan 04+.

**Files:**
- Create: `internal/db/classify/postgres/escalation.go`
- Create: `internal/db/classify/postgres/escalation_test.go`
- Add corpus rows: `SELECT now()` with `escalate_unknown_functions: true` (allowed via allowlist), `SELECT my_func()` with same opts (escalates).

- [ ] **Step 1-3: TDD for `collectFuncCallsAny(*SelectStmt, allow) bool`** — true if the statement contains any FuncCall whose canonical-lowercase name is NOT in `allow`.

```go
package postgres

import (
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// collectFuncCallsAny returns true if the SelectStmt contains any FuncCall whose
// canonical lowercase name (schema-qualified if the FuncName has multiple parts)
// is NOT in allow.
func collectFuncCallsAny(s *pg_query.SelectStmt, allow map[string]struct{}) bool {
	if s == nil {
		return false
	}
	found := false
	walkFuncCalls(s, func(name string) {
		if _, ok := allow[name]; !ok {
			found = true
		}
	})
	return found
}

func walkFuncCalls(node interface{}, visit func(string)) {
	// Stack-based walk over relevant pg_query Node variants. See ast_unsafe_io.go's
	// walker for the same shape; share the helper if possible.
}

// canonicalFuncName returns "schema.name" if the FuncName list has two parts
// (typed as String_ values), otherwise the lowercase single name.
func canonicalFuncName(parts []*pg_query.Node) string {
	if len(parts) == 0 {
		return ""
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s, ok := p.Node.(*pg_query.Node_String_); ok && s.String_ != nil {
			out = append(out, strings.ToLower(s.String_.Sval))
		}
	}
	return strings.Join(out, ".")
}
```

If walking via reflection helpers from pg_query_go is awkward, share a single AST walker between `ast_unsafe_io.go` and `escalation.go` — both walk the same node space looking for `FuncCall`.

- [ ] **Step 4: Update `classifySelect`** to call `collectFuncCallsAny` (already wired in Task 5; replace the stub return value with the real implementation).

- [ ] **Step 5: Add corpus rows. Commit.**

---

## Task 14: Redshift first-keyword fallback (`redshift.go`)

**Why:** Redshift dialect's `UNLOAD` and S3-source `COPY FROM` are not recognized by libpg_query. §7.7 specifies a first-keyword fallback. Phase 1 minimum: classify these two cases per §7.3; everything else falls through to `unknown`.

**Files:**
- Create: `internal/db/classify/postgres/redshift.go`
- Create: `internal/db/classify/postgres/redshift_test.go`
- Add corpus rows with `dialect: redshift`: `UNLOAD ('SELECT *') TO 's3://bucket/key' …`, `COPY t FROM 's3://bucket/key' …`, plus a deliberate parse-failure that should produce `unknown`.

- [ ] **Step 1-3: TDD per Task 5 pattern.**

```go
package postgres

import (
	"regexp"
	"strings"

	"github.com/agentsh/agentsh/internal/db/effects"
)

var unloadRE = regexp.MustCompile(`(?is)^\s*UNLOAD\s*\(`)
var copyFromS3RE = regexp.MustCompile(`(?is)^\s*COPY\s+([^\s(]+)\s+FROM\s+'(s3://[^']+)'`)
var unloadToRE = regexp.MustCompile(`(?is)TO\s+'(s3://[^']+)'`)

// redshiftFirstKeyword is invoked from classifyWithBackend when libpg_query
// fails to parse a Redshift statement. Returns ok=false to mean "fall through
// to unknown".
func redshiftFirstKeyword(sql string, backend effects.ParserBackend) (effects.ClassifiedStatement, bool) {
	switch {
	case unloadRE.MatchString(sql):
		s3 := ""
		if m := unloadToRE.FindStringSubmatch(sql); len(m) == 2 {
			s3 = m[1]
		}
		cs := effects.ClassifiedStatement{
			RawVerb:       "UNLOAD",
			ParserBackend: backend,
			Effects: []effects.Effect{
				{Group: effects.GroupBulkExport, Subtype: effects.SubtypeUnloadToS3, Objects: []effects.ObjectRef{{Kind: effects.ObjectFilesystemPath, Path: s3}}},
				{Group: effects.GroupUnsafeIO, Objects: []effects.ObjectRef{{Kind: effects.ObjectFilesystemPath, Path: s3}}},
				{Group: effects.GroupRead},
			},
		}
		effects.Order(cs.Effects)
		return cs, true
	case copyFromS3RE.MatchString(sql):
		m := copyFromS3RE.FindStringSubmatch(sql)
		tbl := strings.ToLower(strings.TrimSpace(m[1]))
		s3 := m[2]
		cs := effects.ClassifiedStatement{
			RawVerb:       "COPY_FROM_S3",
			ParserBackend: backend,
			Effects: []effects.Effect{
				{
					Group:   effects.GroupBulkLoad,
					Subtype: effects.SubtypeCopyFromS3,
					Objects: []effects.ObjectRef{
						{Kind: effects.ObjectTable, Name: tbl},
						{Kind: effects.ObjectFilesystemPath, Path: s3},
					},
				},
			},
		}
		return cs, true
	}
	return effects.ClassifiedStatement{}, false
}
```

- [ ] **Step 4: Add corpus rows. Commit.**

---

## Task 15: `cmd/dbclassify-pg` — operator CLI

**Why:** Spec authors and operators need a way to round-trip SQL through the classifier and the sample policy without writing Go.

**Files:**
- Create: `cmd/dbclassify-pg/main.go`
- Create: `cmd/dbclassify-pg/main_test.go`

- [ ] **Step 1: Failing test — table-driven exercising flags + stdin.**

Use `os/exec`-style invocation via `exec.Command(os.Args[0], "--", flags…)` is awkward; instead, factor the CLI into a `run(args, stdin io.Reader, stdout io.Writer) error` so tests call `run` directly.

```go
package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun_SelectClassification(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"-dialect=postgres"}, strings.NewReader("SELECT 1"), &out)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out.String(), `"primary_group": "read"`) {
		t.Fatalf("output missing read primary_group: %s", out.String())
	}
}
```

- [ ] **Step 2: Implementation.**

Create `cmd/dbclassify-pg/main.go`:

```go
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/agentsh/agentsh/internal/db/classify/postgres"
	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("dbclassify-pg", flag.ContinueOnError)
	dialectStr := fs.String("dialect", "postgres", "postgres|aurora_postgres|cockroachdb|redshift")
	searchPath := fs.String("search-path", "", "comma-separated identifiers; default empty")
	tempTables := fs.String("temp-tables", "", "comma-separated unqualified names")
	escalate := fs.Bool("escalate-unknown-functions", false, "§7.6 knob")
	noEvaluate := fs.Bool("no-evaluate", false, "skip sample-policy decision")
	if err := fs.Parse(args); err != nil {
		return err
	}

	d, ok := postgres.ParseDialect(*dialectStr)
	if !ok {
		return fmt.Errorf("unknown dialect: %q", *dialectStr)
	}

	sql, err := io.ReadAll(stdin)
	if err != nil {
		return err
	}

	sess := postgres.SessionState{}
	if *searchPath != "" {
		for _, p := range strings.Split(*searchPath, ",") {
			sess.SearchPath = append(sess.SearchPath, strings.ToLower(strings.TrimSpace(p)))
		}
	}
	if *tempTables != "" {
		sess.TempTables = make(map[string]struct{})
		for _, n := range strings.Split(*tempTables, ",") {
			sess.TempTables[strings.ToLower(strings.TrimSpace(n))] = struct{}{}
		}
	}
	opts := postgres.Options{EscalateUnknownFunctions: *escalate}

	stmts, err := postgres.New(d).Classify(string(sql), sess, opts)
	if err != nil {
		return err
	}

	type stmtOut struct {
		RawVerb                  string                          `json:"raw_verb,omitempty"`
		ParserBackend            string                          `json:"parser_backend,omitempty"`
		PrimaryGroup             string                          `json:"primary_group,omitempty"`
		Effects                  []effects.Effect                `json:"effects"`
		Error                    string                          `json:"error,omitempty"`
		DecisionUnderSamplePolicy *decisionOut                   `json:"decision_under_sample_policy,omitempty"`
	}

	out := struct {
		Dialect    string    `json:"dialect"`
		Statements []stmtOut `json:"statements"`
	}{Dialect: d.String()}

	var rs *policy.RuleSet
	if !*noEvaluate {
		rs = policy.MustLoadSample()
	}

	for _, s := range stmts {
		row := stmtOut{
			RawVerb:       s.RawVerb,
			ParserBackend: s.ParserBackend.String(),
			Effects:       s.Effects,
			Error:         s.Error,
		}
		if prim, ok := s.Primary(); ok {
			row.PrimaryGroup = prim.Group.String()
		}
		if rs != nil {
			dec := policy.Evaluate(s, rs, "appdb")
			row.DecisionUnderSamplePolicy = &decisionOut{
				Verb:     dec.Verb.String(),
				RuleName: dec.RuleName,
				Reason:   dec.Reason,
			}
		}
		out.Statements = append(out.Statements, row)
	}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

type decisionOut struct {
	Verb     string `json:"verb"`
	RuleName string `json:"rule_name,omitempty"`
	Reason   string `json:"reason,omitempty"`
}
```

- [ ] **Step 3: Run tests.**

```bash
go test ./cmd/dbclassify-pg/ -v
```

- [ ] **Step 4: Smoke-run on the command line.**

```bash
echo "SELECT * FROM customers" | go run ./cmd/dbclassify-pg
```

Expected: JSON with `primary_group: "read"` and a `decision_under_sample_policy.verb`.

- [ ] **Step 5: Cross-compile and commit.**

```bash
GOOS=windows go build ./cmd/dbclassify-pg
git add cmd/dbclassify-pg
git commit -m "cmd/dbclassify-pg: classifier + sample-policy CLI"
```

---

## Task 16: Backend-parity smoke test + bench

**Why:** §10 of the design doc — single CI gate proving CGO and WASM produce byte-identical classifications. Bench is informational, not a CI gate.

**Files:**
- Create: `internal/db/classify/postgres/parity_test.go`
- Create: `internal/db/classify/postgres/bench_test.go`

- [ ] **Step 1: Parity test.**

```go
//go:build linux && cgo

package postgres

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/db/classify/postgres/corpus"
)

// TestBackendParity runs the corpus under the active build (CGO when this
// file's tags select it) and shells out to a CGO_ENABLED=0 child to obtain
// the WASM-build outputs, then asserts JSON equality of the slices.
//
// Skipped on non-Linux because the WASM child needs the same toolchain.
func TestBackendParity(t *testing.T) {
	if testing.Short() {
		t.Skip("parity test runs the full corpus twice; -short skips")
	}

	rows, err := corpus.LoadAll("corpus")
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(rows) < 50 {
		t.Skipf("parity test wants ≥50 corpus rows; have %d", len(rows))
	}

	// Native (CGO) classifications.
	native := classifyAll(t, rows)

	// WASM child via "go test -run TestBackendParityChild -tags ..." with
	// CGO_ENABLED=0 inheriting the test binary's working directory. Implementation:
	// invoke `go run` against a small helper main that classifies the corpus
	// and prints JSON; or use go test -count=0 -run a sentinel test. Practical
	// choice: factor classifyAll into a public-test helper and have the parent
	// run a child process via `os/exec`.
	cmd := exec.Command("go", "test", "-tags", "wasmparity", "-run", "TestBackendParityWASMChild", "./internal/db/classify/postgres/")
	cmd.Env = append(append([]string{}, ofEnv()...), "CGO_ENABLED=0")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("WASM child: %v\n%s", err, out)
	}
	wasm := strings.TrimSpace(string(out))
	nativeJSON, _ := json.Marshal(native)
	if string(nativeJSON) != wasm {
		t.Fatalf("backend parity mismatch:\nnative=%s\nwasm=%s", nativeJSON, wasm)
	}
}

func ofEnv() []string {
	// passthrough current env minus CGO_ENABLED
	return []string{}
}
```

The straightforward path is two test binaries with different build tags; alternatively, run the corpus twice in-process using two pkg-level Parser instances if `wasilibs/go-pgquery` exposes a `New()` constructor independent of build tags. If the binding is build-tag-gated, the two-test-binary pattern above is mandatory.

For Phase 1, accept that the WASM child shell-out is platform-Linux-only and `t.Skip` elsewhere.

- [ ] **Step 2: Bench.**

```go
package postgres

import (
	"testing"
)

func BenchmarkClassify_50StatementMix(b *testing.B) {
	const sql = `SELECT * FROM customers; INSERT INTO audit_log VALUES (1); UPDATE users SET active = false WHERE id = 1; ...` // ~50 statements
	p := New(DialectPostgres)
	for i := 0; i < b.N; i++ {
		if _, err := p.Classify(sql, SessionState{}, Options{}); err != nil {
			b.Fatal(err)
		}
	}
}
```

Engineer fills in 50 representative statements covering every taxonomy bucket. Bench is informational only; not a CI gate.

- [ ] **Step 3: Commit.**

---

## Task 17: Final verification

**Files:** none new — full-repo checks.

- [ ] **Step 1: Run the entire test suite.**

```bash
go test ./...
```

Expected: PASS.

- [ ] **Step 2: Cross-compile.**

```bash
GOOS=windows go build ./...
GOOS=darwin go build ./...
CGO_ENABLED=0 GOOS=linux go build ./...
```

Expected: all clean.

- [ ] **Step 3: Lint / vet.**

```bash
go vet ./...
```

- [ ] **Step 4: Verify §20 corpus coverage.**

Count corpus rows by category and confirm ≥150 total with at least one row per §20 bullet:

```bash
ls internal/db/classify/postgres/corpus/*.yaml | wc -l
```

Expected: ≥ 150. If the count is lower, add rows to fill the §20 categories before commit.

- [ ] **Step 5: Run dbclassify-pg smoke.**

```bash
echo "INSERT INTO audit_log SELECT * FROM users" | go run ./cmd/dbclassify-pg
```

Expected: JSON with two effects (write, read), correct objects, decision per sample policy.

- [ ] **Step 6: Final commit (if any pending changes).**

```bash
git status
git commit -m "classify/postgres: Plan 03 final verification"
```

---

## Out-of-scope reminders (do NOT do in Plan 03)

- Wire framing, malformed-frame negative-path tests → Plan 04.
- PREPARE/EXECUTE wire-protocol cache → Plan 05.
- Extended Query / transaction state machine → Plan 05.
- COPY data-frame handling → Plan 05.
- DBEvent emission → Plan 04+.
- CancelRequest mapping → Plan 06.
- Catalog-aware resolution / view rewriting / FDW catalog detection → Phase 2/7.
- FunctionCall sub-protocol OID resolution → Phase 2.
- Statement-text redaction operation → Plan 04 (Plan 02 owns the config; Plan 03 doesn't touch the SQL string after parsing).

If a corpus row needs any of the above to pass, defer the row to the appropriate plan rather than reaching across a boundary.
