# DB Plan 08 Catalog Resolver Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a pure Postgres catalog resolver foundation for Phase 2 without changing runtime proxy behavior.

**Architecture:** Introduce `internal/db/catalog` as a platform-agnostic package. It owns catalog data types, a small query interface, snapshot loading from Postgres catalog rows, and deterministic name resolution against an explicit search path. Proxy integration is intentionally deferred to DB Plan 09.

**Tech Stack:** Go, `context`, `database/sql`-style row scanning interfaces, existing `internal/db/effects` object kinds.

---

## File Structure

- Create: `internal/db/catalog/types.go` - catalog identity types, relation/function structs, unresolved reason enum.
- Create: `internal/db/catalog/snapshot.go` - immutable snapshot indexes and lookup helpers.
- Create: `internal/db/catalog/postgres.go` - Postgres catalog SQL and loader using a tiny `Queryer` interface.
- Create: `internal/db/catalog/resolve.go` - relation and function resolution against a snapshot plus search path.
- Create: `internal/db/catalog/fake_test.go` - fake rows/queryer for loader tests.
- Create: `internal/db/catalog/types_test.go` - enum/string and canonical-name tests.
- Create: `internal/db/catalog/snapshot_test.go` - duplicate indexing and lookup tests.
- Create: `internal/db/catalog/postgres_test.go` - loader tests using fake query rows.
- Create: `internal/db/catalog/resolve_test.go` - qualified, unqualified, search-path, duplicate, and missing-object tests.
- Modify: `docs/superpowers/specs/2026-05-14-db-phase-2-roadmap-design.md` - mark Plan 08 complete after implementation.

---

## Task 1: Add Catalog Types

**Files:**
- Create: `internal/db/catalog/types.go`
- Create: `internal/db/catalog/types_test.go`

- [ ] **Step 1: Write enum and canonical-name tests**

Create `internal/db/catalog/types_test.go`:

```go
package catalog

import "testing"

func TestRelationKindString(t *testing.T) {
	tests := map[RelationKind]string{
		RelationTable:             "table",
		RelationPartitionedTable:  "partitioned_table",
		RelationView:              "view",
		RelationMaterializedView:  "materialized_view",
		RelationForeignTable:      "foreign_table",
		RelationSequence:          "sequence",
	}
	for kind, want := range tests {
		if got := kind.String(); got != want {
			t.Fatalf("RelationKind(%d).String() = %q, want %q", kind, got, want)
		}
	}
}

func TestCanonicalNameString(t *testing.T) {
	name := Name{Schema: "public", Name: "orders"}
	if got := name.String(); got != "public.orders" {
		t.Fatalf("Name.String() = %q", got)
	}
}

func TestUnresolvedReasonString(t *testing.T) {
	if got := UnresolvedMissing.String(); got != "missing" {
		t.Fatalf("UnresolvedMissing.String() = %q", got)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```bash
go test ./internal/db/catalog
```

Expected: FAIL because package `internal/db/catalog` does not exist.

- [ ] **Step 3: Add catalog type definitions**

Create `internal/db/catalog/types.go`:

```go
package catalog

import "fmt"

type OID uint32

type Name struct {
	Schema string
	Name   string
}

func (n Name) String() string {
	if n.Schema == "" {
		return n.Name
	}
	return fmt.Sprintf("%s.%s", n.Schema, n.Name)
}

type RelationKind uint8

const (
	RelationTable RelationKind = iota + 1
	RelationPartitionedTable
	RelationView
	RelationMaterializedView
	RelationForeignTable
	RelationSequence
)

func (k RelationKind) String() string {
	switch k {
	case RelationTable:
		return "table"
	case RelationPartitionedTable:
		return "partitioned_table"
	case RelationView:
		return "view"
	case RelationMaterializedView:
		return "materialized_view"
	case RelationForeignTable:
		return "foreign_table"
	case RelationSequence:
		return "sequence"
	default:
		return ""
	}
}

type FunctionVolatility uint8

const (
	VolatilityImmutable FunctionVolatility = iota + 1
	VolatilityStable
	VolatilityVolatile
)

type Column struct {
	Name     string
	TypeOID  OID
	NotNull  bool
	Position int
}

type Relation struct {
	OID     OID
	Name    Name
	Kind    RelationKind
	Owner   string
	Columns []Column
}

type Function struct {
	OID          OID
	Name         Name
	IdentityArgs string
	Volatility   FunctionVolatility
	Strict       bool
	ReturnTypeOID OID
}

type UnresolvedReason uint8

const (
	UnresolvedNone UnresolvedReason = iota
	UnresolvedMissing
	UnresolvedAmbiguous
	UnresolvedUnsupported
	UnresolvedCatalogError
)

func (r UnresolvedReason) String() string {
	switch r {
	case UnresolvedMissing:
		return "missing"
	case UnresolvedAmbiguous:
		return "ambiguous"
	case UnresolvedUnsupported:
		return "unsupported"
	case UnresolvedCatalogError:
		return "catalog_error"
	default:
		return ""
	}
}

type ResolvedRelation struct {
	Relation Relation
	Reason   UnresolvedReason
}

func (r ResolvedRelation) OK() bool {
	return r.Reason == UnresolvedNone
}
```

- [ ] **Step 4: Run the tests**

Run:

```bash
go test ./internal/db/catalog
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/catalog/types.go internal/db/catalog/types_test.go
git commit -m "db: add catalog identity types"
```

---

## Task 2: Build Snapshot Indexes

**Files:**
- Create: `internal/db/catalog/snapshot.go`
- Create: `internal/db/catalog/snapshot_test.go`

- [ ] **Step 1: Write snapshot lookup tests**

Create `internal/db/catalog/snapshot_test.go`:

```go
package catalog

import "testing"

func TestSnapshotRelationLookup(t *testing.T) {
	snap := NewSnapshot([]Relation{
		{OID: 10, Name: Name{Schema: "public", Name: "orders"}, Kind: RelationTable},
		{OID: 11, Name: Name{Schema: "audit", Name: "orders"}, Kind: RelationTable},
	}, nil)

	if rel, ok := snap.RelationByOID(10); !ok || rel.Name.String() != "public.orders" {
		t.Fatalf("RelationByOID(10) = %+v, %v", rel, ok)
	}
	if got := snap.RelationsByUnqualifiedName("orders"); len(got) != 2 {
		t.Fatalf("RelationsByUnqualifiedName returned %d candidates, want 2", len(got))
	}
	if rel, ok := snap.RelationByName(Name{Schema: "audit", Name: "orders"}); !ok || rel.OID != 11 {
		t.Fatalf("RelationByName(audit.orders) = %+v, %v", rel, ok)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```bash
go test ./internal/db/catalog
```

Expected: FAIL because `NewSnapshot` is undefined.

- [ ] **Step 3: Add immutable snapshot indexes**

Create `internal/db/catalog/snapshot.go`:

```go
package catalog

type Snapshot struct {
	relationsByOID   map[OID]Relation
	relationsByName  map[Name]Relation
	relationsByBare  map[string][]Relation
	functionsByOID   map[OID]Function
	functionsByName   map[Name][]Function
}

func NewSnapshot(relations []Relation, functions []Function) Snapshot {
	s := Snapshot{
		relationsByOID:  make(map[OID]Relation, len(relations)),
		relationsByName: make(map[Name]Relation, len(relations)),
		relationsByBare: make(map[string][]Relation, len(relations)),
		functionsByOID:  make(map[OID]Function, len(functions)),
		functionsByName:  make(map[Name][]Function, len(functions)),
	}
	for _, rel := range relations {
		s.relationsByOID[rel.OID] = rel
		s.relationsByName[rel.Name] = rel
		s.relationsByBare[rel.Name.Name] = append(s.relationsByBare[rel.Name.Name], rel)
	}
	for _, fn := range functions {
		s.functionsByOID[fn.OID] = fn
		s.functionsByName[fn.Name] = append(s.functionsByName[fn.Name], fn)
	}
	return s
}

func (s Snapshot) RelationByOID(oid OID) (Relation, bool) {
	rel, ok := s.relationsByOID[oid]
	return rel, ok
}

func (s Snapshot) RelationByName(name Name) (Relation, bool) {
	rel, ok := s.relationsByName[name]
	return rel, ok
}

func (s Snapshot) RelationsByUnqualifiedName(name string) []Relation {
	in := s.relationsByBare[name]
	out := make([]Relation, len(in))
	copy(out, in)
	return out
}

func (s Snapshot) FunctionByOID(oid OID) (Function, bool) {
	fn, ok := s.functionsByOID[oid]
	return fn, ok
}

func (s Snapshot) FunctionsByName(name Name) []Function {
	in := s.functionsByName[name]
	out := make([]Function, len(in))
	copy(out, in)
	return out
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/db/catalog
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/catalog/snapshot.go internal/db/catalog/snapshot_test.go
git commit -m "db: index catalog snapshots"
```

---

## Task 3: Load Postgres Catalog Rows

**Files:**
- Create: `internal/db/catalog/postgres.go`
- Create: `internal/db/catalog/fake_test.go`
- Create: `internal/db/catalog/postgres_test.go`

- [ ] **Step 1: Write loader tests**

Create `internal/db/catalog/postgres_test.go`:

```go
package catalog

import (
	"context"
	"testing"
)

func TestLoadPostgresSnapshotLoadsRelationsAndFunctions(t *testing.T) {
	q := fakeQueryer{
		relations: [][]any{
			{uint32(10), "public", "orders", "r", "app"},
		},
		functions: [][]any{
			{uint32(20), "public", "calculate_total", "integer", "s", true, uint32(23)},
		},
	}
	snap, err := LoadPostgresSnapshot(context.Background(), q)
	if err != nil {
		t.Fatalf("LoadPostgresSnapshot: %v", err)
	}
	rel, ok := snap.RelationByName(Name{Schema: "public", Name: "orders"})
	if !ok || rel.OID != 10 || rel.Kind != RelationTable {
		t.Fatalf("loaded relation = %+v, %v", rel, ok)
	}
	fn, ok := snap.FunctionByOID(20)
	if !ok || fn.Volatility != VolatilityStable || !fn.Strict {
		t.Fatalf("loaded function = %+v, %v", fn, ok)
	}
}
```

- [ ] **Step 2: Add fake query rows**

Create `internal/db/catalog/fake_test.go`:

```go
package catalog

import (
	"context"
	"fmt"
	"strings"
)

type fakeQueryer struct {
	relations [][]any
	functions [][]any
}

func (q fakeQueryer) Query(ctx context.Context, sql string, args ...any) (Rows, error) {
	switch {
	case strings.Contains(sql, "pg_catalog.pg_class"):
		return &fakeRows{rows: q.relations}, nil
	case strings.Contains(sql, "pg_catalog.pg_proc"):
		return &fakeRows{rows: q.functions}, nil
	default:
		return nil, fmt.Errorf("unexpected query: %s", sql)
	}
}

type fakeRows struct {
	rows [][]any
	idx  int
}

func (r *fakeRows) Next() bool {
	return r.idx < len(r.rows)
}

func (r *fakeRows) Scan(dest ...any) error {
	if r.idx >= len(r.rows) {
		return fmt.Errorf("scan past end")
	}
	row := r.rows[r.idx]
	r.idx++
	if len(row) != len(dest) {
		return fmt.Errorf("scan got %d dests, want %d", len(dest), len(row))
	}
	for i := range row {
		switch d := dest[i].(type) {
		case *uint32:
			*d = row[i].(uint32)
		case *string:
			*d = row[i].(string)
		case *bool:
			*d = row[i].(bool)
		default:
			return fmt.Errorf("unsupported dest %T", dest[i])
		}
	}
	return nil
}

func (r *fakeRows) Close() error { return nil }
func (r *fakeRows) Err() error   { return nil }
```

- [ ] **Step 3: Run the tests to verify they fail**

Run:

```bash
go test ./internal/db/catalog
```

Expected: FAIL because `LoadPostgresSnapshot` and `Rows` are undefined.

- [ ] **Step 4: Add Postgres loader**

Create `internal/db/catalog/postgres.go`:

```go
package catalog

import (
	"context"
	"fmt"
)

type Queryer interface {
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
}

type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Close() error
	Err() error
}

const relationSQL = `
select c.oid::int4, n.nspname, c.relname, c.relkind::text, pg_get_userbyid(c.relowner)
from pg_catalog.pg_class c
join pg_catalog.pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r', 'p', 'v', 'm', 'f', 'S')
  and n.nspname not like 'pg_toast%'
order by n.nspname, c.relname`

const functionSQL = `
select p.oid::int4, n.nspname, p.proname,
       pg_catalog.pg_get_function_identity_arguments(p.oid),
       p.provolatile::text, p.proisstrict, p.prorettype::int4
from pg_catalog.pg_proc p
join pg_catalog.pg_namespace n on n.oid = p.pronamespace
where n.nspname not like 'pg_toast%'
order by n.nspname, p.proname, p.oid`

func LoadPostgresSnapshot(ctx context.Context, q Queryer) (Snapshot, error) {
	relations, err := loadRelations(ctx, q)
	if err != nil {
		return Snapshot{}, err
	}
	functions, err := loadFunctions(ctx, q)
	if err != nil {
		return Snapshot{}, err
	}
	return NewSnapshot(relations, functions), nil
}

func loadRelations(ctx context.Context, q Queryer) ([]Relation, error) {
	rows, err := q.Query(ctx, relationSQL)
	if err != nil {
		return nil, fmt.Errorf("query relations: %w", err)
	}
	defer rows.Close()
	var out []Relation
	for rows.Next() {
		var oid uint32
		var schema, name, relkind, owner string
		if err := rows.Scan(&oid, &schema, &name, &relkind, &owner); err != nil {
			return nil, fmt.Errorf("scan relation: %w", err)
		}
		kind, ok := parseRelationKind(relkind)
		if !ok {
			continue
		}
		out = append(out, Relation{OID: OID(oid), Name: Name{Schema: schema, Name: name}, Kind: kind, Owner: owner})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate relations: %w", err)
	}
	return out, nil
}

func loadFunctions(ctx context.Context, q Queryer) ([]Function, error) {
	rows, err := q.Query(ctx, functionSQL)
	if err != nil {
		return nil, fmt.Errorf("query functions: %w", err)
	}
	defer rows.Close()
	var out []Function
	for rows.Next() {
		var oid, ret uint32
		var schema, name, args, volatility string
		var strict bool
		if err := rows.Scan(&oid, &schema, &name, &args, &volatility, &strict, &ret); err != nil {
			return nil, fmt.Errorf("scan function: %w", err)
		}
		vol, ok := parseVolatility(volatility)
		if !ok {
			continue
		}
		out = append(out, Function{
			OID: OID(oid), Name: Name{Schema: schema, Name: name}, IdentityArgs: args,
			Volatility: vol, Strict: strict, ReturnTypeOID: OID(ret),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate functions: %w", err)
	}
	return out, nil
}

func parseRelationKind(s string) (RelationKind, bool) {
	switch s {
	case "r":
		return RelationTable, true
	case "p":
		return RelationPartitionedTable, true
	case "v":
		return RelationView, true
	case "m":
		return RelationMaterializedView, true
	case "f":
		return RelationForeignTable, true
	case "S":
		return RelationSequence, true
	default:
		return 0, false
	}
}

func parseVolatility(s string) (FunctionVolatility, bool) {
	switch s {
	case "i":
		return VolatilityImmutable, true
	case "s":
		return VolatilityStable, true
	case "v":
		return VolatilityVolatile, true
	default:
		return 0, false
	}
}
```

- [ ] **Step 5: Run tests**

Run:

```bash
go test ./internal/db/catalog
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/db/catalog/postgres.go internal/db/catalog/fake_test.go internal/db/catalog/postgres_test.go
git commit -m "db: load postgres catalog snapshots"
```

---

## Task 4: Resolve Relations Against Search Path

**Files:**
- Create: `internal/db/catalog/resolve.go`
- Create: `internal/db/catalog/resolve_test.go`

- [ ] **Step 1: Write relation resolver tests**

Create `internal/db/catalog/resolve_test.go`:

```go
package catalog

import "testing"

func TestResolveQualifiedRelation(t *testing.T) {
	snap := NewSnapshot([]Relation{{OID: 10, Name: Name{Schema: "public", Name: "orders"}, Kind: RelationTable}}, nil)
	got := ResolveRelation(snap, Name{Schema: "public", Name: "orders"}, nil)
	if !got.OK() || got.Relation.OID != 10 {
		t.Fatalf("ResolveRelation qualified = %+v", got)
	}
}

func TestResolveUnqualifiedRelationUsesSearchPath(t *testing.T) {
	snap := NewSnapshot([]Relation{
		{OID: 10, Name: Name{Schema: "public", Name: "orders"}, Kind: RelationTable},
		{OID: 11, Name: Name{Schema: "tenant", Name: "orders"}, Kind: RelationTable},
	}, nil)
	got := ResolveRelation(snap, Name{Name: "orders"}, []string{"tenant", "public"})
	if !got.OK() || got.Relation.OID != 11 {
		t.Fatalf("ResolveRelation search path = %+v", got)
	}
}

func TestResolveUnqualifiedRelationReportsMissing(t *testing.T) {
	snap := NewSnapshot(nil, nil)
	got := ResolveRelation(snap, Name{Name: "orders"}, []string{"public"})
	if got.Reason != UnresolvedMissing {
		t.Fatalf("missing reason = %s", got.Reason.String())
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./internal/db/catalog
```

Expected: FAIL because `ResolveRelation` is undefined.

- [ ] **Step 3: Add relation resolver**

Create `internal/db/catalog/resolve.go`:

```go
package catalog

func ResolveRelation(snap Snapshot, name Name, searchPath []string) ResolvedRelation {
	if name.Schema != "" {
		rel, ok := snap.RelationByName(name)
		if !ok {
			return ResolvedRelation{Reason: UnresolvedMissing}
		}
		return ResolvedRelation{Relation: rel}
	}
	for _, schema := range searchPath {
		if rel, ok := snap.RelationByName(Name{Schema: schema, Name: name.Name}); ok {
			return ResolvedRelation{Relation: rel}
		}
	}
	candidates := snap.RelationsByUnqualifiedName(name.Name)
	switch len(candidates) {
	case 0:
		return ResolvedRelation{Reason: UnresolvedMissing}
	case 1:
		return ResolvedRelation{Relation: candidates[0]}
	default:
		return ResolvedRelation{Reason: UnresolvedAmbiguous}
	}
}
```

- [ ] **Step 4: Run tests**

Run:

```bash
go test ./internal/db/catalog
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/catalog/resolve.go internal/db/catalog/resolve_test.go
git commit -m "db: resolve catalog relations"
```

---

## Task 5: Verify Full Repository And Mark Plan 08 Ready

**Files:**
- Modify: `docs/superpowers/specs/2026-05-14-db-phase-2-roadmap-design.md`

- [ ] **Step 1: Run package tests**

Run:

```bash
go test ./internal/db/catalog
```

Expected: PASS.

- [ ] **Step 2: Run full tests**

Run:

```bash
go test ./...
```

Expected: PASS.

- [ ] **Step 3: Verify cross-platform build**

Run:

```bash
GOOS=windows go build ./...
```

Expected: PASS.

- [ ] **Step 4: Update roadmap status**

In `docs/superpowers/specs/2026-05-14-db-phase-2-roadmap-design.md`, change the Plan 08 external behavior sentence from:

```markdown
External behavior: none. Existing Phase 1 runtime remains unchanged.
```

to:

```markdown
External behavior: none. Existing Phase 1 runtime remains unchanged. Plan 08 is implemented and ready for DB Plan 09 runtime integration.
```

- [ ] **Step 5: Check docs and commit**

Run:

```bash
git diff --check
```

Expected: no output.

Commit:

```bash
git add docs/superpowers/specs/2026-05-14-db-phase-2-roadmap-design.md
git commit -m "docs: mark db plan 08 ready"
```
