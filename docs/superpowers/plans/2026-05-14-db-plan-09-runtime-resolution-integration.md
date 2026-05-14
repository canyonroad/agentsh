# DB Plan 09 Runtime Resolution Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Feed Postgres catalog resolution into the runtime proxy before policy evaluation and DB event emission.

**Architecture:** Keep Phase 1 syntactic objects stable and add parallel resolved metadata on effects. The Postgres proxy initializes a per-connection catalog context after upstream authentication, resolves classified statements through a small runtime adapter, and uses a resolving parser wrapper for Extended Query so the state machine remains pure.

**Tech Stack:** Go, `pgproto3`, existing `internal/db/catalog`, existing `internal/db/effects`, existing Postgres proxy, existing real-Postgres integration harness.

---

## File Structure

- Modify: `internal/db/effects/resolution.go` - add catalog-backed resolution tags and explicit confidence ranking.
- Modify: `internal/db/effects/resolution_test.go` - add parsing and fold tests for catalog-backed tags.
- Create: `internal/db/effects/resolved_object.go` - resolved canonical object metadata carried on effects.
- Create: `internal/db/effects/resolved_object_test.go` - JSON and string tests for resolved metadata.
- Modify: `internal/db/effects/effect.go` - add `ResolvedObjects []ResolvedObjectRef` to `Effect`.
- Modify: `internal/db/events/event.go` - add `object_resolution_reason` for folded catalog failure diagnostics.
- Modify: `internal/db/events/event_test.go` - add DBEvent round-trip coverage for resolved objects and resolution reason.
- Modify: `internal/api/db_lifecycle_sink.go` - surface `object_resolution_reason` in API event fields.
- Modify: `internal/api/db_lifecycle_sink_test.go` - assert API mapping for the new field.
- Modify: `internal/db/proxy/postgres/eventbuilder.go` - set event-level object resolution and resolution reason.
- Modify: `internal/db/proxy/postgres/eventbuilder_test.go` - assert resolved metadata emission.
- Create: `internal/db/proxy/postgres/catalog_runtime.go` - catalog context, snapshot cache, refresh hook, and pgproto3 catalog query rows.
- Create: `internal/db/proxy/postgres/catalog_runtime_test.go` - snapshot cache and pgproto3 row scan tests.
- Modify: `internal/db/proxy/postgres/server.go` - add catalog store to `Server`.
- Modify: `internal/db/proxy/postgres/proxyconn.go` - add per-connection catalog context state.
- Modify: `internal/db/proxy/postgres/handshake.go` - initialize catalog context after upstream auth and before the query loop.
- Create: `internal/db/proxy/postgres/resolve_runtime.go` - pure statement augmentation adapter and resolving parser wrapper.
- Create: `internal/db/proxy/postgres/resolve_runtime_test.go` - relation/function/catalog-unavailable augmentation tests.
- Modify: `internal/db/proxy/postgres/simplequery.go` - resolve Simple Query classifications before interception and policy evaluation.
- Modify: `internal/db/proxy/postgres/extquery.go` - pass resolving parser wrapper into the state machine.
- Modify: `internal/db/proxy/postgres/funccall.go` - resolve FunctionCall OIDs before policy evaluation and event emission.
- Modify: `internal/db/proxy/postgres/preparedcache/cache_test.go` - assert cached classifications keep resolved metadata.
- Modify: `internal/db/proxy/postgres/simplequery_test.go` - add catalog-backed policy test for Simple Query.
- Modify: `internal/db/proxy/postgres/extquery_spine_test.go` - add catalog-backed policy test for Parse.
- Modify: `internal/db/proxy/postgres/funccall_test.go` - add FunctionCall resolved metadata test.
- Modify: `internal/integration/db_postgres_07c_test.go` - add DB Plan 09 real Postgres integration cases.
- Modify: `docs/superpowers/specs/2026-05-14-db-phase-2-roadmap-design.md` - mark Plan 09 implemented after verification.

## Task 1: Add Catalog Resolution Tags And Resolved Object Metadata

**Files:**
- Modify: `internal/db/effects/resolution.go`
- Modify: `internal/db/effects/resolution_test.go`
- Create: `internal/db/effects/resolved_object.go`
- Create: `internal/db/effects/resolved_object_test.go`
- Modify: `internal/db/effects/effect.go`

- [ ] **Step 1: Add failing resolution tag tests**

Append these tests to `internal/db/effects/resolution_test.go`:

```go
func TestResolutionCatalogTags(t *testing.T) {
	cases := map[string]Resolution{
		"catalog_resolved":    ResolutionCatalogResolved,
		"catalog_unresolved":  ResolutionCatalogUnresolved,
		"catalog_unavailable": ResolutionCatalogUnavailable,
	}
	for name, want := range cases {
		got, ok := ParseResolution(name)
		if !ok || got != want {
			t.Fatalf("ParseResolution(%q) = %v, %v; want %v, true", name, got, ok, want)
		}
		if got := want.String(); got != name {
			t.Fatalf("%v.String() = %q, want %q", want, got, name)
		}
	}
}

func TestFoldResolutionUsesCatalogConfidenceRank(t *testing.T) {
	if got := Fold([]Resolution{ResolutionCatalogResolved, ResolutionQualified}); got != ResolutionQualified {
		t.Fatalf("Fold(catalog_resolved, qualified_syntactic) = %v, want qualified_syntactic", got)
	}
	if got := Fold([]Resolution{ResolutionUnresolved, ResolutionCatalogUnavailable}); got != ResolutionCatalogUnavailable {
		t.Fatalf("Fold(unresolved, catalog_unavailable) = %v, want catalog_unavailable", got)
	}
	if got := Fold([]Resolution{ResolutionCatalogResolved}); got != ResolutionCatalogResolved {
		t.Fatalf("Fold(catalog_resolved) = %v", got)
	}
}
```

- [ ] **Step 2: Add failing resolved object JSON tests**

Create `internal/db/effects/resolved_object_test.go`:

```go
package effects

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestResolvedObjectRef_JSONRoundTripRelation(t *testing.T) {
	in := ResolvedObjectRef{
		Source:       ResolvedObjectSourceCatalog,
		Kind:         ResolvedObjectRelation,
		OID:          1259,
		Schema:       "public",
		Name:         "users",
		RelationKind: "table",
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var out ResolvedObjectRef
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.Source != ResolvedObjectSourceCatalog || out.Kind != ResolvedObjectRelation || out.OID != 1259 {
		t.Fatalf("round trip = %+v", out)
	}
	if out.CanonicalName() != "public.users" {
		t.Fatalf("CanonicalName = %q", out.CanonicalName())
	}
}

func TestResolvedObjectRef_JSONRoundTripFunction(t *testing.T) {
	in := ResolvedObjectRef{
		Source:               ResolvedObjectSourceCatalog,
		Kind:                 ResolvedObjectFunction,
		OID:                  42,
		Schema:               "public",
		Name:                 "normalize_email",
		FunctionIdentityArgs: "text",
		FunctionVolatility:   "immutable",
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var out ResolvedObjectRef
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.FunctionIdentityArgs != "text" || out.FunctionVolatility != "immutable" {
		t.Fatalf("function metadata = %+v", out)
	}
}

func TestEffectResolvedObjectsOmitWhenEmpty(t *testing.T) {
	raw, err := json.Marshal(Effect{Group: GroupRead})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(raw) == "" || string(raw) == "null" {
		t.Fatalf("unexpected raw JSON: %s", raw)
	}
	if strings.Contains(string(raw), `"resolved_objects"`) {
		t.Fatalf("resolved_objects should be omitted when empty: %s", raw)
	}
}
```

- [ ] **Step 3: Run focused effects tests and confirm red state**

Run:

```bash
go test ./internal/db/effects -run 'TestResolutionCatalogTags|TestFoldResolutionUsesCatalogConfidenceRank|TestResolvedObjectRef|TestEffectResolvedObjectsOmitWhenEmpty' -count=1
```

Expected: FAIL because the new resolution constants and `ResolvedObjectRef` type do not exist.

- [ ] **Step 4: Implement resolution tags and explicit confidence rank**

Update `internal/db/effects/resolution.go` so the constants and names are:

```go
const (
	ResolutionQualified Resolution = iota
	ResolutionUnqualified
	ResolutionAmbiguousAfterSearchPath
	ResolutionMaybeTempShadowed
	ResolutionUnresolved
	ResolutionCatalogResolved
	ResolutionCatalogUnresolved
	ResolutionCatalogUnavailable
)

var resolutionNames = [...]string{
	ResolutionQualified:                "qualified_syntactic",
	ResolutionUnqualified:              "unqualified_syntactic",
	ResolutionAmbiguousAfterSearchPath: "ambiguous_after_search_path",
	ResolutionMaybeTempShadowed:        "maybe_temp_shadowed",
	ResolutionUnresolved:               "unresolved",
	ResolutionCatalogResolved:          "catalog_resolved",
	ResolutionCatalogUnresolved:        "catalog_unresolved",
	ResolutionCatalogUnavailable:       "catalog_unavailable",
}

var resolutionConfidenceRank = map[Resolution]int{
	ResolutionCatalogResolved:          0,
	ResolutionQualified:                1,
	ResolutionUnqualified:              2,
	ResolutionAmbiguousAfterSearchPath: 3,
	ResolutionMaybeTempShadowed:        4,
	ResolutionUnresolved:               5,
	ResolutionCatalogUnresolved:        6,
	ResolutionCatalogUnavailable:       7,
}
```

Replace `Fold` with:

```go
func Fold(rs []Resolution) Resolution {
	worst := ResolutionQualified
	worstRank := resolutionRank(worst)
	for _, r := range rs {
		if rank := resolutionRank(r); rank > worstRank {
			worst = r
			worstRank = rank
		}
	}
	return worst
}

func resolutionRank(r Resolution) int {
	if rank, ok := resolutionConfidenceRank[r]; ok {
		return rank
	}
	return resolutionConfidenceRank[ResolutionCatalogUnavailable]
}
```

- [ ] **Step 5: Add resolved object metadata type**

Create `internal/db/effects/resolved_object.go`:

```go
package effects

type ResolvedObjectSource string

const (
	ResolvedObjectSourceCatalog ResolvedObjectSource = "catalog"
)

type ResolvedObjectKind string

const (
	ResolvedObjectRelation ResolvedObjectKind = "relation"
	ResolvedObjectFunction ResolvedObjectKind = "function"
)

type ResolvedObjectRef struct {
	Source               ResolvedObjectSource `json:"source,omitempty"`
	Kind                 ResolvedObjectKind   `json:"kind,omitempty"`
	OID                  uint32               `json:"oid,omitempty"`
	Schema               string               `json:"schema,omitempty"`
	Name                 string               `json:"name,omitempty"`
	RelationKind         string               `json:"relation_kind,omitempty"`
	FunctionIdentityArgs string               `json:"function_identity_args,omitempty"`
	FunctionVolatility   string               `json:"function_volatility,omitempty"`
	UnresolvedReason     string               `json:"unresolved_reason,omitempty"`
}

func (r ResolvedObjectRef) CanonicalName() string {
	if r.Schema == "" {
		return r.Name
	}
	return r.Schema + "." + r.Name
}
```

- [ ] **Step 6: Attach resolved objects to effects**

In `internal/db/effects/effect.go`, add the field after `Objects`:

```go
	ResolvedObjects []ResolvedObjectRef `json:"resolved_objects,omitempty"`
```

The beginning of `Effect` should read:

```go
type Effect struct {
	Group           Group
	Subtype         Subtype
	Objects         []ObjectRef
	ResolvedObjects []ResolvedObjectRef `json:"resolved_objects,omitempty"`
	Resolution      Resolution
```

- [ ] **Step 7: Run focused effects tests and commit**

Run:

```bash
go test ./internal/db/effects -run 'TestResolutionCatalogTags|TestFoldResolutionUsesCatalogConfidenceRank|TestResolvedObjectRef|TestEffectResolvedObjectsOmitWhenEmpty' -count=1
```

Expected: PASS.

Commit:

```bash
git add internal/db/effects
git commit -m "db/effects: add catalog resolution metadata"
```

## Task 2: Emit Folded Catalog Resolution In DB Events

**Files:**
- Modify: `internal/db/events/event.go`
- Modify: `internal/db/events/event_test.go`
- Modify: `internal/api/db_lifecycle_sink.go`
- Modify: `internal/api/db_lifecycle_sink_test.go`
- Modify: `internal/db/proxy/postgres/eventbuilder.go`
- Modify: `internal/db/proxy/postgres/eventbuilder_test.go`

- [ ] **Step 1: Add failing DBEvent JSON test**

Append to `internal/db/events/event_test.go`:

```go
func TestDBEvent_ResolvedObjectMetadataRoundTrip(t *testing.T) {
	in := DBEvent{
		EventID:                "db-resolved-1",
		SessionID:              "sess-1",
		Timestamp:              time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC),
		DBService:              "appdb",
		DBFamily:               "postgres",
		DBDialect:              "postgres",
		ObjectResolution:       "catalog_unresolved",
		ObjectResolutionReason: "missing",
		Effects: []effects.Effect{{
			Group:      effects.GroupRead,
			Resolution: effects.ResolutionCatalogUnresolved,
			Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "missing"}},
			ResolvedObjects: []effects.ResolvedObjectRef{{
				Source:           effects.ResolvedObjectSourceCatalog,
				Kind:             effects.ResolvedObjectRelation,
				Name:             "missing",
				UnresolvedReason: "missing",
			}},
		}},
		StatementRedaction: RedactionParametersRedacted,
	}

	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var out DBEvent
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.ObjectResolution != "catalog_unresolved" || out.ObjectResolutionReason != "missing" {
		t.Fatalf("resolution fields = %q / %q", out.ObjectResolution, out.ObjectResolutionReason)
	}
	if len(out.Effects) != 1 || len(out.Effects[0].ResolvedObjects) != 1 {
		t.Fatalf("resolved effects lost: %+v", out.Effects)
	}
}
```

- [ ] **Step 2: Add failing event builder test**

Append to `internal/api/db_lifecycle_sink_test.go`:

```go
func TestDBStatementToEventMapsCatalogResolutionReason(t *testing.T) {
	ev := dbStatementToEvent(dbevents.DBEvent{
		EventID:                "db-resolved-api",
		SessionID:              "sess-1",
		Timestamp:              time.Unix(100, 0).UTC(),
		DBService:              "appdb",
		DBFamily:               "postgres",
		DBDialect:              "postgres",
		ObjectResolution:       "catalog_unresolved",
		ObjectResolutionReason: "missing",
	})
	if ev.Fields["object_resolution"] != "catalog_unresolved" {
		t.Fatalf("object_resolution = %#v", ev.Fields["object_resolution"])
	}
	if ev.Fields["object_resolution_reason"] != "missing" {
		t.Fatalf("object_resolution_reason = %#v", ev.Fields["object_resolution_reason"])
	}
}
```

- [ ] **Step 3: Add failing event builder test**

Append to `internal/db/proxy/postgres/eventbuilder_test.go`:

```go
func TestBuildStatementEvent_SetsCatalogResolutionFields(t *testing.T) {
	sql := "SELECT * FROM users"
	stmt := effects.ClassifiedStatement{
		RawVerb: "SELECT",
		Effects: []effects.Effect{{
			Group:      effects.GroupRead,
			Resolution: effects.ResolutionCatalogResolved,
			Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "users"}},
			ResolvedObjects: []effects.ResolvedObjectRef{{
				Source:       effects.ResolvedObjectSourceCatalog,
				Kind:         effects.ResolvedObjectRelation,
				OID:          1259,
				Schema:       "public",
				Name:         "users",
				RelationKind: "table",
			}},
		}},
		SourceStart: 0,
		SourceEnd:   int32(len(sql)),
	}
	parser := classify_pg.New(classify_pg.DialectPostgres)
	ev := buildStatementEvent(buildArgs{
		Stmt:       stmt,
		SQL:        sql,
		Tier:       policy.RedactParametersRedacted,
		Conn:       connStateForTest("appdb", "postgres", "terminate_reissue"),
		Decision:   policy.Decision{Verb: policy.VerbAllow, RuleKind: policy.RuleKindStatement},
		DenyAction: "none",
		BatchSHA:   sha256Hex(sql),
		Parser:     parser,
	})
	if ev.ObjectResolution != "catalog_resolved" {
		t.Fatalf("ObjectResolution = %q", ev.ObjectResolution)
	}
	if len(ev.Effects) != 1 || len(ev.Effects[0].ResolvedObjects) != 1 {
		t.Fatalf("resolved objects missing from event: %+v", ev.Effects)
	}
	if ev.Effects[0].ResolvedObjects[0].OID != 1259 {
		t.Fatalf("resolved oid = %+v", ev.Effects[0].ResolvedObjects[0])
	}
}
```

- [ ] **Step 4: Run focused event tests and confirm red state**

Run:

```bash
go test ./internal/db/events ./internal/api ./internal/db/proxy/postgres -run 'TestDBEvent_ResolvedObjectMetadataRoundTrip|TestDBStatementToEventMapsCatalogResolutionReason|TestBuildStatementEvent_SetsCatalogResolutionFields' -count=1
```

Expected: FAIL because `ObjectResolutionReason` and event builder propagation do not exist.

- [ ] **Step 5: Add event field**

In `internal/db/events/event.go`, add this field after `ObjectResolution`:

```go
	ObjectResolutionReason string `json:"object_resolution_reason,omitempty"`
```

- [ ] **Step 6: Map the event field into API events**

In `internal/api/db_lifecycle_sink.go`, add this entry after `object_resolution` in `dbStatementToEvent`:

```go
		"object_resolution_reason": ev.ObjectResolutionReason,
```

- [ ] **Step 7: Populate folded resolution in the event builder**

In `internal/db/proxy/postgres/eventbuilder.go`, set these fields in the returned `events.DBEvent`:

```go
		ObjectResolution:       a.Stmt.FoldResolution().String(),
		ObjectResolutionReason: firstResolutionReason(a.Stmt),
```

Add this helper near `hasFilter`:

```go
func firstResolutionReason(stmt effects.ClassifiedStatement) string {
	for _, eff := range stmt.Effects {
		for _, obj := range eff.ResolvedObjects {
			if obj.UnresolvedReason != "" {
				return obj.UnresolvedReason
			}
		}
	}
	return ""
}
```

- [ ] **Step 8: Run focused event tests and commit**

Run:

```bash
go test ./internal/db/events ./internal/api ./internal/db/proxy/postgres -run 'TestDBEvent_ResolvedObjectMetadataRoundTrip|TestDBStatementToEventMapsCatalogResolutionReason|TestBuildStatementEvent_SetsCatalogResolutionFields' -count=1
```

Expected: PASS.

Commit:

```bash
git add internal/db/events internal/api/db_lifecycle_sink.go internal/api/db_lifecycle_sink_test.go internal/db/proxy/postgres/eventbuilder.go internal/db/proxy/postgres/eventbuilder_test.go
git commit -m "db/events: emit catalog resolution metadata"
```

## Task 3: Add Runtime Catalog Context And Snapshot Cache

**Files:**
- Create: `internal/db/proxy/postgres/catalog_runtime.go`
- Create: `internal/db/proxy/postgres/catalog_runtime_test.go`
- Modify: `internal/db/proxy/postgres/server.go`
- Modify: `internal/db/proxy/postgres/proxyconn.go`
- Modify: `internal/db/proxy/postgres/handshake.go`

- [ ] **Step 1: Add failing cache tests**

Create `internal/db/proxy/postgres/catalog_runtime_test.go`:

```go
//go:build linux

package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/agentsh/agentsh/internal/db/catalog"
)

func TestCatalogSnapshotStore_LoadOrGetCachesByServiceDatabaseUser(t *testing.T) {
	loads := 0
	store := newCatalogSnapshotStore(catalogRuntimeLoaderFunc(func(context.Context, *proxyConn) (catalog.Snapshot, []string, string, error) {
		loads++
		return catalog.NewSnapshot([]catalog.Relation{{
			OID:  7,
			Name: catalog.Name{Schema: "public", Name: "users"},
			Kind: catalog.RelationTable,
		}}, nil), []string{"public"}, "", nil
	}))
	pc := &proxyConn{
		svc: Service{Name: "appdb"},
		state: &connState{
			dbService: "appdb",
			database:  "app",
			dbUser:    "agent",
		},
	}
	first := store.loadOrGet(context.Background(), pc)
	second := store.loadOrGet(context.Background(), pc)
	if first.UnavailableReason != "" || second.UnavailableReason != "" {
		t.Fatalf("unexpected unavailable: %+v / %+v", first, second)
	}
	if loads != 1 {
		t.Fatalf("loads = %d, want 1", loads)
	}
}

func TestCatalogSnapshotStore_LoadFailureIsCachedAsUnavailable(t *testing.T) {
	store := newCatalogSnapshotStore(catalogRuntimeLoaderFunc(func(context.Context, *proxyConn) (catalog.Snapshot, []string, string, error) {
		return catalog.Snapshot{}, nil, "snapshot_load_failed", errors.New("boom")
	}))
	pc := &proxyConn{svc: Service{Name: "appdb"}, state: &connState{dbService: "appdb", database: "app", dbUser: "agent"}}
	got := store.loadOrGet(context.Background(), pc)
	if got.UnavailableReason != "snapshot_load_failed" {
		t.Fatalf("UnavailableReason = %q", got.UnavailableReason)
	}
}

func TestPGCatalogRowsScanConversions(t *testing.T) {
	rows := &pgCatalogRows{rows: [][]string{{"42", "public", "users", "true", "3"}}}
	if !rows.Next() {
		t.Fatal("Next = false")
	}
	var oid uint32
	var schema, name string
	var notNull bool
	var pos int
	if err := rows.Scan(&oid, &schema, &name, &notNull, &pos); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if oid != 42 || schema != "public" || name != "users" || !notNull || pos != 3 {
		t.Fatalf("scanned values = %d %q %q %v %d", oid, schema, name, notNull, pos)
	}
}
```

- [ ] **Step 2: Run focused catalog runtime tests and confirm red state**

Run:

```bash
go test ./internal/db/proxy/postgres -run 'TestCatalogSnapshotStore|TestPGCatalogRowsScanConversions' -count=1
```

Expected: FAIL because the runtime catalog types do not exist.

- [ ] **Step 3: Implement catalog context and snapshot cache**

Create `internal/db/proxy/postgres/catalog_runtime.go` with:

```go
//go:build linux

package postgres

import (
	"context"
	"fmt"
	"strconv"
	"sync"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/catalog"
)

type catalogRuntimeContext struct {
	Snapshot          catalog.Snapshot
	SearchPath        []string
	UnavailableReason string
}

type catalogCacheKey struct {
	Service  string
	Database string
	DBUser   string
}

type catalogRuntimeLoader interface {
	LoadCatalogRuntime(ctx context.Context, pc *proxyConn) (catalog.Snapshot, []string, string, error)
}

type catalogRuntimeLoaderFunc func(context.Context, *proxyConn) (catalog.Snapshot, []string, string, error)

func (f catalogRuntimeLoaderFunc) LoadCatalogRuntime(ctx context.Context, pc *proxyConn) (catalog.Snapshot, []string, string, error) {
	return f(ctx, pc)
}

type catalogSnapshotStore struct {
	mu      sync.Mutex
	loader  catalogRuntimeLoader
	entries map[catalogCacheKey]catalogRuntimeContext
}

func newCatalogSnapshotStore(loader catalogRuntimeLoader) *catalogSnapshotStore {
	if loader == nil {
		loader = pgprotoCatalogLoader{}
	}
	return &catalogSnapshotStore{
		loader:  loader,
		entries: make(map[catalogCacheKey]catalogRuntimeContext),
	}
}

func catalogKeyFor(pc *proxyConn) catalogCacheKey {
	return catalogCacheKey{
		Service:  pc.svc.Name,
		Database: pc.state.database,
		DBUser:   pc.state.dbUser,
	}
}

func (s *catalogSnapshotStore) loadOrGet(ctx context.Context, pc *proxyConn) catalogRuntimeContext {
	key := catalogKeyFor(pc)
	s.mu.Lock()
	if entry, ok := s.entries[key]; ok {
		s.mu.Unlock()
		return entry
	}
	s.mu.Unlock()

	snap, searchPath, reason, err := s.loader.LoadCatalogRuntime(ctx, pc)
	entry := catalogRuntimeContext{Snapshot: snap, SearchPath: append([]string(nil), searchPath...)}
	if err != nil {
		if reason == "" {
			reason = "catalog_error"
		}
		entry.UnavailableReason = reason
	}

	s.mu.Lock()
	s.entries[key] = entry
	s.mu.Unlock()
	return entry
}

func (s *catalogSnapshotStore) refresh(ctx context.Context, pc *proxyConn) catalogRuntimeContext {
	key := catalogKeyFor(pc)
	snap, searchPath, reason, err := s.loader.LoadCatalogRuntime(ctx, pc)
	entry := catalogRuntimeContext{Snapshot: snap, SearchPath: append([]string(nil), searchPath...)}
	if err != nil {
		if reason == "" {
			reason = "catalog_error"
		}
		entry.UnavailableReason = reason
	}
	s.mu.Lock()
	s.entries[key] = entry
	s.mu.Unlock()
	return entry
}
```

- [ ] **Step 4: Add pgproto3 catalog row scan support**

In the same file, add:

```go
type pgCatalogRows struct {
	rows [][]string
	idx  int
	err  error
}

func (r *pgCatalogRows) Next() bool {
	return r.idx < len(r.rows)
}

func (r *pgCatalogRows) Scan(dest ...any) error {
	if r.idx >= len(r.rows) {
		return fmt.Errorf("pgCatalogRows.Scan: no current row")
	}
	row := r.rows[r.idx]
	if len(dest) != len(row) {
		return fmt.Errorf("pgCatalogRows.Scan: got %d dests for %d values", len(dest), len(row))
	}
	for i := range dest {
		switch d := dest[i].(type) {
		case *string:
			*d = row[i]
		case *uint32:
			v, err := strconv.ParseUint(row[i], 10, 32)
			if err != nil {
				return err
			}
			*d = uint32(v)
		case *int:
			v, err := strconv.Atoi(row[i])
			if err != nil {
				return err
			}
			*d = v
		case *bool:
			switch row[i] {
			case "t", "true":
				*d = true
			case "f", "false":
				*d = false
			default:
				return fmt.Errorf("pgCatalogRows.Scan: invalid bool %q", row[i])
			}
		default:
			return fmt.Errorf("pgCatalogRows.Scan: unsupported dest %T", dest[i])
		}
	}
	r.idx++
	return nil
}

func (r *pgCatalogRows) Close() error { return nil }
func (r *pgCatalogRows) Err() error   { return r.err }
```

- [ ] **Step 5: Add authenticated pgproto3 loader**

In `catalog_runtime.go`, add:

```go
type pgprotoCatalogLoader struct{}

func (pgprotoCatalogLoader) LoadCatalogRuntime(ctx context.Context, pc *proxyConn) (catalog.Snapshot, []string, string, error) {
	q := pgprotoCatalogQueryer{pc: pc}
	searchPath, err := loadCurrentSchemas(ctx, q)
	if err != nil {
		return catalog.Snapshot{}, nil, "search_path_unavailable", err
	}
	snap, err := catalog.LoadPostgresSnapshot(ctx, q)
	if err != nil {
		return catalog.Snapshot{}, searchPath, "snapshot_load_failed", err
	}
	return snap, searchPath, "", nil
}

type pgprotoCatalogQueryer struct {
	pc *proxyConn
}

func (q pgprotoCatalogQueryer) Query(ctx context.Context, sql string, args ...any) (catalog.Rows, error) {
	if len(args) != 0 {
		return nil, fmt.Errorf("pgprotoCatalogQueryer.Query: args are not supported")
	}
	if q.pc == nil || q.pc.state == nil || q.pc.state.upstreamFE == nil {
		return nil, fmt.Errorf("pgprotoCatalogQueryer.Query: upstream is not ready")
	}
	q.pc.state.upstreamFE.Send(&pgproto3.Query{String: sql})
	if err := q.pc.state.upstreamFE.Flush(); err != nil {
		return nil, err
	}
	var rows [][]string
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		msg, err := q.pc.state.upstreamFE.Receive()
		if err != nil {
			return nil, err
		}
		switch m := msg.(type) {
		case *pgproto3.DataRow:
			row := make([]string, len(m.Values))
			for i, v := range m.Values {
				row[i] = string(v)
			}
			rows = append(rows, row)
		case *pgproto3.ErrorResponse:
			return nil, fmt.Errorf("catalog query failed: %s: %s", m.Code, m.Message)
		case *pgproto3.ReadyForQuery:
			if q.pc.state.smState != nil {
				q.pc.state.smState.LastUpstreamRFQ = m.TxStatus
			}
			return &pgCatalogRows{rows: rows}, nil
		}
	}
}

func loadCurrentSchemas(ctx context.Context, q catalog.Queryer) ([]string, error) {
	rows, err := q.Query(ctx, "select unnest(pg_catalog.current_schemas(true))::text as nspname")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var schema string
		if err := rows.Scan(&schema); err != nil {
			return nil, err
		}
		out = append(out, schema)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
```

- [ ] **Step 6: Wire catalog store into Server and connState**

In `internal/db/proxy/postgres/server.go`, add this unexported test hook to `Config`:

```go
	catalogLoaderForTest catalogRuntimeLoader
```

Add this field to `Server`:

```go
	catalogStore *catalogSnapshotStore
```

In both `New` return paths, initialize the store:

```go
catalogStore: newCatalogSnapshotStore(cfg.catalogLoaderForTest),
```

In `internal/db/proxy/postgres/proxyconn.go`, add to `connState`:

```go
	catalog catalogRuntimeContext
```

- [ ] **Step 7: Initialize catalog context after upstream auth**

In `internal/db/proxy/postgres/handshake.go`, after redaction/tls fields are set and before `simpleQueryLoop(ctx)`, add:

```go
	pc.initializeCatalogContext(ctx)
```

Add this helper to `catalog_runtime.go`:

```go
func (pc *proxyConn) initializeCatalogContext(ctx context.Context) {
	if pc.srv == nil || pc.srv.catalogStore == nil {
		pc.state.catalog = catalogRuntimeContext{UnavailableReason: "catalog_store_unavailable"}
		return
	}
	pc.state.catalog = pc.srv.catalogStore.loadOrGet(ctx, pc)
	if pc.state.catalog.UnavailableReason != "" {
		pc.emitCatalogUnavailable(ctx, pc.state.catalog.UnavailableReason)
	}
}

func (pc *proxyConn) emitCatalogUnavailable(ctx context.Context, reason string) {
	if pc.srv == nil || pc.srv.cfg.Sink == nil {
		return
	}
	_ = pc.srv.cfg.Sink.EmitLifecycle(ctx, events.LifecycleEvent{
		EventID:        newEventID(),
		Timestamp:      timeNow(),
		SessionID:      pc.srv.cfg.AgentSessionID,
		DBService:      pc.svc.Name,
		ClientIdentity: pc.state.clientIdentity,
		Kind:           "db_catalog_unavailable",
		Reason:         reason,
		PeerUID:        pc.state.peerUID,
	})
}
```

Add the `events` import to `catalog_runtime.go`.

- [ ] **Step 8: Run focused catalog runtime tests and commit**

Run:

```bash
go test ./internal/db/proxy/postgres -run 'TestCatalogSnapshotStore|TestPGCatalogRowsScanConversions' -count=1
```

Expected: PASS.

Commit:

```bash
git add internal/db/proxy/postgres/catalog_runtime.go internal/db/proxy/postgres/catalog_runtime_test.go internal/db/proxy/postgres/server.go internal/db/proxy/postgres/proxyconn.go internal/db/proxy/postgres/handshake.go
git commit -m "db/proxy: add catalog runtime context"
```

## Task 4: Add Runtime Statement Resolution Adapter

**Files:**
- Create: `internal/db/proxy/postgres/resolve_runtime.go`
- Create: `internal/db/proxy/postgres/resolve_runtime_test.go`

- [ ] **Step 1: Add failing runtime resolution tests**

Create `internal/db/proxy/postgres/resolve_runtime_test.go`:

```go
//go:build linux

package postgres

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/catalog"
	"github.com/agentsh/agentsh/internal/db/effects"
)

func testCatalogContext() catalogRuntimeContext {
	return catalogRuntimeContext{
		Snapshot: catalog.NewSnapshot([]catalog.Relation{{
			OID:  10,
			Name: catalog.Name{Schema: "public", Name: "users"},
			Kind: catalog.RelationTable,
		}, {
			OID:  11,
			Name: catalog.Name{Schema: "audit", Name: "users"},
			Kind: catalog.RelationTable,
		}, {
			OID:  12,
			Name: catalog.Name{Schema: "public", Name: "active_users"},
			Kind: catalog.RelationView,
		}}, []catalog.Function{{
			OID:          99,
			Name:         catalog.Name{Schema: "public", Name: "normalize_email"},
			IdentityArgs: "text",
			Volatility:   catalog.VolatilityImmutable,
		}}),
		SearchPath: []string{"public"},
	}
}

func TestResolveStatementCatalog_QualifiedRelation(t *testing.T) {
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionQualified,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Schema: "public", Name: "users"}},
	}}}
	got := resolveStatementCatalog(stmt, testCatalogContext())
	eff := got.Effects[0]
	if eff.Resolution != effects.ResolutionCatalogResolved {
		t.Fatalf("Resolution = %v", eff.Resolution)
	}
	if len(eff.ResolvedObjects) != 1 || eff.ResolvedObjects[0].OID != 10 {
		t.Fatalf("ResolvedObjects = %+v", eff.ResolvedObjects)
	}
}

func TestResolveStatementCatalog_UnqualifiedRelationUsesSearchPath(t *testing.T) {
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionUnqualified,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "users"}},
	}}}
	got := resolveStatementCatalog(stmt, testCatalogContext())
	if got.Effects[0].ResolvedObjects[0].Schema != "public" {
		t.Fatalf("resolved schema = %+v", got.Effects[0].ResolvedObjects[0])
	}
}

func TestResolveStatementCatalog_MissingRelation(t *testing.T) {
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionUnqualified,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "missing"}},
	}}}
	got := resolveStatementCatalog(stmt, testCatalogContext())
	eff := got.Effects[0]
	if eff.Resolution != effects.ResolutionCatalogUnresolved {
		t.Fatalf("Resolution = %v", eff.Resolution)
	}
	if eff.ResolvedObjects[0].UnresolvedReason != "missing" {
		t.Fatalf("reason = %+v", eff.ResolvedObjects[0])
	}
}

func TestResolveStatementCatalog_Unavailable(t *testing.T) {
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionUnqualified,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "users"}},
	}}}
	got := resolveStatementCatalog(stmt, catalogRuntimeContext{UnavailableReason: "snapshot_load_failed"})
	if got.Effects[0].Resolution != effects.ResolutionCatalogUnavailable {
		t.Fatalf("Resolution = %v", got.Effects[0].Resolution)
	}
	if got.Effects[0].ResolvedObjects[0].UnresolvedReason != "snapshot_load_failed" {
		t.Fatalf("ResolvedObjects = %+v", got.Effects[0].ResolvedObjects)
	}
}

func TestResolveStatementCatalog_UnsupportedObjectKind(t *testing.T) {
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupSession,
		Resolution: effects.ResolutionQualified,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectGUC, Name: "search_path"}},
	}}}
	got := resolveStatementCatalog(stmt, testCatalogContext())
	eff := got.Effects[0]
	if eff.Resolution != effects.ResolutionCatalogUnresolved {
		t.Fatalf("Resolution = %v", eff.Resolution)
	}
	if eff.ResolvedObjects[0].UnresolvedReason != "unsupported" {
		t.Fatalf("ResolvedObjects = %+v", eff.ResolvedObjects)
	}
}

func TestResolveStatementCatalog_FunctionOID(t *testing.T) {
	oid := int32(99)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:       effects.GroupProcedural,
		Subtype:     effects.SubtypeFunctionCallProtocol,
		FunctionOID: &oid,
	}}}
	got := resolveStatementCatalog(stmt, testCatalogContext())
	eff := got.Effects[0]
	if eff.Resolution != effects.ResolutionCatalogResolved {
		t.Fatalf("Resolution = %v", eff.Resolution)
	}
	if len(eff.ResolvedObjects) != 1 || eff.ResolvedObjects[0].FunctionIdentityArgs != "text" {
		t.Fatalf("ResolvedObjects = %+v", eff.ResolvedObjects)
	}
}
```

- [ ] **Step 2: Run focused resolution tests and confirm red state**

Run:

```bash
go test ./internal/db/proxy/postgres -run TestResolveStatementCatalog -count=1
```

Expected: FAIL because `resolveStatementCatalog` does not exist.

- [ ] **Step 3: Implement statement resolution adapter**

Create `internal/db/proxy/postgres/resolve_runtime.go`:

```go
//go:build linux

package postgres

import (
	classify_pg "github.com/agentsh/agentsh/internal/db/classify/postgres"
	"github.com/agentsh/agentsh/internal/db/catalog"
	"github.com/agentsh/agentsh/internal/db/effects"
)

func resolveStatementCatalog(stmt effects.ClassifiedStatement, ctx catalogRuntimeContext) effects.ClassifiedStatement {
	out := stmt
	out.Effects = make([]effects.Effect, len(stmt.Effects))
	for i, eff := range stmt.Effects {
		out.Effects[i] = resolveEffectCatalog(eff, ctx)
	}
	return out
}

func resolveStatementsCatalog(stmts []effects.ClassifiedStatement, ctx catalogRuntimeContext) []effects.ClassifiedStatement {
	out := make([]effects.ClassifiedStatement, len(stmts))
	for i := range stmts {
		out[i] = resolveStatementCatalog(stmts[i], ctx)
	}
	return out
}

func resolveEffectCatalog(eff effects.Effect, ctx catalogRuntimeContext) effects.Effect {
	out := eff
	if len(eff.Objects) > 0 {
		out.ResolvedObjects = make([]effects.ResolvedObjectRef, 0, len(eff.Objects))
		allResolved := true
		anyRelevant := false
		for _, obj := range eff.Objects {
			resolved, relevant := resolveObjectCatalog(obj, ctx)
			if !relevant {
				continue
			}
			anyRelevant = true
			if resolved.UnresolvedReason != "" {
				allResolved = false
			}
			out.ResolvedObjects = append(out.ResolvedObjects, resolved)
		}
		if anyRelevant {
			if ctx.UnavailableReason != "" {
				out.Resolution = effects.ResolutionCatalogUnavailable
			} else if allResolved {
				out.Resolution = effects.ResolutionCatalogResolved
			} else {
				out.Resolution = effects.ResolutionCatalogUnresolved
			}
		}
	}
	if eff.FunctionOID != nil {
		resolved := resolveFunctionOIDCatalog(*eff.FunctionOID, ctx)
		out.ResolvedObjects = append(out.ResolvedObjects, resolved)
		if ctx.UnavailableReason != "" {
			out.Resolution = effects.ResolutionCatalogUnavailable
		} else if resolved.UnresolvedReason == "" {
			out.Resolution = effects.ResolutionCatalogResolved
		} else {
			out.Resolution = effects.ResolutionCatalogUnresolved
		}
	}
	return out
}
```

- [ ] **Step 4: Implement object and function mapping helpers**

Add to `resolve_runtime.go`:

```go
func resolveObjectCatalog(obj effects.ObjectRef, ctx catalogRuntimeContext) (effects.ResolvedObjectRef, bool) {
	if !isCatalogRelationObject(obj.Kind) {
		return effects.ResolvedObjectRef{
			Source:           effects.ResolvedObjectSourceCatalog,
			Kind:             effects.ResolvedObjectRelation,
			Schema:           obj.Schema,
			Name:             obj.Name,
			UnresolvedReason: "unsupported",
		}, true
	}
	if ctx.UnavailableReason != "" {
		return effects.ResolvedObjectRef{
			Source:           effects.ResolvedObjectSourceCatalog,
			Kind:             effects.ResolvedObjectRelation,
			Schema:           obj.Schema,
			Name:             obj.Name,
			UnresolvedReason: ctx.UnavailableReason,
		}, true
	}
	res := catalog.ResolveRelation(ctx.Snapshot, catalog.Name{Schema: obj.Schema, Name: obj.Name}, ctx.SearchPath)
	if !res.OK() {
		return effects.ResolvedObjectRef{
			Source:           effects.ResolvedObjectSourceCatalog,
			Kind:             effects.ResolvedObjectRelation,
			Schema:           obj.Schema,
			Name:             obj.Name,
			UnresolvedReason: res.Reason.String(),
		}, true
	}
	rel := res.Relation
	return effects.ResolvedObjectRef{
		Source:       effects.ResolvedObjectSourceCatalog,
		Kind:         effects.ResolvedObjectRelation,
		OID:          uint32(rel.OID),
		Schema:       rel.Name.Schema,
		Name:         rel.Name.Name,
		RelationKind: rel.Kind.String(),
	}, true
}

func isCatalogRelationObject(kind effects.ObjectKind) bool {
	switch kind {
	case effects.ObjectTable, effects.ObjectView, effects.ObjectSequence:
		return true
	default:
		return false
	}
}

func resolveFunctionOIDCatalog(oid int32, ctx catalogRuntimeContext) effects.ResolvedObjectRef {
	if ctx.UnavailableReason != "" {
		return effects.ResolvedObjectRef{
			Source:           effects.ResolvedObjectSourceCatalog,
			Kind:             effects.ResolvedObjectFunction,
			OID:              uint32(oid),
			UnresolvedReason: ctx.UnavailableReason,
		}
	}
	res := catalog.ResolveFunctionByOID(ctx.Snapshot, catalog.OID(uint32(oid)))
	if !res.OK() {
		return effects.ResolvedObjectRef{
			Source:           effects.ResolvedObjectSourceCatalog,
			Kind:             effects.ResolvedObjectFunction,
			OID:              uint32(oid),
			UnresolvedReason: res.Reason.String(),
		}
	}
	fn := res.Function
	return effects.ResolvedObjectRef{
		Source:               effects.ResolvedObjectSourceCatalog,
		Kind:                 effects.ResolvedObjectFunction,
		OID:                  uint32(fn.OID),
		Schema:               fn.Name.Schema,
		Name:                 fn.Name.Name,
		FunctionIdentityArgs: fn.IdentityArgs,
		FunctionVolatility:   functionVolatilityString(fn.Volatility),
	}
}

func functionVolatilityString(v catalog.FunctionVolatility) string {
	switch v {
	case catalog.VolatilityImmutable:
		return "immutable"
	case catalog.VolatilityStable:
		return "stable"
	case catalog.VolatilityVolatile:
		return "volatile"
	default:
		return ""
	}
}
```

- [ ] **Step 5: Add resolving parser wrapper**

Add to `resolve_runtime.go`:

```go
type resolvingParser struct {
	base classify_pg.Parser
	ctx  catalogRuntimeContext
}

func (p resolvingParser) Classify(sql string, sess classify_pg.SessionState, opts classify_pg.Options) ([]effects.ClassifiedStatement, error) {
	stmts, err := p.base.Classify(sql, sess, opts)
	return resolveStatementsCatalog(stmts, p.ctx), err
}

func (p resolvingParser) Normalize(sql string) (string, error) {
	return p.base.Normalize(sql)
}

func (pc *proxyConn) resolvingParser(dialect string) classify_pg.Parser {
	return resolvingParser{base: pc.srv.classifierFor(dialect), ctx: pc.state.catalog}
}
```

- [ ] **Step 6: Run focused resolution tests and commit**

Run:

```bash
go test ./internal/db/proxy/postgres -run TestResolveStatementCatalog -count=1
```

Expected: PASS.

Commit:

```bash
git add internal/db/proxy/postgres/resolve_runtime.go internal/db/proxy/postgres/resolve_runtime_test.go
git commit -m "db/proxy: resolve catalog objects at runtime"
```

## Task 5: Wire Simple Query And SQL PREPARE Resolution

**Files:**
- Modify: `internal/db/proxy/postgres/simplequery.go`
- Modify: `internal/db/proxy/postgres/simplequery_test.go`
- Modify: `internal/db/proxy/postgres/preparedcache/cache_test.go`

- [ ] **Step 1: Add failing prepared cache metadata test**

Append to `internal/db/proxy/postgres/preparedcache/cache_test.go`:

```go
func TestCachePreservesResolvedObjects(t *testing.T) {
	c := New(2)
	c.Put("s1", Entry{Classification: effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionCatalogResolved,
		ResolvedObjects: []effects.ResolvedObjectRef{{
			Source: effects.ResolvedObjectSourceCatalog,
			Kind:   effects.ResolvedObjectRelation,
			OID:    10,
			Schema: "public",
			Name:   "users",
		}},
	}}}})
	got, ok := c.Get("s1")
	if !ok {
		t.Fatal("cache miss")
	}
	if len(got.Classification.Effects[0].ResolvedObjects) != 1 {
		t.Fatalf("ResolvedObjects lost: %+v", got.Classification)
	}
}
```

- [ ] **Step 2: Add failing Simple Query policy test**

Append to `internal/db/proxy/postgres/simplequery_test.go`:

```go
func TestHandleQuery_CatalogResolvedPolicyAllow(t *testing.T) {
	pc, clientFE, sink, script := allowPathFixture(t)
	pc.state.smState.LastUpstreamRFQ = 'I'
	pc.state.catalog = testCatalogContext()
	pc.srv.SetPolicy(loadRuleSet(t, `version: 1
name: test
db_services:
  test:
    family: postgres
    dialect: postgres
    upstream: 127.0.0.1:5432
    tls_mode: terminate_reissue
database_rules:
  - name: allow-catalog-read
    db_service: test
    operations: [read]
    objects: [users]
    match_object_resolution: catalog_resolved
    decision: allow
`))

	script([]pgproto3.BackendMessage{
		&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("id")}}},
		&pgproto3.DataRow{Values: [][]byte{[]byte("1")}},
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	})

	loopErr := make(chan error, 1)
	go func() { loopErr <- pc.simpleQueryLoop(context.Background()) }()

	mustSendFromClient(t, clientFE, &pgproto3.Query{String: "SELECT * FROM users"})
	frames := drainNFrames(t, clientFE, 4)
	if _, ok := frames[3].(*pgproto3.ReadyForQuery); !ok {
		t.Fatalf("last frame = %T want ReadyForQuery", frames[3])
	}

	evs := sink.DrainStatements()
	if len(evs) != 1 {
		t.Fatalf("events = %d", len(evs))
	}
	if evs[0].ObjectResolution != "catalog_resolved" {
		t.Fatalf("ObjectResolution = %q", evs[0].ObjectResolution)
	}

	_ = pc.conn.Close()
	select {
	case <-loopErr:
	case <-time.After(time.Second):
	}
}
```

- [ ] **Step 3: Run focused tests and confirm red or behavioral failure**

Run:

```bash
go test ./internal/db/proxy/postgres ./internal/db/proxy/postgres/preparedcache -run 'TestHandleQuery_CatalogResolvedPolicyAllow|TestCachePreservesResolvedObjects' -count=1
```

Expected: prepared cache test passes once Task 1 exists; Simple Query test FAILS because policy evaluation still sees syntactic resolution.

- [ ] **Step 4: Resolve Simple Query classifications before interception**

In `internal/db/proxy/postgres/simplequery.go`, replace:

```go
parser := pc.srv.classifierFor(pc.svc.Dialect)
opts := classifierOptionsFromPolicy(rs)
stmts, _ := parser.Classify(q.String, classify_pg.SessionState{}, opts)
```

with:

```go
parser := pc.resolvingParser(pc.svc.Dialect)
opts := classifierOptionsFromPolicy(rs)
stmts, _ := parser.Classify(q.String, classify_pg.SessionState{}, opts)
```

Keep `emitAllowEvents` and `emitDenyEvents` using `pc.srv.classifierFor` for normalization so event digests do not depend on the wrapper.

- [ ] **Step 5: Run focused tests and commit**

Run:

```bash
go test ./internal/db/proxy/postgres ./internal/db/proxy/postgres/preparedcache -run 'TestHandleQuery_CatalogResolvedPolicyAllow|TestCachePreservesResolvedObjects' -count=1
```

Expected: PASS.

Commit:

```bash
git add internal/db/proxy/postgres/simplequery.go internal/db/proxy/postgres/simplequery_test.go internal/db/proxy/postgres/preparedcache/cache_test.go
git commit -m "db/proxy: resolve simple query catalog objects"
```

## Task 6: Wire Extended Query, Approval, And FunctionCall Resolution

**Files:**
- Modify: `internal/db/proxy/postgres/extquery.go`
- Modify: `internal/db/proxy/postgres/approvalwait.go`
- Modify: `internal/db/proxy/postgres/approvalwait_test.go`
- Modify: `internal/db/proxy/postgres/funccall.go`
- Modify: `internal/db/proxy/postgres/extquery_spine_test.go`
- Modify: `internal/db/proxy/postgres/funccall_test.go`

- [ ] **Step 1: Add failing Extended Query Parse policy test**

Append to `internal/db/proxy/postgres/extquery_spine_test.go`:

```go
func TestExtquery_Parse_CatalogResolvedPolicyAllow(t *testing.T) {
	pc, clientFE, _, _ := extqueryFixture(t, `version: 1
name: test
db_services:
  test:
    family: postgres
    dialect: postgres
    upstream: 127.0.0.1:5432
    tls_mode: terminate_reissue
database_rules:
  - name: allow-catalog-read
    db_service: test
    operations: [read]
    objects: [users]
    match_object_resolution: catalog_resolved
    decision: allow
`)
	pc.state.catalog = testCatalogContext()

	loopErr := make(chan error, 1)
	go func() { loopErr <- pc.simpleQueryLoop(context.Background()) }()

	clientFE.Send(&pgproto3.Parse{Name: "s1", Query: "SELECT * FROM users"})
	if err := clientFE.Flush(); err != nil {
		t.Fatalf("client Flush: %v", err)
	}

	if _, ok := pc.wireCache.Get("s1"); !ok {
		t.Fatal("wire cache missing s1 after catalog-resolved allow")
	}

	_ = pc.conn.Close()
	select {
	case <-loopErr:
	case <-time.After(time.Second):
	}
}
```

- [ ] **Step 2: Add failing FunctionCall resolution test**

Append to `internal/db/proxy/postgres/funccall_test.go`:

```go
func TestFunctionCall_EventIncludesResolvedFunction(t *testing.T) {
	pc, clientFE, sink := newSimpleQueryFixture(t)
	pc.state.smState.LastUpstreamRFQ = 'I'
	pc.srv.SetPolicy(loadRuleSet(t, funcCallPolicyYAML(true)))
	pc.state.catalog = testCatalogContext()

	upClient, upServer := net.Pipe()
	t.Cleanup(func() { _ = upClient.Close(); _ = upServer.Close() })
	pc.state.upstream = upServer
	pc.state.upstreamFE = pgproto3.NewFrontend(upServer, upServer)
	go func() {
		be := pgproto3.NewBackend(upClient, upClient)
		if _, err := be.Receive(); err != nil {
			return
		}
		be.Send(&pgproto3.FunctionCallResponse{Result: []byte{0x01}})
		be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		_ = be.Flush()
	}()

	oid := uint32(99)
	result := make(chan error, 1)
	go func() {
		result <- pc.handleFunctionCall(context.Background(), &pgproto3.FunctionCall{Function: oid})
	}()
	for i := 0; i < 2; i++ {
		if _, err := clientFE.Receive(); err != nil {
			break
		}
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("handleFunctionCall: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handleFunctionCall did not return")
	}

	evs := sink.DrainStatements()
	if len(evs) != 1 {
		t.Fatalf("events = %d", len(evs))
	}
	resolved := evs[0].Effects[0].ResolvedObjects
	if len(resolved) != 1 || resolved[0].Name != "normalize_email" {
		t.Fatalf("resolved function = %+v", resolved)
	}
}
```

- [ ] **Step 3: Run focused Extended Query and FunctionCall tests**

Run:

```bash
go test ./internal/db/proxy/postgres -run 'TestExtquery_Parse_CatalogResolvedPolicyAllow|TestFunctionCall_EventIncludesResolvedFunction|TestEmitApprovalFrameEventIncludesResolvedMetadata' -count=1
```

Expected: FAIL because Extended Query and FunctionCall are not resolving yet.

- [ ] **Step 4: Use resolving parser in Extended Query**

In `internal/db/proxy/postgres/extquery.go`, replace:

```go
parser := pc.srv.classifierFor(pc.svc.Dialect)
```

with:

```go
parser := pc.resolvingParser(pc.svc.Dialect)
```

Leave the state machine API unchanged. The wrapper implements the same parser interface and resolves the returned statements before the state machine calls `policy.Evaluate`.

- [ ] **Step 5: Resolve FunctionCall before policy evaluation**

In `internal/db/proxy/postgres/funccall.go`, after building `cs`, add:

```go
cs = resolveStatementCatalog(cs, pc.state.catalog)
```

This must happen before:

```go
d := policy.Evaluate(cs, rs, policy.ServiceID(pc.svc.Name))
```

- [ ] **Step 6: Assert approval events reuse resolved statements**

Update `internal/db/proxy/postgres/approvalwait_test.go` imports to include:

```go
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/statemachine"
```

Append this test to the same file:

```go
func TestEmitApprovalFrameEventIncludesResolvedMetadata(t *testing.T) {
	pc, _, sink := newSimpleQueryFixture(t)
	pc.state.catalog = testCatalogContext()
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionCatalogResolved,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "users"}},
		ResolvedObjects: []effects.ResolvedObjectRef{{
			Source: effects.ResolvedObjectSourceCatalog,
			Kind:   effects.ResolvedObjectRelation,
			OID:    10,
			Schema: "public",
			Name:   "users",
		}},
	}}}
	pc.emitApprovalFrameEvent(context.Background(), &pgproto3.Parse{Query: "SELECT * FROM users"}, statemachine.ActionApproverWait{
		Stmt: stmt,
		Rule: policy.StatementRule{Name: "approve-read"},
	}, policy.Decision{Verb: policy.VerbApprove, RuleKind: policy.RuleKindStatement, RuleName: "approve-read"}, "none")
	evs := sink.DrainStatements()
	if len(evs) != 1 || evs[0].ObjectResolution != "catalog_resolved" {
		t.Fatalf("events = %+v", evs)
	}
}
```

before `buildStatementEvent`.

- [ ] **Step 7: Run focused tests and commit**

Run:

```bash
go test ./internal/db/proxy/postgres -run 'TestExtquery_Parse_CatalogResolvedPolicyAllow|TestFunctionCall_EventIncludesResolvedFunction|TestEmitApprovalFrameEventIncludesResolvedMetadata' -count=1
```

Expected: PASS.

Commit:

```bash
git add internal/db/proxy/postgres/extquery.go internal/db/proxy/postgres/approvalwait.go internal/db/proxy/postgres/approvalwait_test.go internal/db/proxy/postgres/funccall.go internal/db/proxy/postgres/extquery_spine_test.go internal/db/proxy/postgres/funccall_test.go
git commit -m "db/proxy: resolve extended query and function calls"
```

## Task 7: Add Real Postgres Plan 09 Integration Coverage

**Files:**
- Modify: `internal/integration/db_postgres_07c_test.go`
- Modify: `docs/superpowers/specs/2026-05-14-db-phase-2-roadmap-design.md`

- [ ] **Step 1: Add seed objects for Plan 09**

In `seedDB07C`, add these statements to the existing setup block:

```sql
create schema if not exists plan09;
drop table if exists plan09.users;
create table plan09.users(id int primary key, note text);
insert into plan09.users(id, note) values (1, 'schema-qualified');
create or replace view plan09.active_users as select id, note from plan09.users;
create or replace function plan09.identity_text(v text) returns text
language sql immutable strict as $$ select v $$;
```

- [ ] **Step 2: Add catalog-resolved policy rules to test policy**

In `db07cPolicyYAML()`, add rules that allow `read` only when catalog-resolved:

```yaml
  - name: allow-plan09-catalog-read
    db_service: appdb
    operations: [read]
    objects: [users, active_users]
    match_object_resolution: catalog_resolved
    decision: allow
```

Keep existing Phase 1 rules that the 07c tests need.

- [ ] **Step 3: Add schema-qualified and unqualified integration assertions**

Append a new test:

```go
func TestDB09RealPostgresCatalogResolution(t *testing.T) {
	ctx := context.Background()
	env := startDB07CEnvironment(t, ctx)
	defer env.cleanup()

	seedDB07C(t, ctx, env.hostDSN)
	sess := createDB07CSession(t, ctx, env.client)
	socket := filepath.Join(sess.DBProxySocketDir, "appdb.sock")

	qualified := execDB07CClient(t, ctx, env.client, sess.ID, "-socket", socket, "-mode", "scalar", "-sql", "select note from plan09.users where id = 1", "-simple")
	if qualified.Scalar != "schema-qualified" {
		t.Fatalf("qualified catalog query returned %+v", qualified)
	}
	waitForSessionEvent07C(t, ctx, env.client, sess.ID, func(ev types.Event) bool {
		if ev.Type != "db_statement" || ev.Fields["object_resolution"] != "catalog_resolved" {
			return false
		}
		return strings.Contains(fmt.Sprint(ev.Fields["effects"]), "plan09")
	}, "catalog_resolved schema-qualified event")

	view := execDB07CClient(t, ctx, env.client, sess.ID, "-socket", socket, "-mode", "scalar", "-sql", "select note from plan09.active_users where id = 1", "-simple")
	if view.Scalar != "schema-qualified" {
		t.Fatalf("view catalog query returned %+v", view)
	}
}
```

- [ ] **Step 4: Add missing-object fallback integration assertion**

Append to the new test:

```go
	missing := execDB07CClientAllowFailure(t, ctx, env.client, sess.ID, "-socket", socket, "-mode", "scalar", "-sql", "select * from plan09.missing_relation", "-simple")
	if missing.OK {
		t.Fatalf("missing relation unexpectedly succeeded: %+v", missing)
	}
	waitForSessionEvent07C(t, ctx, env.client, sess.ID, func(ev types.Event) bool {
		return ev.Type == "db_statement" &&
			(ev.Fields["object_resolution"] == "catalog_unresolved" || ev.Fields["object_resolution_reason"] == "missing")
	}, "catalog_unresolved missing-object event")
```

- [ ] **Step 5: Run integration test**

Run:

```bash
go test -tags=integration ./internal/integration -run TestDB09RealPostgresCatalogResolution -count=1
```

Expected: PASS.

- [ ] **Step 6: Update roadmap status**

In `docs/superpowers/specs/2026-05-14-db-phase-2-roadmap-design.md`, change the Plan 09 external behavior sentence from:

```markdown
External behavior: operators can write stricter policies that require catalog-backed resolution, while existing syntactic policies keep working.
```

to:

```markdown
External behavior: operators can write stricter policies that require catalog-backed resolution, while existing syntactic policies keep working. Plan 09 is implemented and ready for DB Plan 10 policy ergonomics.
```

- [ ] **Step 7: Commit integration coverage and docs**

Run:

```bash
git add internal/integration/db_postgres_07c_test.go docs/superpowers/specs/2026-05-14-db-phase-2-roadmap-design.md
git commit -m "db: add runtime catalog resolution integration"
```

## Task 8: Full Verification

**Files:**
- No file edits expected.

- [ ] **Step 1: Run full Go test suite**

Run:

```bash
go test ./...
```

Expected: PASS.

- [ ] **Step 2: Run Windows compilation check**

Run:

```bash
GOOS=windows go build ./...
```

Expected: PASS.

- [ ] **Step 3: Run real Postgres integration suite**

Run:

```bash
go test -tags=integration ./internal/integration -run 'TestDB07C|TestDB09' -count=1
```

Expected: PASS.

- [ ] **Step 4: Check diff hygiene**

Run:

```bash
git diff --check
```

Expected: no output.

- [ ] **Step 5: Commit verification fixes if needed**

If any verification command required code changes, inspect the status:

```bash
git status --short
```

Then commit the verification fixes:

```bash
git add internal/db internal/integration docs/superpowers/specs/2026-05-14-db-phase-2-roadmap-design.md
git commit -m "db: complete plan 09 verification"
```

If no code changes were needed, do not create an empty commit.
