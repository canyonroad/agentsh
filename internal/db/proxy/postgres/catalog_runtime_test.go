//go:build linux

package postgres

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/catalog"
	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/preparedcache"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/statemachine"
)

func TestCatalogSnapshotStore_LoadOrGetCachesByServiceDatabaseUser(t *testing.T) {
	loads := 0
	store := newCatalogSnapshotStore(splitCatalogRuntimeLoader{
		loadSnapshot: func(context.Context, *proxyConn) (catalog.Snapshot, string, error) {
			loads++
			return catalog.NewSnapshot([]catalog.Relation{{
				OID:  7,
				Name: catalog.Name{Schema: "public", Name: "users"},
				Kind: catalog.RelationTable,
			}}, nil), "", nil
		},
		loadSearchPath: func(context.Context, *proxyConn) ([]string, string, error) {
			return []string{"public"}, "", nil
		},
	})
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

func TestCatalogSnapshotStore_CachesSnapshotButLoadsSearchPathPerConnection(t *testing.T) {
	store := newCatalogSnapshotStore(catalogRuntimeLoaderFunc(func(_ context.Context, pc *proxyConn) (catalog.Snapshot, []string, string, error) {
		searchPath := []string{"public"}
		if pc.state.appName == "tenant-client" {
			searchPath = []string{"tenant", "public"}
		}
		return catalog.NewSnapshot([]catalog.Relation{{
			OID:  7,
			Name: catalog.Name{Schema: "public", Name: "users"},
			Kind: catalog.RelationTable,
		}}, nil), searchPath, "", nil
	}))
	first := store.loadOrGet(context.Background(), &proxyConn{
		svc: Service{Name: "appdb"},
		state: &connState{
			dbService: "appdb",
			database:  "app",
			dbUser:    "agent",
			appName:   "public-client",
		},
	})
	second := store.loadOrGet(context.Background(), &proxyConn{
		svc: Service{Name: "appdb"},
		state: &connState{
			dbService: "appdb",
			database:  "app",
			dbUser:    "agent",
			appName:   "tenant-client",
		},
	})
	if len(first.SearchPath) != 1 || first.SearchPath[0] != "public" {
		t.Fatalf("first SearchPath = %#v, want [public]", first.SearchPath)
	}
	if len(second.SearchPath) != 2 || second.SearchPath[0] != "tenant" || second.SearchPath[1] != "public" {
		t.Fatalf("second SearchPath = %#v, want [tenant public]", second.SearchPath)
	}
}

func TestProxyConnRefreshesCatalogSearchPathAfterSuccessfulSessionChange(t *testing.T) {
	store := newCatalogSnapshotStore(catalogRuntimeLoaderFunc(func(_ context.Context, pc *proxyConn) (catalog.Snapshot, []string, string, error) {
		searchPath := []string{"public"}
		if pc.state.appName == "tenant-client" {
			searchPath = []string{"tenant", "public"}
		}
		return catalog.NewSnapshot(nil, nil), searchPath, "", nil
	}))
	pc := &proxyConn{
		srv: &Server{catalogStore: store},
		svc: Service{Name: "appdb"},
		state: &connState{
			dbService: "appdb",
			database:  "app",
			dbUser:    "agent",
			appName:   "public-client",
		},
	}
	pc.state.catalog = store.loadOrGet(context.Background(), pc)
	pc.state.appName = "tenant-client"

	pc.refreshCatalogAfterSuccessfulStatements(context.Background(), []effects.ClassifiedStatement{{
		RawVerb: "SET_SEARCH_PATH=tenant,public",
		Effects: []effects.Effect{{
			Group:   effects.GroupSession,
			Subtype: effects.SubtypeSetSearchPath,
			Objects: []effects.ObjectRef{{Kind: effects.ObjectGUC, Name: "search_path"}},
		}},
	}}, upstreamResult{RowsByStmt: []*int64{nil}})

	if len(pc.state.catalog.SearchPath) != 2 || pc.state.catalog.SearchPath[0] != "tenant" || pc.state.catalog.SearchPath[1] != "public" {
		t.Fatalf("SearchPath = %#v, want [tenant public]", pc.state.catalog.SearchPath)
	}
}

func TestProxyConnRefreshesCatalogSearchPathAfterSuccessfulSetLocal(t *testing.T) {
	store := newCatalogSnapshotStore(catalogRuntimeLoaderFunc(func(_ context.Context, pc *proxyConn) (catalog.Snapshot, []string, string, error) {
		searchPath := []string{"public"}
		if pc.state.appName == "tenant-client" {
			searchPath = []string{"tenant", "public"}
		}
		return catalog.NewSnapshot(nil, nil), searchPath, "", nil
	}))
	pc := &proxyConn{
		srv: &Server{catalogStore: store},
		svc: Service{Name: "appdb"},
		state: &connState{
			dbService: "appdb",
			database:  "app",
			dbUser:    "agent",
			appName:   "public-client",
		},
	}
	pc.state.catalog = store.loadOrGet(context.Background(), pc)
	pc.state.appName = "tenant-client"

	pc.refreshCatalogAfterSuccessfulStatements(context.Background(), []effects.ClassifiedStatement{{
		RawVerb: "SET_LOCAL=search_path:tenant,public",
		Effects: []effects.Effect{{
			Group:   effects.GroupSession,
			Subtype: effects.SubtypeSetLocal,
			Objects: []effects.ObjectRef{{Kind: effects.ObjectGUC, Name: "search_path"}},
		}},
	}}, upstreamResult{RowsByStmt: []*int64{nil}})

	if len(pc.state.catalog.SearchPath) != 2 || pc.state.catalog.SearchPath[0] != "tenant" || pc.state.catalog.SearchPath[1] != "public" {
		t.Fatalf("SearchPath = %#v, want [tenant public]", pc.state.catalog.SearchPath)
	}
}

func TestProxyConnRefreshesCatalogSearchPathAfterRollbackTo(t *testing.T) {
	store := newCatalogSnapshotStore(catalogRuntimeLoaderFunc(func(_ context.Context, pc *proxyConn) (catalog.Snapshot, []string, string, error) {
		searchPath := []string{"public"}
		if pc.state.appName == "tenant-client" {
			searchPath = []string{"tenant", "public"}
		}
		return catalog.NewSnapshot(nil, nil), searchPath, "", nil
	}))
	pc := &proxyConn{
		srv: &Server{catalogStore: store},
		svc: Service{Name: "appdb"},
		state: &connState{
			dbService: "appdb",
			database:  "app",
			dbUser:    "agent",
			appName:   "tenant-client",
		},
	}
	pc.state.catalog = store.loadOrGet(context.Background(), pc)
	pc.state.appName = "public-client"

	pc.refreshCatalogAfterSuccessfulStatements(context.Background(), []effects.ClassifiedStatement{{
		RawVerb: "ROLLBACK_TO",
		Effects: []effects.Effect{{
			Group: effects.GroupTransaction,
		}},
	}}, upstreamResult{RowsByStmt: []*int64{nil}})

	if len(pc.state.catalog.SearchPath) != 1 || pc.state.catalog.SearchPath[0] != "public" {
		t.Fatalf("SearchPath = %#v, want [public]", pc.state.catalog.SearchPath)
	}
}

func TestProxyConnRefreshesCatalogSearchPathAfterResetSessionAuthorization(t *testing.T) {
	store := newCatalogSnapshotStore(catalogRuntimeLoaderFunc(func(_ context.Context, pc *proxyConn) (catalog.Snapshot, []string, string, error) {
		searchPath := []string{"public"}
		if pc.state.appName == "tenant-client" {
			searchPath = []string{"tenant", "public"}
		}
		return catalog.NewSnapshot(nil, nil), searchPath, "", nil
	}))
	pc := &proxyConn{
		srv: &Server{catalogStore: store},
		svc: Service{Name: "appdb"},
		state: &connState{
			dbService: "appdb",
			database:  "app",
			dbUser:    "agent",
			appName:   "tenant-client",
		},
	}
	pc.state.catalog = store.loadOrGet(context.Background(), pc)
	pc.state.appName = "public-client"

	pc.refreshCatalogAfterSuccessfulStatements(context.Background(), []effects.ClassifiedStatement{{
		RawVerb: "RESET=session_authorization",
		Effects: []effects.Effect{{
			Group:   effects.GroupSession,
			Subtype: effects.SubtypeReset,
			Objects: []effects.ObjectRef{{Kind: effects.ObjectGUC, Name: "session_authorization"}},
		}},
	}}, upstreamResult{RowsByStmt: []*int64{nil}})

	if len(pc.state.catalog.SearchPath) != 1 || pc.state.catalog.SearchPath[0] != "public" {
		t.Fatalf("SearchPath = %#v, want [public]", pc.state.catalog.SearchPath)
	}
}

func TestProxyConnDefersSnapshotRefreshInsideTransaction(t *testing.T) {
	snapshotLoads := 0
	store := newCatalogSnapshotStore(splitCatalogRuntimeLoader{
		loadSnapshot: func(context.Context, *proxyConn) (catalog.Snapshot, string, error) {
			snapshotLoads++
			return catalog.NewSnapshot(nil, nil), "", nil
		},
		loadSearchPath: func(context.Context, *proxyConn) ([]string, string, error) {
			return []string{"public"}, "", nil
		},
	})
	pc := &proxyConn{
		srv: &Server{catalogStore: store},
		svc: Service{Name: "appdb"},
		state: &connState{
			dbService: "appdb",
			database:  "app",
			dbUser:    "agent",
			smState:   &statemachine.ConnState{LastUpstreamRFQ: 'T'},
			catalog:   catalogRuntimeContext{SearchPath: []string{"public"}},
		},
	}

	pc.refreshCatalogAfterSuccessfulStatements(context.Background(), []effects.ClassifiedStatement{{
		RawVerb: "CREATE_TABLE",
		Effects: []effects.Effect{{
			Group:   effects.GroupSchemaCreate,
			Subtype: effects.SubtypeCreateTable,
			Objects: []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "pending_table"}},
		}},
	}}, upstreamResult{RowsByStmt: []*int64{nil}})

	if snapshotLoads != 0 {
		t.Fatalf("snapshot loads = %d, want 0 while in transaction", snapshotLoads)
	}
	if !pc.state.catalogSnapshotRefreshPending {
		t.Fatal("catalogSnapshotRefreshPending = false, want true")
	}
	if pc.state.catalog.UnavailableReason != "session_state_changed" {
		t.Fatalf("UnavailableReason = %q, want session_state_changed", pc.state.catalog.UnavailableReason)
	}
}

func TestProxyConnRefreshesPendingSnapshotAtTransactionEnd(t *testing.T) {
	snapshotLoads := 0
	store := newCatalogSnapshotStore(splitCatalogRuntimeLoader{
		loadSnapshot: func(context.Context, *proxyConn) (catalog.Snapshot, string, error) {
			snapshotLoads++
			return catalog.NewSnapshot(nil, nil), "", nil
		},
		loadSearchPath: func(context.Context, *proxyConn) ([]string, string, error) {
			return []string{"public"}, "", nil
		},
	})
	pc := &proxyConn{
		srv: &Server{catalogStore: store},
		svc: Service{Name: "appdb"},
		state: &connState{
			dbService:                     "appdb",
			database:                      "app",
			dbUser:                        "agent",
			smState:                       &statemachine.ConnState{LastUpstreamRFQ: 'I'},
			catalog:                       catalogRuntimeContext{UnavailableReason: "session_state_changed"},
			catalogRefreshPending:         true,
			catalogSnapshotRefreshPending: true,
		},
	}

	pc.refreshCatalogAfterSuccessfulStatements(context.Background(), []effects.ClassifiedStatement{{
		RawVerb: "COMMIT",
		Effects: []effects.Effect{{
			Group: effects.GroupTransaction,
		}},
	}}, upstreamResult{RowsByStmt: []*int64{nil}})

	if snapshotLoads != 1 {
		t.Fatalf("snapshot loads = %d, want 1 after transaction end", snapshotLoads)
	}
	if pc.state.catalogRefreshPending || pc.state.catalogSnapshotRefreshPending {
		t.Fatalf("pending flags not cleared: refresh=%v snapshot=%v", pc.state.catalogRefreshPending, pc.state.catalogSnapshotRefreshPending)
	}
	if pc.state.catalog.UnavailableReason != "" {
		t.Fatalf("UnavailableReason = %q, want empty", pc.state.catalog.UnavailableReason)
	}
}

func TestProxyConnRefreshPendingCatalogContextDefersSnapshotInTransaction(t *testing.T) {
	snapshotLoads := 0
	store := newCatalogSnapshotStore(splitCatalogRuntimeLoader{
		loadSnapshot: func(context.Context, *proxyConn) (catalog.Snapshot, string, error) {
			snapshotLoads++
			return catalog.NewSnapshot(nil, nil), "", nil
		},
		loadSearchPath: func(context.Context, *proxyConn) ([]string, string, error) {
			return []string{"public"}, "", nil
		},
	})
	pc := &proxyConn{
		srv: &Server{catalogStore: store},
		svc: Service{Name: "appdb"},
		state: &connState{
			dbService:                     "appdb",
			database:                      "app",
			dbUser:                        "agent",
			smState:                       &statemachine.ConnState{LastUpstreamRFQ: 'T'},
			catalog:                       catalogRuntimeContext{UnavailableReason: "session_state_changed"},
			catalogRefreshPending:         true,
			catalogSnapshotRefreshPending: true,
		},
	}

	pc.refreshPendingCatalogContext(context.Background())

	if snapshotLoads != 0 {
		t.Fatalf("snapshot loads = %d, want 0 while in transaction", snapshotLoads)
	}
	if !pc.state.catalogRefreshPending || !pc.state.catalogSnapshotRefreshPending {
		t.Fatalf("pending flags cleared: refresh=%v snapshot=%v", pc.state.catalogRefreshPending, pc.state.catalogSnapshotRefreshPending)
	}
}

func TestProxyConnMarksCatalogRefreshPendingForExecutedPortal(t *testing.T) {
	pc := &proxyConn{
		state:     &connState{catalog: catalogRuntimeContext{SearchPath: []string{"public"}}},
		wireCache: preparedcache.New(0),
	}
	pc.wireCache.Put(wirePortalCacheKey("p"), preparedcache.Entry{CatalogRefreshSearchPath: true})

	pc.markCatalogRefreshPendingForExecute(&pgproto3.Execute{Portal: "p"}, []statemachine.Action{&statemachine.ActionForward{}})

	if !pc.state.catalogRefreshPending {
		t.Fatal("catalogRefreshPending = false, want true")
	}
	if pc.state.catalog.UnavailableReason != "session_state_changed" {
		t.Fatalf("UnavailableReason = %q, want session_state_changed", pc.state.catalog.UnavailableReason)
	}
}

func TestProxyConnCachesApprovedParseAndMarksDirty(t *testing.T) {
	pc := &proxyConn{
		state:     &connState{smState: &statemachine.ConnState{}},
		wireCache: preparedcache.New(0),
	}
	stmt := effects.ClassifiedStatement{
		RawVerb: "SELECT",
		Effects: []effects.Effect{{
			Group:      effects.GroupRead,
			Resolution: effects.ResolutionCatalogResolved,
			Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "users"}},
		}},
	}

	pc.cacheApprovedParse(&pgproto3.Parse{Name: "s1", Query: "SELECT * FROM users"}, stmt)

	entry, ok := pc.wireCache.Get("s1")
	if !ok {
		t.Fatal("approved parse was not cached")
	}
	if entry.Classification.RawVerb != "SELECT" {
		t.Fatalf("cached RawVerb = %q, want SELECT", entry.Classification.RawVerb)
	}
	if !pc.state.smState.UpstreamDirtySinceSync {
		t.Fatal("UpstreamDirtySinceSync = false, want true")
	}
}

func TestCatalogSnapshotStore_LoadFailureIsCachedAsUnavailable(t *testing.T) {
	store := newCatalogSnapshotStore(splitCatalogRuntimeLoader{
		loadSnapshot: func(context.Context, *proxyConn) (catalog.Snapshot, string, error) {
			return catalog.Snapshot{}, "snapshot_load_failed", errors.New("boom")
		},
		loadSearchPath: func(context.Context, *proxyConn) ([]string, string, error) {
			return []string{"public"}, "", nil
		},
	})
	pc := &proxyConn{svc: Service{Name: "appdb"}, state: &connState{dbService: "appdb", database: "app", dbUser: "agent"}}
	got := store.loadOrGet(context.Background(), pc)
	if got.UnavailableReason != "snapshot_load_failed" {
		t.Fatalf("UnavailableReason = %q", got.UnavailableReason)
	}
}

func TestCatalogSnapshotStore_LoadOrGetCoalescesConcurrentMisses(t *testing.T) {
	var loads int32
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	store := newCatalogSnapshotStore(splitCatalogRuntimeLoader{
		loadSnapshot: func(context.Context, *proxyConn) (catalog.Snapshot, string, error) {
			atomic.AddInt32(&loads, 1)
			entered <- struct{}{}
			<-release
			return catalog.NewSnapshot(nil, nil), "", nil
		},
		loadSearchPath: func(context.Context, *proxyConn) ([]string, string, error) {
			return []string{"public"}, "", nil
		},
	})
	pc := &proxyConn{svc: Service{Name: "appdb"}, state: &connState{dbService: "appdb", database: "app", dbUser: "agent"}}

	start := make(chan struct{})
	results := make(chan catalogRuntimeContext, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- store.loadOrGet(context.Background(), pc)
		}()
	}
	close(start)
	<-entered

	deadline := time.Now().Add(50 * time.Millisecond)
	for time.Now().Before(deadline) && atomic.LoadInt32(&loads) < 2 {
		time.Sleep(time.Millisecond)
	}
	close(release)
	wg.Wait()
	close(results)

	if got := atomic.LoadInt32(&loads); got != 1 {
		t.Fatalf("loads = %d, want 1", got)
	}
	for got := range results {
		if got.UnavailableReason != "" {
			t.Fatalf("unexpected unavailable context: %+v", got)
		}
		if len(got.SearchPath) != 1 || got.SearchPath[0] != "public" {
			t.Fatalf("SearchPath = %#v, want [public]", got.SearchPath)
		}
	}
}

type splitCatalogRuntimeLoader struct {
	loadSnapshot   func(context.Context, *proxyConn) (catalog.Snapshot, string, error)
	loadSearchPath func(context.Context, *proxyConn) ([]string, string, error)
}

func (l splitCatalogRuntimeLoader) LoadCatalogSnapshot(ctx context.Context, pc *proxyConn) (catalog.Snapshot, string, error) {
	return l.loadSnapshot(ctx, pc)
}

func (l splitCatalogRuntimeLoader) LoadCurrentSearchPath(ctx context.Context, pc *proxyConn) ([]string, string, error) {
	return l.loadSearchPath(ctx, pc)
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

func TestPGProtoCatalogQueryer_DrainsReadyForQueryAfterErrorResponse(t *testing.T) {
	proxySide, upstreamSide := net.Pipe()
	t.Cleanup(func() {
		_ = proxySide.Close()
		_ = upstreamSide.Close()
	})
	pc := &proxyConn{state: &connState{
		upstreamFE: pgproto3.NewFrontend(proxySide, proxySide),
		smState:    &statemachine.ConnState{},
	}}

	serverErr := make(chan error, 1)
	go func() {
		be := pgproto3.NewBackend(upstreamSide, upstreamSide)
		msg, err := be.Receive()
		if err != nil {
			serverErr <- err
			return
		}
		if _, ok := msg.(*pgproto3.Query); !ok {
			serverErr <- errors.New("expected Query")
			return
		}
		be.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "42P01", Message: "missing relation"})
		be.Send(&pgproto3.ReadyForQuery{TxStatus: 'E'})
		serverErr <- be.Flush()
	}()

	rows, err := (pgprotoCatalogQueryer{pc: pc}).Query(context.Background(), "select * from missing_relation")
	if rows != nil {
		t.Fatalf("rows = %#v, want nil", rows)
	}
	if err == nil || !strings.Contains(err.Error(), "42P01") {
		t.Fatalf("err = %v, want catalog query error with SQLSTATE", err)
	}
	if pc.state.smState.LastUpstreamRFQ != 'E' {
		t.Fatalf("LastUpstreamRFQ = %q, want 'E'", pc.state.smState.LastUpstreamRFQ)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server script: %v", err)
	}
}
