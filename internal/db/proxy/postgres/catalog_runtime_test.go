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
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/statemachine"
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

func TestCatalogSnapshotStore_LoadOrGetCoalescesConcurrentMisses(t *testing.T) {
	var loads int32
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	store := newCatalogSnapshotStore(catalogRuntimeLoaderFunc(func(context.Context, *proxyConn) (catalog.Snapshot, []string, string, error) {
		atomic.AddInt32(&loads, 1)
		entered <- struct{}{}
		<-release
		return catalog.NewSnapshot(nil, nil), []string{"public"}, "", nil
	}))
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
