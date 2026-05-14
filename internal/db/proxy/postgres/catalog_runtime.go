//go:build linux

package postgres

import (
	"context"
	"fmt"
	"strconv"
	"sync"

	"github.com/jackc/pgx/v5/pgproto3"
	"golang.org/x/sync/singleflight"

	"github.com/agentsh/agentsh/internal/db/catalog"
	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/events"
)

type catalogRuntimeContext struct {
	Snapshot          catalog.Snapshot
	SearchPath        []string
	UnavailableReason string
}

type catalogSnapshotEntry struct {
	Snapshot          catalog.Snapshot
	UnavailableReason string
}

type catalogCacheKey struct {
	Service  string
	Database string
	DBUser   string
}

type catalogRuntimeLoader interface {
	LoadCatalogSnapshot(ctx context.Context, pc *proxyConn) (catalog.Snapshot, string, error)
	LoadCurrentSearchPath(ctx context.Context, pc *proxyConn) ([]string, string, error)
}

type catalogRuntimeLoaderFunc func(context.Context, *proxyConn) (catalog.Snapshot, []string, string, error)

func (f catalogRuntimeLoaderFunc) LoadCatalogSnapshot(ctx context.Context, pc *proxyConn) (catalog.Snapshot, string, error) {
	snap, _, reason, err := f(ctx, pc)
	return snap, reason, err
}

func (f catalogRuntimeLoaderFunc) LoadCurrentSearchPath(ctx context.Context, pc *proxyConn) ([]string, string, error) {
	_, searchPath, reason, err := f(ctx, pc)
	return searchPath, reason, err
}

type catalogSnapshotStore struct {
	mu      sync.Mutex
	group   singleflight.Group
	loader  catalogRuntimeLoader
	entries map[catalogCacheKey]catalogSnapshotEntry
}

func newCatalogSnapshotStore(loader catalogRuntimeLoader) *catalogSnapshotStore {
	if loader == nil {
		loader = pgprotoCatalogLoader{}
	}
	return &catalogSnapshotStore{
		loader:  loader,
		entries: make(map[catalogCacheKey]catalogSnapshotEntry),
	}
}

func catalogKeyFor(pc *proxyConn) catalogCacheKey {
	return catalogCacheKey{
		Service:  pc.svc.Name,
		Database: pc.state.database,
		DBUser:   pc.state.dbUser,
	}
}

func catalogSingleflightKey(key catalogCacheKey) string {
	return key.Service + "\x00" + key.Database + "\x00" + key.DBUser
}

func (s *catalogSnapshotStore) loadOrGet(ctx context.Context, pc *proxyConn) catalogRuntimeContext {
	searchPath, searchPathReason := s.loadSearchPath(ctx, pc)
	entry := s.loadOrGetSnapshot(ctx, pc)
	return runtimeContextFromSnapshot(entry, searchPath, searchPathReason)
}

func (s *catalogSnapshotStore) loadOrGetSnapshot(ctx context.Context, pc *proxyConn) catalogSnapshotEntry {
	key := catalogKeyFor(pc)
	s.mu.Lock()
	if entry, ok := s.entries[key]; ok {
		s.mu.Unlock()
		return entry
	}
	s.mu.Unlock()

	v, err, _ := s.group.Do(catalogSingleflightKey(key), func() (any, error) {
		s.mu.Lock()
		if entry, ok := s.entries[key]; ok {
			s.mu.Unlock()
			return entry, nil
		}
		s.mu.Unlock()

		entry := s.loadSnapshot(ctx, pc)
		s.mu.Lock()
		s.entries[key] = entry
		s.mu.Unlock()
		return entry, nil
	})
	if err != nil {
		return catalogSnapshotEntry{UnavailableReason: "catalog_error"}
	}
	return v.(catalogSnapshotEntry)
}

func (s *catalogSnapshotStore) refresh(ctx context.Context, pc *proxyConn) catalogRuntimeContext {
	searchPath, searchPathReason := s.loadSearchPath(ctx, pc)
	key := catalogKeyFor(pc)
	entry := s.loadSnapshot(ctx, pc)
	s.mu.Lock()
	s.entries[key] = entry
	s.mu.Unlock()
	return runtimeContextFromSnapshot(entry, searchPath, searchPathReason)
}

func (s *catalogSnapshotStore) refreshSearchPath(ctx context.Context, pc *proxyConn) catalogRuntimeContext {
	searchPath, searchPathReason := s.loadSearchPath(ctx, pc)
	entry := s.loadOrGetSnapshot(ctx, pc)
	return runtimeContextFromSnapshot(entry, searchPath, searchPathReason)
}

func (s *catalogSnapshotStore) loadSearchPath(ctx context.Context, pc *proxyConn) ([]string, string) {
	searchPath, reason, err := s.loader.LoadCurrentSearchPath(ctx, pc)
	if err != nil {
		if reason == "" {
			reason = "search_path_unavailable"
		}
		return nil, reason
	}
	return append([]string(nil), searchPath...), ""
}

func (s *catalogSnapshotStore) loadSnapshot(ctx context.Context, pc *proxyConn) catalogSnapshotEntry {
	snap, reason, err := s.loader.LoadCatalogSnapshot(ctx, pc)
	entry := catalogSnapshotEntry{Snapshot: snap}
	if err != nil {
		if reason == "" {
			reason = "catalog_error"
		}
		entry.UnavailableReason = reason
	}
	return entry
}

func runtimeContextFromSnapshot(entry catalogSnapshotEntry, searchPath []string, searchPathReason string) catalogRuntimeContext {
	reason := entry.UnavailableReason
	if searchPathReason != "" {
		reason = searchPathReason
	}
	return catalogRuntimeContext{
		Snapshot:          entry.Snapshot,
		SearchPath:        append([]string(nil), searchPath...),
		UnavailableReason: reason,
	}
}

type pgCatalogRows struct {
	rows [][]string
	idx  int
	err  error
}

func (r *pgCatalogRows) Next() bool { return r.idx < len(r.rows) }

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

type pgprotoCatalogLoader struct{}

func (pgprotoCatalogLoader) LoadCurrentSearchPath(ctx context.Context, pc *proxyConn) ([]string, string, error) {
	searchPath, err := loadCurrentSchemas(ctx, pgprotoCatalogQueryer{pc: pc})
	if err != nil {
		return nil, "search_path_unavailable", err
	}
	return searchPath, "", nil
}

func (pgprotoCatalogLoader) LoadCatalogSnapshot(ctx context.Context, pc *proxyConn) (catalog.Snapshot, string, error) {
	snap, err := catalog.LoadPostgresSnapshot(ctx, pgprotoCatalogQueryer{pc: pc})
	if err != nil {
		return catalog.Snapshot{}, "snapshot_load_failed", err
	}
	return snap, "", nil
}

type pgprotoCatalogQueryer struct{ pc *proxyConn }

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
	var queryErr error
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
			queryErr = fmt.Errorf("catalog query failed: %s: %s", m.Code, m.Message)
		case *pgproto3.ReadyForQuery:
			if q.pc.state.smState != nil {
				q.pc.state.smState.LastUpstreamRFQ = m.TxStatus
			}
			if queryErr != nil {
				return nil, queryErr
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

func (pc *proxyConn) refreshCatalogAfterSuccessfulStatements(ctx context.Context, stmts []effects.ClassifiedStatement, result upstreamResult) {
	completed := len(result.RowsByStmt)
	if completed > len(stmts) {
		completed = len(stmts)
	}
	if completed == 0 {
		return
	}
	pc.refreshCatalogForStatements(ctx, stmts[:completed])
}

func (pc *proxyConn) refreshCatalogForStatements(ctx context.Context, stmts []effects.ClassifiedStatement) {
	searchPath, snapshot := statementsNeedCatalogRefresh(stmts)
	snapshot = snapshot || pc.state.catalogSnapshotRefreshPending
	if !searchPath && !snapshot {
		return
	}
	if snapshot && pc.catalogSnapshotRefreshMustWait() {
		pc.markCatalogRefreshPendingForNeeds(searchPath, true)
		return
	}
	pc.refreshCatalogContext(ctx, snapshot)
}

func (pc *proxyConn) markCatalogRefreshPending(stmts []effects.ClassifiedStatement) {
	searchPath, snapshot := statementsNeedCatalogRefresh(stmts)
	pc.markCatalogRefreshPendingForNeeds(searchPath, snapshot)
}

func (pc *proxyConn) markCatalogRefreshPendingForNeeds(searchPath, snapshot bool) {
	if !searchPath && !snapshot {
		return
	}
	pc.state.catalogRefreshPending = true
	pc.state.catalogSnapshotRefreshPending = pc.state.catalogSnapshotRefreshPending || snapshot
	pc.state.catalog.UnavailableReason = catalogSessionStateChangedReason
	pc.state.catalog.SearchPath = nil
}

func (pc *proxyConn) refreshPendingCatalogContext(ctx context.Context) {
	if !pc.state.catalogRefreshPending {
		return
	}
	refreshSnapshot := pc.state.catalogSnapshotRefreshPending
	if refreshSnapshot && pc.catalogSnapshotRefreshMustWait() {
		pc.state.catalog.UnavailableReason = catalogSessionStateChangedReason
		pc.state.catalog.SearchPath = nil
		return
	}
	pc.state.catalogRefreshPending = false
	pc.state.catalogSnapshotRefreshPending = false
	pc.refreshCatalogContext(ctx, refreshSnapshot)
}

func (pc *proxyConn) refreshCatalogContext(ctx context.Context, refreshSnapshot bool) {
	if pc.srv == nil || pc.srv.catalogStore == nil {
		pc.state.catalog = catalogRuntimeContext{UnavailableReason: "catalog_store_unavailable"}
		return
	}
	if refreshSnapshot {
		pc.state.catalog = pc.srv.catalogStore.refresh(ctx, pc)
	} else {
		pc.state.catalog = pc.srv.catalogStore.refreshSearchPath(ctx, pc)
	}
	if pc.state.catalog.UnavailableReason != "" {
		pc.emitCatalogUnavailable(ctx, pc.state.catalog.UnavailableReason)
	}
	pc.state.catalogRefreshPending = false
	pc.state.catalogSnapshotRefreshPending = false
}

func (pc *proxyConn) catalogSnapshotRefreshMustWait() bool {
	if pc.state == nil || pc.state.smState == nil {
		return false
	}
	switch pc.state.smState.LastUpstreamRFQ {
	case 'T', 'E':
		return true
	default:
		return false
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
