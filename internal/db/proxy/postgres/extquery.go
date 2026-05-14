//go:build linux

package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgproto3"

	classify_pg "github.com/agentsh/agentsh/internal/db/classify/postgres"
	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/preparedcache"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/statemachine"
)

// handleExtendedFrame translates a pgproto3 frontend frame into a Transition
// invocation and executes the returned Actions against the per-connection
// I/O. Called from simpleQueryLoop for Parse/Bind/Describe/Execute/Sync/
// Flush/Close. The existing handleQuery (Q) and handleUnsupportedFrame
// (FunctionCall, etc.) paths are unchanged in Plan 05a.
func (pc *proxyConn) handleExtendedFrame(ctx context.Context, msg pgproto3.FrontendMessage) error {
	frame := frameFromPgproto(msg)
	if frame == nil {
		return pc.handleUnsupportedFrame(ctx, msg)
	}
	wireView := wireCacheView{c: pc.wireCache}
	parser := pc.resolvingParser(pc.svc.Dialect)
	rs := pc.srv.policy()
	opts := classifierOptionsFromPolicy(rs)
	var parseStmts []effects.ClassifiedStatement
	parse, isParse := msg.(*pgproto3.Parse)
	if isParse {
		parseStmts, _ = parser.Classify(parse.Query, classify_pg.SessionState{}, opts)
	}
	next, actions := statemachine.TransitionWithParser(
		*pc.state.smState,
		frame,
		wireView,
		rs,
		policy.ServiceID(pc.svc.Name),
		parser,
		opts,
	)
	*pc.state.smState = next
	if isParse && len(parseStmts) > 0 && actionsCanForward(actions) {
		searchPath, snapshot := statementsNeedCatalogRefresh(parseStmts)
		pc.wireCache.Put(parse.Name, preparedcache.Entry{
			Classification:           parseStmts[0],
			CatalogRefreshSearchPath: searchPath,
			CatalogRefreshSnapshot:   snapshot,
		})
	}
	if exec, ok := msg.(*pgproto3.Execute); ok {
		pc.markCatalogRefreshPendingForExecute(exec, actions)
	}
	return pc.executeActions(ctx, msg, actions)
}

// executeActions runs each Action against the per-connection I/O.
// origFrame is the original frontend frame, used for ActionForward.
func (pc *proxyConn) executeActions(ctx context.Context, origFrame pgproto3.FrontendMessage, actions []statemachine.Action) error {
	for _, act := range actions {
		switch a := act.(type) {
		case *statemachine.ActionForward:
			if pc.state.upstreamFE == nil {
				return fmt.Errorf("postgres.executeActions: upstreamFE not initialized")
			}
			pc.state.upstreamFE.Send(origFrame)
			if err := pc.state.upstreamFE.Flush(); err != nil {
				return fmt.Errorf("upstream flush: %w", err)
			}
		case *statemachine.ActionSynthError:
			severity := a.Severity
			if severity == "" {
				severity = "ERROR"
			}
			pc.backend.Send(&pgproto3.ErrorResponse{
				Severity:            severity,
				SeverityUnlocalized: severity,
				Code:                a.SQLState,
				Message:             a.Message,
			})
			if err := pc.backend.Flush(); err != nil {
				return fmt.Errorf("client flush: %w", err)
			}
		case *statemachine.ActionSynthReadyForQuery:
			pc.backend.Send(&pgproto3.ReadyForQuery{TxStatus: a.Status})
			if err := pc.backend.Flush(); err != nil {
				return fmt.Errorf("client flush rfq: %w", err)
			}
		case *statemachine.ActionSynthParseComplete:
			pc.backend.Send(&pgproto3.ParseComplete{})
		case *statemachine.ActionSynthBindComplete:
			pc.backend.Send(&pgproto3.BindComplete{})
		case *statemachine.ActionSuppress:
			// drop on the floor
		case *statemachine.ActionInjectRollback:
			if pc.state.upstreamFE == nil {
				return fmt.Errorf("postgres.executeActions: upstreamFE not initialized for ROLLBACK")
			}
			pc.state.upstreamFE.Send(&pgproto3.Query{String: "ROLLBACK"})
			if err := pc.state.upstreamFE.Flush(); err != nil {
				return fmt.Errorf("upstream flush rollback: %w", err)
			}
		case *statemachine.ActionDrainUntilRFQ:
			if _, err := pc.forwardUpstreamUntilRFQ(ctx, timeNow(), 0); err != nil {
				return fmt.Errorf("drain: %w", err)
			}
			pc.refreshPendingCatalogContext(ctx)
		case *statemachine.ActionClose:
			pc.closeUpstream()
			return errInTxTerminate
		case *statemachine.ActionTrackUpstreamRFQ:
			pc.state.smState.LastUpstreamRFQ = a.Status
		case *statemachine.ActionApproverWait:
			if err := pc.runApprovalWait(ctx, origFrame, *a); err != nil {
				return err
			}
		default:
			return fmt.Errorf("postgres: unknown statemachine action %T", a)
		}
	}
	return nil
}

func actionsCanForward(actions []statemachine.Action) bool {
	for _, act := range actions {
		if _, ok := act.(*statemachine.ActionForward); ok {
			return true
		}
	}
	return false
}

func (pc *proxyConn) markCatalogRefreshPendingForExecute(exec *pgproto3.Execute, actions []statemachine.Action) {
	if exec == nil || pc.wireCache == nil || !actionsCanForward(actions) {
		return
	}
	entry, ok := pc.wireCache.Get(wirePortalCacheKey(exec.Portal))
	if !ok {
		return
	}
	pc.markCatalogRefreshPendingForNeeds(entry.CatalogRefreshSearchPath, entry.CatalogRefreshSnapshot)
}

func (pc *proxyConn) cacheApprovedParse(parse *pgproto3.Parse, stmt effects.ClassifiedStatement) {
	if parse == nil || pc.wireCache == nil {
		return
	}
	searchPath, snapshot := statementsNeedCatalogRefresh([]effects.ClassifiedStatement{stmt})
	pc.wireCache.Put(parse.Name, preparedcache.Entry{
		Classification:           stmt,
		CatalogRefreshSearchPath: searchPath,
		CatalogRefreshSnapshot:   snapshot,
	})
	if pc.state != nil && pc.state.smState != nil {
		pc.state.smState.UpstreamDirtySinceSync = true
	}
}

func wirePortalCacheKey(name string) string {
	return "\x00portal:" + name
}

// frameFromPgproto converts a pgproto3.FrontendMessage to a statemachine.Frame.
// Returns nil for messages the Plan 05a dispatcher does not handle
// (FunctionCall, CopyData/Done/Fail) so those still route through
// handleUnsupportedFrame.
func frameFromPgproto(msg pgproto3.FrontendMessage) statemachine.Frame {
	switch m := msg.(type) {
	case *pgproto3.Query:
		return &statemachine.QueryFrame{SQL: m.String}
	case *pgproto3.Parse:
		return &statemachine.ParseFrame{Name: m.Name, SQL: m.Query}
	case *pgproto3.Bind:
		return &statemachine.BindFrame{Portal: m.DestinationPortal, Statement: m.PreparedStatement}
	case *pgproto3.Describe:
		return &statemachine.DescribeFrame{ObjectType: m.ObjectType, Name: m.Name}
	case *pgproto3.Execute:
		return &statemachine.ExecuteFrame{Portal: m.Portal}
	case *pgproto3.Sync:
		return &statemachine.SyncFrame{}
	case *pgproto3.Flush:
		return &statemachine.FlushFrame{}
	case *pgproto3.Close:
		return &statemachine.CloseFrame{ObjectType: m.ObjectType, Name: m.Name}
	case *pgproto3.Terminate:
		return &statemachine.TerminateFrame{}
	default:
		return nil
	}
}

// wireCacheView adapts *preparedcache.Cache to statemachine.CacheView, with
// a CacheValue ↔ preparedcache.Entry conversion at the boundary.
type wireCacheView struct {
	c *preparedcache.Cache
}

func (v wireCacheView) Get(name string) (statemachine.CacheValue, bool) {
	e, ok := v.c.Get(name)
	if !ok {
		return statemachine.CacheValue{}, false
	}
	return statemachine.CacheValue{
		Verb:                     e.Classification.RawVerb,
		GroupID:                  groupIDFromClassification(e.Classification),
		CatalogRefreshSearchPath: e.CatalogRefreshSearchPath,
		CatalogRefreshSnapshot:   e.CatalogRefreshSnapshot,
	}, true
}

func (v wireCacheView) Put(name string, val statemachine.CacheValue) {
	// On Put, the state machine has the minimal CacheValue but not the full
	// ClassifiedStatement. Reconstruct a partial Entry — the classifier
	// re-evaluates at the dispatcher boundary if needed.
	v.c.Put(name, preparedcache.Entry{
		Classification:           effects.ClassifiedStatement{RawVerb: val.Verb},
		CatalogRefreshSearchPath: val.CatalogRefreshSearchPath,
		CatalogRefreshSnapshot:   val.CatalogRefreshSnapshot,
	})
}

func (v wireCacheView) Delete(name string) { v.c.Delete(name) }
func (v wireCacheView) Clear()             { v.c.Clear() }

func groupIDFromClassification(cs effects.ClassifiedStatement) uint8 {
	if len(cs.Effects) == 0 {
		return 0
	}
	return uint8(cs.Effects[0].Group)
}
