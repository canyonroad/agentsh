//go:build linux

package postgres

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/statemachine"
	"github.com/agentsh/agentsh/internal/db/service"
)

type fakeApprover struct {
	mu      sync.Mutex
	calls   int
	approve bool
	hold    time.Duration
}

func (f *fakeApprover) Decide(ctx context.Context, _ effects.ClassifiedStatement, _ time.Duration) (bool, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.hold > 0 {
		select {
		case <-time.After(f.hold):
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	return f.approve, nil
}

func TestNew_DefaultsApproverToNop(t *testing.T) {
	srv, err := New(Config{
		Unavoidability: service.UnavoidabilityOff,
		StateDir:       t.TempDir(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := srv.cfg.Approver.(policy.NopApprover); !ok {
		t.Fatalf("Approver = %T want policy.NopApprover", srv.cfg.Approver)
	}
}

func approveDeletesRuleSet(t *testing.T, timeout string) *policy.RuleSet {
	t.Helper()
	if timeout == "" {
		timeout = "60s"
	}
	return loadRuleSet(t, `version: 1
name: test
db_services:
  test:
    family: postgres
    dialect: postgres
    upstream: 127.0.0.1:5432
    tls_mode: terminate_reissue
database_rules:
  - name: review-delete
    db_service: test
    operations: [DELETE]
    decision: approve
    timeout: `+timeout+`
`)
}

func TestHandleQuery_ApprovalApprove_ForwardsAndEmitsApprove(t *testing.T) {
	pc, clientFE, sink, script := allowPathFixture(t)
	pc.state.smState.LastUpstreamRFQ = 'I'
	pc.srv.SetPolicy(approveDeletesRuleSet(t, "100ms"))
	pc.srv.cfg.Approver = &fakeApprover{approve: true}

	script([]pgproto3.BackendMessage{
		&pgproto3.CommandComplete{CommandTag: []byte("DELETE 1")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	})

	loopErr := make(chan error, 1)
	go func() { loopErr <- pc.simpleQueryLoop(context.Background()) }()

	mustSendFromClient(t, clientFE, &pgproto3.Query{String: "DELETE FROM t"})
	frames := drainNFrames(t, clientFE, 2)
	if _, ok := frames[1].(*pgproto3.ReadyForQuery); !ok {
		t.Fatalf("last frame = %T want ReadyForQuery", frames[1])
	}

	evs := waitStatementEvents(t, sink, 1)
	if evs[0].Decision.Verb != "approve" {
		t.Fatalf("Decision.Verb = %q want approve", evs[0].Decision.Verb)
	}
	if evs[0].Decision.RuleName != "review-delete" {
		t.Fatalf("RuleName = %q want review-delete", evs[0].Decision.RuleName)
	}
	_ = loopErr
}

func TestHandleQuery_ApprovalDenied_RoutesDeny(t *testing.T) {
	pc, clientFE, sink := newSimpleQueryFixture(t)
	pc.state.smState.LastUpstreamRFQ = 'I'
	pc.srv.SetPolicy(approveDeletesRuleSet(t, "100ms"))
	pc.srv.cfg.Approver = &fakeApprover{approve: false}

	loopErr := make(chan error, 1)
	go func() { loopErr <- pc.simpleQueryLoop(context.Background()) }()

	mustSendFromClient(t, clientFE, &pgproto3.Query{String: "DELETE FROM t"})
	er := mustReceiveClientFrame(t, clientFE).(*pgproto3.ErrorResponse)
	if er.Code != "42501" {
		t.Fatalf("Code = %q want 42501", er.Code)
	}
	_ = mustReceiveClientFrame(t, clientFE).(*pgproto3.ReadyForQuery)

	evs := waitStatementEvents(t, sink, 1)
	if evs[0].Decision.Verb != "deny" {
		t.Fatalf("Decision.Verb = %q want deny", evs[0].Decision.Verb)
	}
	if evs[0].TxContext.DenyAction != "approval_denied" {
		t.Fatalf("DenyAction = %q want approval_denied", evs[0].TxContext.DenyAction)
	}
	_ = loopErr
}

func TestHandleQuery_ApprovalTimeout_RoutesDeny(t *testing.T) {
	pc, clientFE, sink := newSimpleQueryFixture(t)
	pc.state.smState.LastUpstreamRFQ = 'I'
	pc.srv.SetPolicy(approveDeletesRuleSet(t, "20ms"))
	pc.srv.cfg.Approver = &fakeApprover{approve: true, hold: time.Second}

	loopErr := make(chan error, 1)
	go func() { loopErr <- pc.simpleQueryLoop(context.Background()) }()

	start := time.Now()
	mustSendFromClient(t, clientFE, &pgproto3.Query{String: "DELETE FROM t"})
	_ = mustReceiveClientFrame(t, clientFE).(*pgproto3.ErrorResponse)
	_ = mustReceiveClientFrame(t, clientFE).(*pgproto3.ReadyForQuery)
	if elapsed := time.Since(start); elapsed < 15*time.Millisecond {
		t.Fatalf("approval returned too quickly: %v", elapsed)
	}

	evs := waitStatementEvents(t, sink, 1)
	if evs[0].TxContext.DenyAction != "approval_timeout" {
		t.Fatalf("DenyAction = %q want approval_timeout", evs[0].TxContext.DenyAction)
	}
	_ = loopErr
}

func TestHandleQuery_NopApproverTimeout_RoutesApprovalTimeout(t *testing.T) {
	pc, clientFE, sink := newSimpleQueryFixture(t)
	pc.state.smState.LastUpstreamRFQ = 'I'
	pc.srv.SetPolicy(approveDeletesRuleSet(t, "20ms"))

	loopErr := make(chan error, 1)
	go func() { loopErr <- pc.simpleQueryLoop(context.Background()) }()

	mustSendFromClient(t, clientFE, &pgproto3.Query{String: "DELETE FROM t"})
	_ = mustReceiveClientFrame(t, clientFE).(*pgproto3.ErrorResponse)
	_ = mustReceiveClientFrame(t, clientFE).(*pgproto3.ReadyForQuery)

	evs := waitStatementEvents(t, sink, 1)
	if evs[0].TxContext.DenyAction != "approval_timeout" {
		t.Fatalf("DenyAction = %q want approval_timeout", evs[0].TxContext.DenyAction)
	}
	_ = loopErr
}

func waitStatementEvents(t *testing.T, sink *events.SyncSink, want int) []events.DBEvent {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		evs := sink.DrainStatements()
		if len(evs) >= want {
			return evs
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d statement events", want)
	return nil
}

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
