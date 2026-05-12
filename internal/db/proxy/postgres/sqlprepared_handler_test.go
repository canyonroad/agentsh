//go:build linux

package postgres

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/events"
)

// preparePolicyYAML returns a policy that allows all reads but denies DELETE.
// Operations are matched by effect group, so PREPARE_DELETE (which has
// GroupDelete effects) is denied, while PREPARE_SELECT is allowed.
func preparePolicyYAML() string {
	return `version: 1
name: test
db_services:
  test:
    family: postgres
    dialect: postgres
    upstream: 127.0.0.1:5432
    tls_mode: terminate_reissue
database_rules:
  - name: allow-all
    db_service: test
    operations: ["*"]
    decision: allow
  - name: deny-deletes
    db_service: test
    operations: [DELETE]
    decision: deny
`
}

// multiQueryUpstreamFixture builds a proxyConn with an upstream net.Pipe whose
// server side responds to a series of scripted frames per Query received.
// responses is a list of frame sequences, one slice per Q received in order.
func multiQueryUpstreamFixture(t *testing.T, responses [][]pgproto3.BackendMessage) (*proxyConn, *pgproto3.Frontend, *events.SyncSink) {
	t.Helper()
	pc, clientFE, sink := newSimpleQueryFixture(t)
	upClient, upServer := net.Pipe()
	t.Cleanup(func() { _ = upClient.Close(); _ = upServer.Close() })
	pc.state.upstream = upServer
	pc.state.upstreamFE = pgproto3.NewFrontend(upServer, upServer)

	go func() {
		be := pgproto3.NewBackend(upClient, upClient)
		for _, msgs := range responses {
			// Receive and discard the inbound Q.
			if _, err := be.Receive(); err != nil {
				return
			}
			for _, m := range msgs {
				be.Send(m)
			}
			if err := be.Flush(); err != nil {
				return
			}
		}
		// Drain remaining bytes until pipe closes.
		buf := make([]byte, 256)
		for {
			_ = upClient.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			if _, err := upClient.Read(buf); err != nil {
				return
			}
		}
	}()

	return pc, clientFE, sink
}

// TestSQLPreparedHandler_PrepareDeny_InterceptedNotForwarded asserts that when
// a policy denies DELETE and the client sends PREPARE x AS DELETE FROM users:
//   - The proxy returns an error (SQLSTATE 42501) without forwarding upstream.
//   - The sink records a deny event for the PREPARE.
//   - A subsequent EXECUTE x gets a cache-miss error (26000), proving the cache
//     was not populated.
func TestSQLPreparedHandler_PrepareDeny_InterceptedNotForwarded(t *testing.T) {
	var (
		mu              sync.Mutex
		upstreamSawAny  bool
	)

	pc, clientFE, sink := newSimpleQueryFixture(t)
	// Wire up an upstream that records if it sees any Q frames.
	upClient, upServer := net.Pipe()
	t.Cleanup(func() { _ = upClient.Close(); _ = upServer.Close() })
	pc.state.upstream = upServer
	pc.state.upstreamFE = pgproto3.NewFrontend(upServer, upServer)

	go func() {
		be := pgproto3.NewBackend(upClient, upClient)
		_ = upClient.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := be.Receive(); err == nil {
			mu.Lock()
			upstreamSawAny = true
			mu.Unlock()
		}
	}()

	pc.state.smState.LastUpstreamRFQ = 'I'
	pc.srv.SetPolicy(loadRuleSet(t, preparePolicyYAML()))

	loopErr := make(chan error, 1)
	go func() { loopErr <- pc.simpleQueryLoop(context.Background()) }()

	// Send PREPARE x AS DELETE FROM users — should be denied.
	mustSendFromClient(t, clientFE, &pgproto3.Query{String: "PREPARE x AS DELETE FROM users"})

	er := mustReceiveClientFrame(t, clientFE)
	errResp, ok := er.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", er)
	}
	if errResp.Code != "42501" {
		t.Fatalf("SQLSTATE = %q want 42501 (insufficient_privilege)", errResp.Code)
	}
	// RFQ must follow (pre-tx deny).
	rfq := mustReceiveClientFrame(t, clientFE)
	if _, ok := rfq.(*pgproto3.ReadyForQuery); !ok {
		t.Fatalf("expected ReadyForQuery after PREPARE deny, got %T", rfq)
	}

	// The upstream must NOT have seen the PREPARE Q.
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	saw := upstreamSawAny
	mu.Unlock()
	if saw {
		t.Fatal("upstream saw a Query frame; PREPARE deny must not forward")
	}

	// Sink must record a deny event for the PREPARE.
	var evs []events.DBEvent
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		evs = sink.DrainStatements()
		if len(evs) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(evs) != 1 {
		t.Fatalf("statement events = %d want 1", len(evs))
	}
	if evs[0].Decision.Verb != "deny" {
		t.Fatalf("event Verb = %q want deny", evs[0].Decision.Verb)
	}

	// Send EXECUTE x — must get cache-miss error (26000) because PREPARE was
	// denied and cache was not populated.
	mustSendFromClient(t, clientFE, &pgproto3.Query{String: "EXECUTE x"})

	er2 := mustReceiveClientFrame(t, clientFE)
	missResp, ok := er2.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("expected ErrorResponse for EXECUTE after denied PREPARE, got %T", er2)
	}
	if missResp.Code != "26000" {
		t.Fatalf("EXECUTE cache-miss SQLSTATE = %q want 26000", missResp.Code)
	}
}

// TestSQLPreparedHandler_PrepareAllow_PopulatesCache_ExecuteHits asserts that
// with an allow-all policy, PREPARE s1 AS SELECT * FROM users followed by
// EXECUTE s1:
//   - Both produce no error responses; the upstream receives and answers both.
//   - The sink records two allow events.
//
// We use a table-qualified SELECT so the effect has objects (a bare "SELECT 1"
// has no objects and the "["*"]" allow rule cannot cover it).
func TestSQLPreparedHandler_PrepareAllow_PopulatesCache_ExecuteHits(t *testing.T) {
	// The upstream receives Q("PREPARE ...") then Q("EXECUTE ...") in sequence.
	responses := [][]pgproto3.BackendMessage{
		// Reply to PREPARE s1 AS SELECT * FROM users
		{
			&pgproto3.CommandComplete{CommandTag: []byte("PREPARE")},
			&pgproto3.ReadyForQuery{TxStatus: 'I'},
		},
		// Reply to EXECUTE s1
		{
			&pgproto3.DataRow{Values: [][]byte{[]byte("alice")}},
			&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
			&pgproto3.ReadyForQuery{TxStatus: 'I'},
		},
	}
	pc, clientFE, sink := multiQueryUpstreamFixture(t, responses)
	pc.state.smState.LastUpstreamRFQ = 'I'
	pc.srv.SetPolicy(allowAllRuleSet(t))

	loopErr := make(chan error, 1)
	go func() { loopErr <- pc.simpleQueryLoop(context.Background()) }()

	// Send PREPARE s1 AS SELECT * FROM users.
	mustSendFromClient(t, clientFE, &pgproto3.Query{String: "PREPARE s1 AS SELECT * FROM users"})

	// Expect CommandComplete + ReadyForQuery forwarded from upstream.
	f1 := mustReceiveClientFrame(t, clientFE)
	if _, ok := f1.(*pgproto3.CommandComplete); !ok {
		t.Fatalf("PREPARE: expected CommandComplete, got %T", f1)
	}
	f2 := mustReceiveClientFrame(t, clientFE)
	if _, ok := f2.(*pgproto3.ReadyForQuery); !ok {
		t.Fatalf("PREPARE: expected ReadyForQuery, got %T", f2)
	}

	// Send EXECUTE s1 — cache hit; proxy rewrites classification to SELECT/users
	// effects, evaluates (allow), and forwards upstream.
	mustSendFromClient(t, clientFE, &pgproto3.Query{String: "EXECUTE s1"})

	// Expect DataRow + CommandComplete + ReadyForQuery.
	e1 := mustReceiveClientFrame(t, clientFE)
	if _, ok := e1.(*pgproto3.DataRow); !ok {
		t.Fatalf("EXECUTE: expected DataRow, got %T", e1)
	}
	e2 := mustReceiveClientFrame(t, clientFE)
	if _, ok := e2.(*pgproto3.CommandComplete); !ok {
		t.Fatalf("EXECUTE: expected CommandComplete, got %T", e2)
	}
	e3 := mustReceiveClientFrame(t, clientFE)
	if _, ok := e3.(*pgproto3.ReadyForQuery); !ok {
		t.Fatalf("EXECUTE: expected ReadyForQuery, got %T", e3)
	}

	// Assert sink has two allow events (one for PREPARE, one for EXECUTE).
	var evs []events.DBEvent
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		evs = append(evs, sink.DrainStatements()...)
		if len(evs) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(evs) < 2 {
		t.Fatalf("statement events = %d want >= 2: %+v", len(evs), evs)
	}
	for i, ev := range evs {
		if ev.Decision.Verb != "allow" {
			t.Errorf("evs[%d].Decision.Verb = %q want allow", i, ev.Decision.Verb)
		}
	}
	_ = loopErr
}

// TestSQLPreparedHandler_ExecuteMiss_Returns26000 asserts that with an allow-all
// policy and no prior PREPARE, sending EXECUTE missing returns SQLSTATE 26000
// and no upstream query is forwarded.
func TestSQLPreparedHandler_ExecuteMiss_Returns26000(t *testing.T) {
	var (
		mu             sync.Mutex
		upstreamSawAny bool
	)

	pc, clientFE, sink := newSimpleQueryFixture(t)
	upClient, upServer := net.Pipe()
	t.Cleanup(func() { _ = upClient.Close(); _ = upServer.Close() })
	pc.state.upstream = upServer
	pc.state.upstreamFE = pgproto3.NewFrontend(upServer, upServer)

	go func() {
		be := pgproto3.NewBackend(upClient, upClient)
		_ = upClient.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := be.Receive(); err == nil {
			mu.Lock()
			upstreamSawAny = true
			mu.Unlock()
		}
	}()

	pc.state.smState.LastUpstreamRFQ = 'I'
	pc.srv.SetPolicy(allowAllRuleSet(t))

	loopErr := make(chan error, 1)
	go func() { loopErr <- pc.simpleQueryLoop(context.Background()) }()

	mustSendFromClient(t, clientFE, &pgproto3.Query{String: "EXECUTE missing"})

	er := mustReceiveClientFrame(t, clientFE)
	errResp, ok := er.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("expected ErrorResponse for EXECUTE miss, got %T", er)
	}
	if errResp.Code != "26000" {
		t.Fatalf("SQLSTATE = %q want 26000 (invalid_sql_statement_name)", errResp.Code)
	}
	// RFQ must follow.
	rfq := mustReceiveClientFrame(t, clientFE)
	if _, ok := rfq.(*pgproto3.ReadyForQuery); !ok {
		t.Fatalf("expected ReadyForQuery after EXECUTE miss, got %T", rfq)
	}

	// The upstream must NOT have seen the EXECUTE Q.
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	saw := upstreamSawAny
	mu.Unlock()
	if saw {
		t.Fatal("upstream saw a Query frame; EXECUTE cache-miss must not forward")
	}

	// No statement events should be emitted for cache-miss (it's a proxy-side
	// synthetic error, not a policy decision).
	evs := sink.DrainStatements()
	if len(evs) != 0 {
		t.Fatalf("unexpected statement events for EXECUTE miss: %+v", evs)
	}
	_ = loopErr
}
