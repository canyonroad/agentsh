//go:build linux

package postgres

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/service"
)

// newSimpleQueryFixture builds a *proxyConn wired to a client-side net.Pipe.
// No upstream connection is established (caller wires one if needed via
// newSimpleQueryFixtureWithUpstream). Returns the client-side Frontend so
// the test can send/receive frames.
func newSimpleQueryFixture(t *testing.T) (*proxyConn, *pgproto3.Frontend, *events.SyncSink) {
	t.Helper()
	clientPipe, proxyPipe := net.Pipe()
	t.Cleanup(func() { _ = clientPipe.Close(); _ = proxyPipe.Close() })

	sink := &events.SyncSink{}
	srv, err := New(Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           sink,
		Services: []Service{{
			Name:     "test",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: "127.0.0.1:5432",
			TLSMode:  "terminate_reissue",
			Listen:   ServiceListener{Kind: "unix", Path: t.TempDir() + "/test.sock"},
			Service:  policy.DBService{Name: "test", TLSMode: "terminate_reissue"},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	svc := srv.cfg.Services[0]
	pc := newProxyConn(srv, svc, proxyPipe, uint32(os.Getuid()))
	clientFE := pgproto3.NewFrontend(clientPipe, clientPipe)
	return pc, clientFE, sink
}

// newSimpleQueryFixtureWithUpstream additionally wires an upstream net.Pipe
// for tests that need to forward (e.g., Terminate forwarding). Drains the
// upstream side so writes don't block.
func newSimpleQueryFixtureWithUpstream(t *testing.T) (*proxyConn, *pgproto3.Frontend, *events.SyncSink) {
	pc, clientFE, sink := newSimpleQueryFixture(t)
	upClient, upServer := net.Pipe()
	t.Cleanup(func() { _ = upClient.Close(); _ = upServer.Close() })
	pc.state.upstream = upServer
	pc.state.upstreamFE = pgproto3.NewFrontend(upServer, upServer)
	go func() {
		b := make([]byte, 4096)
		for {
			if _, err := upClient.Read(b); err != nil {
				return
			}
		}
	}()
	return pc, clientFE, sink
}

func mustSendFromClient(t *testing.T, fe *pgproto3.Frontend, m pgproto3.FrontendMessage) {
	t.Helper()
	fe.Send(m)
	if err := fe.Flush(); err != nil {
		t.Fatalf("client send: %v", err)
	}
}

func mustReceiveClientFrame(t *testing.T, fe *pgproto3.Frontend) pgproto3.BackendMessage {
	t.Helper()
	m, err := fe.Receive()
	if err != nil {
		t.Fatalf("client recv: %v", err)
	}
	return m
}

func TestSimpleQueryLoop_RejectsExtendedQuery(t *testing.T) {
	pc, clientFE, sink := newSimpleQueryFixture(t)
	pc.state.lastUpstreamRFQ = 'I'

	// Run simpleQueryLoop in a goroutine — net.Pipe is synchronous, so the
	// ErrorResponse write blocks until the test reads it below.
	loopErr := make(chan error, 1)
	go func() { loopErr <- pc.simpleQueryLoop(context.Background()) }()

	// Client sends Parse after the loop is running.
	mustSendFromClient(t, clientFE, &pgproto3.Parse{Name: "s1", Query: "SELECT 1"})

	msg := mustReceiveClientFrame(t, clientFE)
	er, ok := msg.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("unexpected first frame: %T", msg)
	}
	if er.Code != "0A000" {
		t.Fatalf("Code = %q want 0A000", er.Code)
	}

	if err := <-loopErr; err == nil {
		t.Fatalf("simpleQueryLoop: want non-nil error on extended-query frame")
	}

	evs := sink.DrainLifecycle()
	if len(evs) != 1 || evs[0].Kind != "db_handshake_fail" {
		t.Fatalf("lifecycle events = %+v", evs)
	}
	if evs[0].ErrorCode != "EXTENDED_QUERY_NOT_SUPPORTED" {
		t.Fatalf("ErrorCode = %q want EXTENDED_QUERY_NOT_SUPPORTED", evs[0].ErrorCode)
	}
}

func TestSimpleQueryLoop_RejectsFunctionCall(t *testing.T) {
	pc, clientFE, sink := newSimpleQueryFixture(t)
	pc.state.lastUpstreamRFQ = 'I'

	// Run loop in goroutine so ErrorResponse write doesn't deadlock.
	loopErr := make(chan error, 1)
	go func() { loopErr <- pc.simpleQueryLoop(context.Background()) }()

	mustSendFromClient(t, clientFE, &pgproto3.FunctionCall{Function: 1234})

	msg := mustReceiveClientFrame(t, clientFE)
	er, ok := msg.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("unexpected first frame: %T", msg)
	}
	if er.Code != "42501" {
		t.Fatalf("Code = %q want 42501", er.Code)
	}

	if err := <-loopErr; err == nil {
		t.Fatalf("simpleQueryLoop: want non-nil error on FunctionCall")
	}

	evs := sink.DrainLifecycle()
	if len(evs) != 1 || evs[0].ErrorCode != "FUNCTION_CALL_PROTOCOL_DENIED" {
		t.Fatalf("lifecycle events = %+v", evs)
	}
}

func TestSimpleQueryLoop_TerminateForwarded(t *testing.T) {
	pc, clientFE, _ := newSimpleQueryFixtureWithUpstream(t)
	pc.state.lastUpstreamRFQ = 'I'

	loopErr := make(chan error, 1)
	go func() { loopErr <- pc.simpleQueryLoop(context.Background()) }()

	mustSendFromClient(t, clientFE, &pgproto3.Terminate{})

	if err := <-loopErr; err != nil {
		t.Fatalf("simpleQueryLoop on Terminate: %v", err)
	}
}

func TestHandleQuery_FrameTooLarge(t *testing.T) {
	pc, clientFE, sink := newSimpleQueryFixture(t)
	pc.state.lastUpstreamRFQ = 'I'
	pc.srv.cfg.MaxQueryBytes = 32

	big := &pgproto3.Query{String: strings.Repeat("SELECT 1; ", 10)} // > 32 bytes

	loopErr := make(chan error, 1)
	go func() { loopErr <- pc.simpleQueryLoop(context.Background()) }()

	mustSendFromClient(t, clientFE, big)

	msg := mustReceiveClientFrame(t, clientFE)
	er, ok := msg.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("first frame = %T want ErrorResponse", msg)
	}
	if er.Code != "54000" {
		t.Fatalf("Code = %q want 54000", er.Code)
	}

	rfq := mustReceiveClientFrame(t, clientFE)
	if _, ok := rfq.(*pgproto3.ReadyForQuery); !ok {
		t.Fatalf("expected ReadyForQuery after FRAME_TOO_LARGE, got %T", rfq)
	}

	if err := <-loopErr; err == nil {
		t.Fatalf("simpleQueryLoop on oversized Q: want err, got nil")
	}

	ev := sink.DrainLifecycle()
	if len(ev) != 1 || ev[0].ErrorCode != "FRAME_TOO_LARGE" {
		t.Fatalf("lifecycle = %+v", ev)
	}
}

// allowAllRuleSet returns a RuleSet that allows all read/write effects on
// service "test" (the dialect used by newSimpleQueryFixture). Uses the
// shared loadRuleSet helper from connect_rule_test.go.
func allowAllRuleSet(t *testing.T) *policy.RuleSet {
	return loadRuleSet(t, `version: 1
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
`)
}

// allowPathFixture extends newSimpleQueryFixture with an upstream pipe whose
// fake-server goroutine reads inbound from the proxy before scripting a
// response. The returned `script` writes the supplied frames to the upstream
// side after one inbound frame is received.
func allowPathFixture(t *testing.T) (pc *proxyConn, clientFE *pgproto3.Frontend, sink *events.SyncSink, script func([]pgproto3.BackendMessage)) {
	pc, clientFE, sink = newSimpleQueryFixture(t)
	up1, up2 := net.Pipe()
	t.Cleanup(func() { _ = up1.Close(); _ = up2.Close() })
	pc.state.upstream = up2
	pc.state.upstreamFE = pgproto3.NewFrontend(up2, up2)
	script = func(msgs []pgproto3.BackendMessage) {
		go func() {
			be := pgproto3.NewBackend(up1, up1)
			// Receive the proxy's 'Q' first.
			if _, err := be.Receive(); err != nil {
				return
			}
			for _, m := range msgs {
				be.Send(m)
			}
			_ = be.Flush()
		}()
	}
	return pc, clientFE, sink, script
}

func drainNFrames(t *testing.T, fe *pgproto3.Frontend, n int) []pgproto3.BackendMessage {
	t.Helper()
	out := make([]pgproto3.BackendMessage, 0, n)
	for i := 0; i < n; i++ {
		m, err := fe.Receive()
		if err != nil {
			t.Fatalf("Receive[%d]: %v", i, err)
		}
		out = append(out, m)
	}
	return out
}

func TestHandleQuery_AllowPath_ForwardsAndEmits(t *testing.T) {
	pc, clientFE, sink, script := allowPathFixture(t)
	pc.state.lastUpstreamRFQ = 'I'
	pc.srv.SetPolicy(allowAllRuleSet(t))

	script([]pgproto3.BackendMessage{
		&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("a")}}},
		&pgproto3.DataRow{Values: [][]byte{[]byte("1")}},
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	})

	loopErr := make(chan error, 1)
	go func() { loopErr <- pc.simpleQueryLoop(context.Background()) }()

	mustSendFromClient(t, clientFE, &pgproto3.Query{String: "SELECT a FROM t"})

	frames := drainNFrames(t, clientFE, 4)
	if _, ok := frames[3].(*pgproto3.ReadyForQuery); !ok {
		t.Fatalf("last frame = %T want ReadyForQuery", frames[3])
	}

	// Allow simpleQueryLoop a tick to emit the event (it does emit *after*
	// forwardUpstreamUntilRFQ returns). Then close the client side to unblock
	// the loop's next Receive — it should return EOF.
	// Simplest: drain the sink with a small retry to tolerate scheduling.
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
	if evs[0].Decision.Verb != "allow" {
		t.Fatalf("event Verb = %q want allow", evs[0].Decision.Verb)
	}
	if evs[0].Result.RowsReturned == nil || *evs[0].Result.RowsReturned != 1 {
		t.Fatalf("RowsReturned = %v want 1", evs[0].Result.RowsReturned)
	}
}

func TestHandleQuery_AllowPath_MultiStmt(t *testing.T) {
	pc, clientFE, sink, script := allowPathFixture(t)
	pc.state.lastUpstreamRFQ = 'I'
	pc.srv.SetPolicy(allowAllRuleSet(t))

	script([]pgproto3.BackendMessage{
		&pgproto3.CommandComplete{CommandTag: []byte("INSERT 0 3")},
		&pgproto3.CommandComplete{CommandTag: []byte("INSERT 0 5")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	})

	loopErr := make(chan error, 1)
	go func() { loopErr <- pc.simpleQueryLoop(context.Background()) }()

	mustSendFromClient(t, clientFE, &pgproto3.Query{String: "INSERT INTO t VALUES (1); INSERT INTO t VALUES (2)"})

	_ = drainNFrames(t, clientFE, 3)

	var evs []events.DBEvent
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		evs = sink.DrainStatements()
		if len(evs) == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(evs) != 2 {
		t.Fatalf("statement events = %d want 2", len(evs))
	}
	if evs[0].Result.RowsAffected == nil || *evs[0].Result.RowsAffected != 3 {
		t.Fatalf("affected[0] = %v want 3", evs[0].Result.RowsAffected)
	}
	if evs[1].Result.RowsAffected == nil || *evs[1].Result.RowsAffected != 5 {
		t.Fatalf("affected[1] = %v want 5", evs[1].Result.RowsAffected)
	}
	if evs[0].CommandID == evs[1].CommandID {
		t.Fatalf("CommandID must differ per stmt: %q / %q", evs[0].CommandID, evs[1].CommandID)
	}
	_ = loopErr
}
