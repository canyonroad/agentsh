//go:build linux

package postgres

import (
	"context"
	"net"
	"os"
	"testing"

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
