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
	"github.com/agentsh/agentsh/internal/db/policy"
)

// funcCallPolicyYAML returns a YAML policy that grants allow on procedural
// or denies it, based on the allowProcedural flag.
func funcCallPolicyYAML(allowProcedural bool) string {
	decision := "deny"
	if allowProcedural {
		decision = "allow"
	}
	return `version: 1
name: test
db_services:
  test:
    family: postgres
    dialect: postgres
    upstream: 127.0.0.1:5432
    tls_mode: terminate_reissue
    allow_function_call_protocol: true
database_rules:
  - name: rule-procedural
    db_service: test
    operations: [procedural]
    decision: ` + decision + `
`
}

// TestFunctionCall_DefaultDenied asserts that when AllowFunctionCallProtocol
// is false (the default), handleFunctionCall returns errUnsupportedFrame and
// the client receives an ErrorResponse with SQLSTATE 42501. The upstream must
// not receive the frame.
func TestFunctionCall_DefaultDenied(t *testing.T) {
	pc, clientFE, sink := newSimpleQueryFixture(t)
	// AllowFunctionCallProtocol defaults to false (zero value).
	pc.state.smState.LastUpstreamRFQ = 'I'

	// Wire a recording upstream.
	var (
		mu             sync.Mutex
		upstreamSawAny bool
	)
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

	// Run handleFunctionCall in a goroutine because synthesizeError drains the
	// client connection (io.Copy), which blocks until the client side is read
	// or the pipe closes.
	result := make(chan error, 1)
	go func() {
		result <- pc.handleFunctionCall(context.Background(), &pgproto3.FunctionCall{Function: 12345})
	}()

	// Client must have received an ErrorResponse with SQLSTATE 42501.
	msg, recvErr := clientFE.Receive()
	if recvErr != nil {
		t.Fatalf("client recv: %v", recvErr)
	}
	er, ok := msg.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", msg)
	}
	if er.Code != "42501" {
		t.Fatalf("SQLSTATE = %q want 42501", er.Code)
	}

	// handleFunctionCall must return errUnsupportedFrame.
	select {
	case err := <-result:
		if err != errUnsupportedFrame {
			t.Fatalf("handleFunctionCall default: want errUnsupportedFrame, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handleFunctionCall did not return within 5s")
	}

	// Upstream must not have received the FunctionCall.
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	saw := upstreamSawAny
	mu.Unlock()
	if saw {
		t.Fatal("upstream saw a frame; FunctionCall default-deny must not forward")
	}

	// Sink must have a lifecycle event with FUNCTION_CALL_PROTOCOL_DENIED.
	evs := sink.DrainLifecycle()
	if len(evs) != 1 || evs[0].ErrorCode != "FUNCTION_CALL_PROTOCOL_DENIED" {
		t.Fatalf("lifecycle events = %+v", evs)
	}
}

// TestFunctionCall_OptIn_Allow asserts that when AllowFunctionCallProtocol is
// true and the policy allows procedural, handleFunctionCall:
//   - forwards the FunctionCall to the upstream;
//   - emits an allow db_statement event with Decision.Verb == "allow",
//     Effects[0].Subtype == function_call_protocol, FunctionOID == 12345.
func TestFunctionCall_OptIn_Allow(t *testing.T) {
	pc, clientFE, sink := newSimpleQueryFixture(t)
	pc.state.smState.LastUpstreamRFQ = 'I'
	pc.srv.SetPolicy(loadRuleSet(t, funcCallPolicyYAML(true)))

	// Wire an upstream that records the received frame and replies.
	var (
		mu            sync.Mutex
		upstreamSawFC bool
	)
	upClient, upServer := net.Pipe()
	t.Cleanup(func() { _ = upClient.Close(); _ = upServer.Close() })
	pc.state.upstream = upServer
	pc.state.upstreamFE = pgproto3.NewFrontend(upServer, upServer)

	go func() {
		// The proxy writes FunctionCall to upServer via its upstreamFE.
		// The upstream side reads with a Backend (which reads FrontendMessages).
		be := pgproto3.NewBackend(upClient, upClient)
		msg, err := be.Receive()
		if err != nil {
			return
		}
		if _, ok := msg.(*pgproto3.FunctionCall); ok {
			mu.Lock()
			upstreamSawFC = true
			mu.Unlock()
		}
		// Send back a FunctionCallResponse + RFQ.
		be.Send(&pgproto3.FunctionCallResponse{Result: []byte{0x01}})
		be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		_ = be.Flush()
	}()

	// Run handleFunctionCall in a goroutine because forwardUpstreamUntilRFQ
	// writes FunctionCallResponse + RFQ to the client pipe, which blocks unless
	// the client side is being drained.
	result := make(chan error, 1)
	go func() {
		result <- pc.handleFunctionCall(context.Background(), &pgproto3.FunctionCall{Function: 12345})
	}()

	// Drain the forwarded upstream frames from the client side
	// (FunctionCallResponse + ReadyForQuery).
	for i := 0; i < 2; i++ {
		if _, err := clientFE.Receive(); err != nil {
			// Pipe may be closed; that's fine if handleFunctionCall already returned.
			break
		}
	}

	// handleFunctionCall must return nil on success.
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("handleFunctionCall opt-in allow: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handleFunctionCall did not return within 5s")
	}

	// Upstream must have received the FunctionCall.
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	saw := upstreamSawFC
	mu.Unlock()
	if !saw {
		t.Fatal("upstream did not receive FunctionCall frame")
	}

	// Sink must have one allow event with the right effects.
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
	ev := evs[0]
	if ev.Decision.Verb != "allow" {
		t.Fatalf("Decision.Verb = %q want allow", ev.Decision.Verb)
	}
	if len(ev.Effects) == 0 {
		t.Fatal("Effects empty, want >= 1")
	}
	eff := ev.Effects[0]
	if eff.Subtype.String() != "function_call_protocol" {
		t.Fatalf("Effects[0].Subtype = %q want function_call_protocol", eff.Subtype.String())
	}
	if eff.FunctionOID == nil || *eff.FunctionOID != 12345 {
		t.Fatalf("Effects[0].FunctionOID = %v want 12345", eff.FunctionOID)
	}
	// Verify that the allow path wires BytesOut from the upstream result.
	// The scripted upstream sends FunctionCallResponse + ReadyForQuery so
	// BytesOut must be > 0.
	if ev.Result.BytesOut <= 0 {
		t.Fatalf("Result.BytesOut = %d want > 0 (upstream result not wired into event)", ev.Result.BytesOut)
	}
}

// TestFunctionCall_OptIn_Deny asserts that when AllowFunctionCallProtocol is
// true and the policy denies procedural, handleFunctionCall:
//   - does NOT forward to the upstream;
//   - the client receives an ErrorResponse with SQLSTATE 42501;
//   - the sink has a deny event with the right FunctionOID.
func TestFunctionCall_OptIn_Deny(t *testing.T) {
	pc, clientFE, sink := newSimpleQueryFixture(t)
	pc.state.smState.LastUpstreamRFQ = 'I'
	pc.srv.SetPolicy(loadRuleSet(t, funcCallPolicyYAML(false)))

	// Wire a recording upstream.
	var (
		mu             sync.Mutex
		upstreamSawAny bool
	)
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

	// Run handleFunctionCall in a goroutine because executeActions writes
	// ErrorResponse + ReadyForQuery to the client pipe, blocking unless read.
	result := make(chan error, 1)
	go func() {
		result <- pc.handleFunctionCall(context.Background(), &pgproto3.FunctionCall{Function: 12345})
	}()

	// Client must have received an ErrorResponse with SQLSTATE 42501.
	msg := mustReceiveClientFrame(t, clientFE)
	er, ok := msg.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", msg)
	}
	if er.Code != "42501" {
		t.Fatalf("SQLSTATE = %q want 42501", er.Code)
	}

	// RFQ must follow (pre-tx deny, LastUpstreamRFQ='I').
	rfq := mustReceiveClientFrame(t, clientFE)
	if _, ok := rfq.(*pgproto3.ReadyForQuery); !ok {
		t.Fatalf("expected ReadyForQuery after deny, got %T", rfq)
	}

	// handleFunctionCall must return nil (pre-tx deny doesn't terminate conn).
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("handleFunctionCall opt-in deny: unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handleFunctionCall did not return within 5s")
	}

	// Upstream must NOT have received the frame.
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	saw := upstreamSawAny
	mu.Unlock()
	if saw {
		t.Fatal("upstream saw a frame; FunctionCall deny must not forward")
	}

	// Sink must have one deny event with FunctionOID == 12345.
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
	ev := evs[0]
	if ev.Decision.Verb != "deny" {
		t.Fatalf("Decision.Verb = %q want deny", ev.Decision.Verb)
	}
	if len(ev.Effects) == 0 {
		t.Fatal("Effects empty")
	}
	eff := ev.Effects[0]
	if eff.FunctionOID == nil || *eff.FunctionOID != 12345 {
		t.Fatalf("Effects[0].FunctionOID = %v want 12345", eff.FunctionOID)
	}
	_ = policy.VerbDeny // verify import used
}
