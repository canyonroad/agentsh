//go:build linux

package postgres

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

type clientBackendObservation struct {
	errorCode string
	rfqStatus byte
}

// extqueryFixture wires a *proxyConn with both client and upstream net.Pipes.
// Returns:
//   - pc: the proxyConn under test
//   - clientFE: drive frames *into* pc by Send-ing on this Frontend
//   - upBackend: read frames *out of* pc on the upstream side; Send back-pressure
//     here to feed responses (e.g., ReadyForQuery for the Drain action)
//   - sink: lifecycle/statement event sink
func extqueryFixture(t *testing.T, policyYAML string) (
	pc *proxyConn,
	clientFE *pgproto3.Frontend,
	upBackend *pgproto3.Backend,
	upRaw net.Conn,
) {
	t.Helper()
	pc, clientFE, _ = newSimpleQueryFixture(t)
	pc.state.smState.LastUpstreamRFQ = 'I'
	pc.srv.SetPolicy(loadRuleSet(t, policyYAML))

	up1, up2 := net.Pipe()
	t.Cleanup(func() { _ = up1.Close(); _ = up2.Close() })
	pc.state.upstream = up2
	pc.state.upstreamFE = pgproto3.NewFrontend(up2, up2)
	upBackend = pgproto3.NewBackend(up1, up1)
	upRaw = up1

	return pc, clientFE, upBackend, upRaw
}

func extqueryDenyPolicyYAML() string {
	return `version: 1
name: test
db_services:
  test: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue}
database_rules:
  - name: allow-read
    db_service: test
    operations: [read]
    decision: allow
  - name: block-delete
    db_service: test
    operations: [delete]
    decision: deny
  - name: block-modify-soft
    db_service: test
    operations: [modify]
    decision: deny
    deny_mode_in_tx: rollback_then_continue
`
}

// Setup notes:
//   newSimpleQueryFixture's clientFE is wired to the proxy-facing side of
//   the net.Pipe, so any Frontend.Send from the test side writes bytes into
//   the proxy's backend.Receive. Tests that expect proxy responses must read
//   them from clientFE; there must be no competing reader on pc.conn.

func TestExtquery_Spine_Parse_AllowForwardsAndCaches(t *testing.T) {
	pc, clientFE, upBackend, _ := extqueryFixture(t, extqueryDenyPolicyYAML())

	// Run the proxy loop in a goroutine.
	loopErr := make(chan error, 1)
	go func() { loopErr <- pc.simpleQueryLoop(context.Background()) }()

	clientFE.Send(&pgproto3.Parse{Name: "s1", Query: "SELECT id FROM users"})
	if err := clientFE.Flush(); err != nil {
		t.Fatalf("client flush: %v", err)
	}

	// Upstream should see the Parse forwarded verbatim.
	deadline := time.Now().Add(2 * time.Second)
	_ = upBackend
	type result struct {
		msg pgproto3.FrontendMessage
		err error
	}
	got := make(chan result, 1)
	go func() {
		m, err := upBackend.Receive()
		got <- result{m, err}
	}()
	select {
	case r := <-got:
		if r.err != nil {
			t.Fatalf("upstream Receive: %v", r.err)
		}
		parse, ok := r.msg.(*pgproto3.Parse)
		if !ok {
			t.Fatalf("upstream got %T; want *pgproto3.Parse", r.msg)
		}
		if parse.Name != "s1" || parse.Query != "SELECT id FROM users" {
			t.Fatalf("Parse mismatch: %#v", parse)
		}
	case <-time.After(time.Until(deadline)):
		t.Fatal("timeout waiting for upstream Parse")
	}

	// wireCache must contain s1 now.
	if _, ok := pc.wireCache.Get("s1"); !ok {
		t.Error("wireCache missing s1 after allow Parse")
	}

	// Tear down loop by closing client conn (best effort).
	_ = pc.conn.Close()
	select {
	case <-loopErr:
	case <-time.After(time.Second):
	}
}

func TestExtquery_Spine_Parse_DenyOutOfTx_SynthsError(t *testing.T) {
	pc, clientFE, upBackend, _ := extqueryFixture(t, extqueryDenyPolicyYAML())

	// Drain client side specifically with a Frontend so we can inspect frames.
	cliRead := make(chan clientBackendObservation, 4)
	clientRead := pgproto3.NewFrontend(pc.conn, pc.conn)
	_ = clientRead

	// Reattach client read by parking the previous drain — net.Pipe gave us
	// pc.conn, but newSimpleQueryFixture already started a draining goroutine
	// from the *test* side via clientFE.Receive. Use clientFE.Receive directly.
	go func() {
		for {
			m, err := clientFE.Receive()
			if err != nil {
				return
			}
			var obs clientBackendObservation
			if er, ok := m.(*pgproto3.ErrorResponse); ok {
				obs.errorCode = er.Code
			}
			if rfq, ok := m.(*pgproto3.ReadyForQuery); ok {
				obs.rfqStatus = rfq.TxStatus
			}
			cliRead <- obs
		}
	}()

	loopErr := make(chan error, 1)
	go func() { loopErr <- pc.simpleQueryLoop(context.Background()) }()

	clientFE.Send(&pgproto3.Parse{Name: "del", Query: "DELETE FROM users"})
	if err := clientFE.Flush(); err != nil {
		t.Fatalf("client flush: %v", err)
	}

	// Client should receive ErrorResponse(42501) then ReadyForQuery('I').
	deadline := time.Now().Add(2 * time.Second)
	var sawErr, sawRFQ bool
	for time.Now().Before(deadline) {
		select {
		case obs := <-cliRead:
			if obs.errorCode != "" {
				if obs.errorCode != "42501" {
					t.Errorf("Code = %q want 42501", obs.errorCode)
				}
				sawErr = true
			}
			if obs.rfqStatus != 0 {
				sawRFQ = true
			}
		case <-time.After(100 * time.Millisecond):
		}
		if sawErr && sawRFQ {
			break
		}
	}
	if !sawErr {
		t.Error("client never received ErrorResponse")
	}
	if !sawRFQ {
		t.Error("client never received ReadyForQuery")
	}

	// Upstream must NOT have received any frame.
	upRecv := make(chan struct{}, 1)
	go func() {
		_, err := upBackend.Receive()
		if err == nil {
			upRecv <- struct{}{}
		}
	}()
	select {
	case <-upRecv:
		t.Error("upstream unexpectedly received a frame after deny")
	case <-time.After(200 * time.Millisecond):
	}

	// wireCache must NOT contain "del".
	if _, ok := pc.wireCache.Get("del"); ok {
		t.Error("wireCache should not retain denied Parse name")
	}

	// State should be Absorbing.
	if !pc.state.smState.Absorbing {
		t.Error("smState.Absorbing should be true after deny")
	}

	_ = pc.conn.Close()
	select {
	case <-loopErr:
	case <-time.After(time.Second):
	}
}

func TestExtquery_Spine_Query_InTx_RollbackThenContinue(t *testing.T) {
	pc, clientFE, upBackend, upRaw := extqueryFixture(t, extqueryDenyPolicyYAML())
	pc.state.smState.LastUpstreamRFQ = 'T' // simulate prior BEGIN

	cliRead := make(chan clientBackendObservation, 8)
	go func() {
		for {
			m, err := clientFE.Receive()
			if err != nil {
				return
			}
			var obs clientBackendObservation
			if er, ok := m.(*pgproto3.ErrorResponse); ok {
				obs.errorCode = er.Code
			}
			if rfq, ok := m.(*pgproto3.ReadyForQuery); ok {
				obs.rfqStatus = rfq.TxStatus
			}
			cliRead <- obs
		}
	}()

	// Pre-arm the upstream to respond to the ROLLBACK injection with a
	// CommandComplete + RFQ('I') so DrainUntilRFQ completes.
	go func() {
		// Expect ROLLBACK Query frame from proxy.
		_ = upRaw.SetReadDeadline(time.Now().Add(3 * time.Second))
		msg, err := upBackend.Receive()
		if err != nil {
			return
		}
		if q, ok := msg.(*pgproto3.Query); !ok || q.String != "ROLLBACK" {
			return
		}
		upBackend.Send(&pgproto3.CommandComplete{CommandTag: []byte("ROLLBACK")})
		upBackend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		_ = upBackend.Flush()
	}()

	loopErr := make(chan error, 1)
	go func() { loopErr <- pc.simpleQueryLoop(context.Background()) }()

	clientFE.Send(&pgproto3.Query{String: "UPDATE users SET x=1"})
	if err := clientFE.Flush(); err != nil {
		t.Fatalf("client flush: %v", err)
	}

	// Client should receive: ErrorResponse(42501) + (eventually) RFQ('I').
	deadline := time.Now().Add(3 * time.Second)
	var sawErr, sawRFQ bool
	for time.Now().Before(deadline) && (!sawErr || !sawRFQ) {
		select {
		case obs := <-cliRead:
			if obs.errorCode == "42501" {
				sawErr = true
			}
			if obs.rfqStatus == 'I' {
				sawRFQ = true
			}
		case <-time.After(100 * time.Millisecond):
		}
	}
	if !sawErr {
		t.Error("client never received ErrorResponse")
	}
	if !sawRFQ {
		t.Error("client never received ReadyForQuery('I') after rollback_then_continue")
	}

	_ = pc.conn.Close()
	select {
	case err := <-loopErr:
		// EOF is fine; we forced the close.
		if err != nil && !errors.Is(err, net.ErrClosed) {
			// loop may also exit on upstream pipe close — both acceptable.
		}
	case <-time.After(time.Second):
	}
}

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

	deadline := time.Now().Add(time.Second)
	for {
		if _, ok := pc.wireCache.Get("s1"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("wire cache missing s1 after catalog-resolved allow")
		}
		time.Sleep(10 * time.Millisecond)
	}

	_ = pc.conn.Close()
	select {
	case <-loopErr:
	case <-time.After(time.Second):
	}
}

func TestExtquery_RedirectParse_ForwardsRewrittenAndCachesMetadata(t *testing.T) {
	pc, clientFE, upBackend, _ := extqueryFixture(t, redirectExtqueryPolicyYAML())
	pc.state.catalog = testCatalogContext()
	pc.redirectPlanner = &fakeRedirectPlanner{plan: redirectRuntimePlan{
		RewrittenSQL:   "select note from public.safe_users where id=$1",
		Rule:           "redirect-users",
		SourceRelation: "public.users",
		TargetRelation: "public.safe_users",
	}}

	loopErr := make(chan error, 1)
	go func() { loopErr <- pc.simpleQueryLoop(context.Background()) }()

	clientFE.Send(&pgproto3.Parse{Name: "client_stmt", Query: "select note from public.users where id=$1"})
	if err := clientFE.Flush(); err != nil {
		t.Fatalf("client flush: %v", err)
	}

	msg, err := upBackend.Receive()
	if err != nil {
		t.Fatalf("upstream Receive: %v", err)
	}
	parse, ok := msg.(*pgproto3.Parse)
	if !ok {
		t.Fatalf("upstream got %T", msg)
	}
	if parse.Name != "client_stmt" {
		t.Fatalf("Parse.Name = %q", parse.Name)
	}
	if parse.Query != "select note from public.safe_users where id=$1" {
		t.Fatalf("Parse.Query = %q", parse.Query)
	}

	entry, ok := pc.wireCache.Get("client_stmt")
	if !ok {
		t.Fatal("wire cache missing client_stmt")
	}
	if entry.Redirect == nil {
		t.Fatal("redirect metadata missing")
	}
	if entry.Redirect.TargetRelation != "public.safe_users" || entry.Classification.RawVerb != "SELECT" {
		t.Fatalf("cache entry = %+v", entry)
	}

	_ = pc.conn.Close()
	select {
	case <-loopErr:
	case <-time.After(time.Second):
	}
}

func TestExtquery_RedirectParse_FailureDoesNotCacheOrForward(t *testing.T) {
	pc, clientFE, upBackend, _ := extqueryFixture(t, redirectExtqueryPolicyYAML())
	pc.state.catalog = testCatalogContext()
	pc.redirectPlanner = &fakeRedirectPlanner{err: errors.New("unsupported_statement")}
	drainClientBackendMessages(clientFE)

	loopErr := make(chan error, 1)
	go func() { loopErr <- pc.simpleQueryLoop(context.Background()) }()

	clientFE.Send(&pgproto3.Parse{Name: "client_stmt", Query: "select note from public.users"})
	if err := clientFE.Flush(); err != nil {
		t.Fatalf("client flush: %v", err)
	}

	if _, ok := pc.wireCache.Get("client_stmt"); ok {
		t.Fatal("failed redirect Parse must not cache statement")
	}

	upRecv := make(chan struct{}, 1)
	go func() {
		if _, err := upBackend.Receive(); err == nil {
			upRecv <- struct{}{}
		}
	}()
	select {
	case <-upRecv:
		t.Fatal("upstream received Parse after redirect failure")
	case <-time.After(200 * time.Millisecond):
	}

	_ = pc.conn.Close()
	select {
	case <-loopErr:
	case <-time.After(time.Second):
	}
}

func redirectExtqueryPolicyYAML() string {
	return `version: 1
name: redirect-extquery
db_services:
  test: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue}
database_rules:
  - name: block-delete
    db_service: test
    operations: [delete]
    decision: deny
  - name: redirect-users
    db_service: test
    operations: [read]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: redirect
    redirect:
      relation: public.safe_users
`
}
