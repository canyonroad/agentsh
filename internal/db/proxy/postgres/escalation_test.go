//go:build linux

package postgres

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/events"
)

// escalationPolicyYAML returns a policy YAML that has:
//   - allow-everyone connection rule
//   - allow-all database rule (operations: ["*"]) so plain reads go through
//   - allow-transaction and allow-session for BEGIN/COMMIT/SET
//   - policies.db.escalate_unknown_functions = escalate
//   - No safe_function_allowlist override (uses the default builtin list)
//
// With escalation on, SELECT do_thing() FROM t is classified as procedural
// (unknown function) + read. The procedural effect has no objects → implicit
// deny wins via foldEffects, so the query is denied even though the allow-all
// rule covers read. With escalation off, the same query is pure read → allowed.
func escalationPolicyYAML(upstream string, escalate bool) string {
	y := fmt.Sprintf(`version: 1
name: escalation-test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: %s
    tls_mode: terminate_plaintext_upstream
    trusted_network: true
database_connection_rules:
  - name: allow-everyone
    db_service: appdb
    decision: allow
database_rules:
  - name: allow-all
    db_service: appdb
    operations: ["*"]
    decision: allow
  - name: allow-transaction
    db_service: appdb
    operations: [transaction]
    decision: allow
  - name: allow-session
    db_service: appdb
    operations: [session]
    decision: allow
`, upstream)
	if escalate {
		y += `policies:
  db:
    escalate_unknown_functions: true
`
	}
	return y
}

// authOKThenQueryScript handles the PostgreSQL handshake and serves one
// query with a single-row result, then drains.
func authOKThenQueryForEscalation(t *testing.T, be *pgproto3.Backend, conn net.Conn) error {
	t.Helper()
	if _, err := be.ReceiveStartupMessage(); err != nil {
		return fmt.Errorf("receive startup: %w", err)
	}
	be.Send(&pgproto3.AuthenticationOk{})
	be.Send(&pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: "on"})
	be.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
	be.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "16.0"})
	be.Send(&pgproto3.BackendKeyData{ProcessID: 42, SecretKey: append([]byte(nil), wantSecret...)})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := be.Flush(); err != nil {
		return fmt.Errorf("flush handshake: %w", err)
	}
	// Handle first query (send one row back).
	msg, err := be.Receive()
	if err != nil {
		return nil // client closed
	}
	if _, ok := msg.(*pgproto3.Query); ok {
		be.Send(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{
			Name:         []byte("result"),
			DataTypeOID:  25, // text
			DataTypeSize: -1,
			TypeModifier: -1,
		}}})
		be.Send(&pgproto3.DataRow{Values: [][]byte{[]byte("ok")}})
		be.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
		be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		if err := be.Flush(); err != nil {
			return nil
		}
	}
	// Drain until client closes.
	buf := make([]byte, 256)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := conn.Read(buf); err != nil {
			return nil
		}
	}
}

// drainStatements polls the SyncSink for events up to deadline.
func drainStatements(sink *events.SyncSink, want int, deadline time.Duration) []events.DBEvent {
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		evs := sink.DrainStatements()
		if len(evs) >= want {
			return evs
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil
}

// TestSpine_Escalation_UnknownFunction_DeniedWhenEscalateOn verifies that
// SELECT do_thing() FROM t is denied when escalate_unknown_functions is true
// because the procedural effect (objects=[]) causes an implicit deny that
// overrides the allow-all read coverage.
func TestSpine_Escalation_UnknownFunction_DeniedWhenEscalateOn(t *testing.T) {
	up := newFakeUpstream(t, withFakeUpstreamScript(authOKThenQueryForEscalation))
	upAddr := up.Address()

	h := startSpineHarness(t, upstreamWithLocalhostHost(upAddr), "terminate_plaintext_upstream", nil, "")
	h.srv.SetPolicy(loadRuleSet(t, escalationPolicyYAML(upAddr, true)))

	stop := runServer(t, h.srv)
	defer stop()

	sockDir := renameSocketForPgx(t, h.sock, 5440)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, pgxConnString(sockDir, 5440))
	if err != nil {
		t.Fatalf("pgx.Connect: %v", err)
	}
	defer conn.Close(context.Background())

	// do_thing() is not in the default safe allowlist → classified as
	// procedural (no objects) + read → implicit deny wins.
	_, err = conn.Exec(ctx, "SELECT do_thing() FROM t")
	if err == nil {
		t.Fatal("expected deny error from proxy, got nil")
	}
	code := pgxErrorCode(err)
	if code != "42501" {
		// Accept any error that isn't "query succeeded" — proxy may also close
		// the connection depending on tx state.
		if !strings.Contains(err.Error(), "42501") {
			t.Logf("error (want 42501 or conn close): %v (code=%s)", err, code)
		}
	}

	evs := drainStatements(h.sink, 1, 2*time.Second)
	if len(evs) == 0 {
		t.Fatal("no statement events recorded")
	}
	if evs[0].Decision.Verb != "deny" {
		t.Fatalf("Decision.Verb = %q want deny (event=%+v)", evs[0].Decision.Verb, evs[0])
	}
}

// TestSpine_Escalation_UnknownFunction_AllowedWhenEscalateOff verifies that
// SELECT do_thing() FROM t is allowed when escalate_unknown_functions is false
// (default): the function is treated as opaque and the query classifies as
// pure read, covered by the allow-all rule.
func TestSpine_Escalation_UnknownFunction_AllowedWhenEscalateOff(t *testing.T) {
	up := newFakeUpstream(t, withFakeUpstreamScript(authOKThenQueryForEscalation))
	upAddr := up.Address()

	h := startSpineHarness(t, upstreamWithLocalhostHost(upAddr), "terminate_plaintext_upstream", nil, "")
	h.srv.SetPolicy(loadRuleSet(t, escalationPolicyYAML(upAddr, false)))

	stop := runServer(t, h.srv)
	defer stop()

	sockDir := renameSocketForPgx(t, h.sock, 5441)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, pgxConnString(sockDir, 5441))
	if err != nil {
		t.Fatalf("pgx.Connect: %v", err)
	}
	defer conn.Close(context.Background())

	// With escalation off, do_thing() is opaque → read objects=[t] → allow-all covers it.
	var result string
	err = conn.QueryRow(ctx, "SELECT do_thing() FROM t").Scan(&result)
	if err != nil {
		t.Fatalf("expected allow (query forwarded), got error: %v", err)
	}

	evs := drainStatements(h.sink, 1, 2*time.Second)
	if len(evs) == 0 {
		t.Fatal("no statement events recorded")
	}
	if evs[0].Decision.Verb != "allow" {
		t.Fatalf("Decision.Verb = %q want allow (event=%+v)", evs[0].Decision.Verb, evs[0])
	}
}
