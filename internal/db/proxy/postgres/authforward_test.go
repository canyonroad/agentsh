//go:build linux

package postgres

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/service"
)

// pairedConns returns (clientConn, proxyClientConn, proxyUpstreamConn, upstreamConn)
// representing the four endpoints around the proxy: client ↔ proxy client-side
// pipe; proxy upstream-side pipe ↔ fake upstream.
func pairedConns(t *testing.T) (clientFE, proxyClientBE, proxyUpstreamFE, upstreamBE net.Conn) {
	t.Helper()
	clientFE, proxyClientBE = net.Pipe()
	proxyUpstreamFE, upstreamBE = net.Pipe()
	t.Cleanup(func() {
		_ = clientFE.Close()
		_ = proxyClientBE.Close()
		_ = proxyUpstreamFE.Close()
		_ = upstreamBE.Close()
	})
	return
}

func newTestProxyConnForAuth(t *testing.T, clientSide, upstreamSide net.Conn) *proxyConn {
	t.Helper()
	srv, err := New(Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: "db.internal:5432",
			TLSMode:  "terminate_reissue",
			Listen:   ServiceListener{Kind: "unix", Path: "/tmp/_test.sock"},
			Service:  policy.DBService{Name: "appdb", TLSMode: "terminate_reissue"},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pc := newProxyConn(srv, srv.cfg.Services[0], clientSide, 1000)
	pc.state.upstream = upstreamSide
	pc.state.upstreamFE = pgproto3.NewFrontend(upstreamSide, upstreamSide)
	return pc
}

func TestForwardAuth_AuthOK_ForwardsToRFQ(t *testing.T) {
	clientFE, proxyClientBE, proxyUpstreamFE, upstreamBE := pairedConns(t)
	pc := newTestProxyConnForAuth(t, proxyClientBE, proxyUpstreamFE)
	upstreamScript := pgproto3.NewBackend(upstreamBE, upstreamBE)
	clientReader := pgproto3.NewFrontend(clientFE, clientFE)

	// Fake upstream: send AuthenticationOk, ParameterStatus, BackendKeyData,
	// ReadyForQuery('I').
	secretBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(secretBytes, 67890)
	go func() {
		upstreamScript.Send(&pgproto3.AuthenticationOk{})
		upstreamScript.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "16"})
		upstreamScript.Send(&pgproto3.BackendKeyData{ProcessID: 12345, SecretKey: secretBytes})
		upstreamScript.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		_ = upstreamScript.Flush()
	}()

	// Client side: read four frames; expect AuthenticationOk → PS → BKD → RFQ.
	doneClient := make(chan error, 1)
	go func() {
		var rfqSeen bool
		for !rfqSeen {
			msg, err := clientReader.Receive()
			if err != nil {
				doneClient <- err
				return
			}
			if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
				rfqSeen = true
			}
		}
		doneClient <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := forwardAuth(ctx, pc); err != nil {
		t.Fatalf("forwardAuth: %v", err)
	}
	if err := <-doneClient; err != nil {
		t.Fatalf("client reader: %v", err)
	}
	if pc.state.upstreamBKD.PID != 12345 || !bytesEqual(pc.state.upstreamBKD.SecretKey, secretBytes) {
		t.Errorf("BKD not captured: got PID=%d SecretKey=%x, want PID=12345 SecretKey=%x",
			pc.state.upstreamBKD.PID, pc.state.upstreamBKD.SecretKey, secretBytes)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestForwardAuth_ScramPlus_FailClosed(t *testing.T) {
	clientFE, proxyClientBE, proxyUpstreamFE, upstreamBE := pairedConns(t)
	pc := newTestProxyConnForAuth(t, proxyClientBE, proxyUpstreamFE)
	upstreamScript := pgproto3.NewBackend(upstreamBE, upstreamBE)
	clientReader := pgproto3.NewFrontend(clientFE, clientFE)

	go func() {
		// Send AuthenticationSASL with SCRAM-SHA-256-PLUS in the list.
		upstreamScript.Send(&pgproto3.AuthenticationSASL{
			AuthMechanisms: []string{"SCRAM-SHA-256", "SCRAM-SHA-256-PLUS"},
		})
		_ = upstreamScript.Flush()
	}()

	// Client reader: expect ErrorResponse with 28000 SCRAM_PLUS_FAIL_CLOSED.
	clientErrCh := make(chan *pgproto3.ErrorResponse, 1)
	go func() {
		for {
			msg, err := clientReader.Receive()
			if err != nil {
				clientErrCh <- nil
				return
			}
			if e, ok := msg.(*pgproto3.ErrorResponse); ok {
				clientErrCh <- e
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := forwardAuth(ctx, pc)
	if err == nil || !errors.Is(err, errScramPlusFailClosed) {
		t.Fatalf("forwardAuth: want errScramPlusFailClosed, got %v", err)
	}
	resp := <-clientErrCh
	if resp == nil {
		t.Fatal("client did not receive ErrorResponse")
	}
	if resp.Code != scramPlusErrorCode {
		t.Errorf("ErrorResponse.Code = %q, want %q", resp.Code, scramPlusErrorCode)
	}
	if !strings.Contains(resp.Message, "SCRAM-SHA-256-PLUS") {
		t.Errorf("ErrorResponse.Message = %q; want it to mention SCRAM-SHA-256-PLUS", resp.Message)
	}
}

func TestForwardAuth_UpstreamErrorResponse_ForwardedVerbatim(t *testing.T) {
	clientFE, proxyClientBE, proxyUpstreamFE, upstreamBE := pairedConns(t)
	pc := newTestProxyConnForAuth(t, proxyClientBE, proxyUpstreamFE)
	upstreamScript := pgproto3.NewBackend(upstreamBE, upstreamBE)
	clientReader := pgproto3.NewFrontend(clientFE, clientFE)

	go func() {
		upstreamScript.Send(&pgproto3.ErrorResponse{
			Severity: "FATAL",
			Code:     "28P01",
			Message:  "password authentication failed for user \"alice\"",
		})
		_ = upstreamScript.Flush()
		_ = upstreamBE.Close() // upstream then closes
	}()

	clientErrCh := make(chan *pgproto3.ErrorResponse, 1)
	go func() {
		for {
			msg, err := clientReader.Receive()
			if err != nil {
				clientErrCh <- nil
				return
			}
			if e, ok := msg.(*pgproto3.ErrorResponse); ok {
				clientErrCh <- e
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := forwardAuth(ctx, pc)
	// Upstream closed after ErrorResponse; forwardAuth should surface an EOF
	// or io.ErrClosedPipe via the read path. The test asserts the client
	// received the ErrorResponse first.
	if err == nil {
		t.Log("forwardAuth returned nil; acceptable if upstream EOF was clean")
	} else if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
		t.Logf("forwardAuth returned: %v (acceptable)", err)
	}
	resp := <-clientErrCh
	if resp == nil {
		t.Fatal("client did not receive ErrorResponse")
	}
	if resp.Code != "28P01" {
		t.Errorf("ErrorResponse.Code = %q, want 28P01", resp.Code)
	}
}

func TestForwardAuth_CapturesUpstreamRFQByte(t *testing.T) {
	clientFE, proxyClientBE, proxyUpstreamFE, upstreamBE := pairedConns(t)
	pc := newTestProxyConnForAuth(t, proxyClientBE, proxyUpstreamFE)
	upstreamScript := pgproto3.NewBackend(upstreamBE, upstreamBE)
	clientReader := pgproto3.NewFrontend(clientFE, clientFE)

	go func() {
		upstreamScript.Send(&pgproto3.AuthenticationOk{})
		upstreamScript.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		_ = upstreamScript.Flush()
	}()

	// Drain client side in the background.
	go func() {
		for {
			if _, err := clientReader.Receive(); err != nil {
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := forwardAuth(ctx, pc); err != nil {
		t.Fatalf("forwardAuth: %v", err)
	}

	if pc.state.smState.LastUpstreamRFQ != 'I' {
		t.Fatalf("lastUpstreamRFQ = %q want 'I'", pc.state.smState.LastUpstreamRFQ)
	}
}
