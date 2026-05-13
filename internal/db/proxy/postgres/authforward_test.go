//go:build linux

package postgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
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
		Unavoidability:  service.UnavoidabilityObserve,
		StateDir:        t.TempDir(),
		Sink:            &events.SyncSink{},
		AgentSessionID:  testAgentSessionID,
		SessionResolver: staticResolver{sessionID: testAgentSessionID, ok: true},
		Logger:          slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: "db.internal:5432",
			TLSMode:  "terminate_reissue",
			Listen:   ServiceListener{Kind: "unix", Path: filepath.Join(t.TempDir(), "test.sock")},
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
	syntheticSecret := []byte{0, 0, 0, 7}
	pc.srv.cancelMap = newCancelMap(cancelMapConfig{
		Max: 10,
		Generate: fixedCancelKeyGenerator([]generatedCancelKey{
			{pid: 1001, secret: syntheticSecret},
		}),
	})
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
	clientBKD := make(chan *pgproto3.BackendKeyData, 1)
	go func() {
		var rfqSeen bool
		for !rfqSeen {
			msg, err := clientReader.Receive()
			if err != nil {
				doneClient <- err
				return
			}
			if bkd, ok := msg.(*pgproto3.BackendKeyData); ok {
				clientBKD <- bkd
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
	select {
	case bkd := <-clientBKD:
		if bkd.ProcessID == 12345 || bytes.Equal(bkd.SecretKey, secretBytes) {
			t.Fatalf("client received real upstream BKD: PID=%d SecretKey=%x", bkd.ProcessID, bkd.SecretKey)
		}
		entry, status := pc.srv.cancelMap.Lookup(bkd.ProcessID, bkd.SecretKey)
		if status != cancelLookupFound {
			t.Fatalf("Lookup synthetic key status = %v, want found", status)
		}
		if entry.RealPID != 12345 || !bytes.Equal(entry.RealSecret, secretBytes) {
			t.Fatalf("mapped real key = (%d,%x), want (12345,%x)", entry.RealPID, entry.RealSecret, secretBytes)
		}
	default:
		t.Fatal("client did not receive BackendKeyData")
	}
	if pc.state.upstreamBKD.PID != 12345 || !bytesEqual(pc.state.upstreamBKD.SecretKey, secretBytes) {
		t.Errorf("BKD not captured: got PID=%d SecretKey=%x, want PID=12345 SecretKey=%x",
			pc.state.upstreamBKD.PID, pc.state.upstreamBKD.SecretKey, secretBytes)
	}
}

func TestForwardAuth_BackendKeyMappingAvailableWhenClientReceivesSyntheticKey(t *testing.T) {
	clientFE, proxyClientBE, proxyUpstreamFE, upstreamBE := pairedConns(t)
	pc := newTestProxyConnForAuth(t, proxyClientBE, proxyUpstreamFE)
	syntheticSecret := []byte{0, 0, 1, 77}
	pc.srv.cancelMap = newCancelMap(cancelMapConfig{
		Max: 10,
		Generate: fixedCancelKeyGenerator([]generatedCancelKey{
			{pid: 17001, secret: syntheticSecret},
		}),
	})
	upstreamScript := pgproto3.NewBackend(upstreamBE, upstreamBE)
	clientReader := pgproto3.NewFrontend(clientFE, clientFE)

	realSecret := []byte{0, 0, 0, 77}
	go func() {
		upstreamScript.Send(&pgproto3.AuthenticationOk{})
		upstreamScript.Send(&pgproto3.BackendKeyData{ProcessID: 777, SecretKey: realSecret})
		upstreamScript.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		_ = upstreamScript.Flush()
	}()

	clientBKD := make(chan *pgproto3.BackendKeyData, 1)
	continueRead := make(chan struct{})
	var releaseRead sync.Once
	releaseClientReader := func() {
		releaseRead.Do(func() { close(continueRead) })
	}
	defer releaseClientReader()
	doneClient := make(chan error, 1)
	go func() {
		for {
			msg, err := clientReader.Receive()
			if err != nil {
				doneClient <- err
				return
			}
			switch m := msg.(type) {
			case *pgproto3.BackendKeyData:
				clientBKD <- &pgproto3.BackendKeyData{
					ProcessID: m.ProcessID,
					SecretKey: append([]byte(nil), m.SecretKey...),
				}
				<-continueRead
			case *pgproto3.ReadyForQuery:
				doneClient <- nil
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	doneForward := make(chan error, 1)
	go func() { doneForward <- forwardAuth(ctx, pc) }()

	var bkd *pgproto3.BackendKeyData
	select {
	case bkd = <-clientBKD:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for client BackendKeyData")
	}
	if bkd.ProcessID == 777 && bytes.Equal(bkd.SecretKey, realSecret) {
		t.Fatalf("client received exact real upstream BKD pair: PID=%d SecretKey=%x", bkd.ProcessID, bkd.SecretKey)
	}
	entry, status := pc.srv.cancelMap.Lookup(bkd.ProcessID, bkd.SecretKey)
	if status != cancelLookupFound {
		t.Fatalf("Lookup synthetic key status = %v, want found", status)
	}
	if entry.RealPID != 777 || !bytes.Equal(entry.RealSecret, realSecret) {
		t.Fatalf("mapped real key = (%d,%x), want (777,%x)", entry.RealPID, entry.RealSecret, realSecret)
	}
	releaseClientReader()

	select {
	case err := <-doneClient:
		if err != nil {
			t.Fatalf("client reader: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for client reader")
	}
	select {
	case err := <-doneForward:
		if err != nil {
			t.Fatalf("forwardAuth: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for forwardAuth")
	}
}

func TestForwardAuth_BackendKeyRegistrationFailure_FailsClosed(t *testing.T) {
	clientFE, proxyClientBE, proxyUpstreamFE, upstreamBE := pairedConns(t)
	pc := newTestProxyConnForAuth(t, proxyClientBE, proxyUpstreamFE)
	pc.srv.cancelMap = newCancelMap(cancelMapConfig{
		Max: 1,
		Generate: fixedCancelKeyGenerator([]generatedCancelKey{
			{pid: 1001, secret: []byte{0, 0, 0, 7}},
			{pid: 1002, secret: []byte{0, 0, 0, 8}},
		}),
	})
	if _, err := pc.srv.cancelMap.Register(cancelMeta{ServiceName: "seed"}, 42, []byte{0, 0, 0, 9}); err != nil {
		t.Fatalf("seed Register: %v", err)
	}

	upstreamScript := pgproto3.NewBackend(upstreamBE, upstreamBE)
	clientReader := pgproto3.NewFrontend(clientFE, clientFE)

	secretBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(secretBytes, 67890)
	go func() {
		upstreamScript.Send(&pgproto3.AuthenticationOk{})
		upstreamScript.Send(&pgproto3.BackendKeyData{ProcessID: 12345, SecretKey: secretBytes})
		_ = upstreamScript.Flush()
		_ = upstreamBE.Close()
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
	if !errors.Is(err, errBackendKeyTableFull) {
		t.Fatalf("forwardAuth err = %v, want errBackendKeyTableFull", err)
	}
	var resp *pgproto3.ErrorResponse
	select {
	case resp = <-clientErrCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for client ErrorResponse")
	}
	if resp == nil {
		t.Fatal("client did not receive ErrorResponse")
	}
	if resp.Message != "BACKEND_KEY_TABLE_FULL" {
		t.Fatalf("ErrorResponse.Message = %q, want BACKEND_KEY_TABLE_FULL", resp.Message)
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
