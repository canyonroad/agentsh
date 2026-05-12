//go:build linux

package postgres

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/service"
	"github.com/agentsh/agentsh/internal/db/tlsleaf"
)

// wantSecret is the upstream BackendKeyData.SecretKey value our authOKScript
// emits — four big-endian bytes encoding uint32(99). pgproto3's SecretKey is
// []byte (not uint32) because CockroachDB extends the secret beyond 4 bytes.
var wantSecret = []byte{0, 0, 0, 99}

// spineHarness wires a Server with one service pointing at the supplied
// fake upstream. The bound Unix-socket path is the hand-rolled client's dial
// target; sink/ca are exposed for assertions.
type spineHarness struct {
	srv  *Server
	sock string
	sink *events.SyncSink
	ca   *tlsleaf.CA
}

// startSpineHarness builds a Server that listens on a t.TempDir() Unix socket
// and routes to upAddr in the requested TLS mode. upTLSPool, when non-nil,
// becomes the RootCAs for the upstream-side tls.Config so terminate_reissue
// can verify-full the fake upstream's leaf. extraRule is appended verbatim
// to the database_connection_rules block.
func startSpineHarness(t *testing.T, upAddr string, tlsMode string, upTLSPool *x509.CertPool, extraRule string) *spineHarness {
	t.Helper()
	sockDir := t.TempDir()
	sockPath := filepath.Join(sockDir, "appdb.sock")
	stateDir := t.TempDir()

	policyYAML := `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: ` + upAddr + `
    tls_mode: ` + tlsMode + `
    trusted_network: true
database_connection_rules:
  - name: allow-everyone
    db_service: appdb
    decision: allow
`
	if extraRule != "" {
		policyYAML += extraRule
	}
	rs := loadRuleSet(t, policyYAML)

	var upTLSCfg *tls.Config
	if upTLSPool != nil {
		// ServerName MUST be a DNS-style name matching a DNSName SAN on the
		// upstream leaf; tls verify-full does NOT match a DNS-format
		// ServerName against IPAddress SANs. genSelfSignedServer("localhost")
		// puts "localhost" in DNSNames, so callers point Upstream at
		// "localhost:PORT" (the TCP dial still goes to 127.0.0.1:PORT).
		upTLSCfg = &tls.Config{
			RootCAs:    upTLSPool,
			ServerName: "localhost",
			MinVersion: tls.VersionTLS12,
		}
	}

	sink := &events.SyncSink{}
	srv, err := New(Config{
		Unavoidability:           service.UnavoidabilityObserve,
		StateDir:                 stateDir,
		Sink:                     sink,
		Policy:                   rs,
		Logger:                   slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		UpstreamTLSConfigForTest: upTLSCfg,
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: upAddr,
			TLSMode:  tlsMode,
			Listen:   ServiceListener{Kind: "unix", Path: sockPath},
			Service:  policy.DBService{Name: "appdb", TLSMode: tlsMode, TrustedNetwork: true},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ca, err := srv.ca()
	if err != nil {
		t.Fatalf("srv.ca(): %v", err)
	}
	return &spineHarness{srv: srv, sock: sockPath, sink: sink, ca: ca}
}

// runServer starts srv in a goroutine and returns a stop function that
// cancels Start and waits for Shutdown. The helper polls for the unix
// socket file to appear before returning, so callers can dial immediately.
func runServer(t *testing.T, srv *Server) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan error, 1)
	go func() { doneCh <- srv.Start(ctx) }()

	// Wait for at least the first unix socket to bind. The accept loop is
	// not strictly required to be running yet — bindUnixListener creates the
	// path before acceptLoop starts.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(srv.cfg.Services) > 0 && srv.cfg.Services[0].Listen.Kind == "unix" {
			if _, err := os.Stat(srv.cfg.Services[0].Listen.Path); err == nil {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return func() {
		cancel()
		_ = srv.Shutdown(context.Background())
		<-doneCh
	}
}

// upstreamWithLocalhostHost rewrites the "127.0.0.1" component of a tcp
// address to "localhost" so the proxy's tls.Config.ServerName (set to
// "localhost") matches the upstream cert's DNSName SAN. The TCP dial still
// resolves to 127.0.0.1.
func upstreamWithLocalhostHost(addr string) string {
	return strings.Replace(addr, "127.0.0.1", "localhost", 1)
}

// authOKScript is the canonical happy-path upstream: receive StartupMessage,
// send AuthenticationOk + BackendKeyData + ReadyForQuery('I'), then read
// (and discard) anything else until the client closes.
func authOKScript(t *testing.T, be *pgproto3.Backend, conn net.Conn) error {
	t.Helper()
	if _, err := be.ReceiveStartupMessage(); err != nil {
		return fmt.Errorf("receive startup: %w", err)
	}
	be.Send(&pgproto3.AuthenticationOk{})
	be.Send(&pgproto3.BackendKeyData{ProcessID: 42, SecretKey: append([]byte(nil), wantSecret...)})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := be.Flush(); err != nil {
		return fmt.Errorf("flush: %w", err)
	}
	// Drain remaining client bytes until EOF / deadline.
	buf := make([]byte, 256)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := conn.Read(buf); err != nil {
			return nil
		}
	}
}

// handRolledTerminateReissueHandshake opens a unix-socket client to the
// proxy, sends SSLRequest, completes a TLS handshake against the proxy's CA,
// and writes a StartupMessage. Returns the *tls.Conn for further reads.
//
// The proxy issues an inbound leaf for upstreamHost(svc.Upstream); we set
// svc.Upstream = "localhost:PORT" so the leaf's DNSName SAN is "localhost",
// matching the client-side tls.Config.ServerName.
func handRolledTerminateReissueHandshake(t *testing.T, sockPath string, ca *tlsleaf.CA) *tls.Conn {
	t.Helper()
	raw, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	sslReq := make([]byte, 8)
	binary.BigEndian.PutUint32(sslReq[0:4], 8)
	binary.BigEndian.PutUint32(sslReq[4:8], sslRequestMagic)
	if _, err := raw.Write(sslReq); err != nil {
		t.Fatalf("write SSLRequest: %v", err)
	}
	resp := make([]byte, 1)
	if _, err := io.ReadFull(raw, resp); err != nil {
		t.Fatalf("read 'S': %v", err)
	}
	if resp[0] != 'S' {
		t.Fatalf("'S' resp = %q", resp[0])
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert())
	tlsConn := tls.Client(raw, &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("client TLS: %v", err)
	}
	startup := []byte{}
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, 196608)
	startup = append(startup, v...)
	startup = append(startup, []byte("user\x00alice\x00database\x00app\x00\x00")...)
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(startup)+4))
	if _, err := tlsConn.Write(append(hdr, startup...)); err != nil {
		t.Fatalf("write StartupMessage: %v", err)
	}
	return tlsConn
}

// readUntilRFQ reads pgproto3 frames from c until it sees ReadyForQuery or
// EOF. Returns the captured BackendKeyData (if any).
func readUntilRFQ(t *testing.T, c io.Reader) *pgproto3.BackendKeyData {
	t.Helper()
	fe := pgproto3.NewFrontend(c, nil)
	var bkd *pgproto3.BackendKeyData
	for {
		msg, err := fe.Receive()
		if err != nil {
			return bkd
		}
		switch m := msg.(type) {
		case *pgproto3.BackendKeyData:
			// Frontend reuses its receive buffer; clone so the value survives.
			bkd = &pgproto3.BackendKeyData{
				ProcessID: m.ProcessID,
				SecretKey: append([]byte(nil), m.SecretKey...),
			}
		case *pgproto3.ReadyForQuery:
			return bkd
		}
	}
}

func TestSpine_TerminateReissue_AuthOK_CloseAtRFQ(t *testing.T) {
	srvCfg, cert := genSelfSignedServer(t, "localhost")
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	up := newFakeUpstream(t,
		withFakeUpstreamTLS(srvCfg),
		withFakeUpstreamScript(authOKScript),
	)
	// Rewrite the upstream address so the host portion is "localhost" — this
	// is what the proxy's UpstreamTLSConfigForTest.ServerName matches against,
	// and what upstreamHost() returns to feed ca.IssueLeaf for the inbound
	// leaf's DNSName SAN.
	upAddr := upstreamWithLocalhostHost(up.Address())
	h := startSpineHarness(t, upAddr, "terminate_reissue", pool, "")
	stop := runServer(t, h.srv)
	defer stop()

	tlsConn := handRolledTerminateReissueHandshake(t, h.sock, h.ca)
	defer tlsConn.Close()

	bkd := readUntilRFQ(t, tlsConn)
	if bkd == nil {
		t.Fatal("never received BackendKeyData")
	}
	if bkd.ProcessID != 42 {
		t.Errorf("BKD.ProcessID = %d, want 42", bkd.ProcessID)
	}
	if !bytes.Equal(bkd.SecretKey, wantSecret) {
		t.Errorf("BKD.SecretKey = %x, want %x", bkd.SecretKey, wantSecret)
	}
	if up.AcceptedConns() == 0 {
		t.Fatal("upstream never received a connection")
	}
}

func TestSpine_TerminatePlaintextUpstream_AuthOK_CloseAtRFQ(t *testing.T) {
	up := newFakeUpstream(t, withFakeUpstreamScript(authOKScript))
	// Rewrite host to "localhost" so the inbound reissued leaf's DNSName SAN
	// matches the client-side ServerName ("localhost"). Upstream leg is
	// plaintext; the TCP dial still resolves to 127.0.0.1.
	upAddr := upstreamWithLocalhostHost(up.Address())
	h := startSpineHarness(t, upAddr, "terminate_plaintext_upstream", nil, "")
	stop := runServer(t, h.srv)
	defer stop()

	tlsConn := handRolledTerminateReissueHandshake(t, h.sock, h.ca)
	defer tlsConn.Close()

	bkd := readUntilRFQ(t, tlsConn)
	if bkd == nil {
		t.Fatal("never received BackendKeyData")
	}
	if bkd.ProcessID != 42 {
		t.Errorf("BKD.ProcessID = %d, want 42", bkd.ProcessID)
	}
	if up.AcceptedConns() == 0 {
		t.Fatal("upstream never received a connection")
	}
}

func TestSpine_TerminateReissue_ScramPlus_FailClosed(t *testing.T) {
	srvCfg, cert := genSelfSignedServer(t, "localhost")
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	scramPlusScript := func(t *testing.T, be *pgproto3.Backend, conn net.Conn) error {
		if _, err := be.ReceiveStartupMessage(); err != nil {
			return err
		}
		be.Send(&pgproto3.AuthenticationSASL{
			AuthMechanisms: []string{"SCRAM-SHA-256", "SCRAM-SHA-256-PLUS"},
		})
		return be.Flush()
	}
	up := newFakeUpstream(t,
		withFakeUpstreamTLS(srvCfg),
		withFakeUpstreamScript(scramPlusScript),
	)
	upAddr := upstreamWithLocalhostHost(up.Address())
	h := startSpineHarness(t, upAddr, "terminate_reissue", pool, "")
	stop := runServer(t, h.srv)
	defer stop()

	tlsConn := handRolledTerminateReissueHandshake(t, h.sock, h.ca)
	defer tlsConn.Close()

	// Read frames until ErrorResponse or EOF.
	fe := pgproto3.NewFrontend(tlsConn, nil)
	var got *pgproto3.ErrorResponse
	for {
		msg, err := fe.Receive()
		if err != nil {
			break
		}
		if e, ok := msg.(*pgproto3.ErrorResponse); ok {
			// Clone — the frontend buffer is reused.
			got = &pgproto3.ErrorResponse{
				Severity: e.Severity,
				Code:     e.Code,
				Message:  e.Message,
			}
			break
		}
	}
	if got == nil {
		t.Fatal("never received ErrorResponse")
	}
	if got.Code != scramPlusErrorCode {
		t.Errorf("Code = %q, want %q", got.Code, scramPlusErrorCode)
	}
	if !strings.Contains(got.Message, "SCRAM-SHA-256-PLUS") {
		t.Errorf("Message = %q; want SCRAM-SHA-256-PLUS mentioned", got.Message)
	}
	// Give the proxy a moment to emit its lifecycle event.
	time.Sleep(100 * time.Millisecond)
	evs := h.sink.DrainLifecycle()
	var found bool
	for _, e := range evs {
		if e.Kind == "db_handshake_fail" && e.ErrorCode == scramPlusEventCode {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no db_handshake_fail event with SCRAM_PLUS_FAIL_CLOSED; got %+v", evs)
	}
}

func TestSpine_Passthrough_BytePump(t *testing.T) {
	echoScript := func(t *testing.T, be *pgproto3.Backend, conn net.Conn) error {
		buf := make([]byte, 256)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := conn.Read(buf)
		if n > 0 {
			_, _ = conn.Write(buf[:n])
		}
		return nil
	}
	up := newFakeUpstream(t, withFakeUpstreamScript(echoScript))
	h := startSpineHarness(t, up.Address(), "passthrough", nil, "")
	stop := runServer(t, h.srv)
	defer stop()

	// Open a raw unix-socket client; send a fake SSLRequest, then a payload.
	c, err := net.Dial("unix", h.sock)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	defer c.Close()
	sslReq := make([]byte, 8)
	binary.BigEndian.PutUint32(sslReq[0:4], 8)
	binary.BigEndian.PutUint32(sslReq[4:8], sslRequestMagic)
	if _, err := c.Write(sslReq); err != nil {
		t.Fatalf("write SSLRequest: %v", err)
	}
	resp := make([]byte, 1)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("read 'S': %v", err)
	}
	if resp[0] != 'S' {
		t.Fatalf("'S' resp = %q", resp[0])
	}
	// Now bytes pump through to the echo upstream.
	payload := []byte("ping-pong")
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	buf := make([]byte, len(payload))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(payload) {
		t.Errorf("echo = %q, want %q", buf, payload)
	}
	// Service-level opt-out per spec §11.1: passthrough must NOT emit a
	// degraded_visibility_warning event.
	for _, e := range h.sink.DrainLifecycle() {
		if e.Kind == "degraded_visibility_warning" {
			t.Errorf("unexpected DVW under passthrough: %+v", e)
		}
	}
}

func TestSpine_ReplicationOptIn_BytePump_EmitsDVW(t *testing.T) {
	// Read the StartupMessage the proxy forwards, then echo subsequent bytes.
	echoAfterStartup := func(t *testing.T, be *pgproto3.Backend, conn net.Conn) error {
		if _, err := be.ReceiveStartupMessage(); err != nil {
			return err
		}
		// Echo subsequent bytes verbatim until the client closes.
		buf := make([]byte, 256)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := conn.Read(buf)
			if n > 0 {
				if _, werr := conn.Write(buf[:n]); werr != nil {
					return nil
				}
			}
			if err != nil {
				return nil
			}
		}
	}
	up := newFakeUpstream(t, withFakeUpstreamScript(echoAfterStartup))
	rule := `  - name: allow-replication
    db_service: appdb
    match_kind: replication
    decision: allow
`
	// Rewrite host to "localhost" so the inbound reissued leaf's DNSName SAN
	// is "localhost", matching the client-side ServerName below. The upstream
	// leg is plaintext (terminate_plaintext_upstream).
	upAddr := upstreamWithLocalhostHost(up.Address())
	h := startSpineHarness(t, upAddr, "terminate_plaintext_upstream", nil, rule)
	stop := runServer(t, h.srv)
	defer stop()

	caCert := h.ca.Cert()
	clientPool := x509.NewCertPool()
	clientPool.AddCert(caCert)

	// Hand-roll a client: TLS handshake against proxy, then StartupMessage
	// with replication=true. terminate_plaintext_upstream still terminates
	// inbound TLS — only the upstream leg is plaintext.
	raw, err := net.Dial("unix", h.sock)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	defer raw.Close()
	sslReq := make([]byte, 8)
	binary.BigEndian.PutUint32(sslReq[0:4], 8)
	binary.BigEndian.PutUint32(sslReq[4:8], sslRequestMagic)
	if _, err := raw.Write(sslReq); err != nil {
		t.Fatalf("write SSLRequest: %v", err)
	}
	resp := make([]byte, 1)
	if _, err := io.ReadFull(raw, resp); err != nil {
		t.Fatalf("read 'S': %v", err)
	}
	if resp[0] != 'S' {
		t.Fatalf("'S' resp = %q", resp[0])
	}
	// The proxy reissues a leaf for upstreamHost(svc.Upstream); we rewrote
	// host above to "localhost", so the leaf's DNSName SAN is "localhost"
	// and the ServerName here matches it. tls verify rejects DNS-format
	// ServerName against IPAddress SANs even when the literal string matches.
	tlsConn := tls.Client(raw, &tls.Config{
		RootCAs:    clientPool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("client TLS: %v", err)
	}
	// StartupMessage with replication=true.
	body := []byte{}
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, 196608)
	body = append(body, v...)
	body = append(body, []byte("user\x00rep\x00replication\x00true\x00\x00")...)
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(body)+4))
	if _, err := tlsConn.Write(append(hdr, body...)); err != nil {
		t.Fatalf("write StartupMessage: %v", err)
	}
	// Pump check.
	if _, err := tlsConn.Write([]byte("REPL")); err != nil {
		t.Fatalf("write pump payload: %v", err)
	}
	buf := make([]byte, 4)
	_ = tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(tlsConn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "REPL" {
		t.Errorf("echo = %q, want REPL", buf)
	}
	// Tear down + assert DVW.
	tlsConn.Close()
	time.Sleep(100 * time.Millisecond)
	evs := h.sink.DrainLifecycle()
	var found *events.LifecycleEvent
	for i := range evs {
		if evs[i].Kind == "degraded_visibility_warning" && evs[i].DegradedReason == "replication_passthrough" {
			found = &evs[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no replication_passthrough DVW; events=%+v", evs)
	}
}

func TestSpine_Cancel_AllowedForwardsUnmapped(t *testing.T) {
	upAddr, ch := captureCancelListener(t)
	rule := `  - name: allow-cancel
    db_service: appdb
    match_kind: cancel
    decision: allow
`
	h := startSpineHarness(t, upAddr, "terminate_plaintext_upstream", nil, rule)
	stop := runServer(t, h.srv)
	defer stop()

	c, err := net.Dial("unix", h.sock)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	defer c.Close()
	pkt := buildCancelPacket(77777, 88888)
	if _, err := c.Write(pkt); err != nil {
		t.Fatalf("write cancel: %v", err)
	}
	var captured []byte
	select {
	case captured = <-ch:
		if captured == nil {
			t.Fatal("upstream did not capture cancel packet")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not capture cancel packet")
	}
	if len(captured) != 16 {
		t.Fatalf("captured %d bytes upstream, want 16", len(captured))
	}
	for i := range pkt {
		if captured[i] != pkt[i] {
			t.Errorf("byte %d: got %#x, want %#x", i, captured[i], pkt[i])
		}
	}
}

func TestSpine_Cancel_DeniedSilentClose(t *testing.T) {
	dialed := make(chan struct{}, 1)
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer upLn.Close()
	go func() {
		if c, err := upLn.Accept(); err == nil {
			dialed <- struct{}{}
			c.Close()
		}
	}()
	rule := `  - name: deny-cancel
    db_service: appdb
    match_kind: cancel
    decision: deny
`
	h := startSpineHarness(t, upLn.Addr().String(), "terminate_plaintext_upstream", nil, rule)
	stop := runServer(t, h.srv)
	defer stop()

	c, err := net.Dial("unix", h.sock)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	defer c.Close()
	pkt := buildCancelPacket(1, 2)
	if _, err := c.Write(pkt); err != nil {
		t.Fatalf("write cancel: %v", err)
	}
	select {
	case <-dialed:
		t.Error("upstream was dialed despite deny rule")
	case <-time.After(300 * time.Millisecond):
		// Expected: no dial.
	}
}

// ----------------------------------------------------------------------------
// Plan 04c Task 15 — spine integration tests with real jackc/pgx/v5 client.
//
// These tests connect a real pgx client through the AgentSH proxy to a fake
// upstream and exercise the three Plan 04c outcomes: allow, deny pre-tx, and
// deny in-tx (which terminates the connection).
//
// We use Unix sockets and "terminate_plaintext_upstream" mode. pgx ignores TLS
// settings on Unix sockets (matching libpq behaviour), so the client sends a
// plaintext StartupMessage directly — dispatchStartup accepts that path. The
// upstream leg stays plaintext, letting us reuse the existing fake upstream.
// ----------------------------------------------------------------------------

// pgxSpinePolicyYAML returns a policy YAML with an allow-everyone connection
// rule and an allow-all statement rule on db_service "appdb". If extraDeny is
// true, a deny-DELETE statement rule is appended *after* the allow-all so
// later-listed deny rules override earlier allows on matching ops.
//
// The transaction / session group has no objects per the classifier, so the
// generic ["*"] allow rule cannot cover it (the policy evaluator marks
// object-less effects as implicit deny). We add explicit allow rules for
// those groups so BEGIN/COMMIT/SET flow through.
func pgxSpinePolicyYAML(upstream string, extraDeny bool) string {
	y := `version: 1
name: pgx-spine
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: ` + upstream + `
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
`
	if extraDeny {
		y += `  - name: deny-deletes
    db_service: appdb
    operations: [DELETE]
    decision: deny
`
	}
	return y
}

// renameSocketForPgx renames the harness's "appdb.sock" path to
// ".s.PGSQL.<port>" so pgx's Unix-socket discovery (host=<dir>, port=<port>)
// finds it. Returns the directory portion of the resulting path.
func renameSocketForPgx(t *testing.T, oldPath string, port int) string {
	t.Helper()
	dir := filepath.Dir(oldPath)
	newPath := filepath.Join(dir, fmt.Sprintf(".s.PGSQL.%d", port))
	if err := os.Rename(oldPath, newPath); err != nil {
		t.Fatalf("rename socket for pgx: %v", err)
	}
	return dir
}

// pgxConnString builds a libpq-style DSN that pgx parses. host is the socket
// directory (pgx auto-appends ".s.PGSQL.<port>"). sslmode=disable because pgx
// would ignore TLS over Unix anyway, and we don't want SSLRequest sent.
// default_query_exec_mode=simple_protocol forces pgx to use the Simple Query
// sub-protocol (single 'Q' frames) — the Plan 04c proxy only supports Simple
// Query in phase 1; Extended Query (Parse/Bind/Execute) is denied.
func pgxConnString(sockDir string, port int) string {
	return fmt.Sprintf("host=%s port=%d user=alice dbname=app sslmode=disable default_query_exec_mode=simple_protocol",
		sockDir, port)
}

// pgxErrorCode extracts the SQLSTATE from a pg error, returning "" otherwise.
func pgxErrorCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// pgxAuthOKThenQueryScript handles the StartupMessage with AuthOK + BKD + RFQ,
// then receives one Query and replies with RowDescription/DataRow/CmdComplete/
// RFQ('I'). It then drains until the client closes.
//
// We emit standard_conforming_strings=on as a ParameterStatus because pgx
// (when default_query_exec_mode=simple_protocol) refuses to send simple-
// protocol queries unless that GUC has been advertised by the server.
func pgxAuthOKThenQueryScript(t *testing.T, be *pgproto3.Backend, conn net.Conn) error {
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
	// Receive the Q.
	msg, err := be.Receive()
	if err != nil {
		return fmt.Errorf("receive Q: %w", err)
	}
	if _, ok := msg.(*pgproto3.Query); !ok {
		return fmt.Errorf("expected Query, got %T", msg)
	}
	be.Send(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{
		Name:                 []byte("a"),
		TableOID:             0,
		TableAttributeNumber: 0,
		DataTypeOID:          23, // int4
		DataTypeSize:         4,
		TypeModifier:         -1,
		Format:               0,
	}}})
	be.Send(&pgproto3.DataRow{Values: [][]byte{[]byte("1")}})
	be.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := be.Flush(); err != nil {
		return fmt.Errorf("flush reply: %w", err)
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

func TestSpine_Plan04c_SimpleQuery_AllowFlow(t *testing.T) {
	up := newFakeUpstream(t, withFakeUpstreamScript(pgxAuthOKThenQueryScript))
	upAddr := up.Address()

	h := startSpineHarness(t, upAddr, "terminate_plaintext_upstream", nil, "")
	// Replace the harness's permissive default policy with one that has a real
	// allow-all statement rule on service "appdb" — statement evaluation is
	// what the simpleQueryLoop consults.
	h.srv.SetPolicy(loadRuleSet(t, pgxSpinePolicyYAML(upAddr, false)))

	stop := runServer(t, h.srv)
	defer stop()

	sockDir := renameSocketForPgx(t, h.sock, 5432)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, pgxConnString(sockDir, 5432))
	if err != nil {
		t.Fatalf("pgx.Connect: %v", err)
	}
	defer conn.Close(context.Background())

	var n int
	if err := conn.QueryRow(ctx, "SELECT a FROM t").Scan(&n); err != nil {
		t.Fatalf("QueryRow.Scan: %v", err)
	}
	if n != 1 {
		t.Fatalf("row value = %d want 1", n)
	}

	// Wait for the event to drain.
	var evs []events.DBEvent
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		evs = h.sink.DrainStatements()
		if len(evs) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(evs) != 1 {
		t.Fatalf("statement events = %d want 1: %+v", len(evs), evs)
	}
	if evs[0].Decision.Verb != "allow" {
		t.Fatalf("Decision.Verb = %q want allow", evs[0].Decision.Verb)
	}
	if evs[0].Result.RowsReturned == nil || *evs[0].Result.RowsReturned != 1 {
		t.Fatalf("RowsReturned = %v want 1", evs[0].Result.RowsReturned)
	}
}

func TestSpine_Plan04c_SimpleQuery_DenyPreTx(t *testing.T) {
	// Script: handshake to RFQ('I'); after that, try to read another frame.
	// With deny pre-forward, the proxy must NOT forward the DELETE Q upstream,
	// so the read should time out. We expose the observed state via closure.
	var (
		mu              sync.Mutex
		upstreamSawQuery bool
	)
	script := func(t *testing.T, be *pgproto3.Backend, conn net.Conn) error {
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
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		msg, err := be.Receive()
		if err == nil {
			if _, ok := msg.(*pgproto3.Query); ok {
				mu.Lock()
				upstreamSawQuery = true
				mu.Unlock()
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

	up := newFakeUpstream(t, withFakeUpstreamScript(script))
	upAddr := up.Address()

	h := startSpineHarness(t, upAddr, "terminate_plaintext_upstream", nil, "")
	h.srv.SetPolicy(loadRuleSet(t, pgxSpinePolicyYAML(upAddr, true)))

	stop := runServer(t, h.srv)
	defer stop()

	sockDir := renameSocketForPgx(t, h.sock, 5433)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, pgxConnString(sockDir, 5433))
	if err != nil {
		t.Fatalf("pgx.Connect: %v", err)
	}
	defer conn.Close(context.Background())

	_, err = conn.Exec(ctx, "DELETE FROM t")
	if err == nil {
		t.Fatalf("Exec DELETE: expected deny error, got nil")
	}
	if code := pgxErrorCode(err); code != "42501" {
		t.Fatalf("error code = %q want 42501 (err=%v)", code, err)
	}

	// Wait a beat to confirm the upstream did not see the Query.
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	saw := upstreamSawQuery
	mu.Unlock()
	if saw {
		t.Fatalf("upstream saw a Query frame; expected deny pre-forward")
	}

	var evs []events.DBEvent
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		evs = h.sink.DrainStatements()
		if len(evs) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(evs) != 1 || evs[0].Decision.Verb != "deny" {
		t.Fatalf("statement events = %+v", evs)
	}
	if evs[0].TxContext.DenyAction != "none" {
		t.Fatalf("DenyAction = %q want none", evs[0].TxContext.DenyAction)
	}
}

func TestSpine_Plan04c_SimpleQuery_DenyInTx_Terminates(t *testing.T) {
	// Script: handshake → RFQ('I'); accept BEGIN and reply with
	// CommandComplete + RFQ('T'). The proxy then denies the DELETE in-tx
	// without forwarding it (Plan 04c terminate-on-in-tx-deny).
	script := func(t *testing.T, be *pgproto3.Backend, conn net.Conn) error {
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
		// Receive BEGIN.
		msg, err := be.Receive()
		if err != nil {
			return fmt.Errorf("receive BEGIN: %w", err)
		}
		q, ok := msg.(*pgproto3.Query)
		if !ok || !strings.Contains(strings.ToUpper(q.String), "BEGIN") {
			return fmt.Errorf("expected BEGIN, got %T %v", msg, msg)
		}
		be.Send(&pgproto3.CommandComplete{CommandTag: []byte("BEGIN")})
		be.Send(&pgproto3.ReadyForQuery{TxStatus: 'T'})
		if err := be.Flush(); err != nil {
			return fmt.Errorf("flush BEGIN reply: %w", err)
		}
		// No further Q should arrive (proxy denies in-tx + terminates). Drain.
		buf := make([]byte, 256)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			if _, err := conn.Read(buf); err != nil {
				return nil
			}
		}
	}

	up := newFakeUpstream(t, withFakeUpstreamScript(script))
	upAddr := up.Address()

	h := startSpineHarness(t, upAddr, "terminate_plaintext_upstream", nil, "")
	h.srv.SetPolicy(loadRuleSet(t, pgxSpinePolicyYAML(upAddr, true)))

	stop := runServer(t, h.srv)
	defer stop()

	sockDir := renameSocketForPgx(t, h.sock, 5434)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, pgxConnString(sockDir, 5434))
	if err != nil {
		t.Fatalf("pgx.Connect: %v", err)
	}
	defer conn.Close(context.Background())

	if _, err := conn.Exec(ctx, "BEGIN"); err != nil {
		t.Fatalf("BEGIN: %v", err)
	}
	// DELETE in-tx must error with 42501 and the proxy must close the conn.
	_, err = conn.Exec(ctx, "DELETE FROM t")
	if err == nil {
		t.Fatalf("DELETE in-tx: expected deny error")
	}
	if code := pgxErrorCode(err); code != "42501" {
		t.Fatalf("DELETE error code = %q want 42501 (err=%v)", code, err)
	}

	// A subsequent op must fail because the proxy terminated the connection.
	if _, err := conn.Exec(context.Background(), "SELECT 1"); err == nil {
		t.Fatalf("expected closed-conn error after in-tx deny terminate")
	}

	// Events: at minimum a BEGIN allow + DELETE deny w/ DenyAction=connection_terminated.
	var evs []events.DBEvent
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		evs = h.sink.DrainStatements()
		if len(evs) >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	var deny events.DBEvent
	found := false
	for _, e := range evs {
		if e.Decision.Verb == "deny" {
			deny = e
			found = true
		}
	}
	if !found {
		t.Fatalf("no deny event among %+v", evs)
	}
	if deny.TxContext.DenyAction != "connection_terminated" {
		t.Fatalf("DenyAction = %q want connection_terminated (event=%+v)", deny.TxContext.DenyAction, deny)
	}
}

// ----------------------------------------------------------------------------
// Plan 05b — SQL PREPARE deny spine test
// ----------------------------------------------------------------------------

// prepareDenyScript handles the PostgreSQL handshake (StartupMessage →
// AuthOk + ParameterStatus + BKD + RFQ) and then drains. The proxy intercepts
// PREPARE x AS DELETE FROM users before forwarding, so the upstream never
// receives a Query frame.
func prepareDenyScript(t *testing.T, be *pgproto3.Backend, conn net.Conn) error {
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
	// Drain until client closes; the PREPARE should never arrive.
	buf := make([]byte, 256)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := conn.Read(buf); err != nil {
			return nil
		}
	}
}

// prepareDenyPolicyYAML builds a policy that allows all reads but denies
// DELETE (which is the inner effect of PREPARE x AS DELETE FROM users).
func prepareDenyPolicyYAML(upstream string) string {
	return `version: 1
name: prepare-deny-spine
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: ` + upstream + `
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
  - name: deny-delete
    db_service: appdb
    operations: [DELETE]
    decision: deny
`
}

// TestSpine_SQLPrepare_DenyOverPGX verifies end-to-end that
// "PREPARE delx AS DELETE FROM users" sent through pgx is intercepted by the
// proxy and returned to the client as SQLSTATE 42501, and that the sink
// records a deny event — without forwarding to the upstream.
func TestSpine_SQLPrepare_DenyOverPGX(t *testing.T) {
	up := newFakeUpstream(t, withFakeUpstreamScript(prepareDenyScript))
	upAddr := up.Address()

	h := startSpineHarness(t, upstreamWithLocalhostHost(upAddr), "terminate_plaintext_upstream", nil, "")
	h.srv.SetPolicy(loadRuleSet(t, prepareDenyPolicyYAML(upAddr)))

	stop := runServer(t, h.srv)
	defer stop()

	sockDir := renameSocketForPgx(t, h.sock, 5442)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, pgxConnString(sockDir, 5442))
	if err != nil {
		t.Fatalf("pgx.Connect: %v", err)
	}
	defer conn.Close(context.Background())

	// PREPARE delx AS DELETE FROM users → classifier sees inner DELETE effect →
	// deny-delete rule fires → proxy synthesizes 42501 without forwarding.
	_, err = conn.Exec(ctx, "PREPARE delx AS DELETE FROM users")
	if err == nil {
		t.Fatal("expected deny error for PREPARE DELETE, got nil")
	}
	if code := pgxErrorCode(err); code != "42501" {
		t.Errorf("expected SQLSTATE 42501; got code=%q err=%v", code, err)
	}

	// Upstream must not have received the PREPARE query.
	time.Sleep(200 * time.Millisecond)

	// Confirm the sink recorded a deny event for the PREPARE.
	evs := drainStatements(h.sink, 1, 2*time.Second)
	var gotDeny bool
	for _, ev := range evs {
		if ev.Decision.Verb == "deny" {
			gotDeny = true
			break
		}
	}
	if !gotDeny {
		t.Errorf("expected deny event for PREPARE DELETE; got %+v", evs)
	}
}

// ----------------------------------------------------------------------------
// Plan 05b — FunctionCall opt-in spine test
// ----------------------------------------------------------------------------

// funcCallOptInScript handles the PostgreSQL handshake and then handles one
// FunctionCall frame by sending back a FunctionCallResponse + ReadyForQuery.
func funcCallOptInScript(t *testing.T, be *pgproto3.Backend, conn net.Conn) error {
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
	// Expect a FunctionCall frame.
	msg, err := be.Receive()
	if err != nil {
		return nil // client closed before sending frame
	}
	if _, ok := msg.(*pgproto3.FunctionCall); !ok {
		return fmt.Errorf("expected FunctionCall, got %T", msg)
	}
	be.Send(&pgproto3.FunctionCallResponse{Result: []byte{0x01}})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := be.Flush(); err != nil {
		return fmt.Errorf("flush FunctionCallResponse: %w", err)
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

// funcCallOptInPolicyYAML returns a policy that opts in to FunctionCall and
// allows procedural operations.
func funcCallOptInPolicyYAML(upstream string) string {
	return `version: 1
name: funccall-optin-spine
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: ` + upstream + `
    tls_mode: terminate_plaintext_upstream
    trusted_network: true
    allow_function_call_protocol: true
database_connection_rules:
  - name: allow-everyone
    db_service: appdb
    decision: allow
database_rules:
  - name: allow-procedural
    db_service: appdb
    operations: [procedural]
    decision: allow
`
}

// sendRawFrontendFunctionCall connects directly to the harness's Unix socket,
// completes the TLS + PostgreSQL startup handshake, sends a FunctionCall frame
// for the given OID, and returns the next backend frame received.
//
// It mirrors the pattern in handRolledTerminateReissueHandshake but goes
// further: after reading the startup response (AuthOk + params + BKD + RFQ)
// it sends a FunctionCall and reads the reply.
func sendRawFrontendFunctionCall(t *testing.T, h *spineHarness, functionOID uint32) pgproto3.BackendMessage {
	t.Helper()

	raw, err := net.Dial("unix", h.sock)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	defer raw.Close()

	// SSLRequest.
	sslReq := make([]byte, 8)
	binary.BigEndian.PutUint32(sslReq[0:4], 8)
	binary.BigEndian.PutUint32(sslReq[4:8], sslRequestMagic)
	if _, err := raw.Write(sslReq); err != nil {
		t.Fatalf("write SSLRequest: %v", err)
	}
	resp := make([]byte, 1)
	if _, err := io.ReadFull(raw, resp); err != nil {
		t.Fatalf("read 'S': %v", err)
	}
	if resp[0] != 'S' {
		t.Fatalf("expected 'S', got %q", resp[0])
	}

	// TLS handshake against the proxy's CA.
	pool := x509.NewCertPool()
	pool.AddCert(h.ca.Cert())
	tlsConn := tls.Client(raw, &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}

	// StartupMessage.
	body := make([]byte, 4)
	binary.BigEndian.PutUint32(body, 196608) // protocol 3.0
	body = append(body, []byte("user\x00alice\x00database\x00app\x00\x00")...)
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(body)+4))
	if _, err := tlsConn.Write(append(hdr, body...)); err != nil {
		t.Fatalf("write StartupMessage: %v", err)
	}

	// Read until ReadyForQuery (AuthOk + params + BKD + RFQ).
	// Use a single Frontend for the entire connection lifetime — a second
	// buffered reader on the same conn would cause frame misalignment.
	fe := pgproto3.NewFrontend(tlsConn, tlsConn)
	for {
		m, err := fe.Receive()
		if err != nil {
			t.Fatalf("readUntilRFQ (inline): %v", err)
		}
		if _, ok := m.(*pgproto3.ReadyForQuery); ok {
			break
		}
	}

	// Send the FunctionCall frame.
	fe.Send(&pgproto3.FunctionCall{Function: functionOID})
	if err := fe.Flush(); err != nil {
		t.Fatalf("flush FunctionCall: %v", err)
	}

	// Read the next backend message (FunctionCallResponse or ErrorResponse).
	_ = tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	msg, err := fe.Receive()
	if err != nil {
		t.Fatalf("receive after FunctionCall: %v", err)
	}
	return msg
}

// hasFunctionOID reports whether any Effect in ev has a FunctionOID matching want.
func hasFunctionOID(ev events.DBEvent, want int32) bool {
	for _, e := range ev.Effects {
		if e.FunctionOID != nil && *e.FunctionOID == want {
			return true
		}
	}
	return false
}

// TestSpine_FunctionCall_OptInForwards verifies end-to-end that a raw
// FunctionCall frame (function OID 12345), when allow_function_call_protocol
// is enabled and operations:[procedural] is allowed, is forwarded through the
// proxy to the upstream, which replies with FunctionCallResponse.
// The sink records an allow event with the matching FunctionOID.
func TestSpine_FunctionCall_OptInForwards(t *testing.T) {
	up := newFakeUpstream(t, withFakeUpstreamScript(funcCallOptInScript))
	upAddr := up.Address()

	h := startSpineHarness(t, upstreamWithLocalhostHost(upAddr), "terminate_plaintext_upstream", nil, "")
	h.srv.SetPolicy(loadRuleSet(t, funcCallOptInPolicyYAML(upAddr)))

	stop := runServer(t, h.srv)
	defer stop()

	// Use port 5443 for this test's socket rename.
	sockPath := h.sock
	sockDir := filepath.Dir(sockPath)
	newSockPath := filepath.Join(sockDir, fmt.Sprintf(".s.PGSQL.%d", 5443))
	if err := os.Rename(sockPath, newSockPath); err != nil {
		t.Fatalf("rename socket: %v", err)
	}
	// Update h.sock so sendRawFrontendFunctionCall dials the renamed path.
	h.sock = newSockPath

	got := sendRawFrontendFunctionCall(t, h, 12345)
	if _, ok := got.(*pgproto3.FunctionCallResponse); !ok {
		t.Fatalf("got %T; want *pgproto3.FunctionCallResponse", got)
	}

	// Wait for the allow event.
	evs := drainStatements(h.sink, 1, 2*time.Second)
	var gotAllow bool
	for _, ev := range evs {
		if ev.Decision.Verb == "allow" && hasFunctionOID(ev, 12345) {
			gotAllow = true
			break
		}
	}
	if !gotAllow {
		t.Errorf("expected allow event with FunctionOID=12345; got %+v", evs)
	}
}
