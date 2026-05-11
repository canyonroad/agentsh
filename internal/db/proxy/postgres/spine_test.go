//go:build linux

package postgres

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
