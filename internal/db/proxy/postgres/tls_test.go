//go:build linux

package postgres

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/service"
)

// startFakeUpstreamForTLSTest binds a tls listener with the supplied tls.Config
// on 127.0.0.1:0 and runs one server goroutine that sends Auth+RFQ on the
// first connection. Returns the listener address.
func startFakeUpstreamForTLSTest(t *testing.T, srvCfg *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatalf("tls.Listen fake upstream: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		be := pgproto3.NewBackend(c, c)
		// Discard the inbound StartupMessage from the proxy.
		_, _ = be.ReceiveStartupMessage()
		be.Send(&pgproto3.AuthenticationOk{})
		be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		_ = be.Flush()
	}()
	return ln.Addr().String()
}

func TestTLS_TerminateReissue_RoundTrip(t *testing.T) {
	// Build a fake-upstream TLS listener with a known cert; install the cert
	// into the proxy's UpstreamTLSConfigForTest trust pool.
	upSrvCfg, upCert := genSelfSignedServer(t, "localhost")
	upListenAddr := startFakeUpstreamForTLSTest(t, upSrvCfg)
	// The listener binds on 127.0.0.1; rewrite to localhost so the proxy's
	// reissued inbound leaf carries "localhost" as a DNSName SAN (not an IP)
	// — crypto/tls verifies DNS-style ServerName against DNSName SANs only.
	_, port, err := net.SplitHostPort(upListenAddr)
	if err != nil {
		t.Fatalf("net.SplitHostPort: %v", err)
	}
	upAddr := net.JoinHostPort("localhost", port)
	pool := x509.NewCertPool()
	pool.AddCert(upCert)

	rs := loadRuleSet(t, `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: `+upAddr+`
    tls_mode: terminate_reissue
database_connection_rules:
  - name: allow-everyone
    db_service: appdb
    decision: allow
`)

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	srv, err := New(Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Policy:         rs,
		UpstreamTLSConfigForTest: &tls.Config{
			RootCAs:    pool,
			ServerName: "localhost",
			MinVersion: tls.VersionTLS12,
		},
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: upAddr,
			TLSMode:  "terminate_reissue",
			Listen:   ServiceListener{Kind: "unix", Path: "/tmp/_unused.sock"},
			Service:  policy.DBService{Name: "appdb", TLSMode: "terminate_reissue"},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pc := newProxyConn(srv, srv.cfg.Services[0], a, 1000)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	srvDone := make(chan error, 1)
	go func() { srvDone <- pc.run(ctx) }()

	sslReq := make([]byte, 8)
	binary.BigEndian.PutUint32(sslReq[0:4], 8)
	binary.BigEndian.PutUint32(sslReq[4:8], 80877103)
	if _, err := b.Write(sslReq); err != nil {
		t.Fatalf("write SSLRequest: %v", err)
	}
	resp := make([]byte, 1)
	if _, err := io.ReadFull(b, resp); err != nil {
		t.Fatalf("read SSL resp: %v", err)
	}
	if resp[0] != 'S' {
		t.Fatalf("SSL resp = %q, want 'S'", resp[0])
	}

	ca, err := srv.ca()
	if err != nil {
		t.Fatalf("srv.ca(): %v", err)
	}
	clientPool := x509.NewCertPool()
	clientPool.AddCert(ca.Cert())

	tlsConn := tls.Client(b, &tls.Config{
		RootCAs:    clientPool,
		ServerName: "localhost",
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}

	body := []byte{}
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, 196608)
	body = append(body, v...)
	body = append(body, []byte("user\x00alice\x00database\x00app\x00\x00")...)
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(body)+4))
	if _, err := tlsConn.Write(append(hdr, body...)); err != nil {
		t.Fatalf("write StartupMessage: %v", err)
	}
	// Read the upstream-driven AuthenticationOk frame the proxy forwards.
	// The fake upstream in tls_test sends AuthOk + RFQ; the proxy closes
	// after forwarding RFQ. First byte should be 'R' (Authentication).
	first := make([]byte, 1)
	if _, err := io.ReadFull(tlsConn, first); err != nil {
		t.Fatalf("read post-startup: %v", err)
	}
	if first[0] != 'R' {
		t.Errorf("first post-startup byte = %q, want 'R' (Authentication)", first[0])
	}

	_ = tlsConn.Close()
	cancel()
	select {
	case err := <-srvDone:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			t.Logf("server returned: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not exit after cancel")
	}
}
