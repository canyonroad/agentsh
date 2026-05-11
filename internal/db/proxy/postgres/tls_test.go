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

	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/service"
)

func TestTLS_TerminateReissue_RoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

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
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert())

	tlsConn := tls.Client(b, &tls.Config{
		RootCAs:    pool,
		ServerName: "db.internal",
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
	first := make([]byte, 1)
	if _, err := io.ReadFull(tlsConn, first); err != nil {
		t.Fatalf("read post-startup: %v", err)
	}
	if first[0] != 'E' {
		t.Errorf("first post-startup byte = %q, want 'E'", first[0])
	}

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
