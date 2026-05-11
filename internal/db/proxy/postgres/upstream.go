//go:build linux

package postgres

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

const upstreamDialTimeout = 10 * time.Second

// dialUpstream opens a TCP connection to svc.Upstream and, for
// terminate_reissue, wraps it in tls.Client using system roots + verify-full
// (MinVersion=TLS12, ServerName from the upstream host). For
// terminate_plaintext_upstream returns the raw TCP conn. For passthrough,
// returns the raw TCP conn — callers must not attempt their own TLS
// negotiation; the client's encrypted bytes are forwarded as-is.
//
// cfg.UpstreamTLSConfigForTest, when non-nil, replaces the production TLS
// config entirely. Test-only. Production callsites leave it nil.
//
// Returns both the conn and a *pgproto3.Frontend bound to it; the Frontend
// is what auth-byte forwarding uses. Callers that do not need typed-frame
// access (passthrough, cancel) ignore the Frontend.
func dialUpstream(ctx context.Context, svc Service, cfg Config) (net.Conn, *pgproto3.Frontend, error) {
	dctx, cancel := context.WithTimeout(ctx, upstreamDialTimeout)
	defer cancel()

	d := &net.Dialer{}
	rawConn, err := d.DialContext(dctx, "tcp", svc.Upstream)
	if err != nil {
		return nil, nil, fmt.Errorf("upstream dial %q: %w", svc.Upstream, err)
	}

	var conn net.Conn = rawConn
	if svc.TLSMode == "terminate_reissue" {
		tlsCfg := upstreamTLSConfig(svc, cfg)
		tlsConn := tls.Client(rawConn, tlsCfg)
		if err := tlsConn.HandshakeContext(dctx); err != nil {
			_ = rawConn.Close()
			return nil, nil, fmt.Errorf("upstream TLS handshake %q: %w", svc.Upstream, err)
		}
		conn = tlsConn
	}
	fe := pgproto3.NewFrontend(conn, conn)
	return conn, fe, nil
}

// upstreamTLSConfig returns the production TLS config for terminate_reissue
// upstream connections, or the test override when set.
func upstreamTLSConfig(svc Service, cfg Config) *tls.Config {
	if cfg.UpstreamTLSConfigForTest != nil {
		return cfg.UpstreamTLSConfigForTest
	}
	host, _, err := net.SplitHostPort(svc.Upstream)
	if err != nil {
		host = svc.Upstream // fall back; tls.Client will fail later with a clearer error
	}
	pool, _ := x509.SystemCertPool() // nil pool falls back to system roots in tls.Client
	return &tls.Config{
		RootCAs:    pool,
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}
}
