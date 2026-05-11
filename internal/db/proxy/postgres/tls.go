//go:build linux

package postgres

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/jackc/pgx/v5/pgproto3"
)

// handleSSLRequest negotiates inbound TLS per the service's tls_mode.
// Plan 04b supports terminate_reissue and terminate_plaintext_upstream
// (passthrough is rejected at Server.New). Both terminate-mode paths
// reissue a leaf for the upstream hostname (extracted from svc.Upstream).
func (pc *proxyConn) handleSSLRequest(ctx context.Context) error {
	switch pc.svc.TLSMode {
	case "terminate_reissue", "terminate_plaintext_upstream":
		return pc.terminateInbound(ctx)
	default:
		// Should not happen: passthrough is rejected at Server.New.
		// Defensive: refuse SSL so the client falls back or errors out.
		_, err := pc.conn.Write([]byte{'N'})
		return err
	}
}

// terminateInbound responds 'S' to SSLRequest and runs tls.Server using
// a leaf issued for the upstream hostname. After the handshake the proxy
// swaps pc.conn and pc.backend to the encrypted stream so dispatchStartup
// reads the post-TLS StartupMessage transparently.
func (pc *proxyConn) terminateInbound(ctx context.Context) error {
	if _, err := pc.conn.Write([]byte{'S'}); err != nil {
		return fmt.Errorf("write SSL 'S': %w", err)
	}
	host, err := upstreamHost(pc.svc.Upstream)
	if err != nil {
		return fmt.Errorf("parse upstream %q: %w", pc.svc.Upstream, err)
	}
	ca, err := pc.srv.ca()
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}
	leaf, err := ca.IssueLeaf(host)
	if err != nil {
		return fmt.Errorf("issue leaf for %q: %w", host, err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
		// Capture the SNI value the client offered for audit (§13.2 advisory).
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			pc.state.sniHostname = chi.ServerName
			return leaf, nil
		},
	}
	tlsConn := tls.Server(pc.conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("inbound TLS handshake: %w", err)
	}
	pc.conn = tlsConn
	pc.backend = pgproto3.NewBackend(tlsConn, tlsConn)
	pc.state.tlsTerminated = true
	return nil
}

// upstreamHost extracts the host portion from a "host:port" Upstream string.
func upstreamHost(upstream string) (string, error) {
	host, _, err := net.SplitHostPort(upstream)
	if err != nil {
		return upstream, fmt.Errorf("net.SplitHostPort: %w", err)
	}
	if host == "" {
		return "", fmt.Errorf("empty host in upstream %q", upstream)
	}
	return host, nil
}
