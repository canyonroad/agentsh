//go:build linux

package postgres

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/jackc/pgx/v5/pgproto3"
)

// handleSSLRequest negotiates the SSL response and runs the appropriate
// post-S flow per service.TLSMode.
//
// terminate_reissue / terminate_plaintext_upstream: respond 'S', run
// tls.Server with a leaf for the upstream hostname, swap pc.conn /
// pc.backend to the encrypted stream, return to dispatchStartup so it
// reads the post-TLS StartupMessage.
//
// passthrough: respond 'S', dial upstream plaintext, hand off to bytePump.
// The client's encrypted bytes are forwarded verbatim; upstream's own 'S'
// response (if any) is pumped back to client. No TLS termination occurs
// on either side.
func (pc *proxyConn) handleSSLRequest(ctx context.Context) error {
	switch pc.svc.TLSMode {
	case "terminate_reissue", "terminate_plaintext_upstream":
		return pc.terminateInbound(ctx)
	case "passthrough":
		return pc.passthroughAfterSSL(ctx)
	default:
		// Defensive — unknown mode. Refuse SSL so the client falls back or
		// errors out.
		_, err := pc.conn.Write([]byte{'N'})
		return err
	}
}

// passthroughAfterSSL responds 'S' to the inbound SSLRequest, dials upstream
// plaintext, and runs bytePump until either side closes. Returns
// errPassthroughDone (a sentinel) so dispatchStartup's caller breaks out
// of the for-loop cleanly.
func (pc *proxyConn) passthroughAfterSSL(ctx context.Context) error {
	if _, err := pc.conn.Write([]byte{'S'}); err != nil {
		return fmt.Errorf("write passthrough 'S': %w", err)
	}
	upstream, _, err := dialUpstream(ctx, pc.svc, pc.srv.cfg)
	if err != nil {
		// Synthesize ErrorResponse on the inbound (still-plaintext) stream.
		// This will appear inside the TLS bytes the client wraps; clients
		// typically present this as "server closed connection during
		// startup". Best-effort.
		_ = pc.conn.Close()
		return fmt.Errorf("passthrough upstream dial: %w", err)
	}
	pc.state.upstream = upstream
	// No SNI peek here — Plan 04b's extractSNI helper is plumbed into the
	// proxy's tls.Server GetCertificate path, not used in passthrough. A
	// future task may peek client bytes pre-pump to capture SNI; out of
	// scope for 04b₂.
	if err := bytePump(ctx, pc.conn, pc.state.upstream); err != nil {
		return fmt.Errorf("passthrough bytePump: %w", err)
	}
	return errPassthroughDone
}

// errPassthroughDone is the sentinel returned by passthroughAfterSSL so
// dispatchStartup knows to break out of its for-loop without trying to read
// another startup message.
var errPassthroughDone = errors.New("postgres: passthrough complete")

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
