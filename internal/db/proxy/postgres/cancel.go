//go:build linux

package postgres

import (
	"context"
	"fmt"
	"net"
	"time"
)

const cancelDialTimeout = 5 * time.Second

// forwardCancel dials svc.Upstream plaintext (CancelRequest is plaintext per
// the PG protocol — no SSLRequest preamble), writes the client packet
// verbatim, and closes. No auth, no TLS, no response.
//
// Packet length is variable: 16 bytes for vanilla Postgres (4-byte length +
// 4-byte magic + 4-byte PID + 4-byte secret), longer for CockroachDB's
// extended secret. Floor of 12 bytes covers length+magic+PID; a valid
// CancelRequest from pgproto3 always carries at least that much.
//
// In 04b₂ the (PID, Secret) values are forwarded un-mapped — Plan 06 adds
// the mapping table. Until Plan 06 lands, the upstream's actual PID/Secret
// were forwarded to the client as BackendKeyData in 04b₂'s forwardAuth, so
// the cancel happens to work end-to-end (see design §7 risks).
func forwardCancel(ctx context.Context, svc Service, packet []byte) error {
	if len(packet) < 12 {
		return fmt.Errorf("postgres.forwardCancel: packet is %d bytes; want >= 12", len(packet))
	}
	dctx, cancel := context.WithTimeout(ctx, cancelDialTimeout)
	defer cancel()
	d := &net.Dialer{}
	conn, err := d.DialContext(dctx, "tcp", svc.Upstream)
	if err != nil {
		return fmt.Errorf("postgres.forwardCancel: dial %q: %w", svc.Upstream, err)
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(cancelDialTimeout))
	if _, err := conn.Write(packet); err != nil {
		return fmt.Errorf("postgres.forwardCancel: write: %w", err)
	}
	return nil
}
