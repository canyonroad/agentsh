//go:build linux

package postgres

import (
	"context"
	"net"
	"strconv"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/events"
)

// connState is the per-connection state carried through the 04b handshake.
// 04b₂ grows this with upstream-side fields (BackendKeyData, RFQ tracker).
type connState struct {
	dbService      string
	dbUser         string
	database       string
	appName        string
	clientIdentity string
	sniHostname    string
	replication    bool
	tlsTerminated  bool
	peerUID        uint32

	// Upstream-side state. Set by handleStartupMessage after dialUpstream
	// succeeds. closeUpstream() (defined below) closes both as needed.
	upstream   net.Conn
	upstreamFE *pgproto3.Frontend

	// upstreamBKD captures the real upstream BackendKeyData (PID, Secret)
	// for Plan 06's mapping table. 04b₂ forwards verbatim to client — the
	// values are recorded but not used.
	//
	// SecretKey is a byte slice (not uint32) because pgx v5's
	// pgproto3.BackendKeyData.SecretKey is []byte: standard PostgreSQL uses
	// 4 bytes, but CockroachDB extends this with a longer secret. Storing
	// the raw bytes preserves whatever the upstream sent.
	upstreamBKD struct {
		PID       uint32
		SecretKey []byte
	}

	// degradedReason is set when the proxy enters a passthrough-equivalent
	// state via an explicit opt-in (replication_passthrough in 04b₂;
	// gssenc_passthrough lands in Plan 05). Used by the DVW emitter.
	degradedReason string
}

// logger narrows *slog.Logger to just the methods we use, so tests can
// substitute a no-op when verbose output would clutter t.Log.
type logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Debug(msg string, args ...any)
}

// proxyConn drives one client connection through the 04b handshake. It
// owns the *pgproto3.Backend used for client-facing framing and the
// connState. Branches plugged in by Tasks 5–7:
//
//   - handshake.go (Task 5): startup-packet dispatch.
//   - tls.go      (Task 6): inbound TLS termination.
//   - connect_rule.go (Task 7): connect-kind connection-rule eval + §13.3.
//
// On exit the conn is closed by the caller (acceptLoop's deferred Close).
type proxyConn struct {
	srv     *Server
	svc     Service
	logger  logger
	conn    net.Conn // current client-facing conn (becomes *tls.Conn after Task 6)
	backend *pgproto3.Backend
	state   *connState
}

func newProxyConn(srv *Server, svc Service, conn net.Conn, peerUID uint32) *proxyConn {
	return &proxyConn{
		srv:     srv,
		svc:     svc,
		logger:  srv.logger,
		conn:    conn,
		backend: pgproto3.NewBackend(conn, conn),
		state: &connState{
			dbService:      svc.Name,
			peerUID:        peerUID,
			clientIdentity: clientIdentityFromUID(peerUID),
		},
	}
}

func clientIdentityFromUID(uid uint32) string {
	return formatUID(uid)
}

// formatUID returns "uid:N". Delegates to strconv.FormatUint for conversion.
func formatUID(uid uint32) string {
	return "uid:" + strconv.FormatUint(uint64(uid), 10)
}

// run is the per-connection driver. Delegates to dispatchStartup (handshake.go)
// which handles SSLRequest, GSSENCRequest, CancelRequest, and StartupMessage.
// Task 7 inserts connect-rule eval inside dispatchStartup ahead of the
// not-yet-wired error.
func (pc *proxyConn) run(ctx context.Context) error {
	defer pc.closeUpstream()
	return pc.dispatchStartup(ctx)
}

// closeUpstream closes the upstream conn if it was opened. Safe to call
// multiple times.
func (pc *proxyConn) closeUpstream() {
	if pc.state.upstream != nil {
		_ = pc.state.upstream.Close()
		pc.state.upstream = nil
	}
}

// emitHandshakeFail emits a db_handshake_fail LifecycleEvent into the
// configured sink. errorCode populates the event's ErrorCode field; the
// matching SQLSTATE is on the wire ErrorResponse.
func (pc *proxyConn) emitHandshakeFail(ctx context.Context, errorCode string) {
	if pc.srv.cfg.Sink == nil {
		return
	}
	ev := events.LifecycleEvent{
		EventID:        newEventID(),
		Timestamp:      timeNow(),
		DBService:      pc.svc.Name,
		ClientIdentity: pc.state.clientIdentity,
		Kind:           "db_handshake_fail",
		PeerUID:        pc.state.peerUID,
		ErrorCode:      errorCode,
		SNIHostname:    pc.state.sniHostname,
	}
	_ = pc.srv.cfg.Sink.EmitLifecycle(ctx, ev)
}

// emitDegradedVisibility emits a degraded_visibility_warning LifecycleEvent
// with the supplied reason classifications. degradedReason is the typed
// enum value ("replication_passthrough" / "gssenc_passthrough"); reason is
// the free-form spec-level reason string.
func (pc *proxyConn) emitDegradedVisibility(ctx context.Context, degradedReason, reason string) {
	if pc.srv.cfg.Sink == nil {
		return
	}
	ev := events.LifecycleEvent{
		EventID:        newEventID(),
		Timestamp:      timeNow(),
		DBService:      pc.svc.Name,
		ClientIdentity: pc.state.clientIdentity,
		Kind:           "degraded_visibility_warning",
		Reason:         reason,
		PeerUID:        pc.state.peerUID,
		DegradedReason: degradedReason,
		SNIHostname:    pc.state.sniHostname,
	}
	_ = pc.srv.cfg.Sink.EmitLifecycle(ctx, ev)
}
