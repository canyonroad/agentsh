//go:build linux

package postgres

import (
	"context"
	"net"

	"github.com/jackc/pgx/v5/pgproto3"
)

// connState is the per-connection state carried through the 04b handshake.
// 04b₂ grows this with upstream-side fields (BackendKeyData, RFQ tracker).
type connState struct {
	dbService      string
	dbUser         string
	database       string
	appName        string
	clientIdentity string // "uid:<peer_uid>" placeholder until Plan 07
	sniHostname    string // best-effort; set by tls.go and sni.go in later tasks
	replication    bool
	tlsTerminated  bool   // true once inbound TLS handshake completes (Task 6)
	peerUID        uint32 // captured at SO_PEERCRED time
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

// formatUID returns "uid:N". Implemented without strconv to keep the
// import set minimal in Task 4; Task 7 may swap to strconv.FormatUint
// if it grows callers that already use strconv.
func formatUID(uid uint32) string {
	const digits = "0123456789"
	if uid == 0 {
		return "uid:0"
	}
	var buf [12]byte
	pos := len(buf)
	v := uid
	for v > 0 {
		pos--
		buf[pos] = digits[v%10]
		v /= 10
	}
	return "uid:" + string(buf[pos:])
}

// run is the per-connection driver. Task 5 replaces this body with the
// startup-packet dispatch. The current stub reads the first message and
// returns; this satisfies the proxyconn_test.go "returns cleanly" expectation.
func (pc *proxyConn) run(ctx context.Context) error {
	_, err := pc.backend.ReceiveStartupMessage()
	return err
}
