package testserver

import (
	"context"
	"sync"

	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
)

// DialerFor returns a transport.Dialer backed by this server's
// bufconn listener. The returned Conn satisfies transport.Conn (the
// local Conn interface in this package is the same shape); the
// type assertion below is safe because grpcConn implements both.
//
// Typical use:
//
//	srv := testserver.New(testserver.Options{})
//	defer srv.Close()
//	tr, err := transport.New(transport.Options{
//	    Dialer:    srv.DialerFor(),
//	    AgentID:   "test",
//	    SessionID: "s1",
//	    WAL:       w,
//	})
//
// Each call to the returned Dialer opens a fresh bufconn stream, so
// reconnect-loop tests can observe multiple dial → SessionInit →
// SessionAck cycles against the same Server.
func (s *Server) DialerFor() transport.Dialer {
	return transport.DialerFunc(func(ctx context.Context) (transport.Conn, error) {
		c, err := s.Dial(ctx)
		if err != nil {
			return nil, err
		}
		return c.(transport.Conn), nil
	})
}

// RoutingDialer is a transport.Dialer whose backend Server can be
// swapped atomically to simulate server restarts in tests. Dial
// always delegates to whichever *Server is current at call time.
type RoutingDialer struct {
	mu  sync.Mutex
	cur *Server
}

// NewRoutingDialer returns a RoutingDialer initially backed by s.
func NewRoutingDialer(s *Server) *RoutingDialer {
	return &RoutingDialer{cur: s}
}

// Switch atomically re-points the dialer at a new server. Any
// subsequent Dial calls open streams against the new server.
func (r *RoutingDialer) Switch(s *Server) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cur = s
}

// Dial implements transport.Dialer by opening a stream on the current
// server.
func (r *RoutingDialer) Dial(ctx context.Context) (transport.Conn, error) {
	r.mu.Lock()
	cur := r.cur
	r.mu.Unlock()
	return cur.DialerFor().Dial(ctx)
}
