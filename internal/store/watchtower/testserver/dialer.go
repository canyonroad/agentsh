package testserver

import (
	"context"

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
