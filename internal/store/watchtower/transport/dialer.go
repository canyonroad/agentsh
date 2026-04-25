package transport

import "context"

// Dialer establishes a new Conn to the watchtower endpoint.
type Dialer interface {
	Dial(ctx context.Context) (Conn, error)
}

// DialerFunc adapts a function to the Dialer interface.
type DialerFunc func(ctx context.Context) (Conn, error)

func (f DialerFunc) Dial(ctx context.Context) (Conn, error) { return f(ctx) }
