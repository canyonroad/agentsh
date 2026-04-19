package transport

import (
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// Conn is the abstraction over a bidirectional WTP gRPC stream so that
// transport tests can substitute a fake. It is NOT safe for concurrent
// use: the transport state machine performs all Send/Recv calls from a
// single goroutine.
type Conn interface {
	Send(msg *wtpv1.ClientMessage) error
	Recv() (*wtpv1.ServerMessage, error)
	CloseSend() error
}
