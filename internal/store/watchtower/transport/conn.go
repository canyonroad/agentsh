package transport

import (
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// Conn is the abstraction over a bidirectional WTP gRPC stream so that
// transport tests can substitute a fake.
//
// Concurrency contract (mirrors gRPC's ClientStream):
//   - A single sender goroutine and a single receiver goroutine MAY
//     operate concurrently — i.e. one Send may overlap one Recv.
//   - Multiple concurrent Senders are NOT safe.
//   - Multiple concurrent Receivers are NOT safe.
//   - CloseSend MUST NOT race with a concurrent Send. Callers are
//     responsible for sequencing Send and CloseSend on the sender
//     goroutine.
type Conn interface {
	Send(msg *wtpv1.ClientMessage) error
	Recv() (*wtpv1.ServerMessage, error)
	CloseSend() error
}
