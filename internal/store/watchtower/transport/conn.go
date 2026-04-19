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
//
// Lifecycle contract:
//   - CloseSend is the half-close primitive: it signals "no more sends"
//     to the peer. Recv may still return data the peer had queued before
//     observing the half-close. The underlying stream/connection remains
//     open until the peer drains and closes its sending half (or until
//     Close is called).
//   - Close is the full-teardown primitive: it aborts the stream and
//     releases all resources. After Close, Send/Recv/CloseSend MUST
//     return an error (or be no-ops). Close MUST be idempotent so error
//     paths can call it without coordinating with a successful close.
type Conn interface {
	Send(msg *wtpv1.ClientMessage) error
	Recv() (*wtpv1.ServerMessage, error)
	CloseSend() error
	Close() error
}
