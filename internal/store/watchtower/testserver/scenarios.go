// Package testserver is a hermetic, in-process WTP (Watchtower Transport
// Protocol) server built on top of google.golang.org/grpc/test/bufconn.
// It exists for tests that need to exercise the Transport client end-to-
// end (Connecting → Replaying → Live) without a real network stack.
//
// Scenarios (see Options) model the negative cases the spec's §"Client
// behavior" and §"Error handling" sections require the Transport to
// tolerate: stale ack watermarks, dropped connections after N batches,
// and server-initiated goaway frames. More scenarios land in Task 21
// (assertion helpers).
//
// Production code MUST NOT import this package. It is scoped to _test.go
// files via the testserver → transport dependency; nothing in the
// production build graph references it.
package testserver

import "time"

// Options controls the server's behavior. Zero values use defaults (ack
// accepted, no drops, no goaway, in-order BatchAck per EventBatch).
type Options struct {
	// AckDelay introduces an artificial delay before each ACK (SessionAck
	// and BatchAck) is sent. Used to exercise the Transport's behavior
	// when the server is slow. Zero = no delay.
	AckDelay time.Duration

	// DropAfterBatchN closes the stream (returns an error from the
	// server Stream handler) after observing N EventBatch messages on
	// the current connection. Zero = never drop. The Transport should
	// observe the drop as a recv error and regress to Connecting.
	DropAfterBatchN int

	// GoawayAfterBatchN sends a Goaway ServerMessage after observing N
	// EventBatch messages, then returns nil from the Stream handler
	// (graceful half-close on the server side). Zero = never goaway.
	GoawayAfterBatchN int

	// StaleWatermark overrides the SessionAck's AckHighWatermarkSeq with
	// a value that may be BEHIND the client's actual persisted ack.
	// Used to exercise the `ResendNeeded` / `Anomaly` cursor-split
	// branches of applyServerAckTuple. Zero = "advertise whatever the
	// client supplied" (matches client's persistedAck on the wire).
	StaleWatermark uint64

	// RejectSession causes the SessionAck to carry Accepted=false with
	// the RejectReason string below. Used to exercise the terminal
	// StateShutdown path in runConnecting.
	RejectSession bool
	RejectReason  string
}
