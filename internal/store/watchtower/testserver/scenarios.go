// Package testserver is a hermetic, in-process WTP (Watchtower
// Transport Protocol) server built on top of
// google.golang.org/grpc/test/bufconn.
//
// SCOPE (as of Task 20): the server handles SessionInit / SessionAck,
// EventBatch / BatchAck, Heartbeat, and Goaway. It is suitable for
// tests that drive the Transport through its Connecting state and
// exercise acknowledgment + reconnect-loop behavior. END-TO-END
// replay/live flows are NOT yet fully testable against this server
// because the Transport itself has three deferred prerequisites:
//
//  1. Transport.Run does NOT start the runRecv goroutine (no post-dial
//     hook lands until Task 22/27); inbound BatchAck / ServerHeartbeat
//     frames are not consumed once the loop reaches Live.
//  2. Production EventBatch encoding (encodeBatchMessage /
//     buildEventBatchFn) returns empty *wtpv1.ClientMessage shells
//     until Task 22 wires the real builder.
//  3. runLive's inflight counter is increment-only (pre-existing).
//
// Consequently, tests that instantiate Transport.New with this
// server's DialerFor and expect meaningful traffic past Live entry
// will observe placeholder frames. Until the Transport prerequisites
// land, this package's real value is:
//
//   - Exercising SessionInit → SessionAck scenarios (accept, reject,
//     stale/non-zero ack watermark, ack delay).
//   - Exercising the drop-after-N-batches and goaway-after-N-batches
//     transitions at the wire level (without expecting the Transport
//     to respond correctly to the subsequent server frames).
//
// Scenario knobs (see Options) model the negative cases the spec's
// §"Client behavior" and §"Error handling" sections require the
// Transport to eventually tolerate. More scenarios and assertion
// helpers land in Task 21.
//
// Production code MUST NOT import this package. The only legitimate
// consumer is _test.go code in the transport / store packages.
package testserver

import (
	"log/slog"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
)

// Options controls the server's behavior. Zero values use defaults
// (SessionAck Accepted=true with watermark (0, 0), no drops, no
// goaway, in-order BatchAck per EventBatch, no delay).
type Options struct {
	// AckDelay introduces an artificial delay before each ACK
	// (SessionAck and BatchAck) is sent. Used to exercise the
	// Transport's behavior when the server is slow. Zero = no delay.
	AckDelay time.Duration

	// DropAfterBatchN closes the stream (returns an error from the
	// server Stream handler) after observing N EventBatch messages on
	// the CURRENT STREAM. Each Dial starts a fresh counter, so
	// reconnect-loop tests see the configured threshold on each
	// attempt. Zero = never drop.
	DropAfterBatchN int

	// GoawayAfterBatchN sends a Goaway ServerMessage after observing
	// N EventBatch messages on the CURRENT STREAM, then returns nil
	// from the Stream handler. Per-stream semantics identical to
	// DropAfterBatchN. Zero = never goaway.
	GoawayAfterBatchN int

	// SessionAckSeq is the literal ack_high_watermark_seq value sent
	// in SessionAck. Zero sends 0 (not "mirror the client's
	// watermark") — use this to drive the applyServerAckTuple first-
	// apply / resend-needed / anomaly branches by choosing the exact
	// tuple the server should claim. SessionAckGeneration works the
	// same way for the generation field. The Transport's own logic
	// decides whether the advertised tuple is behind, equal to, or
	// ahead of its persistedAck; the testserver is not aware of the
	// client's state.
	SessionAckSeq        uint64
	SessionAckGeneration uint32

	// RejectSession causes SessionAck to carry Accepted=false with
	// the RejectReason string below. Used to exercise the terminal
	// StateShutdown path in runConnecting.
	RejectSession bool
	RejectReason  string

	// Metrics, if non-nil, enables inbound-EventBatch validation. Each
	// received EventBatch runs through wtpv1.ValidateEventBatch; a
	// non-nil validation error is routed through
	// transport.ClassifyAndIncInvalidFrame (which bumps
	// wtp_dropped_invalid_frame_total{reason=...}) and the stream is
	// dropped — matching the spec §"Frame validation and forward
	// compatibility" receiver contract. Nil keeps the pre-Task-22b
	// behavior (no validation; EventBatches are tallied regardless of
	// envelope correctness), which is what the existing tests expect
	// since the Transport currently emits placeholder empty batches.
	Metrics transport.Metrics

	// Logger sinks the classifier's WARN output when the defense-in-
	// depth path fires. Defaults to slog.Default() if nil. Only
	// consulted when Metrics is non-nil.
	Logger *slog.Logger
}
