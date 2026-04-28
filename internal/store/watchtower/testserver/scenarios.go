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
	//
	// BatchAckDelay overrides this field for BatchAck specifically
	// when both are set. Use BatchAckDelay alone when the test needs
	// the SessionAck to arrive promptly (so EventBatch sends can flow)
	// while still holding back per-batch acknowledgements.
	AckDelay time.Duration

	// BatchAckDelay introduces an artificial delay before each
	// BatchAck is sent. When non-zero, it takes precedence over
	// AckDelay for the BatchAck path only; AckDelay continues to
	// govern SessionAck timing. Zero = fall back to AckDelay (which
	// may itself be zero = no delay).
	//
	// Use this field when a test needs the session handshake to
	// complete normally (so EventBatch sends can flow) but wants to
	// keep the ack cursor unmoved for a bounded window — e.g. a
	// server-restart test that must confirm at least one batch landed
	// before pulling the plug.
	BatchAckDelay time.Duration

	// DropAfterBatchN closes the stream (returns an error from the
	// server Stream handler) after observing N EventBatch messages on
	// the CURRENT STREAM. Each Dial starts a fresh counter, so
	// reconnect-loop tests see the configured threshold on each
	// attempt. Zero = never drop.
	DropAfterBatchN int

	// DropAfterBatchNOnce, when true, arms DropAfterBatchN for the
	// FIRST stream only — subsequent reconnects are served normally.
	// Lets Phase 11 "drop-then-replay" component tests exercise a
	// single drop boundary and then verify the replay completes,
	// without falling into an infinite drop loop (the default
	// per-stream DropAfterBatchN would fire again on every reconnect
	// and the replayed records after the Nth batch would never land).
	DropAfterBatchNOnce bool

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

	// CloseAfterSessionInitRecv, when true, returns from the Stream
	// handler immediately after the first SessionInit is received and
	// validated (BEFORE sending SessionAck). Lets component tests drive
	// the runConnecting recv-failed path: the client's conn.Recv() then
	// surfaces an EOF / stream-closed error, classified as
	// WTPSessionFailureReasonRecvFailed.
	//
	// Mutually exclusive with RejectSession and
	// RespondWithUnexpectedMessage. When more than one is set the
	// handler picks the first matching branch in the order they appear
	// in this struct.
	CloseAfterSessionInitRecv bool

	// RespondWithUnexpectedMessage, when true, sends a BatchAck
	// ServerMessage (instead of SessionAck) in response to a
	// SessionInit. Lets component tests drive the runConnecting
	// unexpected-message path: the client's first Recv after
	// SessionInit returns a non-SessionAck variant, classified as
	// WTPSessionFailureReasonUnexpectedMessage.
	RespondWithUnexpectedMessage bool

	// TransportLossAckDelay introduces an artificial delay before the
	// BatchAck for a TransportLoss frame is sent. When non-zero, the
	// server holds the ack for this duration before sending it. This
	// lets tests verify that the in-flight slot is held by the loss
	// frame's to_sequence until the ack arrives. Zero = no delay.
	TransportLossAckDelay time.Duration

	// Metrics, if non-nil, receives counter increments for inbound
	// EventBatch / SessionInit validation failures via
	// transport.ClassifyAndIncInvalidFrame. Validation itself is
	// UNCONDITIONAL — spec compliance is not coupled to observability
	// wiring. When Metrics is nil the server routes classification to
	// a local noop sink, so malformed SessionInit / EventBatch frames
	// are STILL dropped (the stream is torn down and the batch is
	// not tallied); only the metric side-effect is suppressed. Wire
	// a real *internal/metrics.WTPMetrics when the test asserts on
	// the wtp_dropped_invalid_frame_total{reason=...} counter or the
	// defense-in-depth WARN.
	Metrics transport.Metrics

	// Logger sinks the classifier's defense-in-depth WARN (emitted
	// only when a non-*wtpv1.ValidationError reaches the classifier —
	// SHOULD NEVER happen in production; if it does, the log lets
	// operators identify the non-validator caller). Defaults to
	// slog.Default() when nil.
	Logger *slog.Logger
}
