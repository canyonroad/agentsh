package testserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

// bufSize is the bufconn listener's backing buffer. 1 MiB is enough for
// any single proto frame the Transport emits (EventBatch is capped well
// below that by BatcherOptions.MaxBytes in test configurations).
const bufSize = 1 << 20

// Server is an in-process WTP server on a bufconn listener.
type Server struct {
	opts     Options
	listener *bufconn.Listener
	grpcSrv  *grpc.Server

	mu      sync.Mutex
	batches []*wtpv1.EventBatch

	closed atomic.Bool
}

// New constructs a Server and starts serving in the background. Close
// MUST be called when the test finishes so the grpc.Server's Serve
// goroutine exits cleanly. New never returns an error — a failed
// listener panics (the bufconn.Listen constructor does not fail).
func New(opts Options) *Server {
	s := &Server{
		opts:     opts,
		listener: bufconn.Listen(bufSize),
		grpcSrv:  grpc.NewServer(),
	}
	wtpv1.RegisterWatchtowerServer(s.grpcSrv, s.handler())
	go func() { _ = s.grpcSrv.Serve(s.listener) }()
	return s
}

// Close stops the server. Idempotent via closed CAS so tests can call
// it unconditionally (e.g. from defer and t.Cleanup).
func (s *Server) Close() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	s.grpcSrv.Stop()
}

// Batches returns a deep-copied snapshot of EventBatch messages the
// server has received in order. Each *EventBatch in the returned
// slice is a proto.Clone of the recorded message, so callers can
// freely mutate, sort, or extract sub-fields without corrupting the
// server's internal record (which later assertion helpers and
// later test phases rely on).
//
// Safe to call concurrently with an active stream.
func (s *Server) Batches() []*wtpv1.EventBatch {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*wtpv1.EventBatch, len(s.batches))
	for i, b := range s.batches {
		out[i] = proto.Clone(b).(*wtpv1.EventBatch)
	}
	return out
}

// addBatch records a received EventBatch and returns the new total
// count. Called under the stream handler's goroutine.
//
// A nil *EventBatch is normalized to an empty value before storage.
// This is defensive — a malformed wire frame (or a future test that
// sends a ClientMessage_EventBatch with EventBatch unset) must not
// panic later assertions inside proto.Clone or the Body oneof
// accessors. Storing an empty batch instead surfaces as
// ErrUnsupportedCompression (Body oneof unset) from the assertion
// helpers, which is the more useful diagnostic.
func (s *Server) addBatch(b *wtpv1.EventBatch) int {
	if b == nil {
		b = &wtpv1.EventBatch{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.batches = append(s.batches, b)
	return len(s.batches)
}

// Conn is the full-duplex stream returned by Dial. It satisfies the
// transport.Conn interface shape (Send / Recv / CloseSend / Close) so
// a Server can drop into transport.New's Options.Dialer via DialerFor.
type Conn interface {
	Send(*wtpv1.ClientMessage) error
	Recv() (*wtpv1.ServerMessage, error)
	CloseSend() error
	Close() error
}

// Dial opens a client-side stream over the bufconn listener. The
// returned Conn wraps the gRPC stream and its ClientConn; Close
// releases both.
func (s *Server) Dial(ctx context.Context) (Conn, error) {
	cc, err := grpc.DialContext(ctx,
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return s.listener.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, err
	}
	stream, err := wtpv1.NewWatchtowerClient(cc).Stream(ctx)
	if err != nil {
		_ = cc.Close()
		return nil, err
	}
	return &grpcConn{stream: stream, cc: cc}, nil
}

// grpcConn adapts a gRPC bidi stream + its ClientConn into the
// transport.Conn-shaped Conn interface. CloseSend half-closes the
// send side; Close fully tears down the underlying ClientConn and
// cancels any in-flight Recv.
type grpcConn struct {
	stream wtpv1.Watchtower_StreamClient
	cc     *grpc.ClientConn
	closed atomic.Bool
}

func (g *grpcConn) Send(m *wtpv1.ClientMessage) error   { return g.stream.Send(m) }
func (g *grpcConn) Recv() (*wtpv1.ServerMessage, error) { return g.stream.Recv() }
func (g *grpcConn) CloseSend() error                    { return g.stream.CloseSend() }

// Close is idempotent so error paths (including t.Cleanup + defer
// pairs) can call it without coordinating with a graceful teardown.
func (g *grpcConn) Close() error {
	if !g.closed.CompareAndSwap(false, true) {
		return nil
	}
	return g.cc.Close()
}

// srvHandler is the server-side WatchtowerServer implementation. The
// Stream handler walks ClientMessage frames in a loop and applies the
// Server's scenario options (drop, goaway, stale watermark, reject).
type srvHandler struct {
	wtpv1.UnimplementedWatchtowerServer
	s *Server
}

func (s *Server) handler() *srvHandler { return &srvHandler{s: s} }

// Stream implements the WatchtowerServer bidi streaming RPC. Every
// ClientMessage variant the Transport can emit is handled:
//
//   - SessionInit → SessionAck (honouring RejectSession +
//     SessionAckSeq / SessionAckGeneration).
//   - EventBatch → tally + BatchAck (honouring DropAfterBatchN +
//     GoawayAfterBatchN). The drop/goaway counters are PER STREAM
//     (per Dial), not global, so a Server reused across multiple
//     Dial calls (reconnect-loop tests) sees each new stream start
//     at 0 batches regardless of how many batches prior streams
//     received.
//   - Heartbeat → no-op (the Transport uses it as a liveness probe;
//     the server's implicit "no error" response is the only signal
//     needed).
//
// Unknown ClientMessage variants are ignored so a future proto
// addition does not break existing tests silently. Add a scenario
// Option if a specific negative test needs to observe unknown-frame
// handling.
func (h *srvHandler) Stream(stream grpc.BidiStreamingServer[wtpv1.ClientMessage, wtpv1.ServerMessage]) error {
	// Per-stream batch counter. DropAfterBatchN and GoawayAfterBatchN
	// reference this, NOT the Server's cumulative s.batches count —
	// each Dial starts a fresh stream with its own counter so
	// reconnect-loop tests can observe the configured threshold on
	// each attempt.
	var streamBatches int
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		switch x := msg.Msg.(type) {
		case *wtpv1.ClientMessage_SessionInit:
			if h.s.opts.Metrics != nil {
				// Receiver-side frame validation (spec §"Frame
				// validation and forward compatibility") mirrors the
				// EventBatch branch below: validate the inbound
				// SessionInit, route any failure through the canonical
				// classifier (bumps
				// wtp_dropped_invalid_frame_total{reason=...}), and
				// drop the stream so the client backs off. Gated on
				// opts.Metrics so the existing tests keep their
				// pre-Task-22b behavior.
				if verr := wtpv1.ValidateSessionInit(x.SessionInit); verr != nil {
					logger := h.s.opts.Logger
					if logger == nil {
						logger = slog.Default()
					}
					transport.ClassifyAndIncInvalidFrame(logger, h.s.opts.Metrics, verr)
					return fmt.Errorf("testserver: invalid inbound SessionInit: %w", verr)
				}
			}
			if h.s.opts.AckDelay > 0 {
				select {
				case <-stream.Context().Done():
					return stream.Context().Err()
				case <-time.After(h.s.opts.AckDelay):
				}
			}
			if h.s.opts.RejectSession {
				if err := stream.Send(&wtpv1.ServerMessage{
					Msg: &wtpv1.ServerMessage_SessionAck{
						SessionAck: &wtpv1.SessionAck{
							Accepted:     false,
							RejectReason: h.s.opts.RejectReason,
						},
					},
				}); err != nil {
					return err
				}
				return nil
			}
			if err := stream.Send(&wtpv1.ServerMessage{
				Msg: &wtpv1.ServerMessage_SessionAck{
					SessionAck: &wtpv1.SessionAck{
						Accepted:            true,
						AckHighWatermarkSeq: h.s.opts.SessionAckSeq,
						Generation:          h.s.opts.SessionAckGeneration,
					},
				},
			}); err != nil {
				return err
			}
		case *wtpv1.ClientMessage_EventBatch:
			if h.s.opts.Metrics != nil {
				// Receiver-side frame validation (spec §"Frame
				// validation and forward compatibility"). On the
				// server side this is the canonical live call site
				// for transport.ClassifyAndIncInvalidFrame: the
				// classifier stamps
				// wtp_dropped_invalid_frame_total{reason=...}
				// using the proto-typed Reason, and the stream is
				// dropped so the client backs off and reconnects.
				// Gated on opts.Metrics so the existing tests that
				// don't wire metrics keep their pre-Task-22b
				// behavior (placeholder empty EventBatches are
				// tallied, not validated).
				if verr := wtpv1.ValidateEventBatch(x.EventBatch); verr != nil {
					logger := h.s.opts.Logger
					if logger == nil {
						logger = slog.Default()
					}
					transport.ClassifyAndIncInvalidFrame(logger, h.s.opts.Metrics, verr)
					return fmt.Errorf("testserver: invalid inbound EventBatch: %w", verr)
				}
			}
			_ = h.s.addBatch(x.EventBatch)
			streamBatches++
			if h.s.opts.DropAfterBatchN > 0 && streamBatches >= h.s.opts.DropAfterBatchN {
				return errors.New("testserver: drop after batch")
			}
			if h.s.opts.GoawayAfterBatchN > 0 && streamBatches >= h.s.opts.GoawayAfterBatchN {
				// Best-effort goaway — propagate any Send error so
				// tests that expect the server to observe the wire
				// do not silently pass on a peer-already-closed
				// stream.
				if err := stream.Send(&wtpv1.ServerMessage{
					Msg: &wtpv1.ServerMessage_Goaway{Goaway: &wtpv1.Goaway{}},
				}); err != nil {
					return err
				}
				return nil
			}
			// Normal case: one BatchAck per EventBatch, pointing at
			// the last event's (generation, sequence). If the
			// EventBatch is empty (e.g. a compressed batch we do not
			// inspect, or a Heartbeat-style empty frame), the ack
			// points at (0, 0) which the Transport's
			// applyServerAckTuple helper treats as a no-op under the
			// steady-state cursor.
			var (
				lastSeq uint64
				lastGen uint32
			)
			if u := x.EventBatch.GetUncompressed(); u != nil {
				if events := u.GetEvents(); len(events) > 0 {
					last := events[len(events)-1]
					lastSeq = last.GetSequence()
					lastGen = last.GetGeneration()
				}
			}
			if h.s.opts.AckDelay > 0 {
				select {
				case <-stream.Context().Done():
					return stream.Context().Err()
				case <-time.After(h.s.opts.AckDelay):
				}
			}
			if err := stream.Send(&wtpv1.ServerMessage{
				Msg: &wtpv1.ServerMessage_BatchAck{
					BatchAck: &wtpv1.BatchAck{
						AckHighWatermarkSeq: lastSeq,
						Generation:          lastGen,
					},
				},
			}); err != nil {
				return err
			}
		case *wtpv1.ClientMessage_Heartbeat:
			// Transport's liveness probe; no ack required.
		}
	}
}
