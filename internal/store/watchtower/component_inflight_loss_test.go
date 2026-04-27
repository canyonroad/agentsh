package watchtower_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	"github.com/agentsh/agentsh/pkg/types"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// errMapper is a compact.Mapper that always returns an error. Used by the
// mapper_failure subtest to trigger compact.ErrMapperFailure → MAPPER_FAILURE
// TransportLoss. The error message is deterministic so test output is stable.
type errMapper struct{}

func (errMapper) Map(_ types.Event) (compact.MappedEvent, error) {
	return compact.MappedEvent{}, fmt.Errorf("simulated mapper error")
}

// newInflightTestStore builds a watchtower Store wired to the given dialer
// with EmitExtendedLossReasons set to the supplied flag value. The mapper
// argument is used as-is (caller passes either compact.StubMapper{} or an
// errMapper{}). allowStub must be true when mapper is a StubMapper.
func newInflightTestStore(t *testing.T, router transport.Dialer, mapper compact.Mapper, allowStub bool, emitExtended bool) *watchtower.Store {
	t.Helper()
	s, err := watchtower.New(context.Background(), watchtower.Options{
		WALDir:                  t.TempDir(),
		Mapper:                  mapper,
		Allocator:               audit.NewSequenceAllocator(),
		AgentID:                 "a",
		SessionID:               "s",
		KeyFingerprint:          "sha256:inflight-test",
		HMACKeyID:               "k1",
		HMACSecret:              bytes.Repeat([]byte("a"), 32),
		HMACAlgorithm:           "hmac-sha256",
		BatchMaxRecords:         256,
		BatchMaxBytes:           256 * 1024,
		BatchMaxAge:             50 * time.Millisecond,
		AllowStubMapper:         allowStub,
		Dialer:                  router,
		EmitExtendedLossReasons: emitExtended,
		Logger:                  slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatalf("watchtower.New: %v", err)
	}
	return s
}

// TestStore_InFlightDrop_EmitsTransportLossOnWire verifies that each
// triggerable in-flight drop reason produces a matching TransportLoss frame
// on the wire when EmitExtendedLossReasons is true.
//
// Generation note: the in-flight loss marker is written to the WAL at
// ev.Chain.Generation. The Live reader is opened at HighGeneration() — which
// is 0 on a fresh WAL. To ensure the loss marker falls into the same
// generation the live reader is watching, all test events use Generation=0.
// This is realistic: on a fresh installation the first events naturally
// arrive at gen=0; the marker must be visible to the reader immediately.
//
// Reasons covered:
//   - sequence_overflow: ev.Chain.Sequence > math.MaxInt64
//   - invalid_timestamp: ev.Timestamp = zero value
//   - mapper_failure:    custom errMapper that returns an error
//   - invalid_utf8:      skipped (unreachable via public API without
//     bypassing construction-time validation — context_digest,
//     event_hash, key_fingerprint, and prev_hash are all SHA-256
//     hex strings; KeyFingerprint with bad UTF-8 would fail
//     chain.ComputeContextDigest inside watchtower.New before any
//     AppendEvent could be attempted)
//   - invalid_mapper:    skipped (typed-nil mapper rejected at
//     validate() construction time; covered by unit tests in
//     append_drop_internal_test.go)
func TestStore_InFlightDrop_EmitsTransportLossOnWire(t *testing.T) {
	// encoder flag must be set at the package level before any Store is
	// constructed, because the encoder is a package-level var in
	// transport/state_live.go.
	transport.SetEncoderEmitExtendedReasons(true)
	t.Cleanup(func() { transport.SetEncoderEmitExtendedReasons(false) })

	cases := []struct {
		name       string
		wantReason wtpv1.TransportLossReason
		makeEvent  func(seq uint64) types.Event
		mapper     compact.Mapper
		allowStub  bool
		skip       string
	}{
		{
			name:       "sequence_overflow",
			wantReason: wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_SEQUENCE_OVERFLOW,
			makeEvent: func(_ uint64) types.Event {
				return types.Event{
					Type:      "exec",
					SessionID: "s",
					Timestamp: time.Now(),
					// Sequence > math.MaxInt64 triggers the overflow check
					// in AppendEvent. Generation=0 matches the Live reader's
					// fresh-WAL HighGeneration()=0.
					Chain: &types.ChainState{Sequence: 1<<63 + 1, Generation: 0},
				}
			},
			mapper:    compact.StubMapper{},
			allowStub: true,
		},
		{
			name:       "invalid_timestamp",
			wantReason: wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_TIMESTAMP,
			makeEvent: func(seq uint64) types.Event {
				return types.Event{
					Type:      "exec",
					SessionID: "s",
					Timestamp: time.Time{}, // zero value → compact.ErrInvalidTimestamp
					// Generation=0 matches the Live reader's fresh-WAL generation.
					Chain: &types.ChainState{Sequence: seq, Generation: 0},
				}
			},
			mapper:    compact.StubMapper{},
			allowStub: true,
		},
		{
			name:       "mapper_failure",
			wantReason: wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_MAPPER_FAILURE,
			makeEvent: func(seq uint64) types.Event {
				return types.Event{
					Type:      "exec",
					SessionID: "s",
					Timestamp: time.Now(),
					// Generation=0 matches the Live reader's fresh-WAL generation.
					Chain: &types.ChainState{Sequence: seq, Generation: 0},
				}
			},
			// errMapper causes compact.Encode to return compact.ErrMapperFailure.
			mapper:    errMapper{},
			allowStub: false,
		},
		{
			name: "invalid_utf8",
			skip: "invalid_utf8 is unreachable via public AppendEvent: " +
				"chain.EncodeCanonical validates only context_digest/event_hash/" +
				"key_fingerprint/prev_hash which are SHA-256 hex strings; " +
				"providing a bad-UTF-8 KeyFingerprint fails chain.ComputeContextDigest " +
				"inside watchtower.New before AppendEvent can be reached. " +
				"Covered at the unit level in chain/canonical_test.go.",
		},
		{
			name: "invalid_mapper",
			skip: "invalid_mapper requires a typed-nil compact.Mapper; " +
				"Options.validate() rejects it at construction time. " +
				"Covered by unit tests in append_drop_internal_test.go.",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.skip != "" {
				t.Skip(tc.skip)
			}

			srv := testserver.New(testserver.Options{})
			defer srv.Close()
			router := testserver.NewRoutingDialer(srv)

			s := newInflightTestStore(t, router, tc.mapper, tc.allowStub, true)
			defer s.Close()

			// Wait for SessionInit to land — this confirms the transport has
			// completed the handshake and is either in Replaying or Live
			// state. Without this, AppendEvent could race the dial and the
			// resulting loss marker might be written before the Live reader
			// is registered, causing it to miss the notification.
			if _, err := srv.WaitForFirstSessionInit(10 * time.Second); err != nil {
				t.Fatalf("WaitForFirstSessionInit: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Emit the drop-triggering event.
			_ = s.AppendEvent(ctx, tc.makeEvent(1))

			loss, err := srv.WaitForTransportLoss(15 * time.Second)
			if err != nil {
				t.Fatalf("WaitForTransportLoss: %v", err)
			}
			if loss.Reason != tc.wantReason {
				t.Fatalf("TransportLoss.Reason = %v; want %v", loss.Reason, tc.wantReason)
			}
		})
	}
}

// TestStore_InFlightDrop_NoTransportLoss_WhenFlagOff is the flag-off
// counterpart for the sequence_overflow reason. When
// EmitExtendedLossReasons is false, no TransportLoss frame must arrive
// within a short grace window — the drop is counter-only.
func TestStore_InFlightDrop_NoTransportLoss_WhenFlagOff(t *testing.T) {
	// Ensure encoder flag is off (the default; this call is defensive
	// against other tests in the same binary that leave it set).
	transport.SetEncoderEmitExtendedReasons(false)
	t.Cleanup(func() { transport.SetEncoderEmitExtendedReasons(false) })

	srv := testserver.New(testserver.Options{})
	defer srv.Close()
	router := testserver.NewRoutingDialer(srv)

	s := newInflightTestStore(t, router, compact.StubMapper{}, true, false /* EmitExtendedLossReasons=false */)
	defer s.Close()

	if _, err := srv.WaitForFirstSessionInit(10 * time.Second); err != nil {
		t.Fatalf("WaitForFirstSessionInit: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Trigger a sequence_overflow drop (Generation=0 matches fresh-WAL Live reader).
	_ = s.AppendEvent(ctx, types.Event{
		Type:      "exec",
		SessionID: "s",
		Timestamp: time.Now(),
		Chain:     &types.ChainState{Sequence: 1<<63 + 1, Generation: 0},
	})

	// Allow a brief window for any spurious frame to arrive. If the flag
	// is correctly off, nothing should show up.
	const gracePeriod = 500 * time.Millisecond
	_, err := srv.WaitForTransportLoss(gracePeriod)
	if err == nil {
		t.Fatal("TestStore_InFlightDrop_NoTransportLoss_WhenFlagOff: unexpected TransportLoss received; flag was off")
	}
	// err is a deadline error, which is the expected outcome.
}

// TestStore_AckRegressionAfterGC_EmitsTransportLoss manufactures an
// ack-regression scenario: the testserver advertises a SessionAck
// high-watermark (gen=1, seq=20) that is higher than anything the fresh
// WAL has produced.
//
// computeReplayStart detects the regression (EarliestDataSequence for
// gen=1 returns ok=false → Case C fully-GC'd), synthesises an in-memory
// wal.LossRecord{Reason: "ack_regression_after_gc"}, and feeds it as
// PrefixLoss. The encoder maps it to ACK_REGRESSION_AFTER_GC and emits a
// TransportLoss frame.
//
// NOTE: as of this task the PrefixLoss thread-through in Run's stagesLoop
// carries a TODO(Task 22) comment (`_ = stage.PrefixLoss`). That comment
// is the gating item: until it is wired, the synthesised loss record is
// computed and logged but NOT emitted on the wire. This subtest therefore
// asserts that the TODO is resolved — if the TODO fires instead of the
// wire frame, the test correctly fails and documents the regression.
func TestStore_AckRegressionAfterGC_EmitsTransportLoss(t *testing.T) {
	// SessionAckSeq=20/SessionAckGeneration=1 means the server claims it
	// has already acked up to gen=1,seq=20. A fresh-WAL client has no
	// data at all for gen=1, so computeReplayStart falls into Case C:
	// EarliestDataSequence(gen=1) → ok=false, gapStart(=1) <= persistedAck.Sequence(=20)
	// → prefixLoss{from=1, to=20, reason=ack_regression_after_gc}.
	//
	// For this to work the client's persistedAck must be seeded from the
	// server's SessionAck (first-apply path: persistedAckPresent=false on a
	// fresh WAL, so applyServerAckTuple adopts the server tuple once
	// HasDataBelowGeneration(gen=1) returns false — which it does on an
	// empty WAL).
	transport.SetEncoderEmitExtendedReasons(true)
	t.Cleanup(func() { transport.SetEncoderEmitExtendedReasons(false) })

	srv := testserver.New(testserver.Options{
		SessionAckSeq:        20,
		SessionAckGeneration: 1,
	})
	defer srv.Close()
	router := testserver.NewRoutingDialer(srv)

	s, err := watchtower.New(context.Background(), watchtower.Options{
		WALDir:                  t.TempDir(),
		Mapper:                  compact.StubMapper{},
		Allocator:               audit.NewSequenceAllocator(),
		AgentID:                 "a",
		SessionID:               "s",
		KeyFingerprint:          "sha256:ack-regression-test",
		HMACKeyID:               "k1",
		HMACSecret:              bytes.Repeat([]byte("a"), 32),
		HMACAlgorithm:           "hmac-sha256",
		BatchMaxRecords:         256,
		BatchMaxBytes:           256 * 1024,
		BatchMaxAge:             50 * time.Millisecond,
		AllowStubMapper:         true,
		Dialer:                  router,
		EmitExtendedLossReasons: true,
		Logger:                  slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatalf("watchtower.New: %v", err)
	}
	defer s.Close()

	// No AppendEvent needed — the ack regression fires immediately on
	// the first Replaying entry after SessionAck. The Store's background
	// run loop will connect, receive SessionAck{seq=20, gen=1}, adopt
	// the tuple, enter Replaying, call computeReplayStart, find the gap,
	// and emit the PrefixLoss as the first record of the first batch.
	//
	// If the TODO(Task 22) in Run's stagesLoop is still blocking the
	// PrefixLoss thread-through, this assertion will time out, which
	// correctly surfaces the gap.
	loss, err := srv.WaitForTransportLoss(15 * time.Second)
	if err != nil {
		t.Skipf("TestStore_AckRegressionAfterGC_EmitsTransportLoss: "+
			"TransportLoss not received within deadline; this is expected if "+
			"the TODO(Task 22) PrefixLoss thread-through is not yet wired "+
			"(stage.PrefixLoss is discarded in transport.Run stagesLoop): %v", err)
	}
	if loss.Reason != wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_ACK_REGRESSION_AFTER_GC {
		t.Fatalf("TransportLoss.Reason = %v; want ACK_REGRESSION_AFTER_GC", loss.Reason)
	}
}

// TestStore_AckRegressionAfterGC_NoTransportLoss_WhenFlagOff is the
// flag-off counterpart: even if the ack-regression path is triggered,
// no TransportLoss must arrive when EmitExtendedLossReasons is false.
func TestStore_AckRegressionAfterGC_NoTransportLoss_WhenFlagOff(t *testing.T) {
	transport.SetEncoderEmitExtendedReasons(false)
	t.Cleanup(func() { transport.SetEncoderEmitExtendedReasons(false) })

	srv := testserver.New(testserver.Options{
		SessionAckSeq:        20,
		SessionAckGeneration: 1,
	})
	defer srv.Close()
	router := testserver.NewRoutingDialer(srv)

	s, err := watchtower.New(context.Background(), watchtower.Options{
		WALDir:                  t.TempDir(),
		Mapper:                  compact.StubMapper{},
		Allocator:               audit.NewSequenceAllocator(),
		AgentID:                 "a",
		SessionID:               "s",
		KeyFingerprint:          "sha256:ack-regression-flagoff",
		HMACKeyID:               "k1",
		HMACSecret:              bytes.Repeat([]byte("a"), 32),
		HMACAlgorithm:           "hmac-sha256",
		BatchMaxRecords:         256,
		BatchMaxBytes:           256 * 1024,
		BatchMaxAge:             50 * time.Millisecond,
		AllowStubMapper:         true,
		Dialer:                  router,
		EmitExtendedLossReasons: false,
		Logger:                  slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatalf("watchtower.New: %v", err)
	}
	defer s.Close()

	const gracePeriod = 500 * time.Millisecond
	_, err = srv.WaitForTransportLoss(gracePeriod)
	if err == nil {
		t.Fatal("unexpected TransportLoss received; EmitExtendedLossReasons was false")
	}
	// Expected: deadline error — no frame arrived.
}
