package watchtower_test

import (
	"bytes"
	"context"
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

// TestStore_TransportLossInflightSlot_RetiredByBatchAck verifies that a
// TransportLoss frame occupies an inflight slot and that the slot is
// released when the server sends a BatchAck for the frame's to_sequence.
//
// Setup:
//   - MaxInflight=1 so a single un-acked frame fills the window.
//   - TransportLossAckDelay=5s on the first server so the BatchAck for
//     the TransportLoss frame is held.
//   - sequence_overflow drop triggers immediately, emitting a
//     TransportLoss{reason=SEQUENCE_OVERFLOW, to_sequence=overflow_seq}.
//
// The test then:
//  1. Confirms the loss frame arrived at the held-ack server.
//  2. Switches the RoutingDialer to a new server with no delay so the
//     BatchAck arrives promptly on the next reconnect.
//  3. Appends a valid event and confirms it eventually reaches the new
//     server — demonstrating the inflight slot was freed.
func TestStore_TransportLossInflightSlot_RetiredByBatchAck(t *testing.T) {
	transport.SetEncoderEmitExtendedReasons(true)
	t.Cleanup(func() { transport.SetEncoderEmitExtendedReasons(false) })

	// First server: holds the BatchAck for TransportLoss frames for 5s
	// so the inflight slot stays occupied during the assertion window.
	// SessionAckSeq=0 / SessionAckGeneration=0 → fresh-start watermark.
	srvHeld := testserver.New(testserver.Options{
		TransportLossAckDelay: 5 * time.Second,
	})
	defer srvHeld.Close()

	router := testserver.NewRoutingDialer(srvHeld)

	s, err := watchtower.New(context.Background(), watchtower.Options{
		WALDir:                  t.TempDir(),
		Mapper:                  compact.StubMapper{},
		Allocator:               audit.NewSequenceAllocator(),
		AgentID:                 "a",
		SessionID:               "s",
		KeyFingerprint:          "sha256:inflight-slot-test",
		HMACKeyID:               "k1",
		HMACSecret:              bytes.Repeat([]byte("a"), 32),
		HMACAlgorithm:           "hmac-sha256",
		BatchMaxRecords:         256,
		BatchMaxBytes:           256 * 1024,
		BatchMaxAge:             50 * time.Millisecond,
		AllowStubMapper:         true,
		Dialer:                  router,
		EmitExtendedLossReasons: true,
		MaxInflight:             1,
		BackoffInitial:          10 * time.Millisecond,
		BackoffMax:              50 * time.Millisecond,
		Logger:                  slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatalf("watchtower.New: %v", err)
	}
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Wait for the handshake before triggering the drop, so the Live reader
	// is registered and will see the WAL notification from AppendLoss.
	if _, err := srvHeld.WaitForFirstSessionInit(10 * time.Second); err != nil {
		t.Fatalf("WaitForFirstSessionInit: %v", err)
	}

	// Trigger a sequence_overflow drop. Generation=0 matches the Live reader's
	// fresh-WAL HighGeneration()=0 so the loss marker is visible to the reader.
	// The emitted TransportLoss frame occupies the one inflight slot; the ack
	// is held for 5s by srvHeld.
	const overflowSeq = uint64(1<<63 + 1)
	_ = s.AppendEvent(ctx, types.Event{
		Type:      "exec",
		SessionID: "s",
		Timestamp: time.Now(),
		Chain:     &types.ChainState{Sequence: overflowSeq, Generation: 0},
	})

	// Step 1: confirm the loss frame arrived at srvHeld. The ack is
	// being withheld so the inflight slot is still occupied.
	loss, err := srvHeld.WaitForTransportLoss(60 * time.Second)
	if err != nil {
		t.Fatalf("WaitForTransportLoss (srvHeld): %v", err)
	}
	if loss.Reason != wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_SEQUENCE_OVERFLOW {
		t.Fatalf("unexpected loss reason: %v", loss.Reason)
	}
	// Step 2: swap the router to a new server with no delay. The
	// transport will reconnect (stream error when srvHeld is closed or
	// after the delay expires) and send a fresh SessionInit to srvFree.
	// With MaxInflight=1 and the prior slot now released by the new
	// server's immediate BatchAck, subsequent sends can proceed.
	srvFree := testserver.New(testserver.Options{})
	defer srvFree.Close()
	// Close the held server to force an immediate reconnect rather than
	// waiting for the 5s delay to expire.
	srvHeld.Close()
	router.Switch(srvFree)

	// Step 3: append a valid event with a normal sequence. After the
	// reconnect the inflight slot is free and this event must reach
	// srvFree. Generation=0 keeps the event in the same WAL generation
	// as the loss record, so the replay/live reader sees it without a
	// generation boundary issue.
	const validSeq = uint64(1)
	if err := s.AppendEvent(ctx, types.Event{
		Type:      "exec",
		SessionID: "s",
		Timestamp: time.Now(),
		Chain:     &types.ChainState{Sequence: validSeq, Generation: 0},
	}); err != nil {
		t.Fatalf("AppendEvent valid: %v", err)
	}

	// Poll srvFree for the valid event's sequence.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		for _, b := range srvFree.Batches() {
			u := b.GetUncompressed()
			if u == nil {
				continue
			}
			for _, ev := range u.GetEvents() {
				if ev.GetSequence() == validSeq && ev.GetGeneration() == 0 {
					// The inflight slot was freed and the event was delivered.
					return
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("valid event seq=1 did not arrive at srvFree within deadline; inflight slot may not have been retired")
}
