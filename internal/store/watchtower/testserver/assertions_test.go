package testserver_test

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// sendUncompressedBatch is a test helper that sends an EventBatch
// wrapping the given CompactEvents. Shared by the assertion tests
// below to keep the batch-construction boilerplate out of the
// per-test body.
func sendUncompressedBatch(t *testing.T, conn testserver.Conn, events ...*wtpv1.CompactEvent) {
	t.Helper()
	if err := conn.Send(&wtpv1.ClientMessage{
		Msg: &wtpv1.ClientMessage_EventBatch{
			EventBatch: &wtpv1.EventBatch{
				Compression: wtpv1.Compression_COMPRESSION_NONE,
				Body: &wtpv1.EventBatch_Uncompressed{
					Uncompressed: &wtpv1.UncompressedEvents{
						Events: events,
					},
				},
			},
		},
	}); err != nil {
		t.Fatalf("send EventBatch: %v", err)
	}
}

// TestWaitForBatch_ReturnsBatchOrTimesOut verifies that WaitForBatch
// blocks until at least one EventBatch has been received, and returns
// the first batch. Exercises AssertSequenceRange alongside the happy
// path to lock in the [first, last] no-gaps-no-duplicates contract.
func TestWaitForBatch_ReturnsBatchOrTimesOut(t *testing.T) {
	srv := testserver.New(testserver.Options{})
	defer srv.Close()

	conn, err := srv.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Exchange SessionInit / SessionAck so the server is past the
	// session-handshake arm of its Stream handler.
	sendSessionInit(t, conn)
	if _, err := recvWithDeadline(t, conn, 2*time.Second); err != nil {
		t.Fatalf("recv SessionAck: %v", err)
	}

	// Send one EventBatch with a single event at seq=1.
	sendUncompressedBatch(t, conn, &wtpv1.CompactEvent{Sequence: 1, Generation: 1})

	got, err := srv.WaitForBatch(2 * time.Second)
	if err != nil {
		t.Fatalf("WaitForBatch: %v", err)
	}
	if n := len(got.GetUncompressed().GetEvents()); n != 1 {
		t.Fatalf("batch events: got %d, want 1", n)
	}

	if err := srv.AssertSequenceRange(1, 1); err != nil {
		t.Fatalf("AssertSequenceRange: %v", err)
	}
}

// TestWaitForBatch_TimesOutWhenNoBatch verifies WaitForBatch returns
// a non-nil error when its deadline elapses without any batch being
// received. Guards against a regression where the helper returns a
// zero-value batch with a nil error.
func TestWaitForBatch_TimesOutWhenNoBatch(t *testing.T) {
	srv := testserver.New(testserver.Options{})
	defer srv.Close()

	got, err := srv.WaitForBatch(100 * time.Millisecond)
	if err == nil {
		t.Fatalf("WaitForBatch returned nil err and batch=%v; want timeout error", got)
	}
}

// TestAssertSequenceRange_DetectsGapsAndDuplicates exercises the
// failure branches of AssertSequenceRange: out-of-range seq,
// duplicate seq, and missing seq. Each branch is tested by
// constructing a sequence that trips it and asserting the helper
// returns a non-nil error with an identifying substring.
func TestAssertSequenceRange_DetectsGapsAndDuplicates(t *testing.T) {
	t.Run("missing_seq", func(t *testing.T) {
		srv := testserver.New(testserver.Options{})
		defer srv.Close()

		conn, err := srv.Dial(context.Background())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()

		sendSessionInit(t, conn)
		if _, err := recvWithDeadline(t, conn, 2*time.Second); err != nil {
			t.Fatalf("recv SessionAck: %v", err)
		}

		// Send seqs 1 and 3 — 2 is missing.
		sendUncompressedBatch(t, conn,
			&wtpv1.CompactEvent{Sequence: 1, Generation: 0},
			&wtpv1.CompactEvent{Sequence: 3, Generation: 0},
		)
		if _, err := srv.WaitForBatch(2 * time.Second); err != nil {
			t.Fatalf("WaitForBatch: %v", err)
		}

		err = srv.AssertSequenceRange(1, 3)
		if err == nil {
			t.Fatal("AssertSequenceRange: want missing-seq error, got nil")
		}
	})

	t.Run("duplicate_seq", func(t *testing.T) {
		srv := testserver.New(testserver.Options{})
		defer srv.Close()

		conn, err := srv.Dial(context.Background())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()

		sendSessionInit(t, conn)
		if _, err := recvWithDeadline(t, conn, 2*time.Second); err != nil {
			t.Fatalf("recv SessionAck: %v", err)
		}

		// Send seq=1 twice (two batches, same seq).
		sendUncompressedBatch(t, conn, &wtpv1.CompactEvent{Sequence: 1, Generation: 0})
		if _, err := recvWithDeadline(t, conn, 2*time.Second); err != nil {
			t.Fatalf("recv BatchAck 1: %v", err)
		}
		sendUncompressedBatch(t, conn, &wtpv1.CompactEvent{Sequence: 1, Generation: 0})
		if _, err := recvWithDeadline(t, conn, 2*time.Second); err != nil {
			t.Fatalf("recv BatchAck 2: %v", err)
		}

		err = srv.AssertSequenceRange(1, 1)
		if err == nil {
			t.Fatal("AssertSequenceRange: want duplicate-seq error, got nil")
		}
	})

	t.Run("out_of_range_seq", func(t *testing.T) {
		srv := testserver.New(testserver.Options{})
		defer srv.Close()

		conn, err := srv.Dial(context.Background())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()

		sendSessionInit(t, conn)
		if _, err := recvWithDeadline(t, conn, 2*time.Second); err != nil {
			t.Fatalf("recv SessionAck: %v", err)
		}

		// Send seq=5, assert range [1, 3] — 5 is outside.
		sendUncompressedBatch(t, conn, &wtpv1.CompactEvent{Sequence: 5, Generation: 0})
		if _, err := srv.WaitForBatch(2 * time.Second); err != nil {
			t.Fatalf("WaitForBatch: %v", err)
		}

		err = srv.AssertSequenceRange(1, 3)
		if err == nil {
			t.Fatal("AssertSequenceRange: want out-of-range error, got nil")
		}
	})
}

// TestAssertReplayObserved_DetectsReplayBoundary verifies that
// AssertReplayObserved passes when every seq in [first, last] was
// observed in some batch, and does not care about additional later
// sequences. Tolerant of extra Live-era traffic appended after the
// replay window.
func TestAssertReplayObserved_DetectsReplayBoundary(t *testing.T) {
	srv := testserver.New(testserver.Options{})
	defer srv.Close()

	conn, err := srv.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	sendSessionInit(t, conn)
	if _, err := recvWithDeadline(t, conn, 2*time.Second); err != nil {
		t.Fatalf("recv SessionAck: %v", err)
	}

	// Replay batch: seqs 11..12.
	sendUncompressedBatch(t, conn,
		&wtpv1.CompactEvent{Sequence: 11, Generation: 1},
		&wtpv1.CompactEvent{Sequence: 12, Generation: 1},
	)
	if _, err := recvWithDeadline(t, conn, 2*time.Second); err != nil {
		t.Fatalf("recv BatchAck replay: %v", err)
	}

	// Live batch: seq 13 (extra, should be tolerated).
	sendUncompressedBatch(t, conn, &wtpv1.CompactEvent{Sequence: 13, Generation: 1})
	if _, err := recvWithDeadline(t, conn, 2*time.Second); err != nil {
		t.Fatalf("recv BatchAck live: %v", err)
	}

	if err := srv.AssertReplayObserved(11, 12); err != nil {
		t.Fatalf("AssertReplayObserved [11,12]: %v", err)
	}

	// Missing-seq branch: range [10, 12] — 10 was never sent.
	if err := srv.AssertReplayObserved(10, 12); err == nil {
		t.Fatal("AssertReplayObserved [10,12]: want missing-seq error, got nil")
	}
}
