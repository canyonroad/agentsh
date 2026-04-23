package testserver_test

import (
	"context"
	"errors"
	"strings"
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

// sendCompressedBatchMarker is a test helper that sends an EventBatch
// whose Body is the `compressed_payload` oneof variant — a valid wire
// shape per the proto contract (§7.3): compression=ZSTD with a non-
// empty bytes payload. The testserver records the message but does
// not decode it; the assertion helpers must surface
// ErrUnsupportedCompression for that recorded shape.
//
// The payload bytes are an opaque non-empty blob — the helpers never
// look inside, and decoding is intentionally out of scope.
func sendCompressedBatchMarker(t *testing.T, conn testserver.Conn) {
	t.Helper()
	if err := conn.Send(&wtpv1.ClientMessage{
		Msg: &wtpv1.ClientMessage_EventBatch{
			EventBatch: &wtpv1.EventBatch{
				Compression: wtpv1.Compression_COMPRESSION_ZSTD,
				Body: &wtpv1.EventBatch_CompressedPayload{
					CompressedPayload: []byte{0x01, 0x02, 0x03, 0x04},
				},
			},
		},
	}); err != nil {
		t.Fatalf("send compressed EventBatch: %v", err)
	}
}

// TestWaitForFirstBatch_ReturnsFirstBatch verifies the happy path:
// after one batch is recorded, WaitForFirstBatch returns a deep copy
// of it and AssertSequenceRange accepts the contiguous window.
func TestWaitForFirstBatch_ReturnsFirstBatch(t *testing.T) {
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

	sendUncompressedBatch(t, conn, &wtpv1.CompactEvent{Sequence: 1, Generation: 1})

	got, err := srv.WaitForFirstBatch(2 * time.Second)
	if err != nil {
		t.Fatalf("WaitForFirstBatch: %v", err)
	}
	if n := len(got.GetUncompressed().GetEvents()); n != 1 {
		t.Fatalf("batch events: got %d, want 1", n)
	}

	// Mutating the returned batch MUST NOT affect the server's
	// internal record (deep-copy contract).
	got.GetUncompressed().Events = nil
	if n := len(srv.Batches()[0].GetUncompressed().GetEvents()); n != 1 {
		t.Fatalf("after caller mutation, server's batch has %d events; want 1 (deep-copy broken)", n)
	}

	if err := srv.AssertSequenceRange(1, 1); err != nil {
		t.Fatalf("AssertSequenceRange: %v", err)
	}
}

// TestWaitForFirstBatch_TimesOutWhenNoBatch verifies that the helper
// returns a non-nil error when the deadline elapses without any
// batch being recorded.
func TestWaitForFirstBatch_TimesOutWhenNoBatch(t *testing.T) {
	srv := testserver.New(testserver.Options{})
	defer srv.Close()

	got, err := srv.WaitForFirstBatch(100 * time.Millisecond)
	if err == nil {
		t.Fatalf("WaitForFirstBatch returned nil err and batch=%v; want timeout error", got)
	}
	if got != nil {
		t.Fatalf("WaitForFirstBatch returned batch=%v; want nil on timeout", got)
	}
}

// TestWaitForFirstBatch_ReturnsImmediatelyOnStaleBatch locks in the
// documented semantics: WaitForFirstBatch returns the FIRST batch
// ever recorded, not "the next batch after this call." A second
// call after a batch is already in the server sees it immediately.
// This is a subtle trap — scenario authors who need "wait for new
// data" must snapshot len(Batches()) themselves.
func TestWaitForFirstBatch_ReturnsImmediatelyOnStaleBatch(t *testing.T) {
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
	sendUncompressedBatch(t, conn, &wtpv1.CompactEvent{Sequence: 1})
	if _, err := srv.WaitForFirstBatch(2 * time.Second); err != nil {
		t.Fatalf("first WaitForFirstBatch: %v", err)
	}

	// Second call with a tiny deadline should STILL succeed because
	// the first batch is already recorded.
	start := time.Now()
	if _, err := srv.WaitForFirstBatch(100 * time.Millisecond); err != nil {
		t.Fatalf("second WaitForFirstBatch: %v", err)
	}
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Fatalf("second WaitForFirstBatch took %v; want ~instant (first-batch-ever semantics)", d)
	}
}

// TestAssertSequenceRange_DetectsGapsAndDuplicates exercises the
// failure branches of AssertSequenceRange: out-of-range, duplicate,
// and missing seq. Each branch asserts BOTH non-nil error AND the
// diagnostic substring so a future regression that swaps or
// generalizes the error messages is caught.
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

		sendUncompressedBatch(t, conn,
			&wtpv1.CompactEvent{Sequence: 1},
			&wtpv1.CompactEvent{Sequence: 3},
		)
		if _, err := srv.WaitForFirstBatch(2 * time.Second); err != nil {
			t.Fatalf("WaitForFirstBatch: %v", err)
		}

		err = srv.AssertSequenceRange(1, 3)
		if err == nil {
			t.Fatal("AssertSequenceRange: want missing-seq error, got nil")
		}
		if !strings.Contains(err.Error(), "missing seq 2") {
			t.Fatalf("AssertSequenceRange err=%q, want substring %q", err.Error(), "missing seq 2")
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

		sendUncompressedBatch(t, conn, &wtpv1.CompactEvent{Sequence: 1})
		if _, err := recvWithDeadline(t, conn, 2*time.Second); err != nil {
			t.Fatalf("recv BatchAck 1: %v", err)
		}
		sendUncompressedBatch(t, conn, &wtpv1.CompactEvent{Sequence: 1})
		if _, err := recvWithDeadline(t, conn, 2*time.Second); err != nil {
			t.Fatalf("recv BatchAck 2: %v", err)
		}

		err = srv.AssertSequenceRange(1, 1)
		if err == nil {
			t.Fatal("AssertSequenceRange: want duplicate-seq error, got nil")
		}
		if !strings.Contains(err.Error(), "duplicate seq 1") {
			t.Fatalf("AssertSequenceRange err=%q, want substring %q", err.Error(), "duplicate seq 1")
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

		sendUncompressedBatch(t, conn, &wtpv1.CompactEvent{Sequence: 5})
		if _, err := srv.WaitForFirstBatch(2 * time.Second); err != nil {
			t.Fatalf("WaitForFirstBatch: %v", err)
		}

		err = srv.AssertSequenceRange(1, 3)
		if err == nil {
			t.Fatal("AssertSequenceRange: want out-of-range error, got nil")
		}
		if !strings.Contains(err.Error(), "outside expected range") || !strings.Contains(err.Error(), "seq 5") {
			t.Fatalf("AssertSequenceRange err=%q, want out-of-range substring", err.Error())
		}
	})
}

// TestAssertRange_InvalidBoundsRejected verifies that first > last
// is rejected with ErrInvalidRange BEFORE any batch iteration. A
// swapped-argument test-setup bug would otherwise silently pass
// when no batches are recorded (empty loop = nil return). Also
// verifies the helper-name prefix so CI-log grep contracts don't
// silently drift.
func TestAssertRange_InvalidBoundsRejected(t *testing.T) {
	srv := testserver.New(testserver.Options{})
	defer srv.Close()

	err := srv.AssertSequenceRange(10, 5)
	if err == nil {
		t.Fatal("AssertSequenceRange(10, 5): want ErrInvalidRange, got nil")
	}
	if !errors.Is(err, testserver.ErrInvalidRange) {
		t.Fatalf("AssertSequenceRange(10, 5) err=%v, want errors.Is(..., ErrInvalidRange)", err)
	}
	if !strings.HasPrefix(err.Error(), "AssertSequenceRange[10..5]: ") {
		t.Fatalf("AssertSequenceRange err=%q, want helper-name prefix", err.Error())
	}

	err = srv.AssertReplayObserved(10, 5)
	if err == nil {
		t.Fatal("AssertReplayObserved(10, 5): want ErrInvalidRange, got nil")
	}
	if !errors.Is(err, testserver.ErrInvalidRange) {
		t.Fatalf("AssertReplayObserved(10, 5) err=%v, want errors.Is(..., ErrInvalidRange)", err)
	}
	if !strings.HasPrefix(err.Error(), "AssertReplayObserved[10..5]: ") {
		t.Fatalf("AssertReplayObserved err=%q, want helper-name prefix", err.Error())
	}
}

// TestAssertRange_CompressedBatchFailsFast verifies that a recorded
// batch whose Body is not UncompressedEvents causes the assertion
// helpers to return ErrUnsupportedCompression rather than silently
// skip. Also checks the helper-name prefix so the grep-friendly
// diagnostic contract is locked in.
func TestAssertRange_CompressedBatchFailsFast(t *testing.T) {
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

	sendCompressedBatchMarker(t, conn)
	if _, err := srv.WaitForFirstBatch(2 * time.Second); err != nil {
		t.Fatalf("WaitForFirstBatch: %v", err)
	}

	err = srv.AssertSequenceRange(0, 0)
	if err == nil {
		t.Fatal("AssertSequenceRange on compressed batch: want ErrUnsupportedCompression, got nil")
	}
	if !errors.Is(err, testserver.ErrUnsupportedCompression) {
		t.Fatalf("AssertSequenceRange err=%v, want errors.Is(..., ErrUnsupportedCompression)", err)
	}
	if !strings.HasPrefix(err.Error(), "AssertSequenceRange[0..0]: ") {
		t.Fatalf("AssertSequenceRange err=%q, want helper-name prefix", err.Error())
	}

	err = srv.AssertReplayObserved(0, 0)
	if err == nil {
		t.Fatal("AssertReplayObserved on compressed batch: want ErrUnsupportedCompression, got nil")
	}
	if !errors.Is(err, testserver.ErrUnsupportedCompression) {
		t.Fatalf("AssertReplayObserved err=%v, want errors.Is(..., ErrUnsupportedCompression)", err)
	}
	if !strings.HasPrefix(err.Error(), "AssertReplayObserved[0..0]: ") {
		t.Fatalf("AssertReplayObserved err=%q, want helper-name prefix", err.Error())
	}
}

// TestServerBatches_DeepCopyIsolatesCallerMutation locks in the
// Server.Batches() deep-copy contract. A caller that mutates the
// returned *EventBatch (zeroing events, replacing oneof, etc.) MUST
// NOT corrupt the server's internal record — later Batches() calls
// and later assertion helpers must still see the original data.
//
// Regression guard: if a future refactor reverts Batches() to a
// shallow copy, this test fails because the second snapshot would
// inherit the mutation from the first.
func TestServerBatches_DeepCopyIsolatesCallerMutation(t *testing.T) {
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

	sendUncompressedBatch(t, conn,
		&wtpv1.CompactEvent{Sequence: 7, Generation: 2},
	)
	if _, err := srv.WaitForFirstBatch(2 * time.Second); err != nil {
		t.Fatalf("WaitForFirstBatch: %v", err)
	}

	// Snapshot 1: mutate the returned batch aggressively.
	snap1 := srv.Batches()
	if len(snap1) != 1 {
		t.Fatalf("snap1 len=%d, want 1", len(snap1))
	}
	snap1[0].Compression = wtpv1.Compression_COMPRESSION_ZSTD
	snap1[0].Body = nil
	if u := snap1[0].GetUncompressed(); u != nil {
		u.Events = nil
	}

	// Snapshot 2: fresh deep copy — must be unaffected by snap1's
	// mutations.
	snap2 := srv.Batches()
	if len(snap2) != 1 {
		t.Fatalf("snap2 len=%d, want 1", len(snap2))
	}
	if snap2[0].GetCompression() != wtpv1.Compression_COMPRESSION_NONE {
		t.Fatalf("snap2 compression=%v; want COMPRESSION_NONE (snap1 mutation leaked into server state)",
			snap2[0].GetCompression())
	}
	events := snap2[0].GetUncompressed().GetEvents()
	if len(events) != 1 || events[0].GetSequence() != 7 || events[0].GetGeneration() != 2 {
		t.Fatalf("snap2 events=%+v; want one event (7, 2) (snap1 mutation corrupted server state)", events)
	}

	// The sequence-range assertion MUST also still see the original
	// data — without the deep copy, snap1's mutation would have
	// wiped the internal record and compactEventSequences would
	// return empty.
	if err := srv.AssertSequenceRange(7, 7); err != nil {
		t.Fatalf("AssertSequenceRange post-mutation: %v (deep-copy broken)", err)
	}
}

// TestAssertReplayObserved_DetectsReplayBoundary verifies that
// AssertReplayObserved passes when every seq in [first, last] was
// observed in some batch, tolerating extra seqs past `last`.
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

	sendUncompressedBatch(t, conn,
		&wtpv1.CompactEvent{Sequence: 11, Generation: 1},
		&wtpv1.CompactEvent{Sequence: 12, Generation: 1},
	)
	if _, err := recvWithDeadline(t, conn, 2*time.Second); err != nil {
		t.Fatalf("recv BatchAck replay: %v", err)
	}

	sendUncompressedBatch(t, conn, &wtpv1.CompactEvent{Sequence: 13, Generation: 1})
	if _, err := recvWithDeadline(t, conn, 2*time.Second); err != nil {
		t.Fatalf("recv BatchAck live: %v", err)
	}

	if err := srv.AssertReplayObserved(11, 12); err != nil {
		t.Fatalf("AssertReplayObserved [11,12]: %v", err)
	}

	// Missing-seq: 10 was never sent.
	err = srv.AssertReplayObserved(10, 12)
	if err == nil {
		t.Fatal("AssertReplayObserved [10,12]: want missing-seq error, got nil")
	}
	if !strings.Contains(err.Error(), "missing seq 10") {
		t.Fatalf("AssertReplayObserved err=%q, want substring %q", err.Error(), "missing seq 10")
	}
}

// TestServer_NilEventBatchDoesNotPanic verifies the test-harness
// non-goal documented on addBatch: a ClientMessage_EventBatch whose
// EventBatch pointer is nil must not panic ANY of the public
// recording / assertion entry points (Batches, WaitForFirstBatch,
// AssertSequenceRange, AssertReplayObserved), and must surface as
// ErrUnsupportedCompression with the helper-name prefix on both
// assertion helpers.
//
// Regression guard for the Missing finding in roborev #5743+5746:
// a future refactor that drops the nil-normalization in addBatch
// would panic inside proto.Clone or one of the GetXxx accessors,
// and this test would fail with a panic-recovered goroutine error
// rather than a clean assertion. The test-harness contract is
// that malformed client frames surface as a diagnostic error, not
// a panic — across the FULL public surface, not just one entry.
func TestServer_NilEventBatchDoesNotPanic(t *testing.T) {
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

	if err := conn.Send(&wtpv1.ClientMessage{
		Msg: &wtpv1.ClientMessage_EventBatch{EventBatch: nil},
	}); err != nil {
		t.Fatalf("send nil EventBatch: %v", err)
	}
	if _, err := recvWithDeadline(t, conn, 2*time.Second); err != nil {
		t.Fatalf("recv BatchAck: %v", err)
	}

	// 1. WaitForFirstBatch — must not panic on the nil-Body batch.
	got, err := srv.WaitForFirstBatch(2 * time.Second)
	if err != nil {
		t.Fatalf("WaitForFirstBatch: %v", err)
	}
	if got == nil {
		t.Fatalf("WaitForFirstBatch returned nil; want non-nil empty *EventBatch")
	}
	// Empty-shape contract: addBatch normalizes nil → empty
	// EventBatch{}, so the returned batch must have no Body
	// oneof set, COMPRESSION_UNSPECIFIED, and zero from/to seq.
	if got.GetBody() != nil {
		t.Fatalf("WaitForFirstBatch.Body=%T; want nil (empty normalization broken)", got.GetBody())
	}
	if got.GetCompression() != wtpv1.Compression_COMPRESSION_UNSPECIFIED {
		t.Fatalf("WaitForFirstBatch.Compression=%v; want UNSPECIFIED", got.GetCompression())
	}
	if got.GetFromSequence() != 0 || got.GetToSequence() != 0 {
		t.Fatalf("WaitForFirstBatch from/to=(%d, %d); want (0, 0)", got.GetFromSequence(), got.GetToSequence())
	}

	// 2. Batches() — same empty-shape contract on EVERY field.
	bs := srv.Batches()
	if len(bs) != 1 {
		t.Fatalf("Batches len=%d, want 1", len(bs))
	}
	if bs[0] == nil {
		t.Fatalf("Batches[0] is nil; want non-nil empty *EventBatch")
	}
	if bs[0].GetBody() != nil {
		t.Fatalf("Batches[0].Body=%T; want nil", bs[0].GetBody())
	}
	if bs[0].GetCompression() != wtpv1.Compression_COMPRESSION_UNSPECIFIED {
		t.Fatalf("Batches[0].Compression=%v; want UNSPECIFIED", bs[0].GetCompression())
	}
	if bs[0].GetFromSequence() != 0 || bs[0].GetToSequence() != 0 {
		t.Fatalf("Batches[0] from/to=(%d, %d); want (0, 0)", bs[0].GetFromSequence(), bs[0].GetToSequence())
	}

	// 3. AssertSequenceRange — ErrUnsupportedCompression with prefix.
	err = srv.AssertSequenceRange(1, 1)
	if err == nil {
		t.Fatal("AssertSequenceRange on nil-Body batch: want error, got nil")
	}
	if !errors.Is(err, testserver.ErrUnsupportedCompression) {
		t.Fatalf("AssertSequenceRange err=%v, want errors.Is(..., ErrUnsupportedCompression)", err)
	}
	if !strings.HasPrefix(err.Error(), "AssertSequenceRange[1..1]: ") {
		t.Fatalf("AssertSequenceRange err=%q, want helper-name prefix", err.Error())
	}

	// 4. AssertReplayObserved — same surface contract.
	err = srv.AssertReplayObserved(1, 1)
	if err == nil {
		t.Fatal("AssertReplayObserved on nil-Body batch: want error, got nil")
	}
	if !errors.Is(err, testserver.ErrUnsupportedCompression) {
		t.Fatalf("AssertReplayObserved err=%v, want errors.Is(..., ErrUnsupportedCompression)", err)
	}
	if !strings.HasPrefix(err.Error(), "AssertReplayObserved[1..1]: ") {
		t.Fatalf("AssertReplayObserved err=%q, want helper-name prefix", err.Error())
	}
}
