package transport_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
)

// openTestWAL opens a WAL with conservative defaults that the replayer tests
// can share. SegmentSize is small enough to roll within a few records but
// MaxTotalBytes is large enough that no overflow GC kicks in (loss markers
// would change the assertions).
func openTestWAL(t *testing.T) *wal.WAL {
	t.Helper()
	dir := t.TempDir()
	w, err := wal.Open(wal.Options{
		Dir:           dir,
		SegmentSize:   64 * 1024,
		MaxTotalBytes: 1 << 20,
		SyncMode:      wal.SyncImmediate,
	})
	if err != nil {
		t.Fatalf("wal.Open: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

// TestReplayer_StopsAtTailWatermark verifies the replayer surfaces every
// record covered by the entry-time tail watermark and reports done. Three
// records are appended, seq=2 is acked, and one more record (seq=3) is
// appended past the ack. A Reader started at start = ack+1 = 3 must surface
// at least seq=3 and report done.
//
// Round-1 review note: an earlier draft of the Replayer early-exited when
// rec.Sequence reached tailSeq, which would have stranded any trailing
// loss marker that overflow GC appended at the WAL tail mid-replay. The
// fix removes that early-exit; the SOLE done signal is now TryNext
// returning ok=false. As a consequence, records appended AFTER NewReplayer
// captures tailSeq may also surface in the final batch — they are
// "Live-era" records, but the server treats EventBatch records identically
// regardless of state, so this is harmless. tailSeq is preserved as a
// minimum-replay bound, not a hard stop. This test asserts the minimum-
// bound contract: at least seq=3 is emitted, and TailSequence() reflects
// the value sampled at NewReplayer time (NOT advanced by the post-entry
// append).
func TestReplayer_StopsAtTailWatermark(t *testing.T) {
	w := openTestWAL(t)

	// Append seqs 0, 1, 2 then ack through seq=2.
	for i := int64(0); i < 3; i++ {
		if _, err := w.Append(i, 0, []byte{byte(i)}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if err := w.MarkAcked(0, 2); err != nil {
		t.Fatalf("mark acked: %v", err)
	}
	// Append one more so the replayer has work past the ack watermark.
	if _, err := w.Append(3, 0, []byte{0x33}); err != nil {
		t.Fatalf("append 3: %v", err)
	}

	rdr, err := w.NewReader(3) // start = ack+1; first emit must be seq>=3
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}
	defer rdr.Close()

	r := transport.NewReplayer(rdr, transport.ReplayerOptions{
		MaxBatchRecords: 100,
		MaxBatchBytes:   16 * 1024,
	})

	// Inject a post-entry record. tailSeq was captured at NewReplayer time
	// (highSeq=3) so TailSequence() must remain 3, but per the round-1
	// fix the new contract permits this seq=4 record to surface in the
	// final batch (the underlying Reader sees it via TryNext before
	// observing ok=false).
	if _, err := w.Append(4, 0, []byte{0x44}); err != nil {
		t.Fatalf("append 4 (post-entry): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	emitted := 0
	seenSeqs := []uint64{}
	for {
		batch, done, err := r.NextBatch(ctx)
		if err != nil {
			t.Fatalf("NextBatch: %v", err)
		}
		for _, rec := range batch.Records {
			emitted++
			seenSeqs = append(seenSeqs, rec.Sequence)
		}
		if done {
			break
		}
	}
	// Minimum-bound contract: seq=3 (tailSeq) MUST be emitted. Seq=4 may
	// or may not surface depending on the Reader catching it before
	// TryNext returns ok=false — both outcomes are valid.
	if emitted < 1 {
		t.Fatalf("emitted: got %d (seqs=%v), want at least 1 (seq=3 must surface)", emitted, seenSeqs)
	}
	if seenSeqs[0] != 3 {
		t.Fatalf("first emitted seq: got %d, want 3", seenSeqs[0])
	}
	// TailSequence is sampled once at NewReplayer time and MUST NOT
	// advance with post-entry appends.
	if got, want := r.TailSequence(), uint64(3); got != want {
		t.Fatalf("tail seq: got %d, want %d (the post-entry append must NOT advance tailSeq)", got, want)
	}
}

// TestReplayer_FiltersBeforeStartSequence appends 5 records, opens a Reader
// at start=3, and asserts the Replayer emits only seqs 3, 4, 5 — exercising
// the new nextSeq filter inside Reader.Next/TryNext. Without the filter the
// reader would yield seqs 1..5 and this test would catch the regression.
func TestReplayer_FiltersBeforeStartSequence(t *testing.T) {
	w := openTestWAL(t)

	for i := int64(1); i <= 5; i++ {
		if _, err := w.Append(i, 0, []byte{byte(i)}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	rdr, err := w.NewReader(3) // emit seqs >= 3 only; 1, 2 must be filtered
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}
	defer rdr.Close()

	r := transport.NewReplayer(rdr, transport.ReplayerOptions{
		MaxBatchRecords: 100,
		MaxBatchBytes:   16 * 1024,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	got := []uint64{}
	for {
		batch, done, err := r.NextBatch(ctx)
		if err != nil {
			t.Fatalf("NextBatch: %v", err)
		}
		for _, rec := range batch.Records {
			got = append(got, rec.Sequence)
		}
		if done {
			break
		}
	}
	want := []uint64{3, 4, 5}
	if len(got) != len(want) {
		t.Fatalf("got seqs %v, want %v", got, want)
	}
	for i, s := range want {
		if got[i] != s {
			t.Fatalf("seq[%d]: got %d, want %d (full got=%v)", i, got[i], s, got)
		}
	}
}

// openOverflowWAL opens a WAL with the overflow-test sizing (4 KiB segments,
// 12 KiB cap) so the lossy overflow path fires deterministically — the same
// shape as wal/overflow_test.go's TestWAL_OverflowEmitsLossMarker. Mirrors
// openTestWAL but with the tighter budget; we cannot share openTestWAL because
// its sizing intentionally avoids overflow GC for clean replay assertions.
func openOverflowWAL(t *testing.T) *wal.WAL {
	t.Helper()
	dir := t.TempDir()
	w, err := wal.Open(wal.Options{
		Dir:           dir,
		SegmentSize:   4 * 1024,
		MaxTotalBytes: 12 * 1024,
		SyncMode:      wal.SyncImmediate,
	})
	if err != nil {
		t.Fatalf("wal.Open: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

// drainReplayer pulls every batch from r until done is reported and returns
// the flat slice of records observed (in emit order). Caller-supplied ctx
// bounds the loop. Used by the loss-marker tests below where the assertions
// are about what surfaced, not how it was batched.
func drainReplayer(t *testing.T, r *transport.Replayer, ctx context.Context) []wal.Record {
	t.Helper()
	var out []wal.Record
	for {
		batch, done, err := r.NextBatch(ctx)
		if err != nil {
			t.Fatalf("NextBatch: %v", err)
		}
		out = append(out, batch.Records...)
		if done {
			return out
		}
	}
}

// TestReplayer_DeliversLossMarkerBeforeStart proves the Reader's nextSeq
// filter does NOT apply to RecordLoss entries — even when the caller's
// start cursor is past the loss marker's payload range, the marker MUST
// still surface so the receiver can record the gap. Without the
// loss-marker carve-out in reader.go (the explicit "Loss markers are NOT
// subject to the nextSeq filter" branch), this test would observe zero
// loss records.
//
// Setup: drive overflow GC by appending 30 ~1-KiB records under a 12-KiB
// cap; that produces at least one TransportLoss marker covering some
// early sequence range. We then open a Reader at start=20 — a cursor
// that is beyond every overflow-affected seq the GC could plausibly
// have stamped on the marker — and assert at least one RecordLoss
// emerges from the Replayer.
func TestReplayer_DeliversLossMarkerBeforeStart(t *testing.T) {
	w := openOverflowWAL(t)

	// Tight budget + 30 records = at least one overflow GC pass; each
	// pass appends a TransportLoss marker covering the dropped segment's
	// sequence range. Mirror overflow_test.go's payload sizing so the
	// budget arithmetic stays deterministic across changes.
	payload := bytes.Repeat([]byte("x"), 1024)
	for seq := int64(0); seq < 30; seq++ {
		if _, err := w.Append(seq, 0, payload); err != nil {
			t.Fatalf("append %d: %v", seq, err)
		}
	}

	// start=20 — a seq well past anything the early overflow drops would
	// have covered. If reader.go ever regressed and started filtering
	// loss markers by nextSeq, this Reader would surface zero RecordLoss
	// entries despite at least one marker being on disk.
	rdr, err := w.NewReader(20)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	defer rdr.Close()

	r := transport.NewReplayer(rdr, transport.ReplayerOptions{
		MaxBatchRecords: 100,
		MaxBatchBytes:   16 * 1024,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	got := drainReplayer(t, r, ctx)
	losses := 0
	for _, rec := range got {
		if rec.Kind == wal.RecordLoss {
			losses++
		}
	}
	if losses == 0 {
		t.Fatalf("expected at least one RecordLoss to surface despite start=20; got none (records=%d)", len(got))
	}
}

// TestReplayer_DeliversTrailingLossMarker is the regression for the
// round-1 finding that motivated removing the `rec.Sequence >= tailSeq`
// early-exit. The race the early-exit lost: while replay drains, overflow
// GC can drop a segment containing replay-era seqs and append a
// compensating loss marker AT THE WAL TAIL. The marker's WAL position is
// strictly beyond tailSeq even though its Loss.ToSequence is within the
// replay window. With the early-exit, the Replayer would return done=true
// the moment it observed a RecordData with seq>=tailSeq and never reach
// the trailing marker — silently dropping the gap notice.
//
// We synthesize the race deterministically by directly calling
// AppendLoss after NewReplayer captures tailSeq: the loss marker is
// then a real WAL record sitting past tailSeq's WAL position, and the
// underlying Reader will surface it before TryNext returns ok=false
// (the SOLE done signal under the new contract).
//
// Bug-injection plan (round-1 process step): temporarily reintroduce
// the `if rec.Sequence >= r.tailSeq` early-exit in replayer.go's
// NextBatch loop and confirm THIS TEST FAILS (zero loss records
// emitted). Then remove and confirm PASS.
func TestReplayer_DeliversTrailingLossMarker(t *testing.T) {
	w := openTestWAL(t)

	// 3 records on disk before NewReplayer captures tailSeq=3 (the
	// highSeq under the WAL lock at construction time).
	for i := int64(0); i < 3; i++ {
		if _, err := w.Append(i, 0, []byte{byte(i)}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	rdr, err := w.NewReader(0)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	defer rdr.Close()

	r := transport.NewReplayer(rdr, transport.ReplayerOptions{
		MaxBatchRecords: 100,
		MaxBatchBytes:   16 * 1024,
	})

	// Sample tailSeq AFTER construction so the assertion below can
	// confirm the post-entry append is genuinely past it (a
	// confidence-check on the test setup, not on the production code).
	tail := r.TailSequence()
	if tail == 0 {
		t.Fatalf("tail watermark should be non-zero; got %d", tail)
	}

	// Append the trailing loss marker AFTER NewReplayer captures
	// tailSeq. AppendLoss writes the marker as a real WAL record at a
	// position strictly past tailSeq's WAL position — exactly the race
	// shape the round-1 fix addresses.
	loss := wal.LossRecord{
		FromSequence: 1,
		ToSequence:   2,
		Generation:   0,
		Reason:       "overflow",
	}
	if err := w.AppendLoss(loss); err != nil {
		t.Fatalf("AppendLoss: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got := drainReplayer(t, r, ctx)

	losses := 0
	for _, rec := range got {
		if rec.Kind == wal.RecordLoss {
			losses++
		}
	}
	if losses == 0 {
		t.Fatalf("expected the trailing TransportLoss marker to surface before done=true; got 0 (records=%d). Round-1 regression: the `rec.Sequence >= tailSeq` early-exit returned done before the Reader could surface this marker.", len(got))
	}
}

// TestReplayer_LossOnlyScenario covers the degenerate case where the WAL
// stream contains ONLY synthetic TransportLoss markers (no user data).
// The Replayer must still drain to completion and surface every marker —
// loss notices are first-class records in the WAL and must propagate to
// the receiver regardless of whether any user data exists.
//
// Direct AppendLoss calls (rather than driving overflow) keep the test
// hermetic: we observe exactly the markers we wrote, with no
// segmentation noise. This also exercises the Reader path that handles
// loss markers BEFORE encountering any RecordData (lastGoodSeq=0 etc.).
func TestReplayer_LossOnlyScenario(t *testing.T) {
	w := openTestWAL(t)

	losses := []wal.LossRecord{
		{FromSequence: 1, ToSequence: 5, Generation: 0, Reason: "overflow"},
		{FromSequence: 6, ToSequence: 10, Generation: 0, Reason: "overflow"},
		{FromSequence: 11, ToSequence: 15, Generation: 0, Reason: "crc_corruption"},
	}
	for _, l := range losses {
		if err := w.AppendLoss(l); err != nil {
			t.Fatalf("AppendLoss(%+v): %v", l, err)
		}
	}

	rdr, err := w.NewReader(0)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	defer rdr.Close()

	r := transport.NewReplayer(rdr, transport.ReplayerOptions{
		MaxBatchRecords: 100,
		MaxBatchBytes:   16 * 1024,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	got := drainReplayer(t, r, ctx)

	// All three markers MUST surface; no RecordData should appear
	// (this WAL never received an Append that wasn't a loss marker).
	gotLoss := 0
	gotData := 0
	for _, rec := range got {
		switch rec.Kind {
		case wal.RecordLoss:
			gotLoss++
		case wal.RecordData:
			gotData++
		}
	}
	if gotLoss != len(losses) {
		t.Fatalf("RecordLoss count: got %d, want %d (records=%v)", gotLoss, len(losses), got)
	}
	if gotData != 0 {
		t.Fatalf("RecordData count: got %d, want 0 (loss-only WAL must produce no RecordData)", gotData)
	}
}
