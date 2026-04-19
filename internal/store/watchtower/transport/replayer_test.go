package transport_test

import (
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

// TestReplayer_StopsAtTailWatermark verifies the replayer stops when the
// reader has caught up to the entry-time tail watermark. Three records are
// appended, seq=2 is acked, and one more record (seq=3) is appended past
// the ack. A Reader started at start = ack+1 = 3 must surface exactly one
// record (seq=3) and report done.
//
// Crucially, after NewReplayer captures the tail watermark, an additional
// record is appended at seq=4. The Replayer MUST NOT surface it — that
// record belongs to the Live state, not Replaying. This catches the bug
// where the Replayer's done flag is gated only by "TryNext exhausted" and
// not by the captured tail watermark, which would silently let post-entry
// records leak into the replay batch.
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
	// (highSeq=3), so this seq=4 record MUST be left for the Live state.
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
	if emitted != 1 {
		t.Fatalf("emitted: got %d (seqs=%v), want 1 (seq=3 only — ack covers 0..2 and seq=4 is post-entry)", emitted, seenSeqs)
	}
	if seenSeqs[0] != 3 {
		t.Fatalf("emitted seq: got %d, want 3", seenSeqs[0])
	}
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
