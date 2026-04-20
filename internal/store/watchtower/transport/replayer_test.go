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

// TestReplayer_TailIsTuple_HardStopsOnSeqExceedingTail regresses the Task 14b
// tail-tuple termination contract. Setup: append seqs 1..3 in gen=1, drive
// MarkAcked(1, 2) so the WAL state has gen=1 RecordData up to seq=3 with
// ack at seq=2. Open a Reader scoped to gen=1 with Start=3. Construct a
// Replayer; assert Tail() == (1, 3). Append seqs 4 and 5 in gen=1 (post-entry
// — must NOT extend replay) and seq=1 in gen=2 (cross-gen — must NOT extend
// replay either). Drain via NextBatch.
//
// Assertions:
//  - First record surfaced is gen=1 seq=3 (within-window).
//  - At most one over-tail RecordData surfaces (the boundary record), and if
//    it does it must be gen=1 seq=4.
//  - No record with Generation=2 is surfaced (the segment-iteration filter
//    in Reader blocks gen=2 segments entirely).
//  - done=true is returned.
//  - LastReplayedSequence() returns (1, ∈{3,4}).
//  - Tail() unchanged at (1, 3).
//
// CRITICAL: under the round-12 design (scalar tailSeq=3), the Replayer would
// compare rec.Sequence > 3 and surface gen=2's seq=4 as a within-window record
// (the scalar compare ignores generation), then surface gen=2's seq=4 BEFORE
// returning done=true — silently leaking a different-generation record into
// the replay window. The tuple compare blocks this.
func TestReplayer_TailIsTuple_HardStopsOnSeqExceedingTail(t *testing.T) {
	w := openTestWAL(t)

	// Append gen=1 seqs 1..3, then ack through seq=2.
	for i := int64(1); i <= 3; i++ {
		if _, err := w.Append(i, 1, []byte{byte(i)}); err != nil {
			t.Fatalf("append gen=1 seq=%d: %v", i, err)
		}
	}
	if err := w.MarkAcked(1, 2); err != nil {
		t.Fatalf("MarkAcked(1, 2): %v", err)
	}

	rdr, err := w.NewReader(wal.ReaderOptions{Generation: 1, Start: 3})
	if err != nil {
		t.Fatalf("NewReader gen=1 start=3: %v", err)
	}
	defer rdr.Close()

	r, err := transport.NewReplayer(rdr, transport.ReplayerOptions{
		MaxBatchRecords: 100,
		MaxBatchBytes:   16 * 1024,
	})
	if err != nil {
		t.Fatalf("NewReplayer: %v", err)
	}
	tailGen, tailSeq := r.Tail()
	if tailGen != 1 || tailSeq != 3 {
		t.Fatalf("Tail: got (%d, %d), want (1, 3)", tailGen, tailSeq)
	}

	// Inject post-entry appends: gen=1 seqs 4, 5 (must NOT extend replay
	// past the boundary record); then roll to gen=2 seq=1 (cross-gen —
	// must NOT surface at all).
	if _, err := w.Append(4, 1, []byte{0x44}); err != nil {
		t.Fatalf("append post-entry gen=1 seq=4: %v", err)
	}
	if _, err := w.Append(5, 1, []byte{0x55}); err != nil {
		t.Fatalf("append post-entry gen=1 seq=5: %v", err)
	}
	if _, err := w.Append(1, 2, []byte{0x21}); err != nil {
		t.Fatalf("append post-entry gen=2 seq=1: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	type seenRec struct {
		gen uint32
		seq uint64
	}
	var seen []seenRec
	for {
		batch, done, err := r.NextBatch(ctx)
		if err != nil {
			t.Fatalf("NextBatch: %v", err)
		}
		for _, rec := range batch.Records {
			if rec.Kind != wal.RecordData {
				continue
			}
			seen = append(seen, seenRec{gen: rec.Generation, seq: rec.Sequence})
		}
		if done {
			break
		}
	}

	if len(seen) == 0 {
		t.Fatalf("no RecordData surfaced; want at least gen=1 seq=3")
	}
	// First record MUST be gen=1 seq=3 (the within-window record).
	if seen[0].gen != 1 || seen[0].seq != 3 {
		t.Fatalf("first surfaced: got (%d, %d), want (1, 3)", seen[0].gen, seen[0].seq)
	}
	// No gen=2 record may surface — the segment-iteration filter must skip
	// the gen=2 segment entirely.
	for _, s := range seen {
		if s.gen == 2 {
			t.Fatalf("gen=2 record surfaced: (%d, %d) — segment-iteration filter must skip gen=2 segments; full=%v", s.gen, s.seq, seen)
		}
	}
	// At most one over-tail RecordData (gen=1 seq=4).
	overTail := 0
	for _, s := range seen {
		if s.gen == 1 && s.seq > 3 {
			overTail++
			if s.seq != 4 {
				t.Fatalf("over-tail seq: got %d, want 4 (only seq=4 may surface as the boundary record); seen=%v", s.seq, seen)
			}
		}
	}
	if overTail > 1 {
		t.Fatalf("over-tail count: got %d, want <=1; seen=%v", overTail, seen)
	}
	// LastReplayedSequence is (1, 3) or (1, 4) depending on whether the
	// boundary record surfaced.
	lrGen, lrSeq := r.LastReplayedSequence()
	if lrGen != 1 {
		t.Fatalf("LastReplayedSequence gen: got %d, want 1", lrGen)
	}
	if !(lrSeq == 3 || lrSeq == 4) {
		t.Fatalf("LastReplayedSequence seq: got %d, want 3 or 4 (boundary)", lrSeq)
	}
	// Tail must NOT have advanced from post-entry appends.
	tg, ts := r.Tail()
	if tg != 1 || ts != 3 {
		t.Fatalf("Tail post-replay: got (%d, %d), want (1, 3) — post-entry appends must NOT advance the snapshot", tg, ts)
	}
}

// TestReplayer_StopsAtTailWatermark verifies the hard-stop contract:
// RecordData with seq > tailSeq terminates replay immediately. Three
// records are appended, seq=2 is acked, one more (seq=3) is appended past
// the ack, NewReplayer captures tailSeq=3, then a post-entry seq=4 is
// appended. The Replayer MUST surface seq=3 (a within-window record), MAY
// surface seq=4 as the boundary record (if the Reader catches it before
// done), and MUST NOT surface any seq>4 even if appends keep arriving. The
// boundary record (seq=4), if surfaced, MUST be the LAST RecordData in the
// final batch.
//
// Round-2 review note: the round-1 fix removed the early-exit on
// rec.Sequence >= tailSeq entirely so the Replayer drained until
// TryNext returned ok=false. Under sustained appends that signal may
// never arrive, so replay would never terminate (spec at design.md:586
// requires the finite (ack_hw, wal_hw_at_entry] window). The round-2
// fix restores a HARD stop on RecordData seq > tailSeq while leaving
// loss-marker handling untouched: loss markers always surface, and a
// trailing loss marker that lands at the WAL tail AFTER an over-tail
// RecordData is the responsibility of the Live state's Reader (see
// LastReplayedSequence docstring + design.md:586). The hard stop also
// guarantees TestReplayer_TerminatesUnderConcurrentAppends terminates.
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

	rdr, err := w.NewReader(wal.ReaderOptions{Generation: 0, Start: 3}) // start = ack+1; first emit must be seq>=3
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}
	defer rdr.Close()

	r, err := transport.NewReplayer(rdr, transport.ReplayerOptions{
		MaxBatchRecords: 100,
		MaxBatchBytes:   16 * 1024,
	})
	if err != nil {
		t.Fatalf("NewReplayer: %v", err)
	}
	if _, got := r.Tail(); got != uint64(3) {
		t.Fatalf("tail seq: got %d, want %d", got, 3)
	}

	// Inject post-entry records. tailSeq was captured at NewReplayer time
	// (highSeq=3) so TailSequence() must remain 3. Per the round-2 hard-
	// stop contract, AT MOST ONE over-tail RecordData (seq=4) may surface
	// as the boundary record, and seq=5 must NEVER surface.
	if _, err := w.Append(4, 0, []byte{0x44}); err != nil {
		t.Fatalf("append 4 (post-entry): %v", err)
	}
	if _, err := w.Append(5, 0, []byte{0x55}); err != nil {
		t.Fatalf("append 5 (post-entry): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	emitted := 0
	seenSeqs := []uint64{}
	var lastBatch transport.ReplayBatch
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
			lastBatch = batch
			break
		}
	}

	// Hard-stop contract: seq=3 (within-window) MUST be emitted.
	if emitted < 1 {
		t.Fatalf("emitted: got %d (seqs=%v), want at least 1 (seq=3 must surface)", emitted, seenSeqs)
	}
	if seenSeqs[0] != 3 {
		t.Fatalf("first emitted seq: got %d, want 3", seenSeqs[0])
	}

	// Validate the over-tail boundary rule: AT MOST one over-tail seq may
	// appear (seq=4); seq=5 MUST NOT surface; if seq=4 surfaces, it MUST
	// be the LAST RecordData in the final batch.
	overTailCount := 0
	var lastDataSeq uint64
	haveData := false
	for _, s := range seenSeqs {
		if s > 3 {
			overTailCount++
			if s != 4 {
				t.Fatalf("over-tail seq: got %d, want at most 4 (seq>4 must not surface under hard-stop contract); seqs=%v", s, seenSeqs)
			}
		}
	}
	if overTailCount > 1 {
		t.Fatalf("over-tail count: got %d, want <=1 (boundary record only); seqs=%v", overTailCount, seenSeqs)
	}
	for _, rec := range lastBatch.Records {
		if rec.Kind == wal.RecordData {
			lastDataSeq = rec.Sequence
			haveData = true
		}
	}
	if overTailCount == 1 {
		if !haveData || lastDataSeq != 4 {
			t.Fatalf("boundary record placement: last RecordData in final batch was seq=%d (haveData=%v), want seq=4 (the boundary record must be the LAST RecordData in the final batch)", lastDataSeq, haveData)
		}
		if _, got := r.LastReplayedSequence(); got != 4 {
			t.Fatalf("LastReplayedSequence: got %d, want 4 (boundary record was seq=4)", got)
		}
	} else {
		// No boundary record surfaced — Reader observed ok=false before
		// reading seq=4. LastReplayedSequence must reflect the last
		// within-window emission (seq=3).
		if _, got := r.LastReplayedSequence(); got != 3 {
			t.Fatalf("LastReplayedSequence: got %d, want 3 (no boundary record surfaced)", got)
		}
	}

	// Tail is sampled once at NewReplayer time and MUST NOT
	// advance with post-entry appends.
	if _, got := r.Tail(); got != uint64(3) {
		t.Fatalf("tail seq: got %d, want %d (the post-entry append must NOT advance tailSeq)", got, 3)
	}
}

// TestReplayer_TerminatesUnderConcurrentAppends is the round-2 liveness
// regression: it proves the hard-stop on RecordData seq > tailSeq lets
// replay terminate even while appends keep arriving. Without the hard
// stop (the round-1 drain-until-ok=false behaviour) the test would time
// out because TryNext keeps yielding fresh records faster than replay
// can drain them.
//
// Bug-injection plan: temporarily remove the
// `if rec.Kind == wal.RecordData && rec.Sequence > r.tailSeq` branch in
// replayer.go's NextBatch loop; this test should TIMEOUT or FAIL.
// Restore the branch; it should PASS.
func TestReplayer_TerminatesUnderConcurrentAppends(t *testing.T) {
	t.Parallel()
	w := openTestWAL(t)

	// Pre-seed some records so tailSeq > 0.
	for i := int64(1); i <= 10; i++ {
		if _, err := w.Append(i, 1, []byte("seed-payload")); err != nil {
			t.Fatalf("seed append %d: %v", i, err)
		}
	}

	rdr, err := w.NewReader(wal.ReaderOptions{Generation: 1, Start: 0})
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	defer rdr.Close()

	// tailSeq snapshotted at 10 (the highest seq pre-seeded). Use no
	// batch caps so the inner NextBatch loop drains until EITHER the
	// hard stop triggers (RecordData seq > tailSeq) OR TryNext returns
	// ok=false. With the bug injected (hard stop removed), the inner
	// loop will never exit because the appender keeps the WAL tail
	// moving ahead of TryNext, so NextBatch never returns and the test
	// times out.
	rep, err := transport.NewReplayer(rdr, transport.ReplayerOptions{
		MaxBatchRecords: 0,
		MaxBatchBytes:   0,
	})
	if err != nil {
		t.Fatalf("NewReplayer: %v", err)
	}
	if _, got := rep.Tail(); got != 10 {
		t.Fatalf("Tail seq: got %d, want 10", got)
	}

	// Spin up an appender that keeps writing past tailSeq for the
	// duration of the test. The appender writes as fast as Append
	// returns — no per-iteration sleep — so the WAL tail moves under
	// the replayer continuously. Without the hard stop the replayer
	// would chase these forever (TryNext would never return ok=false
	// because the appender keeps replenishing the live segment).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	appendDone := make(chan struct{})
	go func() {
		defer close(appendDone)
		seq := int64(11)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_, err := w.Append(seq, 1, []byte("live-payload"))
			if err != nil {
				return
			}
			seq++
		}
	}()

	// Replay must terminate within a generous deadline even with
	// appends ongoing.
	deadline := time.Now().Add(5 * time.Second)
	seenData := 0
	maxSeqSeen := uint64(0)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("replay did not terminate within 5s under concurrent appends; saw %d data records", seenData)
		}
		batch, done, err := rep.NextBatch(context.Background())
		if err != nil {
			t.Fatalf("NextBatch: %v", err)
		}
		for _, rec := range batch.Records {
			if rec.Kind == wal.RecordData {
				seenData++
				if rec.Sequence > maxSeqSeen {
					maxSeqSeen = rec.Sequence
				}
			}
		}
		if done {
			break
		}
	}
	cancel()
	<-appendDone

	// Replay must have surfaced at least the seed records (1..10).
	if seenData < 10 {
		t.Fatalf("expected >= 10 RecordData (seed), got %d", seenData)
	}
	// Hard-stop contract: at most ONE record with seq > tailSeq may
	// surface (the boundary record we read before exiting). Without
	// the hard stop the replayer would chase appends and surface
	// many over-tail records — this assertion is the regression
	// guard. Goroutine scheduling could mean the hard stop never
	// actually fires (replayer drains seed and exits via ok=false
	// before appender writes anything), so we tolerate maxSeqSeen
	// up to tailSeq+1 but reject anything further.
	tailSeq := func() uint64 { _, s := rep.Tail(); return s }()
	if maxSeqSeen > tailSeq+1 {
		t.Fatalf("hard-stop violated: maxSeqSeen=%d, tailSeq=%d (must be <= tailSeq+1)", maxSeqSeen, tailSeq)
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

	rdr, err := w.NewReader(wal.ReaderOptions{Generation: 0, Start: 3}) // emit seqs >= 3 only; 1, 2 must be filtered
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}
	defer rdr.Close()

	r, err := transport.NewReplayer(rdr, transport.ReplayerOptions{
		MaxBatchRecords: 100,
		MaxBatchBytes:   16 * 1024,
	})
	if err != nil {
		t.Fatalf("NewReplayer: %v", err)
	}

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
	rdr, err := w.NewReader(wal.ReaderOptions{Generation: 0, Start: 20})
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	defer rdr.Close()

	r, err := transport.NewReplayer(rdr, transport.ReplayerOptions{
		MaxBatchRecords: 100,
		MaxBatchBytes:   16 * 1024,
	})
	if err != nil {
		t.Fatalf("NewReplayer: %v", err)
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
		t.Fatalf("expected at least one RecordLoss to surface despite start=20; got none (records=%d)", len(got))
	}
}

// TestReplayer_DeliversWithinWindowLossMarker validates that loss markers
// covering sequences within the (ack_hw, wal_hw_at_entry] replay window
// surface during replay. We seed the WAL with a synthetic loss marker
// (covering seqs 1..2) plus three RecordData entries and assert the
// drained stream includes the loss marker.
//
// Round-2 note: the round-1 test (TestReplayer_DeliversTrailingLossMarker)
// asserted that a loss marker appended AFTER NewReplayer captures
// tailSeq surfaces during replay. With the round-2 hard-stop contract
// restored, that "trailing loss marker after over-tail data" race is
// no longer Replayer's responsibility — it falls to the Live state's
// Reader (loss markers bypass the Reader's nextSeq filter, so Live's
// reader will encounter and surface the marker even though Live opens
// at max(lastReplayedSeq+1, ackHW+1) past the marker's seq range).
// See LastReplayedSequence's docstring + the trailing-loss-marker race
// commentary in NextBatch.
//
// TODO(Task 17): add a Live-state regression test that drives an
// append-loss-marker-AFTER-over-tail-data sequence and asserts the
// marker surfaces through Live's Reader.
func TestReplayer_DeliversWithinWindowLossMarker(t *testing.T) {
	w := openTestWAL(t)

	// Append a loss marker covering seqs 1..2 BEFORE the data records,
	// so it sits at a WAL position before tailSeq and is unambiguously
	// within the replay window.
	loss := wal.LossRecord{
		FromSequence: 1,
		ToSequence:   2,
		Generation:   0,
		Reason:       "overflow",
	}
	if err := w.AppendLoss(loss); err != nil {
		t.Fatalf("AppendLoss: %v", err)
	}
	for i := int64(0); i < 3; i++ {
		if _, err := w.Append(i, 0, []byte{byte(i)}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	rdr, err := w.NewReader(wal.ReaderOptions{Generation: 0, Start: 0})
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	defer rdr.Close()

	r, err := transport.NewReplayer(rdr, transport.ReplayerOptions{
		MaxBatchRecords: 100,
		MaxBatchBytes:   16 * 1024,
	})
	if err != nil {
		t.Fatalf("NewReplayer: %v", err)
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
		t.Fatalf("expected the within-window TransportLoss marker to surface; got 0 (records=%d)", len(got))
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

	rdr, err := w.NewReader(wal.ReaderOptions{Generation: 0, Start: 0})
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	defer rdr.Close()

	r, err := transport.NewReplayer(rdr, transport.ReplayerOptions{
		MaxBatchRecords: 100,
		MaxBatchBytes:   16 * 1024,
	})
	if err != nil {
		t.Fatalf("NewReplayer: %v", err)
	}
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
