package wal

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

func TestWAL_OpenEmptyDir(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if w.HighWatermark() != 0 || w.HighGeneration() != 0 {
		t.Errorf("fresh WAL hw = (%d,%d), want (0,0)", w.HighWatermark(), w.HighGeneration())
	}
}

func TestWAL_AppendThenReplay(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	for i := uint64(0); i < 5; i++ {
		_, err := w.Append(int64(i), 0, []byte("payload"))
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// Reopen and verify high-watermark recovered.
	w2, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	if w2.HighWatermark() != 4 {
		t.Errorf("recovered HighWatermark = %d, want 4", w2.HighWatermark())
	}
}

func TestWAL_RejectsClosedAppend(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = w.Append(0, 0, []byte("x"))
	if err == nil {
		t.Fatal("expected closed error")
	}
	if !IsClean(err) {
		t.Errorf("Closed-write error must be Clean (no I/O attempted)")
	}
}

func TestWAL_RejectsOversizedPayload(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 1024, MaxTotalBytes: 8 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	big := make([]byte, 2048)
	_, err = w.Append(0, 0, big)
	if err == nil {
		t.Fatal("expected oversized error")
	}
	if !IsClean(err) {
		t.Errorf("Oversized payload error must be Clean (validated pre-I/O)")
	}
}

func listSegments(t *testing.T, dir string) []string {
	t.Helper()
	d := filepath.Join(dir, "segments")
	entries, err := os.ReadDir(d)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// TestWAL_HighWaterSequenceMatchesReader verifies the WAL-side accessor
// reports the same value as Reader.WALHighWaterSequence() and the back-compat
// HighWatermark() alias, both before and after additional appends and Reader
// closure.
func TestWAL_HighWaterSequenceMatchesReader(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for seq := int64(1); seq <= 5; seq++ {
		if _, err := w.Append(seq, 1, []byte("p")); err != nil {
			t.Fatalf("append seq=%d: %v", seq, err)
		}
	}
	r, err := w.NewReader(ReaderOptions{Generation: 1, Start: 0})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := w.HighWaterSequence(), uint64(5); got != want {
		t.Errorf("WAL.HighWaterSequence() = %d, want %d", got, want)
	}
	if got, want := r.WALHighWaterSequence(), uint64(5); got != want {
		t.Errorf("Reader.WALHighWaterSequence() = %d, want %d", got, want)
	}
	if got, want := w.HighWatermark(), uint64(5); got != want {
		t.Errorf("WAL.HighWatermark() back-compat alias = %d, want %d", got, want)
	}
	for seq := int64(6); seq <= 8; seq++ {
		if _, err := w.Append(seq, 1, []byte("p")); err != nil {
			t.Fatalf("append seq=%d: %v", seq, err)
		}
	}
	if got, want := w.HighWaterSequence(), uint64(8); got != want {
		t.Errorf("after extra appends WAL.HighWaterSequence() = %d, want %d", got, want)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := w.HighWaterSequence(), uint64(8); got != want {
		t.Errorf("after Reader.Close(), WAL.HighWaterSequence() = %d, want %d", got, want)
	}
}

// TestWAL_EarliestDataSequence covers the four cases from the plan:
// empty, single segment, post-GC same-gen, mixed-gen on disk.
func TestWAL_EarliestDataSequence(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		dir := t.TempDir()
		w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		seq, ok, err := w.EarliestDataSequence(1)
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if ok || seq != 0 {
			t.Errorf("empty WAL EarliestDataSequence(1) = (%d, %v), want (0, false)", seq, ok)
		}
	})

	t.Run("single_segment", func(t *testing.T) {
		dir := t.TempDir()
		w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		for s := int64(1); s <= 5; s++ {
			if _, err := w.Append(s, 1, []byte("x")); err != nil {
				t.Fatal(err)
			}
		}
		seq, ok, err := w.EarliestDataSequence(1)
		if err != nil || !ok || seq != 1 {
			t.Errorf("EarliestDataSequence(1) = (%d, %v, %v); want (1, true, nil)", seq, ok, err)
		}
		_, ok2, err2 := w.EarliestDataSequence(2)
		if err2 != nil || ok2 {
			t.Errorf("EarliestDataSequence(2) = (_, %v, %v); want (_, false, nil)", ok2, err2)
		}
	})

	t.Run("post_gc_same_gen", func(t *testing.T) {
		dir := t.TempDir()
		// Tight per-segment budget so 50 records spread across many segments
		// and MarkAcked(1, 20) reclaims the oldest sealed segment(s).
		w, err := Open(Options{Dir: dir, SegmentSize: 256, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		payload := bytes.Repeat([]byte("p"), 64)
		for s := int64(1); s <= 50; s++ {
			if _, err := w.Append(s, 1, payload); err != nil {
				t.Fatalf("append seq=%d: %v", s, err)
			}
		}
		if err := w.MarkAcked(1, 20); err != nil {
			t.Fatal(err)
		}
		seq, ok, err := w.EarliestDataSequence(1)
		if err != nil || !ok {
			t.Fatalf("EarliestDataSequence(1) after GC = (%d, %v, %v); want (>20, true, nil)", seq, ok, err)
		}
		if seq <= 20 {
			t.Errorf("EarliestDataSequence(1) after MarkAcked(1, 20) = %d; want > 20 (oldest survivors)", seq)
		}
	})

	t.Run("mixed_gen_on_disk", func(t *testing.T) {
		dir := t.TempDir()
		w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		for s := int64(1); s <= 5; s++ {
			if _, err := w.Append(s, 1, []byte("g1")); err != nil {
				t.Fatal(err)
			}
		}
		for s := int64(1); s <= 5; s++ {
			if _, err := w.Append(s, 2, []byte("g2")); err != nil {
				t.Fatal(err)
			}
		}
		seq1, ok1, err1 := w.EarliestDataSequence(1)
		if err1 != nil || !ok1 || seq1 != 1 {
			t.Errorf("EarliestDataSequence(1) = (%d, %v, %v); want (1, true, nil)", seq1, ok1, err1)
		}
		seq2, ok2, err2 := w.EarliestDataSequence(2)
		if err2 != nil || !ok2 || seq2 != 1 {
			t.Errorf("EarliestDataSequence(2) = (%d, %v, %v); want (1, true, nil)", seq2, ok2, err2)
		}
		// Drop all gen=1 by acking past its top: MarkAcked uses a lex (gen, seq)
		// watermark; (gen=1, seq=5) silently GCs every sealed gen=1 segment.
		if err := w.MarkAcked(1, 5); err != nil {
			t.Fatal(err)
		}
		_, okPost1, errPost1 := w.EarliestDataSequence(1)
		if errPost1 != nil {
			t.Fatalf("post-GC EarliestDataSequence(1) err = %v, want nil", errPost1)
		}
		if okPost1 {
			t.Errorf("post-GC EarliestDataSequence(1) ok = true, want false (gen=1 reclaimed)")
		}
		seqPost2, okPost2, errPost2 := w.EarliestDataSequence(2)
		if errPost2 != nil || !okPost2 || seqPost2 != 1 {
			t.Errorf("post-GC EarliestDataSequence(2) = (%d, %v, %v); want (1, true, nil)",
				seqPost2, okPost2, errPost2)
		}
	})
}

// TestWAL_WrittenDataHighWaterReturnsFalseForFutureGen pins the safety
// invariant that an as-yet-unwritten generation reports ok=false even when
// other generations are populated.
func TestWAL_WrittenDataHighWaterReturnsFalseForFutureGen(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	// Fresh WAL: any gen returns ok=false.
	if seq, ok, err := w.WrittenDataHighWater(1); err != nil || ok || seq != 0 {
		t.Errorf("fresh WrittenDataHighWater(1) = (%d, %v, %v); want (0, false, nil)", seq, ok, err)
	}
	if _, err := w.Append(1, 1, []byte("x")); err != nil {
		t.Fatal(err)
	}
	for _, gen := range []uint32{2, 7} {
		seq, ok, err := w.WrittenDataHighWater(gen)
		if err != nil || ok || seq != 0 {
			t.Errorf("future gen %d WrittenDataHighWater = (%d, %v, %v); want (0, false, nil)",
				gen, seq, ok, err)
		}
	}
}

// TestWAL_WrittenDataHighWaterReturnsFalseForGenWithOnlyHeader is the round-11
// safety regression: opening a new INPROGRESS segment for gen=N (which writes
// a SegmentHeader with that gen) MUST NOT make WrittenDataHighWater(N) report
// ok=true. Without the data-bearing distinction, an attacker (or buggy server)
// could ack an unwritten generation and trigger lower-gen GC of unsent data.
func TestWAL_WrittenDataHighWaterReturnsFalseForGenWithOnlyHeader(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for s := int64(1); s <= 5; s++ {
		if _, err := w.Append(s, 1, []byte("g1")); err != nil {
			t.Fatal(err)
		}
	}
	// Drive a gen roll without writing a RecordData in gen=2: a
	// generation roll seals current then opens a fresh segment with the
	// new gen header. Use the AppendLoss path: it opens a header-only
	// segment for the requested gen if w.current is sealed/missing — but
	// AppendLoss reuses w.current, so we instead force a generation-roll
	// seal by appending a single record in gen=2 then immediately rolling
	// it to gen=3 without any data record landing in gen=2 BEYOND that one.
	// Simplest path: roll directly via openNewSegmentLocked-style via Append
	// in gen=2, but we want NO RecordData in gen=2. We achieve a "header-only"
	// gen=2 by leaving gen=1 sealed and opening a fresh segment via a loss
	// marker. AppendLoss opens a new segment with FlagGenInit when w.current
	// is nil. So we must close the current sealed-via-roll segment first.
	//
	// Simpler approach: seal gen=1 by rolling to gen=2 with a single Append,
	// then verify WrittenDataHighWater(2) reports the seq. Then for the
	// header-only assertion, roll to gen=3 with a single append and assert
	// WrittenDataHighWater(3)==1 — this is NOT header-only.
	//
	// To exercise header-only-for-gen=N we need to seal current and open a
	// fresh segment with gen=N before any RecordData lands. That's exactly
	// what an INPROGRESS segment carrying only the header looks like at
	// recovery time. We simulate it by closing the WAL, hand-creating an
	// INPROGRESS segment for gen=2 with no records, and reopening.
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	segDir := filepath.Join(dir, "segments")
	// Pick an unused index past anything on disk to avoid collisions.
	headerOnlyIdx := uint64(time.Now().UnixNano())
	// OpenSegment writes the header and fsyncs.
	seg, err := OpenSegment(segDir, headerOnlyIdx, SegmentHeader{Version: SegmentVersion, Flags: FlagGenInit, Generation: 2}, 4*1024-int(SegmentHeaderSize))
	if err != nil {
		t.Fatal(err)
	}
	if err := seg.Close(); err != nil {
		t.Fatal(err)
	}
	// Reopen the WAL: recovery seeds w.highGen from the header but no
	// RecordData was decoded for gen=2.
	w2, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	seq, ok, err := w2.WrittenDataHighWater(2)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if ok || seq != 0 {
		t.Errorf("header-only gen=2 WrittenDataHighWater = (%d, %v); want (0, false)", seq, ok)
	}
	// Now append a real record in gen=2 and assert ok flips to true.
	if _, err := w2.Append(1, 2, []byte("real")); err != nil {
		t.Fatal(err)
	}
	seq, ok, err = w2.WrittenDataHighWater(2)
	if err != nil || !ok || seq != 1 {
		t.Errorf("after Append in gen=2, WrittenDataHighWater(2) = (%d, %v, %v); want (1, true, nil)",
			seq, ok, err)
	}
}

// TestWAL_WrittenDataHighWaterTracksAppend asserts the in-memory map advances
// on every successful Append for the matching generation, leaves other
// generations alone.
func TestWAL_WrittenDataHighWaterTracksAppend(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for s := int64(1); s <= 5; s++ {
		if _, err := w.Append(s, 1, []byte("p")); err != nil {
			t.Fatal(err)
		}
	}
	seq, ok, err := w.WrittenDataHighWater(1)
	if err != nil || !ok || seq != 5 {
		t.Errorf("after 5 appends, WrittenDataHighWater(1) = (%d, %v, %v); want (5, true, nil)", seq, ok, err)
	}
	for s := int64(6); s <= 8; s++ {
		if _, err := w.Append(s, 1, []byte("p")); err != nil {
			t.Fatal(err)
		}
	}
	seq, ok, err = w.WrittenDataHighWater(1)
	if err != nil || !ok || seq != 8 {
		t.Errorf("after 3 more appends, WrittenDataHighWater(1) = (%d, %v, %v); want (8, true, nil)", seq, ok, err)
	}
	if _, ok2, err2 := w.WrittenDataHighWater(2); err2 != nil || ok2 {
		t.Errorf("WrittenDataHighWater(2) bumped by gen=1 appends: ok=%v err=%v", ok2, err2)
	}
}

// TestWAL_WrittenDataHighWaterAfterRoll covers the per-gen independent
// tracking after multiple generation rolls.
func TestWAL_WrittenDataHighWaterAfterRoll(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for s := int64(1); s <= 5; s++ {
		if _, err := w.Append(s, 1, []byte("g1")); err != nil {
			t.Fatal(err)
		}
	}
	for s := int64(1); s <= 3; s++ {
		if _, err := w.Append(s, 2, []byte("g2")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.Append(1, 3, []byte("g3")); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		gen     uint32
		wantSeq uint64
		wantOK  bool
	}{
		{1, 5, true},
		{2, 3, true},
		{3, 1, true},
		{4, 0, false},
	}
	for _, tc := range tests {
		seq, ok, err := w.WrittenDataHighWater(tc.gen)
		if err != nil {
			t.Errorf("gen=%d err = %v, want nil", tc.gen, err)
			continue
		}
		if seq != tc.wantSeq || ok != tc.wantOK {
			t.Errorf("WrittenDataHighWater(%d) = (%d, %v); want (%d, %v)",
				tc.gen, seq, ok, tc.wantSeq, tc.wantOK)
		}
	}
}

// TestWAL_WrittenDataHighWaterIgnoresLossMarkers asserts loss markers do
// NOT advance the per-gen data high-water (the same-shape attack as a
// header-only generation).
func TestWAL_WrittenDataHighWaterIgnoresLossMarkers(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for s := int64(1); s <= 3; s++ {
		if _, err := w.Append(s, 1, []byte("d")); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.AppendLoss(LossRecord{FromSequence: 4, ToSequence: 10, Generation: 1, Reason: "overflow"}); err != nil {
		t.Fatal(err)
	}
	// Drive a gen roll via Append in gen=2.
	if _, err := w.Append(1, 2, []byte("d2")); err != nil {
		t.Fatal(err)
	}
	// Revert the in-memory state by asserting baseline before the second loss.
	seq1, ok1, err1 := w.WrittenDataHighWater(1)
	if err1 != nil || !ok1 || seq1 != 3 {
		t.Errorf("WrittenDataHighWater(1) = (%d, %v, %v); want (3, true, nil) — loss marker after seq 3 must not bump",
			seq1, ok1, err1)
	}
	// Now append a loss marker in gen=2 (the only kind of "record" past the
	// initial Append in gen=2 — but that initial Append already bumped seq=1).
	// Use a fresh directory to test the "only loss markers in gen=2" case.
	dir2 := t.TempDir()
	w2, err := Open(Options{Dir: dir2, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	for s := int64(1); s <= 3; s++ {
		if _, err := w2.Append(s, 1, []byte("d")); err != nil {
			t.Fatal(err)
		}
	}
	// AppendLoss(gen=2) when w2.current is gen=1: appendLossLocked writes
	// to the existing live segment (which is still gen=1). The loss marker
	// itself doesn't seed a new gen-2 segment.  To create a gen=2 with ONLY
	// a loss marker, we need to seal gen=1 first then AppendLoss(gen=2).
	// Simplest: hand-construct a segment with header gen=2 and write only
	// a loss marker payload directly via OpenSegment.
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}
	segDir2 := filepath.Join(dir2, "segments")
	idx := uint64(time.Now().UnixNano())
	seg, err := OpenSegment(segDir2, idx, SegmentHeader{Version: SegmentVersion, Flags: FlagGenInit, Generation: 2}, 4*1024-int(SegmentHeaderSize))
	if err != nil {
		t.Fatal(err)
	}
	lossPayload := encodeLossPayload(LossRecord{FromSequence: 0, ToSequence: 0, Generation: 2, Reason: "crc_corruption"})
	if err := seg.WriteRecord(lossPayload); err != nil {
		t.Fatal(err)
	}
	if err := seg.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := seg.Close(); err != nil {
		t.Fatal(err)
	}
	w3, err := Open(Options{Dir: dir2, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w3.Close()
	seq2, ok2, err2 := w3.WrittenDataHighWater(2)
	if err2 != nil {
		t.Fatalf("WrittenDataHighWater(2) err = %v, want nil", err2)
	}
	if ok2 || seq2 != 0 {
		t.Errorf("loss-marker-only gen=2 WrittenDataHighWater = (%d, %v); want (0, false)", seq2, ok2)
	}
}

// TestWAL_WrittenDataHighWater_IsConstantTime is the round-13 perf-budget
// regression test. Because the production implementation is mandated to be
// O(1) (in-memory map lookup), a 100x growth in segment count must NOT
// produce more than a 5x slowdown per call. Without approach 1, segment-scan
// implementations would yield ~100x slowdown.
//
// Test gated behind testing.Short() so go test -short skips it.
func TestWAL_WrittenDataHighWater_IsConstantTime(t *testing.T) {
	if testing.Short() {
		t.Skip("perf test")
	}
	const n = 10000

	// High-segment-count WAL.
	dirHigh := t.TempDir()
	wHigh, err := Open(Options{Dir: dirHigh, SegmentSize: 256, MaxTotalBytes: 16 * 1024 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer wHigh.Close()
	payload := bytes.Repeat([]byte("x"), 64)
	for s := int64(1); s <= 5000; s++ {
		if _, err := wHigh.Append(s, 1, payload); err != nil {
			t.Fatalf("seq=%d: %v", s, err)
		}
	}
	// Sanity baseline.
	seq, ok, err := wHigh.WrittenDataHighWater(1)
	if err != nil || !ok || seq != 5000 {
		t.Fatalf("baseline WrittenDataHighWater(1) = (%d, %v, %v); want (5000, true, nil)", seq, ok, err)
	}

	startHigh := time.Now()
	for i := 0; i < n; i++ {
		_, _, _ = wHigh.WrittenDataHighWater(1)
	}
	tHigh := time.Since(startHigh) / n

	// Low-segment-count WAL.
	dirLow := t.TempDir()
	wLow, err := Open(Options{Dir: dirLow, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer wLow.Close()
	for s := int64(1); s <= 50; s++ {
		if _, err := wLow.Append(s, 1, []byte("y")); err != nil {
			t.Fatal(err)
		}
	}
	startLow := time.Now()
	for i := 0; i < n; i++ {
		_, _, _ = wLow.WrittenDataHighWater(1)
	}
	tLow := time.Since(startLow) / n

	// Generous 5x budget — a 100x growth in segment count under the O(1)
	// approach yields effectively the same per-call latency. Approach 2
	// would yield ~100x and trip this assertion.
	if tHigh > 5*tLow && tHigh > 10*time.Microsecond {
		t.Errorf("WrittenDataHighWater scales with segment count: tHigh=%v tLow=%v (want tHigh < 5*tLow)", tHigh, tLow)
	}

	// Future-gen short-circuit: also O(1) (no scan needed for an absent gen).
	startFuture := time.Now()
	for i := 0; i < n; i++ {
		_, _, _ = wHigh.WrittenDataHighWater(99)
	}
	tFuture := time.Since(startFuture) / n
	if tFuture > 5*tLow && tFuture > 10*time.Microsecond {
		t.Errorf("WrittenDataHighWater(future-gen) is not O(1): tFuture=%v tLow=%v", tFuture, tLow)
	}
}
