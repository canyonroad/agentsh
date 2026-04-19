package wal

import (
	"io"
	"testing"
	"time"
)

func TestReader_AppendNotifyNext(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	r, err := w.NewReader(0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := w.Append(0, 0, []byte("first")); err != nil {
		t.Fatal(err)
	}
	// Notify may have already coalesced — drain non-blocking and proceed.
	select {
	case <-r.Notify():
	default:
	}
	rec, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if rec.Kind != RecordData || rec.Sequence != 0 || string(rec.Payload) != "first" {
		t.Errorf("rec = %+v, want kind=Data seq=0 payload=first", rec)
	}
}

func TestReader_StreamsSequentially(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := int64(0); i < 5; i++ {
		if _, err := w.Append(i, 0, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	r, err := w.NewReader(0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for i := uint64(0); i < 5; i++ {
		rec, err := r.Next()
		if err != nil {
			t.Fatalf("seq=%d: %v", i, err)
		}
		if rec.Kind != RecordData {
			t.Fatalf("seq=%d kind=%v, want RecordData", i, rec.Kind)
		}
		if rec.Sequence != i {
			t.Errorf("got seq=%d, want %d", rec.Sequence, i)
		}
	}
}

// TestReader_AdvancesPastLiveSegmentAfterSizeRoll regresses the round-1 finding
// that curLive was latched at open and never re-evaluated. After a live
// segment seals via size roll, a reader tailing on EOF would block forever
// instead of advancing to the next segment.
func TestReader_AdvancesPastLiveSegmentAfterSizeRoll(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 64, MaxTotalBytes: 1 << 20, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.Append(0, 0, []byte{'a', 'b', 'c', 'd'}); err != nil {
		t.Fatal(err)
	}
	r, err := w.NewReader(0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	rec0, err := r.Next()
	if err != nil {
		t.Fatalf("Next 0: %v", err)
	}
	if rec0.Sequence != 0 {
		t.Fatalf("seq 0: got %d", rec0.Sequence)
	}
	// Reader is now at EOF on the live segment. Force a size roll by
	// appending records that don't fit, sealing segment 0.
	if _, err := w.Append(1, 0, []byte{'e', 'f', 'g', 'h'}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(2, 0, []byte{'i', 'j', 'k', 'l'}); err != nil {
		t.Fatal(err)
	}
	// Reader must advance past the now-sealed segment 0 and surface seq=1, 2.
	seenSeqs := []uint64{}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rec, err := r.Next()
		if err == io.EOF {
			select {
			case <-r.Notify():
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if rec.Kind != RecordData {
			continue
		}
		seenSeqs = append(seenSeqs, rec.Sequence)
		if len(seenSeqs) == 2 {
			break
		}
	}
	if len(seenSeqs) != 2 || seenSeqs[0] != 1 || seenSeqs[1] != 2 {
		t.Errorf("post-roll seen sequences = %v, want [1 2]", seenSeqs)
	}
}

// TestReader_AdvancesPastLiveSegmentAfterGenerationRoll exercises the same
// rollover handling for a generation roll (Append with a higher gen forces a
// new segment with FlagGenInit).
func TestReader_AdvancesPastLiveSegmentAfterGenerationRoll(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.Append(0, 7, []byte("g7-r0")); err != nil {
		t.Fatal(err)
	}
	r, err := w.NewReader(0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	rec, err := r.Next()
	if err != nil {
		t.Fatalf("Next 0: %v", err)
	}
	if rec.Generation != 7 || rec.Sequence != 0 {
		t.Fatalf("got %+v", rec)
	}
	// Roll generation. WAL seals segment 0 and opens a new one for gen=8.
	if _, err := w.Append(0, 8, []byte("g8-r0")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rec, err := r.Next()
		if err == io.EOF {
			select {
			case <-r.Notify():
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if rec.Kind == RecordData && rec.Generation == 8 && rec.Sequence == 0 {
			return
		}
	}
	t.Errorf("Reader stalled across generation roll; never saw gen=8 seq=0")
}

// TestReader_SkipsGCdSegmentsContinuingPastLossMarker regresses the round-1
// finding that os.Open on a GC'd queued segment errored out instead of
// skipping. After ack-driven silent GC reclaims a sealed segment a lagging
// reader had snapshotted, the reader must skip the missing segment and
// continue from the next available one without aborting.
func TestReader_SkipsGCdSegmentsContinuingPastLossMarker(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 64, MaxTotalBytes: 1 << 20, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	// Append seqs 0..5; small SegmentSize → 3 sealed segments [0,1], [2,3], [4,5].
	for i := int64(0); i < 6; i++ {
		if _, err := w.Append(i, 0, []byte{byte(i), 'Z'}); err != nil {
			t.Fatal(err)
		}
	}
	// Snapshot the directory in a Reader BEFORE acking.
	r, err := w.NewReader(0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// Ack everything so gcAckedLocked silently reclaims sealed segments on
	// the next Append.
	if err := w.MarkAcked(0, 5); err != nil {
		t.Fatal(err)
	}
	// Trigger an Append that exercises the overflow/GC path. Appending in
	// a fresh generation forces a seal+open, which gives gcAckedLocked a
	// reason to walk the sealed set.
	if _, err := w.Append(6, 1, []byte("post")); err != nil {
		t.Fatal(err)
	}
	// Drain the reader. Pre-fix this would have errored on os.Open of a
	// reclaimed sealed segment; the bar here is "Next never returns an
	// error and surfaces at least the still-present records".
	seenSeqs := []uint64{}
	for i := 0; i < 30; i++ {
		rec, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Next iter=%d: %v", i, err)
		}
		if rec.Kind == RecordData {
			seenSeqs = append(seenSeqs, rec.Sequence)
		}
	}
	if len(seenSeqs) == 0 {
		t.Errorf("reader saw zero records; expected at least the live ones")
	}
	// Round-2 strengthening: any seqs that did surface must be monotonic.
	// A non-monotonic sequence here would indicate the missing-segment skip
	// path masked a real open error and we accidentally re-yielded an old
	// segment after advancing past it.
	for i := 1; i < len(seenSeqs); i++ {
		if seenSeqs[i] <= seenSeqs[i-1] {
			t.Errorf("non-monotonic seqs after GC: %v", seenSeqs)
		}
	}
}

// TestReader_FollowsLiveSegmentRenamedBetweenSnapshotAndOpen regresses the
// round-2 finding that the round-1 ENOENT fast-path conflated GC with the
// rename-on-seal case. A queued .INPROGRESS that the WAL sealed via size or
// generation roll between NewReader's directory snapshot and the segment-open
// call must still be read from its sealed twin — silently dropping it would
// lose user records that are still on disk (rename is not a loss event, so no
// TransportLoss marker would compensate).
func TestReader_FollowsLiveSegmentRenamedBetweenSnapshotAndOpen(t *testing.T) {
	dir := t.TempDir()
	// SegmentSize=64 fits two records; the third forces a size roll that
	// seals (.INPROGRESS → .seg) the existing live segment.
	w, err := Open(Options{Dir: dir, SegmentSize: 64, MaxTotalBytes: 1 << 20, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.Append(0, 0, []byte{'a', 'a'}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(1, 0, []byte{'b', 'b'}); err != nil {
		t.Fatal(err)
	}
	// Snapshot the directory into a Reader BEFORE the seal — r.segments now
	// holds the .INPROGRESS name for segment 0.
	r, err := w.NewReader(0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// Force a size roll: third record won't fit in segment 0, so seg 0 is
	// renamed (.INPROGRESS → .seg) and a new live segment opens for seq 2.
	if _, err := w.Append(2, 0, []byte{'c', 'c'}); err != nil {
		t.Fatal(err)
	}
	// The .INPROGRESS path the Reader has queued no longer exists; only its
	// sealed twin does. Round-2 bug: Reader treats the missing .INPROGRESS
	// as GC and skips it, losing seqs 0 and 1.
	seenSeqs := []uint64{}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rec, err := r.Next()
		if err == io.EOF {
			select {
			case <-r.Notify():
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if rec.Kind != RecordData {
			continue
		}
		seenSeqs = append(seenSeqs, rec.Sequence)
		if len(seenSeqs) == 3 {
			break
		}
	}
	want := []uint64{0, 1, 2}
	if len(seenSeqs) != 3 || seenSeqs[0] != want[0] || seenSeqs[1] != want[1] || seenSeqs[2] != want[2] {
		t.Errorf("seen seqs = %v, want %v (records from the renamed segment must not be silently dropped)", seenSeqs, want)
	}
}

// TestReader_BlocksUntilNotifyAfterEOF asserts the Notify/Next contract: after
// Next returns io.EOF, the reader must wait on Notify before re-trying. A new
// Append must wake the channel within a short timeout, and the next Next call
// must return the new record.
func TestReader_BlocksUntilNotifyAfterEOF(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	r, err := w.NewReader(0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// Drain to EOF — empty WAL.
	for {
		_, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("unexpected: %v", err)
		}
	}
	// Drain the notify channel if it has anything (state is fresh; should be empty).
	select {
	case <-r.Notify():
	default:
	}
	// Now append and verify Notify fires within 1s.
	if _, err := w.Append(0, 0, []byte("late")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-r.Notify():
	case <-time.After(time.Second):
		t.Fatal("Notify did not fire after Append within 1s")
	}
	rec, err := r.Next()
	if err != nil {
		t.Fatalf("Next after notify: %v", err)
	}
	if rec.Kind != RecordData || rec.Sequence != 0 || string(rec.Payload) != "late" {
		t.Errorf("unexpected post-notify record: %+v", rec)
	}
}
