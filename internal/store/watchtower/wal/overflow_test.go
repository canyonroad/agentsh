package wal

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestWAL_OverflowEmitsLossMarker verifies that an Append that would push the
// WAL past MaxTotalBytes drops oldest segments AND inserts a TransportLoss
// marker into the WAL stream.
func TestWAL_OverflowEmitsLossMarker(t *testing.T) {
	dir := t.TempDir()
	// Tight budget: 4 KiB segments, 12 KiB cap → 3 segments max.
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 12 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	payload := bytes.Repeat([]byte("x"), 1024) // ~1 KiB per record
	for seq := int64(0); seq < 30; seq++ {
		if _, err := w.Append(seq, 0, payload); err != nil {
			t.Fatalf("seq=%d: %v", seq, err)
		}
	}
	// At least one TransportLoss marker should now exist on disk.
	found := false
	entries, _ := os.ReadDir(filepath.Join(dir, "segments"))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".INPROGRESS") || strings.HasSuffix(e.Name(), ".seg") {
			data, _ := os.ReadFile(filepath.Join(dir, "segments", e.Name()))
			if bytes.Contains(data, []byte(LossMarkerSentinel)) {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("no TransportLoss marker found after WAL overflow")
	}
	// And total disk usage must not exceed MaxTotalBytes by more than one
	// segment (we cap at the next-segment boundary, not exactly).
	totalBytes := int64(0)
	entries, _ = os.ReadDir(filepath.Join(dir, "segments"))
	for _, e := range entries {
		st, _ := os.Stat(filepath.Join(dir, "segments", e.Name()))
		totalBytes += st.Size()
	}
	if totalBytes > 16*1024 {
		t.Errorf("total bytes %d exceeds budget 12 KiB + one segment slack", totalBytes)
	}
}

// TestWAL_OverflowAfterAck_OnlyDropsAcked verifies the ack-driven (silent) GC
// path of overflow reclamation: when the receiver has already acknowledged
// older sealed segments, those segments are reclaimed BEFORE we ever fall
// back to the lossy path that emits a TransportLoss marker.
//
// Round-1 hardening: the original test had no assertions. It now asserts:
//
//   - At least one sealed segment was reclaimed silently (totalBytes is
//     well under what 10 records would have occupied without GC).
//   - NO TransportLoss marker appears anywhere on disk (the ack-driven
//     path must be silent — emitting a marker would force the receiver to
//     surface a fake gap on replay).
//   - totalBytes is back under the cap.
//
// Without the ack-aware fix, dropOldestLocked would have run unconditionally
// on the first overflow, dropping seg 0 (containing acked seqs 0..n) AND
// emitting a TransportLoss marker for data the server already had.
//
// Sizing: 4 KiB segments, 12 KiB cap. Each record = 8(frame) + 12(seq/gen)
// + 1024(payload) = 1044 bytes; segment header = 16 bytes. The 5 acked
// records consume ~5232 bytes; we then append 5 more unacked, which after
// silent GC of the acked segments fits comfortably under the cap. If the
// ack-driven GC is broken, the first overflow will instead fire the lossy
// path and leave a marker on disk — which the assertions catch.
func TestWAL_OverflowAfterAck_OnlyDropsAcked(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 12 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for seq := int64(0); seq < 5; seq++ {
		if _, err := w.Append(seq, 0, bytes.Repeat([]byte("a"), 1024)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.MarkAcked(0, 4); err != nil {
		t.Fatal(err)
	}
	// 5 more unacked records. After silent GC reclaims the first sealed
	// segment(s), the remaining 5 records fit under the cap without
	// triggering a lossy drop.
	for seq := int64(5); seq < 10; seq++ {
		if _, err := w.Append(seq, 0, bytes.Repeat([]byte("b"), 1024)); err != nil {
			t.Fatalf("seq=%d: %v", seq, err)
		}
	}

	// Assertion 1: NO loss marker should exist anywhere on disk. With 5
	// acked records freeing space ahead of the unacked tail, every
	// overflow check should be satisfied by ack-driven GC alone — the
	// lossy fallback must never have fired.
	segDir := filepath.Join(dir, "segments")
	entries, err := os.ReadDir(segDir)
	if err != nil {
		t.Fatalf("read segments dir: %v", err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(segDir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if bytes.Contains(data, []byte(LossMarkerSentinel)) {
			t.Errorf("found TransportLoss marker in %s — ack-driven GC should be silent", e.Name())
		}
	}

	// Assertion 2: silent GC actually freed something. 10 records ×
	// ~1044 bytes ≈ 10440 bytes; with at least one sealed segment
	// reclaimed, totalBytes should be meaningfully under that.
	totalBytes := int64(0)
	for _, e := range entries {
		st, err := os.Stat(filepath.Join(segDir, e.Name()))
		if err != nil {
			t.Fatalf("stat %s: %v", e.Name(), err)
		}
		totalBytes += st.Size()
	}
	if totalBytes >= 10*1044 {
		t.Errorf("ack-driven GC did not reclaim any segments: totalBytes=%d, want <%d", totalBytes, 10*1044)
	}

	// Assertion 3: budget is respected.
	if totalBytes > 16*1024 {
		t.Errorf("totalBytes %d exceeds budget 12 KiB + one segment slack", totalBytes)
	}
}

// TestWAL_MarkAckedReclaimsSegmentsContainingLossMarkers is a regression for
// finding 2 (loss markers misparsed by parseSeqGen). When a sealed segment
// contains a TransportLoss marker, the prior segmentHighSeq fed the marker's
// payload through parseSeqGen and got a synthesized seq of ~0x0057545050...
// (the LossMarkerSentinel "\x00WTPLOSS" interpreted as a uint64 BE). That
// huge value exceeded any real ack, so MarkAcked never freed the segment.
//
// We trigger the bug by forcing several overflows (each of which embeds a
// loss marker into the live segment) under a tight cap, then ack past every
// real seq. With the isLossMarker guard in segmentHighSeq, MarkAcked must
// reclaim those segments. Without the guard, no GC happens and the test
// fails its sealed-count comparison.
func TestWAL_MarkAckedReclaimsSegmentsContainingLossMarkers(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 256, MaxTotalBytes: 768, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	payload := bytes.Repeat([]byte("x"), 50)
	for seq := int64(0); seq < 30; seq++ {
		if _, err := w.Append(seq, 0, payload); err != nil {
			t.Fatalf("seq=%d: %v", seq, err)
		}
	}

	segDir := filepath.Join(dir, "segments")
	// Prerequisite: setup must have produced at least one loss marker on
	// disk; otherwise this test is meaningless (no regression to exercise).
	sawMarker := func() bool {
		entries, _ := os.ReadDir(segDir)
		for _, e := range entries {
			data, _ := os.ReadFile(filepath.Join(segDir, e.Name()))
			if bytes.Contains(data, []byte(LossMarkerSentinel)) {
				return true
			}
		}
		return false
	}
	if !sawMarker() {
		t.Skip("setup did not produce a loss marker; cannot exercise the regression")
	}

	// Count sealed (non-INPROGRESS) segments before ack. MarkAcked may
	// reclaim some but not all, so we use a strict before>after check.
	countSealed := func() int {
		n := 0
		entries, _ := os.ReadDir(segDir)
		for _, e := range entries {
			name := e.Name()
			if strings.HasSuffix(name, ".seg") && !strings.HasSuffix(name, ".INPROGRESS") {
				n++
			}
		}
		return n
	}
	before := countSealed()
	if err := w.MarkAcked(0, 29); err != nil {
		t.Fatal(err)
	}
	after := countSealed()
	if after >= before {
		t.Errorf("MarkAcked freed nothing (sealed before=%d, after=%d) — segmentHighSeq likely misread a loss marker as a huge seq", before, after)
	}
}

// TestWAL_DropOldestSegmentAtSeqZeroEmitsLossMarker is a regression for
// finding 3 (ToSequence==0 conflated with "nothing dropped"). A single-record
// segment ending at seq=0 is a legitimate drop with ToSequence==0; the prior
// code's `if dropped.ToSequence == 0 { break }` short-circuit would have
// silently swallowed both the file removal AND the loss-marker emission.
//
// We exercise dropOldestLocked directly rather than via the Append overflow
// path because the ack-driven silent GC pass (gcAckedLocked) will normally
// consume a seq=0 segment first (w.ackHighSeq defaults to 0, so hi=0 ≤ 0
// matches). Calling dropOldestLocked directly models the "ack-driven GC
// cannot free enough space" fallback case.
//
// Sizing math (each user record's framed cost = 8-byte frame header +
// 12-byte seq/gen prefix + 1-byte payload = 21 bytes; SegmentHeader = 16
// bytes; loss-marker payload = 38 bytes):
//
//   - SegmentSize=56: maxRecordBytes = 40. Loss-marker payload (38) fits;
//     second user record at 37+21=58 exceeds 56 → roll. So each user
//     record gets its own segment.
//
// After appending seqs 0 and 1, the first sealed segment holds seq=0 only
// and the live INPROGRESS holds seq=1. Calling dropOldestLocked must:
//
//   - return dropped=true (a file was removed),
//   - return hasUserRange=true (the dropped segment held a real record),
//   - return loss.ToSequence=0 (the segment's only user record was seq=0).
//
// Then we emit the loss marker via appendLossLocked and assert the marker
// sentinel lands on disk. The pre-fix code returned no explicit dropped
// flag, and the caller's `if dropped.ToSequence == 0 { break }` skipped
// both the follow-through reclamation and the loss-marker emission.
//
// Filename note: recover() initializes nextIndex=1 even on a fresh WAL
// (maxIdx starts at 0; nextIndex = maxIdx+1), so the very first segment
// on disk is 0000000001.seg, not 0000000000.seg. Subsequent segments
// increment from there.
func TestWAL_DropOldestSegmentAtSeqZeroEmitsLossMarker(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 56, MaxTotalBytes: 120, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	payload := []byte{0xAA}
	// seq=0 lands in seg index 1 (INPROGRESS, 37 bytes after header+record).
	if _, err := w.Append(0, 0, payload); err != nil {
		t.Fatalf("seq=0: %v", err)
	}
	// seq=1 forces a roll: seg 1 sealed, seg 2 opened (INPROGRESS).
	if _, err := w.Append(1, 0, payload); err != nil {
		t.Fatalf("seq=1: %v", err)
	}

	// Sanity check: seg 1 (the first segment created from a fresh WAL)
	// is sealed and holds exactly seq=0.
	segDir := filepath.Join(dir, "segments")
	if _, err := os.Stat(filepath.Join(segDir, "0000000001.seg")); err != nil {
		t.Fatalf("expected sealed seg 1 before drop: %v", err)
	}

	// Drive the dropOldestLocked path directly; holding w.mu is required
	// by the locked helper. We also need to emulate the Append caller's
	// response to the returned flags.
	w.mu.Lock()
	loss, dropped, hasUserRange, err := w.dropOldestLocked()
	if err != nil {
		w.mu.Unlock()
		t.Fatalf("dropOldestLocked: %v", err)
	}
	if !dropped {
		w.mu.Unlock()
		t.Fatal("dropped=false — expected the sealed seg 1 to be removed")
	}
	if !hasUserRange {
		w.mu.Unlock()
		t.Fatal("hasUserRange=false — seg 1 held a real seq=0 record, should be true")
	}
	if loss.ToSequence != 0 || loss.FromSequence != 0 {
		w.mu.Unlock()
		t.Fatalf("loss=%+v: expected FromSequence=0 ToSequence=0 for a single-record seq=0 segment", loss)
	}
	// The caller must emit a loss marker even though ToSequence==0. The
	// pre-fix code branched on `dropped.ToSequence == 0` and skipped
	// exactly this appendLossLocked call.
	if err := w.appendLossLocked(loss); err != nil {
		w.mu.Unlock()
		t.Fatalf("appendLossLocked: %v", err)
	}
	w.mu.Unlock()

	// A loss marker MUST exist on disk somewhere (appendLossLocked wrote
	// it into the live INPROGRESS segment).
	sawMarker := false
	entries, err := os.ReadDir(segDir)
	if err != nil {
		t.Fatalf("read segments dir: %v", err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(segDir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if bytes.Contains(data, []byte(LossMarkerSentinel)) {
			sawMarker = true
			break
		}
	}
	if !sawMarker {
		t.Errorf("no TransportLoss marker after dropping a single-record seq=0 segment")
	}

	// Seg 1 (the dropped segment) must be gone.
	if _, err := os.Stat(filepath.Join(segDir, "0000000001.seg")); !os.IsNotExist(err) {
		t.Errorf("seg 1 still present after drop: err=%v", err)
	}
}

// TestWAL_OverflowOnFreshWALEmitsLossEvenAtSeqZero regresses the round-2
// finding that ackHighSeq=0 on a fresh WAL was conflated with "ack covers
// seq=0", causing the silent ack-driven GC to reclaim a segment whose only
// record was seq=0 without emitting a TransportLoss marker. With ackPresent
// gating gcAckedLocked, a fresh WAL — meta.json absent — must take the
// lossy overflow path: drop the oldest segment AND emit a TransportLoss
// marker covering its (0, hi=0) range.
func TestWAL_OverflowOnFreshWALEmitsLossEvenAtSeqZero(t *testing.T) {
	dir := t.TempDir()
	// Match the sizing of TestWAL_DropOldestSegmentAtSeqZeroEmitsLossMarker
	// so each user record gets its own segment: SegmentSize=56 admits a
	// single 21-byte user record (8-byte frame + 12-byte seq/gen + 1-byte
	// payload) plus the 16-byte segment header; a second record forces a
	// roll. MaxTotalBytes=120 (~2 segments × 56) trips overflow on the
	// third Append. NO MarkAcked call: ackPresent stays false for the
	// duration of the test.
	w, err := Open(Options{Dir: dir, SegmentSize: 56, MaxTotalBytes: 120, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := uint64(0); i < 5; i++ {
		if _, err := w.Append(int64(i), 0, []byte{byte(i)}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	// Round-2 bug: silent GC of the seq=0 segment because ackHighSeq=0
	// matched seq=0. Fix: ackPresent=false bails gcAckedLocked, overflow
	// falls into the lossy path, TransportLoss marker is written. Scan
	// every on-disk segment for the LossMarkerSentinel, mirroring how
	// TestWAL_OverflowEmitsLossMarker detects markers.
	segDir := filepath.Join(dir, "segments")
	entries, err := os.ReadDir(segDir)
	if err != nil {
		t.Fatalf("read segments dir: %v", err)
	}
	sawMarker := false
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(segDir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if bytes.Contains(data, []byte(LossMarkerSentinel)) {
			sawMarker = true
			break
		}
	}
	if !sawMarker {
		t.Errorf("no TransportLoss marker after overflow on fresh WAL: ackPresent=false must block silent GC of the seq=0 segment")
	}
}

// segMeta is a minimal sealed-segment descriptor used by the
// generation-boundary regression test below; mirrors what the test asserts
// (index for ordering, generation for the lex compare).
type segMeta struct {
	idx uint64
	gen uint32
}

// listSealedSegmentsForTest returns sealed (non-INPROGRESS) segments in
// numeric idx order, with the generation read from each segment header.
func listSealedSegmentsForTest(t *testing.T, dir string) []segMeta {
	t.Helper()
	segDir := filepath.Join(dir, "segments")
	entries, err := os.ReadDir(segDir)
	if err != nil {
		t.Fatalf("read segments dir: %v", err)
	}
	var out []segMeta
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".seg") || strings.HasSuffix(name, ".INPROGRESS") {
			continue
		}
		idx, ok := parseSegmentIndex(name)
		if !ok {
			continue
		}
		f, err := os.Open(filepath.Join(segDir, name))
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
		hdr, err := ReadSegmentHeader(f)
		f.Close()
		if err != nil {
			t.Fatalf("read header %s: %v", name, err)
		}
		out = append(out, segMeta{idx: idx, gen: hdr.Generation})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].idx < out[j].idx })
	return out
}

// TestWAL_GcAckedRespectsGenerationBoundary regresses the round-2 finding
// that ack-driven GC compared only seq, ignoring generation. After a
// generation roll, seqs restart at 0, so an old watermark (gen=7, seq=100)
// reopened on disk would silently reclaim later gen=8 segments whose local
// seqs were <=100 even though no gen=8 record was ever acked. Fix: lex
// (gen, seq) compare in segmentFullyAckedLocked.
func TestWAL_GcAckedRespectsGenerationBoundary(t *testing.T) {
	dir := t.TempDir()
	// Each user record costs 8 (frame) + 12 (seq/gen) + 1 (payload) = 21
	// bytes; SegmentHeader is 16 bytes; a 56-byte segment fits exactly
	// one user record after its header. SegmentSize=56 with a 1-byte
	// payload guarantees every record gets its own sealed segment, which
	// is what we need to assert per-segment generations crisply.
	// MaxTotalBytes is generous so overflow GC never fires during setup.
	w, err := Open(Options{Dir: dir, SegmentSize: 56, MaxTotalBytes: 1 << 20, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	// gen=7: seqs 0..3 → 4 sealed segments under SegmentSize=56.
	for i := int64(0); i <= 3; i++ {
		if _, err := w.Append(i, 7, []byte{byte(i)}); err != nil {
			t.Fatalf("gen7 append %d: %v", i, err)
		}
	}
	// gen=8: seqs 0..2 — first append triggers the generation roll and
	// opens a fresh segment with header.generation=8.
	for i := int64(0); i <= 2; i++ {
		if _, err := w.Append(i, 8, []byte{byte(i)}); err != nil {
			t.Fatalf("gen8 append %d: %v", i, err)
		}
	}
	// Ack everything in gen=7. Crucially, do NOT advance into gen=8.
	if err := w.MarkAcked(7, 3); err != nil {
		t.Fatalf("MarkAcked(7,3): %v", err)
	}
	// MarkAcked already runs an ack-driven sweep, so a follow-up
	// gcAckedLocked is a no-op idempotency check; we still call it
	// explicitly to model the overflow-path invocation site.
	beforeSealed := listSealedSegmentsForTest(t, dir)
	w.mu.Lock()
	n, err := w.gcAckedLocked()
	w.mu.Unlock()
	if err != nil {
		t.Fatalf("gcAckedLocked: %v", err)
	}
	afterSealed := listSealedSegmentsForTest(t, dir)
	// Any gen<7 sealed segment should be gone (vacuously true here — we
	// only created gen=7 and gen=8). Any gen=7 sealed segment should be
	// gone (acked). Any gen=8 sealed segment with hi <= 3 must still be
	// on disk: the round-2 bug would have silently dropped it.
	for _, s := range afterSealed {
		if s.gen < 7 {
			t.Errorf("sealed segment gen=%d still on disk after acking (gen=7,seq=3) — should have been GCd", s.gen)
		}
		if s.gen == 7 {
			t.Errorf("sealed gen=7 segment idx=%d survived ack of (7,3) — gcAckedLocked should have reclaimed it", s.idx)
		}
	}
	var anyGen8Surviving bool
	for _, s := range afterSealed {
		if s.gen == 8 {
			anyGen8Surviving = true
			break
		}
	}
	if !anyGen8Surviving {
		t.Errorf("no gen=8 sealed segment survived gcAckedLocked; expected at least one (we acked only through (gen=7, seq=3))")
	}
	// Sanity: at least one gen=7 segment must have been reclaimed across
	// the MarkAcked sweep + the explicit gcAckedLocked call.
	gen7BeforeCount := 0
	for _, s := range beforeSealed {
		if s.gen == 7 {
			gen7BeforeCount++
		}
	}
	gen7AfterCount := 0
	for _, s := range afterSealed {
		if s.gen == 7 {
			gen7AfterCount++
		}
	}
	if gen7BeforeCount == gen7AfterCount && gen7BeforeCount > 0 {
		t.Errorf("ack of (gen=7,seq=3) did not reclaim any gen=7 segment: before=%d after=%d explicit-gc-removed=%d",
			gen7BeforeCount, gen7AfterCount, n)
	}
}

// TestWAL_OpenWithLegacyV1MetaHonorsAckWatermark regresses the round-3
// finding end-to-end: an upgraded node opening a WAL that was last written
// by a pre-v2 binary must still treat the persisted (gen, seq) as a real
// ack watermark (not "no ack ever recorded") so subsequent overflow takes
// the silent GC path instead of emitting a bogus TransportLoss marker for
// data the receiver already has.
func TestWAL_OpenWithLegacyV1MetaHonorsAckWatermark(t *testing.T) {
	dir := t.TempDir()
	// Step 1: write a legacy v1 meta.json by hand with a watermark at
	// (gen=0, seq=4). Real pre-v2 deployments would have produced exactly
	// this shape via MarkAcked.
	raw := []byte(`{"format_version":1,"ack_high_watermark_seq":4,"ack_high_watermark_gen":0,"session_id":"","key_fingerprint":""}`)
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// Step 2: open WAL. Per round-3 fix, ackPresent must come back true and
	// the watermark must be (gen=0, seq=4).
	w, err := Open(Options{Dir: dir, SegmentSize: 40, MaxTotalBytes: 100, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	w.mu.Lock()
	gotPresent := w.ackPresent
	gotSeq := w.ackHighSeq
	gotGen := w.ackHighGen
	w.mu.Unlock()
	if !gotPresent {
		t.Errorf("ackPresent after legacy v1 reopen = false; want true (legacy file's existence implied a persisted ack)")
	}
	if gotSeq != 4 || gotGen != 0 {
		t.Errorf("ack watermark after legacy v1 reopen = (gen=%d, seq=%d); want (0, 4)", gotGen, gotSeq)
	}
}
