package wal

import (
	"bytes"
	"os"
	"path/filepath"
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
	if err := w.MarkAcked(4); err != nil {
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
	if err := w.MarkAcked(29); err != nil {
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
