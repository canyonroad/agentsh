package wal

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestWAL_AppendAfterAmbiguousLatchesFatal pins the contract that any
// ambiguous failure latches the WAL into a fatal state so subsequent appends
// fail fast (clean, ErrFatal-wrapped) rather than running against a
// possibly-mutated segment. Without this latch, the documented contract is
// "treat the chain as broken" but the WAL still happily accepts the next
// Append, which can compound on-disk corruption.
//
// We force the latched-fatal state by setting w.fatalErr directly under the
// lock — this is white-box but it is the only way to deterministically
// exercise the second-Append fast-path without a full fault-injection
// harness for filesystem ops.
func TestWAL_AppendAfterAmbiguousLatchesFatal(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	// First Append should succeed.
	if _, err := w.Append(0, 0, []byte("first")); err != nil {
		t.Fatalf("first append failed: %v", err)
	}
	// Simulate an ambiguous failure on a prior Append by latching fatal
	// directly. Production code reaches this state via failAmbiguousLocked
	// when WriteRecord, Sync, or a roll step returns an error.
	w.mu.Lock()
	w.fatalErr = errors.New("simulated ambiguous failure")
	w.mu.Unlock()

	_, err = w.Append(1, 0, []byte("second"))
	if err == nil {
		t.Fatal("Append after latched fatal must fail")
	}
	if !IsClean(err) {
		t.Errorf("post-latch Append err must be Clean (no I/O attempted), got %v", err)
	}
	if IsAmbiguous(err) {
		t.Errorf("post-latch Append err must NOT be Ambiguous, got %v", err)
	}
	if !errors.Is(err, ErrFatal) {
		t.Errorf("post-latch Append err must wrap ErrFatal, got %v", err)
	}
}

// TestWAL_OpenRejectsSyncDeferred pins the Open-time guard. SyncDeferred
// describes a forward-compatible mode but the periodic-sync hook is not yet
// wired; accepting it would let acknowledged appends linger in the
// bufio.Writer until Close, which would silently lose records on crash.
// The fail-fast at Open is the safer surface — the caller adjusts
// configuration before any events are written.
func TestWAL_OpenRejectsSyncDeferred(t *testing.T) {
	dir := t.TempDir()
	_, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncDeferred})
	if err == nil {
		t.Fatal("Open with SyncDeferred must fail until the periodic-sync hook is implemented")
	}
}

// TestWAL_RecoverTruncatesCorruptTail is the regression for the
// "appends-after-corrupt-tail" hole: a truncated or CRC-bad tail used to
// stay on disk after recovery, so the next Append wrote past the garbage
// and a future replay stopped at the same bad bytes — never reaching the
// newly appended records.
//
// The fix is to scan the live segment, remember the offset of the first
// byte past the last good record, and truncate before reopening for
// append. After truncation, a fresh Append + reopen + replay must surface
// both records.
func TestWAL_RecoverTruncatesCorruptTail(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(0, 0, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// Locate the live INPROGRESS file and append garbage bytes that will
	// trigger ErrCorruptFrame (or io.ErrUnexpectedEOF) on next scan.
	segDir := filepath.Join(dir, "segments")
	entries, err := os.ReadDir(segDir)
	if err != nil {
		t.Fatal(err)
	}
	var livePath string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".INPROGRESS" {
			livePath = filepath.Join(segDir, e.Name())
			break
		}
	}
	if livePath == "" {
		t.Fatal("no .INPROGRESS file found after Close")
	}
	// Append 5 garbage bytes (less than an 8-byte frame header) so the
	// next ReadRecord sees an unrecoverable short read — exactly the
	// "truncated tail" scenario the fix must handle.
	f, err := os.OpenFile(livePath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen: recovery must scan, hit the bad tail, truncate, and reopen
	// for append. Then a fresh Append should land at the truncated offset.
	w2, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatalf("reopen after corrupt tail failed: %v", err)
	}
	if _, err := w2.Append(1, 0, []byte("second")); err != nil {
		t.Fatalf("Append after truncated recovery failed: %v", err)
	}
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}

	// Final reopen + manual scan of the live file: the recovered
	// high-watermark MUST reach seq=1, proving the second record is
	// readable past the formerly-corrupt offset.
	w3, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w3.Close()
	if got := w3.HighWatermark(); got != 1 {
		t.Errorf("HighWatermark after recovery+append+replay = %d, want 1", got)
	}
}

// TestWAL_RecoverPicksNumericMaxIndex is the regression for the
// lex-vs-numeric ordering hole. Once segment indices cross 10^10, filename
// order ("12345678901..." vs "09999999999...") stops matching numeric
// order, and a sort.Strings()-based "last wins" picks the wrong segment.
//
// We pre-create two segment files (one sealed at 9_999_999_999, one
// in-progress at 12_345_678_901) and verify recovery picks the
// numerically-larger inProgress entry as the live segment, which means
// nextIndex must be 12_345_678_902 after Open.
func TestWAL_RecoverPicksNumericMaxIndex(t *testing.T) {
	dir := t.TempDir()
	segDir := filepath.Join(dir, "segments")
	if err := os.MkdirAll(segDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Helper: write a valid segment header at the given path so recovery's
	// scan path doesn't fail on a header parse error.
	writeHeader := func(path string) {
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := WriteSegmentHeader(f, SegmentHeader{Version: SegmentVersion, Flags: 0, Generation: 0}); err != nil {
			t.Fatal(err)
		}
	}

	const lowSealed uint64 = 9_999_999_999
	const highInProgress uint64 = 12_345_678_901

	sealedPath := filepath.Join(segDir, fmt.Sprintf("%010d.seg", lowSealed))
	inProgressPath := filepath.Join(segDir, fmt.Sprintf("%010d.seg.INPROGRESS", highInProgress))
	writeHeader(sealedPath)
	writeHeader(inProgressPath)

	// Lex-order would put "09999999999.seg" after "12345678901.seg.INPROGRESS"
	// (because "1..." < "9...") so the buggy code would treat the sealed
	// segment as "later." Numeric order correctly puts the inProgress
	// segment as the live one.
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatalf("Open with mixed digit-count indices failed: %v", err)
	}
	defer w.Close()

	w.mu.Lock()
	gotNextIndex := w.nextIndex
	gotCurrent := w.current
	w.mu.Unlock()

	if gotNextIndex != highInProgress+1 {
		t.Errorf("nextIndex = %d, want %d (numeric max + 1)", gotNextIndex, highInProgress+1)
	}
	if gotCurrent == nil {
		t.Fatal("expected the highInProgress segment to be reopened as live; got nil")
	}
	if gotCurrent.Index() != highInProgress {
		t.Errorf("live segment index = %d, want %d", gotCurrent.Index(), highInProgress)
	}
}

// TestWAL_RecoverFailsOnSmallerSegmentSize regresses the round-2 finding
// that wrapping the "payloadLen > maxPayload" branch in ErrCorruptFrame
// caused recovery to silently truncate valid records when an operator
// restarted the daemon with a smaller wal.segment_size than what wrote
// the segment.
//
// The fix narrows ErrCorruptFrame to the structurally-impossible case
// (length < 4) and leaves the over-bound case as an unwrapped error,
// which recovery surfaces as a hard Open failure rather than treating it
// as truncatable corruption. We exercise that here by writing a record
// whose framed payload exceeds the new (smaller) segment's per-record
// budget — recovery must refuse to open, not silently chop the file.
func TestWAL_RecoverFailsOnSmallerSegmentSize(t *testing.T) {
	dir := t.TempDir()
	// Open with a generous segment size so the framed (12-byte seq/gen
	// prefix + payload) record + 8-byte frame header + 16-byte segment
	// header all fit. We use a payload that is comfortably larger than
	// the smaller-restart per-record budget (smallSize - 16 - 8 - 12).
	const largeSize int64 = 4 * 1024
	const smallSize int64 = 256
	w, err := Open(Options{Dir: dir, SegmentSize: largeSize, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	// Pick a payload that fits under largeSize but exceeds the smaller
	// budget by a wide margin: the smaller per-record cap is
	// smallSize-SegmentHeaderSize = 240 bytes total for header+seq/gen+payload,
	// so a 1 KiB payload is well past it.
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = 0xA5
	}
	if _, err := w.Append(0, 0, payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen with the smaller segment size: recovery must surface a hard
	// error instead of silently truncating the previously-valid record.
	_, err = Open(Options{Dir: dir, SegmentSize: smallSize, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err == nil {
		t.Fatal("Open with smaller segment_size must fail rather than silently truncate valid records")
	}
	// The error must NOT be ErrCorruptFrame: that would put recovery on
	// the truncate-and-continue path, which is the bug being regressed.
	if errors.Is(err, ErrCorruptFrame) {
		t.Errorf("Open err = %v; expected an unwrapped over-bound error, NOT ErrCorruptFrame", err)
	}
}
