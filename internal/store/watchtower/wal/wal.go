package wal

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SyncMode controls whether each Append fsyncs synchronously or via a timer.
type SyncMode int

const (
	// SyncImmediate causes every Append to fsync the segment before returning.
	SyncImmediate SyncMode = iota
	// SyncDeferred batches fsyncs onto a timer driven by SyncInterval. The
	// timer-driven path is not yet wired by this WAL: there is no public
	// flush hook the higher-level Task can call between appends, so a crash
	// in this mode would silently lose acknowledged records. Open() rejects
	// SyncDeferred until the periodic-sync API is added; this constant is
	// kept so the surface is forward-compatible.
	SyncDeferred
)

// Options configures a WAL. Defaults are not applied here — callers should
// pre-validate via internal/config (which does apply defaults).
type Options struct {
	Dir           string
	SegmentSize   int64
	MaxTotalBytes int64
	SyncMode      SyncMode
	SyncInterval  time.Duration
}

// AppendResult is returned by WAL.Append. GenerationRolled is set exactly when
// this Append rolled the segment for a new generation (i.e. the previous
// segment was sealed and a fresh segment was opened with the new generation
// header). The first record on a brand-new WAL does NOT count as a roll.
type AppendResult struct {
	GenerationRolled bool
}

// FailureClass classifies an Append failure into clean or ambiguous, driving
// the caller's transactional Compute → Append → Commit/Fatal pattern.
type FailureClass int

const (
	// FailureNone is the zero value used for non-failure paths.
	FailureNone FailureClass = iota
	// FailureClean means no I/O was attempted (validation rejected the call).
	// The caller can safely retry or surface the error without re-shaping
	// downstream chain state.
	FailureClean
	// FailureAmbiguous means I/O was attempted and the on-disk state may or
	// may not have been mutated. The caller MUST treat the chain as broken
	// (audit.SinkChain.Fatal).
	FailureAmbiguous
)

// AppendError wraps an Append error with its classification. Use IsClean or
// IsAmbiguous to inspect; use errors.As for type-assertion.
type AppendError struct {
	Class FailureClass
	Op    string
	Err   error
}

func (e *AppendError) Error() string { return fmt.Sprintf("wal %s: %v", e.Op, e.Err) }
func (e *AppendError) Unwrap() error { return e.Err }

// IsClean reports whether err (or any error in its chain) is an AppendError
// classified as FailureClean. Returns false for nil.
func IsClean(err error) bool {
	var ae *AppendError
	if errors.As(err, &ae) {
		return ae.Class == FailureClean
	}
	return false
}

// IsAmbiguous reports whether err (or any error in its chain) is an
// AppendError classified as FailureAmbiguous. Returns false for nil.
func IsAmbiguous(err error) bool {
	var ae *AppendError
	if errors.As(err, &ae) {
		return ae.Class == FailureAmbiguous
	}
	return false
}

// ErrClosed is wrapped in a clean AppendError when Append is called on a
// closed WAL. No I/O is attempted.
var ErrClosed = errors.New("wal: closed")

// ErrFatal is wrapped in a clean AppendError when Append is called on a WAL
// that has previously returned an ambiguous failure. The WAL latches into
// a fatal state on any ambiguous error so subsequent appends fail fast
// without compounding on-disk corruption — the caller MUST Close the WAL
// and reopen it to resume. The original ambiguous error is wrapped via
// fmt.Errorf("%w: %v", ErrFatal, originalErr) so callers can inspect both
// via errors.Is(err, ErrFatal) and the formatted message.
var ErrFatal = errors.New("wal: fatal error — WAL must be closed and reopened")

// recordOverhead is the per-record on-disk cost beyond the payload bytes
// themselves: an 8-byte frame header (uint32 length + uint32 CRC) plus the
// 12-byte (seq:int64 + gen:uint32) prefix this WAL adds to each record so
// recovery can read the high-watermark without parsing the protobuf payload.
const recordOverhead = 8 + 12

// sealedSuffix and inprogressSuffix are the on-disk filename suffixes for
// sealed and in-progress segment files, respectively. Centralized here so
// recover()'s parseSegmentIndex helper can switch on them without rebuilding
// the suffix string at each call site.
const (
	sealedSuffix     = segmentExt
	inprogressSuffix = segmentExt + inProgressSuffix
)

// WAL is the per-sink write-ahead log. Concurrency: AppendEvent serialization
// is the caller's responsibility (the WTP Store holds an outer lock); WAL's
// own internal mutex protects the segment switch but does not allow
// concurrent Append from multiple goroutines.
type WAL struct {
	opts   Options
	maxRec int

	mu         sync.Mutex
	current    *Segment
	segDir     string
	closed     bool
	fatalErr   error
	highSeq    uint64
	highGen    uint32
	nextIndex  uint64
	totalBytes int64
	// ackHighSeq mirrors Meta.AckHighWatermarkSeq so the overflow path can
	// distinguish sealed segments that the receiver already has (silent GC)
	// from sealed segments holding still-unacked data (must emit a
	// TransportLoss marker on drop). Loaded from meta.json at Open;
	// updated by MarkAcked (which also persists it). Zero is a valid value
	// (nothing acked yet).
	ackHighSeq uint64
}

// segmentEntry pairs a segment filename with its parsed numeric index so
// recovery can pick the numeric maximum (rather than the lexicographic
// maximum, which silently breaks once an index crosses 10^10).
type segmentEntry struct {
	name string
	idx  uint64
}

// Open opens or creates the WAL directory at opts.Dir. On open, all sealed
// segments are scanned and the highest (sequence, generation) is recovered.
// Any .INPROGRESS file is reopened for append.
func Open(opts Options) (*WAL, error) {
	if opts.Dir == "" {
		return nil, errors.New("wal.Open: Dir required")
	}
	if opts.SegmentSize <= int64(SegmentHeaderSize) {
		return nil, fmt.Errorf("wal: SegmentSize %d must exceed SegmentHeaderSize %d",
			opts.SegmentSize, SegmentHeaderSize)
	}
	// Per-record cap is the segment budget minus the fixed segment header.
	// Both the framing layer and the segment writer use this to bound a
	// single record's payload; computing it once here keeps OpenSegment,
	// ReopenSegment, and ReadRecord aligned with the configured segment
	// size.
	maxRec := int(opts.SegmentSize - int64(SegmentHeaderSize))
	if maxRec <= 0 || uint64(maxRec) > MaxFramedPayload {
		return nil, fmt.Errorf("wal: SegmentSize %d invalid; need room for header+record within MaxFramedPayload",
			opts.SegmentSize)
	}
	// SyncDeferred is documented as a forward-compatible mode but the
	// periodic-sync hook is not yet implemented. Accepting it would let
	// successful appends linger in the bufio.Writer until Close, so a
	// crash would silently drop acknowledged records — exactly the
	// failure mode this WAL is built to prevent. Reject it explicitly
	// until the timer task is wired up; the failure is at Open time so
	// callers can adjust configuration before any events are written.
	if opts.SyncMode != SyncImmediate {
		return nil, errors.New("wal.Open: only SyncImmediate is implemented; SyncDeferred requires the periodic-sync timer hook")
	}
	segDir := filepath.Join(opts.Dir, "segments")
	if err := os.MkdirAll(segDir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir segments: %w", err)
	}
	w := &WAL{opts: opts, maxRec: maxRec, segDir: segDir}
	// Load the ack watermark BEFORE recover() so the overflow path (which
	// can fire on the very first Append after Open) sees a consistent
	// view: sealed segments fully covered by ack are silently GC'd, while
	// segments holding unacked records emit a TransportLoss marker on
	// drop. Missing meta.json is fine — a fresh WAL has nothing acked yet
	// (zero is the correct default). Any other read error is fatal at
	// open time.
	if m, err := ReadMeta(opts.Dir); err == nil {
		w.ackHighSeq = m.AckHighWatermarkSeq
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read meta: %w", err)
	}
	if err := w.recover(); err != nil {
		return nil, err
	}
	return w, nil
}

// parseSegmentIndex extracts the numeric index from a segment filename. It
// recognizes both the sealed (".seg") and in-progress (".seg.INPROGRESS")
// suffixes. Returns (0, false) for any other name.
//
// Implementation note: an earlier version used fmt.Sscanf("%010d", ...) which
// silently caps at 10 digits and would fail to recover indices ≥ 10^10. We
// strip the suffix and parse the remaining prefix as a uint64 instead.
func parseSegmentIndex(name string) (uint64, bool) {
	var prefix string
	switch {
	case strings.HasSuffix(name, inprogressSuffix):
		prefix = strings.TrimSuffix(name, inprogressSuffix)
	case strings.HasSuffix(name, sealedSuffix):
		prefix = strings.TrimSuffix(name, sealedSuffix)
	default:
		return 0, false
	}
	idx, err := strconv.ParseUint(prefix, 10, 64)
	if err != nil {
		return 0, false
	}
	return idx, true
}

// pickMaxByIndex returns the entry with the largest numeric index, or false
// if entries is empty. Used by recover() to find the live (or last sealed)
// segment without relying on lexicographic order — once segment indices
// cross 10^10 (digit count changes), filename order stops matching numeric
// order and a sort.Strings()-based "last wins" picks the wrong segment.
func pickMaxByIndex(entries []segmentEntry) (segmentEntry, bool) {
	if len(entries) == 0 {
		return segmentEntry{}, false
	}
	max := entries[0]
	for _, e := range entries[1:] {
		if e.idx > max.idx {
			max = e
		}
	}
	return max, true
}

// isLossMarker reports whether payload is a synthetic TransportLoss record
// inserted by AppendLoss/appendLossLocked. Discriminates by the fixed
// LossMarkerSentinel prefix; ordinary records carry an arbitrary protobuf
// payload after their seq/gen framing, so the sentinel never collides.
//
// All scan paths (recover, segmentHighSeq, dropOldestLocked) MUST call this
// before parseSeqGen — the sentinel's first 8 bytes ("\x00WTPLOSS") would
// otherwise decode as seq ≈ 0x0057545050... which is a real-looking but
// utterly bogus high-watermark, defeating MarkAcked GC.
func isLossMarker(payload []byte) bool {
	return len(payload) >= len(LossMarkerSentinel) &&
		string(payload[:len(LossMarkerSentinel)]) == LossMarkerSentinel
}

func (w *WAL) recover() error {
	dirEntries, err := os.ReadDir(w.segDir)
	if err != nil {
		return fmt.Errorf("readdir segments: %w", err)
	}
	var sealed, inProgress []segmentEntry
	for _, e := range dirEntries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		idx, ok := parseSegmentIndex(name)
		if !ok {
			continue
		}
		switch {
		case strings.HasSuffix(name, inprogressSuffix):
			inProgress = append(inProgress, segmentEntry{name: name, idx: idx})
		case strings.HasSuffix(name, sealedSuffix):
			sealed = append(sealed, segmentEntry{name: name, idx: idx})
		}
	}
	// Sort by numeric index for deterministic processing (currently only the
	// "compute totalBytes" loop walks every entry; the live-segment picks
	// below use pickMaxByIndex, not the sort order).
	sort.Slice(sealed, func(i, j int) bool { return sealed[i].idx < sealed[j].idx })
	sort.Slice(inProgress, func(i, j int) bool { return inProgress[i].idx < inProgress[j].idx })

	// Rebuild high-watermark (the segment file index, not the record seq) by
	// taking the numeric maximum across both sealed and inProgress.
	maxIdx := uint64(0)
	if e, ok := pickMaxByIndex(sealed); ok && e.idx >= maxIdx {
		maxIdx = e.idx
	}
	if e, ok := pickMaxByIndex(inProgress); ok && e.idx >= maxIdx {
		maxIdx = e.idx
	}
	w.nextIndex = maxIdx + 1

	// Scan the live (or last sealed) segment for the highest seq/gen seen.
	// scanForRecovery returns the offset of the first byte AFTER the last
	// known-good record, so a corrupt or truncated tail can be truncated
	// before we reopen the file for append. Returning the offset (and not
	// just the high-watermark) is what closes the "appending after a
	// corrupt tail" hole that recovery used to leave open.
	scanForRecovery := func(path string) (lastGood int64, scanErr error) {
		f, err := os.Open(path)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		hdr, err := ReadSegmentHeader(f)
		if err != nil {
			return 0, err
		}
		// Seed the high-water generation from the header so an empty
		// segment still updates highGen. Real records will overwrite
		// these as the loop progresses.
		w.highGen = hdr.Generation
		// After reading the header, the cursor is at SegmentHeaderSize.
		// Track the offset of the first byte past the last successfully
		// decoded record so the caller can truncate any garbage tail.
		lastGood = int64(SegmentHeaderSize)
		for {
			payload, err := ReadRecord(f, w.maxRec)
			// Recovery treats a clean EOF, a truncated tail
			// (io.ErrUnexpectedEOF), a CRC mismatch, and a
			// structurally corrupt frame header (ErrCorruptFrame)
			// as the same "stop scanning" signal. The framing
			// layer wraps the underlying io errors with %w, so use
			// errors.Is so wrapping doesn't break the recovery loop.
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
				errors.Is(err, ErrCRCMismatch) || errors.Is(err, ErrCorruptFrame) {
				return lastGood, nil
			}
			if err != nil {
				return lastGood, err
			}
			// Only advance lastGood after we have actually decoded
			// a record; this is the offset at which the next
			// record would begin.
			off, err := f.Seek(0, io.SeekCurrent)
			if err != nil {
				return lastGood, err
			}
			lastGood = off
			// Loss markers carry the LossMarkerSentinel prefix instead
			// of an encodeSeqGenFrame, so feeding their bytes to
			// parseSeqGen would yield a junk seq (the sentinel bytes
			// decode as ~0x0057545050... = a huge number) and corrupt
			// the recovered high-watermark. Skip them here — they do
			// not advance the user-record stream.
			if isLossMarker(payload) {
				continue
			}
			if seq, gen, ok := parseSeqGen(payload); ok {
				w.highSeq = seq
				w.highGen = gen
			}
		}
	}

	// truncateLiveSegment chops the .INPROGRESS file at lastGood. Without
	// this, a recovered corrupt or truncated tail stays on disk; the next
	// Append writes after the bad bytes, and a future recovery scan stops
	// at the same bad tail — never reaching the newly appended records.
	truncateLiveSegment := func(path string, lastGood int64) error {
		f, err := os.OpenFile(path, os.O_RDWR, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return err
		}
		if st.Size() == lastGood {
			return nil
		}
		if err := f.Truncate(lastGood); err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			return err
		}
		// Sync the parent directory too so the size change is durable
		// across crashes (the segment dir uses the cross-platform
		// fsync-parent-dir helper used elsewhere in this package).
		return syncDir(filepath.Dir(path))
	}

	if e, ok := pickMaxByIndex(inProgress); ok {
		// Reopen for append. Scan first to seed high-watermark, truncate
		// any corrupt tail, then reopen the writer at EOF.
		path := filepath.Join(w.segDir, e.name)
		lastGood, err := scanForRecovery(path)
		if err != nil {
			return err
		}
		if err := truncateLiveSegment(path, lastGood); err != nil {
			return fmt.Errorf("truncate live segment: %w", err)
		}
		seg, err := ReopenSegment(path, w.maxRec)
		if err != nil {
			return err
		}
		w.current = seg
		// Use the existing index, not a fresh one.
		w.nextIndex = seg.Index() + 1
	} else if e, ok := pickMaxByIndex(sealed); ok {
		// Last segment is sealed; scan it for high-watermark only. A
		// sealed segment with a corrupt tail is a deeper inconsistency
		// — we cannot rewrite a sealed file from inside recovery — but
		// at least the high-watermark is bounded by the last good
		// record so future generations don't reuse a seq.
		path := filepath.Join(w.segDir, e.name)
		if _, err := scanForRecovery(path); err != nil {
			return err
		}
	}

	// Compute total bytes for overflow tracking AFTER any truncation, so
	// the byte budget reflects the post-recovery on-disk size.
	for _, e := range sealed {
		st, err := os.Stat(filepath.Join(w.segDir, e.name))
		if err != nil {
			return err
		}
		w.totalBytes += st.Size()
	}
	for _, e := range inProgress {
		st, err := os.Stat(filepath.Join(w.segDir, e.name))
		if err != nil {
			return err
		}
		w.totalBytes += st.Size()
	}
	return nil
}

// HighWatermark returns the highest sequence number the WAL has durably
// recorded, across both sealed segments and the live .INPROGRESS file. The
// value is the seq value itself (e.g. 4 after appending seqs 0..4), not a
// count.
func (w *WAL) HighWatermark() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.highSeq
}

// HighGeneration returns the generation of the most recently appended record.
func (w *WAL) HighGeneration() uint32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.highGen
}

// failAmbiguousLocked latches the WAL into a fatal state and returns an
// AppendError classified as FailureAmbiguous. Callers MUST hold w.mu. After
// this call, every subsequent Append fails fast with a clean ErrFatal-wrapped
// error rather than running against the partially-mutated segment — that's
// what closes the "compound corruption" hole the previous code had open.
func (w *WAL) failAmbiguousLocked(op string, err error) error {
	if w.fatalErr == nil {
		w.fatalErr = err
	}
	return &AppendError{Class: FailureAmbiguous, Op: op, Err: err}
}

// Append writes a record with the given (seq, gen) and payload. See spec
// §"Append — clean vs ambiguous failure classification" for the failure
// taxonomy.
//
// The caller (WTP Store.AppendEvent) MUST follow this with audit.SinkChain.Commit
// on success, or audit.SinkChain.Fatal on ambiguous failure.
func (w *WAL) Append(seq int64, gen uint32, payload []byte) (AppendResult, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return AppendResult{}, &AppendError{Class: FailureClean, Op: "append", Err: ErrClosed}
	}
	// Latched fatal: any prior ambiguous failure must prevent further
	// appends so partial mutations don't compound. Surface as a clean
	// failure (no I/O attempted on this call) wrapping ErrFatal so the
	// caller's transactional pattern can detect the latch via errors.Is.
	if w.fatalErr != nil {
		return AppendResult{}, &AppendError{
			Class: FailureClean,
			Op:    "append",
			Err:   fmt.Errorf("%w: %v", ErrFatal, w.fatalErr),
		}
	}
	// The on-disk per-record cost is 8 (frame header) + 12 (seq/gen prefix)
	// + len(payload). Reject up-front if even a fresh segment couldn't fit
	// it after the 16-byte segment header; this is a clean failure because
	// no I/O has been attempted yet.
	if int64(recordOverhead+len(payload)) > w.opts.SegmentSize-int64(SegmentHeaderSize) {
		return AppendResult{}, &AppendError{Class: FailureClean, Op: "append", Err: fmt.Errorf("payload %d exceeds segment budget", len(payload))}
	}

	// Overflow reclamation, in two phases:
	//
	//  1. Drop sealed segments fully covered by the ack watermark. NO
	//     TransportLoss marker is emitted for these — the receiver
	//     already has those records, so injecting a marker would force
	//     it to spuriously surface a gap on replay.
	//
	//  2. If still over budget, fall back to dropping the oldest sealed
	//     segment unconditionally and emit a TransportLoss marker for
	//     any unacked records it carried. Loop until under budget OR
	//     no more sealed segments remain (in which case we accept the
	//     overage for one record).
	//
	// Both phases must fire BEFORE the segment-full roll below so we
	// never seal+open a new segment that immediately pushes us past
	// the cap.
	if w.totalBytes+int64(w.opts.SegmentSize) > w.opts.MaxTotalBytes {
		if _, err := w.gcAckedLocked(); err != nil {
			return AppendResult{}, w.failAmbiguousLocked("overflow-gc-acked", err)
		}
		for w.totalBytes+int64(w.opts.SegmentSize) > w.opts.MaxTotalBytes {
			loss, dropped, hasUserRange, err := w.dropOldestLocked()
			if err != nil {
				return AppendResult{}, w.failAmbiguousLocked("overflow-gc", err)
			}
			if !dropped {
				// Nothing left to drop; proceed and accept the
				// overage. The dropped flag is the source of truth
				// here — we MUST NOT use ToSequence==0 as a
				// "nothing dropped" sentinel because a single-record
				// segment at seq=0 is a legitimate drop with
				// ToSequence==0.
				break
			}
			if !hasUserRange {
				// Dropped segment held only loss markers (or was
				// otherwise empty of user records). The file is
				// gone, but no additional marker is needed —
				// emitting one would manufacture a fake gap. Loop
				// and try the next sealed file.
				continue
			}
			// dropOldestLocked may have removed the oldest sealed
			// segment, but the live (.INPROGRESS) segment is excluded
			// from the sealed set, so w.current remains valid. Open
			// a fresh segment if there isn't one yet (recover-from-
			// empty case).
			if w.current == nil {
				seg, err := w.openNewSegmentLocked(gen, FlagGenInit)
				if err != nil {
					return AppendResult{}, w.failAmbiguousLocked("overflow-open", err)
				}
				w.current = seg
			}
			if err := w.appendLossLocked(loss); err != nil {
				return AppendResult{}, w.failAmbiguousLocked("overflow-loss", err)
			}
		}
	}

	rolled := false
	// Generation roll: seal current segment, open a new one with the new gen.
	// This is the ONLY place that sets rolled=true. The fresh-WAL "first
	// record opens a segment" path below intentionally leaves rolled=false
	// so the very first Append doesn't claim a generation roll occurred.
	if w.current != nil && w.current.Generation() != gen {
		if err := w.sealCurrentLocked(); err != nil {
			return AppendResult{}, w.failAmbiguousLocked("seal-on-gen-roll", err)
		}
		seg, err := w.openNewSegmentLocked(gen, FlagGenInit)
		if err != nil {
			return AppendResult{}, w.failAmbiguousLocked("open-on-gen-roll", err)
		}
		w.current = seg
		rolled = true
	}
	// Open the very first segment (fresh WAL or recovery left no live
	// segment). Mark with FlagGenInit since any first segment IS a new
	// generation, but do NOT set rolled — the boundary semantics only
	// apply when an existing segment was sealed for a generation change.
	if w.current == nil {
		seg, err := w.openNewSegmentLocked(gen, FlagGenInit)
		if err != nil {
			return AppendResult{}, w.failAmbiguousLocked("open-first", err)
		}
		w.current = seg
	}
	// Segment full → roll within the same generation. No FlagGenInit on
	// the new segment because the generation is unchanged.
	if w.current.Bytes()+int64(recordOverhead+len(payload)) > w.opts.SegmentSize {
		if err := w.sealCurrentLocked(); err != nil {
			return AppendResult{}, w.failAmbiguousLocked("seal-on-full", err)
		}
		seg, err := w.openNewSegmentLocked(gen, 0)
		if err != nil {
			return AppendResult{}, w.failAmbiguousLocked("open-on-full", err)
		}
		w.current = seg
	}

	// The payload encodes its own (seq, gen) for recovery. Prepend a small
	// header here so we can recover seq/gen on replay without parsing the
	// protobuf payload.
	framed := encodeSeqGenFrame(seq, gen, payload)

	if err := w.current.WriteRecord(framed); err != nil {
		return AppendResult{}, w.failAmbiguousLocked("write-record", err)
	}
	if w.opts.SyncMode == SyncImmediate {
		if err := w.current.Sync(); err != nil {
			return AppendResult{}, w.failAmbiguousLocked("sync", err)
		}
	}

	w.highSeq = uint64(seq)
	w.highGen = gen
	// totalBytes accounting: framed already includes the 12-byte seq/gen
	// prefix; the framing layer adds the 8-byte frame header on top.
	w.totalBytes += int64(8 + len(framed))
	return AppendResult{GenerationRolled: rolled}, nil
}

func (w *WAL) sealCurrentLocked() error {
	if w.current == nil {
		return nil
	}
	if _, err := w.current.Seal(); err != nil {
		return err
	}
	w.current = nil
	return nil
}

func (w *WAL) openNewSegmentLocked(gen uint32, flags uint16) (*Segment, error) {
	idx := w.nextIndex
	w.nextIndex++
	return OpenSegment(w.segDir, idx, SegmentHeader{Version: SegmentVersion, Flags: flags, Generation: gen}, w.maxRec)
}

// Close seals the live segment (if any) without removing INPROGRESS — instead
// flushes and closes for clean reopen. The next Open will reopen the
// .INPROGRESS file.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if w.current != nil {
		if err := w.current.Close(); err != nil {
			return err
		}
		w.current = nil
	}
	return nil
}

// encodeSeqGenFrame prepends 12 bytes of (seq:int64 BE, gen:uint32 BE) to
// payload so a recovery scan can read seq+gen without parsing the protobuf.
func encodeSeqGenFrame(seq int64, gen uint32, payload []byte) []byte {
	out := make([]byte, 12+len(payload))
	for i := 0; i < 8; i++ {
		out[7-i] = byte(seq >> (8 * i))
	}
	for i := 0; i < 4; i++ {
		out[11-i] = byte(gen >> (8 * i))
	}
	copy(out[12:], payload)
	return out
}

// parseSeqGen decodes the 12-byte (seq:uint64 BE, gen:uint32 BE) prefix
// emitted by encodeSeqGenFrame. The seq is returned as uint64 because the
// high-watermark fields are uint64; encodeSeqGenFrame always stores
// non-negative seq values, so the bit pattern is identical.
func parseSeqGen(framed []byte) (uint64, uint32, bool) {
	if len(framed) < 12 {
		return 0, 0, false
	}
	var seq uint64
	for i := 0; i < 8; i++ {
		seq |= uint64(framed[i]) << (8 * (7 - i))
	}
	var gen uint32
	for i := 0; i < 4; i++ {
		gen |= uint32(framed[8+i]) << (8 * (3 - i))
	}
	return seq, gen, true
}

// LossMarkerSentinel is a fixed byte string embedded in the framed payload of
// a synthetic TransportLoss record. Used by recovery and tests to identify
// loss markers without parsing the protobuf payload (which carries seq=0,
// gen=N for a marker — sentinels avoid ambiguity).
const LossMarkerSentinel = "\x00WTPLOSS\x00"

// LossRecord describes a synthetic TransportLoss inserted into the WAL stream.
type LossRecord struct {
	FromSequence uint64
	ToSequence   uint64
	Generation   uint32
	Reason       string // "overflow" | "crc_corruption"
}

// AppendLoss writes a synthetic TransportLoss record into the WAL stream so
// the transport's reader observes the gap inline. Always fsync'd. Used by the
// overflow path and the CRC-corruption recovery path.
//
// Respects the closed and latched-fatal contracts established in Task 12: a
// closed WAL returns FailureClean ErrClosed; a previously-latched fatal
// returns a clean ErrFatal-wrapped error without attempting I/O. Any I/O
// failure inside the lock is classified as ambiguous via failAmbiguousLocked
// so the WAL latches into the fatal state.
func (w *WAL) AppendLoss(loss LossRecord) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return &AppendError{Class: FailureClean, Op: "append-loss", Err: ErrClosed}
	}
	if w.fatalErr != nil {
		return &AppendError{
			Class: FailureClean,
			Op:    "append-loss",
			Err:   fmt.Errorf("%w: %v", ErrFatal, w.fatalErr),
		}
	}
	if w.current == nil {
		seg, err := w.openNewSegmentLocked(loss.Generation, FlagGenInit)
		if err != nil {
			return w.failAmbiguousLocked("open-loss-segment", err)
		}
		w.current = seg
	}
	payload := encodeLossPayload(loss)
	if err := w.current.WriteRecord(payload); err != nil {
		return w.failAmbiguousLocked("write-loss", err)
	}
	if err := w.current.Sync(); err != nil {
		return w.failAmbiguousLocked("sync-loss", err)
	}
	w.totalBytes += int64(8 + len(payload))
	return nil
}

// encodeLossPayload encodes a LossRecord into the on-disk loss-marker layout:
//
//	offset  size  field
//	0       10    LossMarkerSentinel
//	10      8     FromSequence (uint64 BE)
//	18      8     ToSequence   (uint64 BE)
//	26      4     Generation   (uint32 BE)
//	30      N     Reason       (UTF-8, no terminator)
//
// Total length is 30 + len(reason) bytes. The Reason has no length prefix
// because the framing layer's record length implicitly bounds it.
func encodeLossPayload(l LossRecord) []byte {
	out := make([]byte, 10+8+8+4+len(l.Reason))
	copy(out[0:10], LossMarkerSentinel)
	for i := 0; i < 8; i++ {
		out[17-i] = byte(l.FromSequence >> (8 * i))
	}
	for i := 0; i < 8; i++ {
		out[25-i] = byte(l.ToSequence >> (8 * i))
	}
	for i := 0; i < 4; i++ {
		out[29-i] = byte(l.Generation >> (8 * i))
	}
	copy(out[30:], l.Reason)
	return out
}

// MarkAcked records the highest-acked sequence in meta.json and GCs sealed
// segments whose highest sequence is <= seq. The live (.INPROGRESS) segment
// is never removed.
//
// Returns nil even if no segments were eligible for GC. Callers do not need
// to filter on whether progress was made.
//
// Filename ordering uses the numeric segment index (parseSegmentIndex), not
// lexicographic order on filenames — once an index crosses 10^10 the digit
// count changes and lex order silently picks the wrong "oldest" file. The
// current per-segment scan via segmentHighSeq is the safety check that
// prevents us from removing a segment whose tail records are still unacked.
func (w *WAL) MarkAcked(seq uint64) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	// Persist the new ack watermark and mirror it on the in-memory WAL so
	// the overflow path's silent-GC pass (gcAckedLocked) can consult it
	// without a meta.json read on every Append. Use the maximum to make
	// MarkAcked monotonic — if a caller passes an older seq (replay,
	// out-of-order ack), we hold the high-water value already on disk.
	if seq > w.ackHighSeq {
		w.ackHighSeq = seq
	}
	if err := WriteMeta(w.opts.Dir, Meta{
		AckHighWatermarkSeq: w.ackHighSeq,
		AckHighWatermarkGen: w.highGen,
	}); err != nil {
		return err
	}
	entries, err := os.ReadDir(w.segDir)
	if err != nil {
		return err
	}
	var sealed []segmentEntry
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, sealedSuffix) || strings.HasSuffix(name, inprogressSuffix) {
			continue
		}
		idx, ok := parseSegmentIndex(name)
		if !ok {
			continue
		}
		sealed = append(sealed, segmentEntry{name: name, idx: idx})
	}
	sort.Slice(sealed, func(i, j int) bool { return sealed[i].idx < sealed[j].idx })
	removed := false
	for _, e := range sealed {
		path := filepath.Join(w.segDir, e.name)
		hi, err := segmentHighSeq(path, w.maxRec)
		if err != nil {
			continue
		}
		if hi <= w.ackHighSeq {
			st, _ := os.Stat(path)
			if err := os.Remove(path); err == nil {
				if st != nil {
					w.totalBytes -= st.Size()
				}
				removed = true
			}
		}
	}
	if removed {
		if err := syncDir(w.segDir); err != nil {
			return err
		}
	}
	return nil
}

// segmentHighSeq returns the highest sequence number recorded in the segment
// at path. A scan is required because the WAL does not maintain a per-segment
// index. Used by MarkAcked GC and by overflow GC to identify safe-to-drop
// segments.
//
// Errors during the read loop (truncation, CRC mismatch, corrupt frames)
// are treated as "stop scanning" so a partially-written segment still
// reports its highest known-good seq rather than failing outright; the
// caller decides whether that's safe to act on.
func segmentHighSeq(path string, maxPayload int) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if _, err := ReadSegmentHeader(f); err != nil {
		return 0, err
	}
	var hi uint64
	for {
		payload, err := ReadRecord(f, maxPayload)
		if err == io.EOF {
			return hi, nil
		}
		if err != nil {
			return hi, nil
		}
		// Loss markers are sentinel-framed, not seq/gen-framed; feeding
		// their bytes to parseSeqGen would synthesize a junk seq from
		// the LossMarkerSentinel prefix and prevent MarkAcked from ever
		// freeing this segment. Skip them — they do not represent a
		// user record and so contribute nothing to the high-watermark.
		if isLossMarker(payload) {
			continue
		}
		if seq, _, ok := parseSeqGen(payload); ok {
			if seq > hi {
				hi = seq
			}
		}
	}
}

// appendLossLocked writes a TransportLoss marker into the live segment and
// fsyncs it. Caller MUST hold w.mu and MUST have ensured w.current != nil.
// Used by the overflow path; AppendLoss is the public entry point that
// handles the closed/fatal/no-segment preconditions.
func (w *WAL) appendLossLocked(loss LossRecord) error {
	payload := encodeLossPayload(loss)
	if err := w.current.WriteRecord(payload); err != nil {
		return err
	}
	if err := w.current.Sync(); err != nil {
		return err
	}
	w.totalBytes += int64(8 + len(payload))
	return nil
}

// dropOldestLocked drops the oldest sealed segment from disk. Returns:
//
//   - loss: the (FromSequence, ToSequence, Generation) range of user records
//     that were in the dropped segment. Zero values are valid when
//     hasUserRange is false (e.g. the segment held only a loss marker, or
//     the file was unreadable past its header).
//   - dropped: true if a file was actually removed; false if no sealed
//     segments existed to drop. The caller MUST consult this flag, NOT
//     loss.ToSequence, to decide whether reclamation made progress —
//     ToSequence==0 is a legitimate range end (a single-record segment at
//     seq=0) and conflating it with "nothing dropped" silently swallows
//     real reclamation work.
//   - hasUserRange: true if loss covers at least one real (non-loss-marker)
//     record, i.e. the caller should emit a TransportLoss marker. False
//     means the dropped segment was empty or held only loss markers — no
//     marker needed; loop and try again on the next sealed file.
//   - err: any I/O error encountered while removing the file.
//
// The live (.INPROGRESS) segment is excluded; we never drop the file we're
// writing to. Sort order is numeric (parsed segment index) so digit-count
// transitions past idx=10^10 don't silently misorder lex-sorted names.
//
// Caller MUST hold w.mu.
func (w *WAL) dropOldestLocked() (loss LossRecord, dropped bool, hasUserRange bool, err error) {
	entries, readErr := os.ReadDir(w.segDir)
	if readErr != nil {
		return LossRecord{}, false, false, readErr
	}
	var sealed []segmentEntry
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, sealedSuffix) || strings.HasSuffix(name, inprogressSuffix) {
			continue
		}
		idx, ok := parseSegmentIndex(name)
		if !ok {
			continue
		}
		sealed = append(sealed, segmentEntry{name: name, idx: idx})
	}
	if len(sealed) == 0 {
		return LossRecord{}, false, false, nil
	}
	sort.Slice(sealed, func(i, j int) bool { return sealed[i].idx < sealed[j].idx })
	oldest := sealed[0].name
	path := filepath.Join(w.segDir, oldest)
	f, openErr := os.Open(path)
	if openErr != nil {
		return LossRecord{}, false, false, openErr
	}
	hdr, _ := ReadSegmentHeader(f)
	var fromSeq, toSeq uint64
	first := true
	for {
		payload, readRecErr := ReadRecord(f, w.maxRec)
		if readRecErr == io.EOF || readRecErr != nil {
			break
		}
		// Skip loss markers; they do not represent user records and so
		// must not contribute to the (fromSeq, toSeq) range carried by
		// the new TransportLoss marker emitted for THIS drop. Without
		// this, parseSeqGen would synthesize a junk seq from the
		// LossMarkerSentinel prefix and inject it into the range.
		if isLossMarker(payload) {
			continue
		}
		if seq, _, ok := parseSeqGen(payload); ok {
			if first {
				fromSeq = seq
				first = false
			}
			toSeq = seq
		}
	}
	f.Close()
	st, _ := os.Stat(path)
	if removeErr := os.Remove(path); removeErr != nil {
		return LossRecord{}, false, false, removeErr
	}
	if st != nil {
		w.totalBytes -= st.Size()
	}
	if syncErr := syncDir(w.segDir); syncErr != nil {
		// File is gone but the directory entry may not be durable.
		// Surface as ambiguous via the caller's failAmbiguousLocked.
		return LossRecord{}, true, false, syncErr
	}
	// hasUserRange == !first: we observed at least one real record.
	hasUserRange = !first
	return LossRecord{FromSequence: fromSeq, ToSequence: toSeq, Generation: hdr.Generation, Reason: "overflow"}, true, hasUserRange, nil
}

// gcAckedLocked removes every sealed segment whose highest user-record
// sequence is <= w.ackHighSeq. No TransportLoss marker is emitted for these
// drops because the receiver already has the data. Stops at the first
// segment that contains any unacked record (segments are processed in
// numeric idx order, which equals seq order since seqs are monotonic across
// generations within a single WAL).
//
// Returns the number of segments removed. Errors during a single segment's
// scan or removal are surfaced to the caller; ack-driven GC is best-effort
// and any I/O failure inside the lock should latch the WAL via
// failAmbiguousLocked at the call site.
//
// Caller MUST hold w.mu.
func (w *WAL) gcAckedLocked() (int, error) {
	entries, err := os.ReadDir(w.segDir)
	if err != nil {
		return 0, err
	}
	var sealed []segmentEntry
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, sealedSuffix) || strings.HasSuffix(name, inprogressSuffix) {
			continue
		}
		idx, ok := parseSegmentIndex(name)
		if !ok {
			continue
		}
		sealed = append(sealed, segmentEntry{name: name, idx: idx})
	}
	if len(sealed) == 0 {
		return 0, nil
	}
	sort.Slice(sealed, func(i, j int) bool { return sealed[i].idx < sealed[j].idx })
	removed := 0
	for _, e := range sealed {
		path := filepath.Join(w.segDir, e.name)
		hi, scanErr := segmentHighSeq(path, w.maxRec)
		if scanErr != nil {
			// segmentHighSeq currently swallows scan errors and only
			// returns errors from open/header read. Treat as fatal:
			// we cannot decide safely whether to drop this file.
			return removed, scanErr
		}
		if hi > w.ackHighSeq {
			// Numeric idx order matches seq order, so the first
			// segment with unacked content guarantees no later
			// segment is fully covered either. Early-break.
			break
		}
		st, _ := os.Stat(path)
		if rmErr := os.Remove(path); rmErr != nil {
			return removed, rmErr
		}
		if st != nil {
			w.totalBytes -= st.Size()
		}
		removed++
	}
	if removed > 0 {
		if err := syncDir(w.segDir); err != nil {
			return removed, err
		}
	}
	return removed, nil
}
