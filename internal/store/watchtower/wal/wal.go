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
