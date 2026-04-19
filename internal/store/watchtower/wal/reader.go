package wal

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// RecordKind discriminates the kinds of records the Reader can surface.
type RecordKind int

const (
	// RecordData is an ordinary user record carrying the seq/gen frame plus
	// the caller's payload (with the 12-byte seq/gen prefix already stripped).
	RecordData RecordKind = iota
	// RecordLoss is a synthetic TransportLoss notice — either a marker the
	// WAL itself appended via AppendLoss/overflow GC, or one the Reader
	// synthesized when ReadRecord returned ErrCRCMismatch on a sealed
	// segment. Loss carries the affected (FromSequence, ToSequence,
	// Generation) range.
	RecordLoss
	// RecordGenerationRoll is reserved for future use; the transport
	// currently detects rolls by comparing Record.Generation values across
	// consecutive RecordData entries, so the Reader does not emit these.
	RecordGenerationRoll
)

// Record is one item surfaced by Reader.Next. For RecordData, Sequence and
// Generation come from the framed seq/gen prefix and Payload is the bytes
// after that prefix. For RecordLoss, Loss carries the decoded LossRecord
// (Sequence/Payload are unset; Generation mirrors Loss.Generation for ease of
// inspection).
type Record struct {
	Kind       RecordKind
	Sequence   uint64
	Generation uint32
	Payload    []byte
	Loss       LossRecord
}

// ErrReaderClosed is returned by Reader.Next after Close (or the WAL itself
// closing the reader).
var ErrReaderClosed = errors.New("wal: reader closed")

// Reader streams records from the WAL in segment-index order. Closing the WAL
// drops the reader's open file handle automatically; subsequent Next calls
// return ErrReaderClosed.
type Reader struct {
	w      *WAL
	notify chan struct{}

	mu       sync.Mutex
	segments []segmentEntry // remaining segments in numeric-index order
	current  *os.File
	curHdr   SegmentHeader
	curIdx   uint64 // numeric segment index of `current`; used to detect rollover from .INPROGRESS to .seg.
	curLive  bool   // true if `current` is an .INPROGRESS file (re-tail on EOF)
	// nextScanIdx is the smallest segment index NOT yet enqueued in
	// `segments` from a previous scan. When `segments` empties and `current`
	// is nil, Next re-reads the directory and adds segments with idx >=
	// nextScanIdx, so appends made after NewReader are picked up without a
	// reopen.
	nextScanIdx uint64
	// lastGoodSeq is the highest user sequence successfully decoded so far
	// within the CURRENT generation. It is carried across segment boundaries
	// within a generation (seqs continue monotonically across segments
	// inside one generation) and reset to zero only on a generation change.
	// Used to anchor the FromSequence of a loss record synthesized from
	// ErrCRCMismatch.
	lastGoodSeq uint64
	// lastGoodGen is the generation of the last successfully decoded user
	// record (or, before any decode, of the most recently opened segment
	// header). Compared to a freshly opened segment's header to decide
	// whether to reset lastGoodSeq.
	lastGoodGen    uint32
	lastGoodGenSet bool // true once lastGoodGen reflects a real seen generation.
	// nextSeq is the lowest user sequence the Reader will surface; records
	// with Sequence < nextSeq are dropped from RecordData yields. Set by
	// NewReader from start+1 so callers express an "exclusive" cursor with
	// the same semantics as ack watermarks. Loss records are NOT filtered
	// by nextSeq — the transport must propagate every loss notice.
	nextSeq uint64
	// lastEmittedSeq is the highest user sequence successfully returned to
	// a caller so far, monotonic across the Reader's lifetime (does NOT
	// reset on a generation change, unlike lastGoodSeq). Surfaced via
	// LastSequence() so the Replayer can detect the catch-up condition
	// (TryNext returned ok=false AND LastSequence >= tailSeq).
	lastEmittedSeq uint64
	closed         bool
}

// NewReader returns a Reader that surfaces RecordData entries with sequence
// >= start (i.e. the first record returned has Sequence == start or later).
// Pass start=0 to receive every user record from the beginning of the
// on-disk stream — the same behaviour Task 14 shipped. RecordLoss entries
// are NOT filtered by start; the transport must propagate every loss notice
// regardless of the caller's cursor.
//
// The on-disk stream is still walked in segment-index order; records that
// predate start are read off the disk and dropped on the floor by Next /
// TryNext. This keeps the API simple at the cost of skipping work — fast-
// forward by segment-index hint is left as a future optimization.
//
// Callers replaying after an ack pass start = ackHighSeq + 1 to skip the
// already-acknowledged tail (Task 16's Replayer enforces this idiom).
func (w *WAL) NewReader(start uint64) (*Reader, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil, ErrClosed
	}
	r := &Reader{w: w, notify: make(chan struct{}, 1), nextSeq: start}
	if err := r.rescanLocked(); err != nil {
		return nil, err
	}
	w.readers = append(w.readers, r)
	return r, nil
}

// rescanLocked refreshes the segments queue from disk, picking up any segment
// files added since the last scan (or since NewReader if this is the first
// pass). Caller MUST hold r.mu.
//
// We track nextScanIdx so a re-scan after segments emptied does not
// re-enqueue files we already streamed: a sealed segment that was previously
// the live INPROGRESS keeps the same numeric index, so an idx < nextScanIdx
// check excludes it cleanly.
func (r *Reader) rescanLocked() error {
	entries, err := os.ReadDir(r.w.segDir)
	if err != nil {
		return err
	}
	var found []segmentEntry
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, sealedSuffix) && !strings.HasSuffix(name, inprogressSuffix) {
			continue
		}
		idx, ok := parseSegmentIndex(name)
		if !ok {
			continue
		}
		if idx < r.nextScanIdx {
			continue
		}
		found = append(found, segmentEntry{name: name, idx: idx})
	}
	// Numeric sort — lexicographic order silently breaks once segment indices
	// cross a digit-count boundary (10^10), and parseSegmentIndex already
	// handed us the parsed integer.
	sort.Slice(found, func(i, j int) bool { return found[i].idx < found[j].idx })
	r.segments = append(r.segments, found...)
	if n := len(found); n > 0 {
		r.nextScanIdx = found[n-1].idx + 1
	}
	return nil
}

// Notify returns a channel that receives a wake-up signal each time Append or
// AppendLoss persists a new record. The channel is single-buffered and
// coalescing — multiple appends between Next calls collapse to one signal,
// and the caller MUST drain Next() to io.EOF before waiting on Notify again.
func (r *Reader) Notify() <-chan struct{} { return r.notify }

// maybeDemoteLiveLocked checks whether a segment opened as live (curLive=true)
// has since been sealed via a size or generation roll. Returns true if the
// segment was demoted (caller should fall through and re-attempt the read on
// the same handle to drain remaining bytes; the next EOF will be treated as a
// sealed-segment EOF). Caller MUST hold r.mu.
func (r *Reader) maybeDemoteLiveLocked() (bool, error) {
	if !r.curLive {
		return false, nil
	}
	entries, err := os.ReadDir(r.w.segDir)
	if err != nil {
		return false, err
	}
	var sealedSamePath, hasNewer bool
	for _, e := range entries {
		name := e.Name()
		idx, ok := parseSegmentIndex(name)
		if !ok {
			continue
		}
		if idx > r.curIdx {
			hasNewer = true
		}
		if idx == r.curIdx && strings.HasSuffix(name, sealedSuffix) && !strings.HasSuffix(name, inprogressSuffix) {
			sealedSamePath = true
		}
	}
	if !sealedSamePath && !hasNewer {
		return false, nil
	}
	// Segment is no longer live — flip the latch so the sealed-EOF path
	// drains the handle to real EOF and advances. Rescan so any newer
	// segments produced by the roll are queued.
	r.curLive = false
	if err := r.rescanLocked(); err != nil {
		return true, err
	}
	return true, nil
}

// Next returns the next available record. Returns io.EOF when the reader is
// caught up; the caller should wait on Notify and call Next again. Returns
// ErrReaderClosed if Close (or WAL.Close) has run.
func (r *Reader) Next() (Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return Record{}, ErrReaderClosed
	}
	rec, ok, err := r.nextLocked()
	if err != nil {
		return Record{}, err
	}
	if !ok {
		return Record{}, io.EOF
	}
	return rec, nil
}

// TryNext returns the next available record without blocking. ok=false means
// no record is currently available (the reader is caught up to the WAL tail
// or to an unsealed live segment) — unlike Next, it does NOT return io.EOF
// for this case. err is non-nil only on hard read failures (corrupt headers,
// unparseable seq/gen frames, etc.); ErrCRCMismatch is still surfaced as a
// RecordLoss with ok=true. Returns ErrReaderClosed if Close has run.
//
// Implementation note: TryNext and Next share the loop body via nextLocked.
// Do NOT duplicate the loop here — that path has accreted enough segment-
// rollover, GC-skip, rename-on-seal, and CRC-mismatch handling that two
// copies will drift.
func (r *Reader) TryNext() (Record, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return Record{}, false, ErrReaderClosed
	}
	return r.nextLocked()
}

// LastSequence returns the highest user sequence the Reader has surfaced via
// Next or TryNext so far. Monotonic across the Reader's lifetime — does NOT
// reset on a generation change, unlike the internal lastGoodSeq used for
// loss-anchor calculations. Zero before the first emission.
func (r *Reader) LastSequence() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastEmittedSeq
}

// WALHighWaterSequence returns the highest sequence ever appended to the
// underlying WAL at call time. Used by Replayer to capture an entry-time
// tail watermark.
func (r *Reader) WALHighWaterSequence() uint64 {
	r.w.mu.Lock()
	defer r.w.mu.Unlock()
	return r.w.highSeq
}

// nextLocked drives the segment-walk loop and returns one of:
//
//	(rec, true,  nil)  — a record was decoded
//	(_,   false, nil)  — caught up to tail (or live-segment EOF); no record
//	(_,   false, err)  — hard error (bad header, malformed frame, ...)
//
// Caller MUST hold r.mu.
func (r *Reader) nextLocked() (Record, bool, error) {
	for {
		if r.current == nil {
			if len(r.segments) == 0 {
				// Re-scan for any new segments produced by Append since
				// the last walk; if still empty, we are caught up.
				if err := r.rescanLocked(); err != nil {
					return Record{}, false, err
				}
				if len(r.segments) == 0 {
					return Record{}, false, nil
				}
			}
			next := r.segments[0]
			r.segments = r.segments[1:]
			path := filepath.Join(r.w.segDir, next.name)
			// openedLive tracks whether the file we actually opened is a
			// live .INPROGRESS — defaults to the queued name's suffix but
			// the sealed-twin probe below can flip it false if we end up
			// opening a renamed-since-snapshot .seg instead.
			openedLive := strings.HasSuffix(next.name, inprogressSuffix)
			f, err := os.Open(path)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					// ENOENT is ambiguous on an .INPROGRESS path: the
					// segment may have been (a) reclaimed by ack-driven
					// GC, or (b) sealed via rename to .seg between our
					// directory snapshot and this open. Case (b) means
					// the records are still on disk under the sealed
					// twin; silently skipping would drop them with no
					// loss marker (rename-on-seal is not a loss event).
					// So discriminate: probe the sealed twin first when
					// the queued name was .INPROGRESS, and only fall
					// through to skip if both files are gone (true GC).
					// A queued .seg can only disappear via GC.
					if strings.HasSuffix(next.name, inprogressSuffix) {
						sealedPath := filepath.Join(r.w.segDir, segmentName(next.idx))
						sf, sErr := os.Open(sealedPath)
						if sErr == nil {
							f = sf
							// We opened the sealed twin, not the live file.
							openedLive = false
							// Fall through to header read below.
						} else if errors.Is(sErr, fs.ErrNotExist) {
							continue
						} else {
							return Record{}, false, sErr
						}
					} else {
						continue
					}
				} else {
					return Record{}, false, err
				}
			}
			hdr, err := ReadSegmentHeader(f)
			if err != nil {
				_ = f.Close()
				return Record{}, false, err
			}
			r.current = f
			r.curHdr = hdr
			r.curIdx = next.idx
			r.curLive = openedLive
			// Carry lastGoodSeq across segment boundaries within the same
			// generation; reset only on a generation change. Seqs restart
			// at 0 on every generation roll, so a per-seq compare across
			// generations would be meaningless.
			if !r.lastGoodGenSet || hdr.Generation != r.lastGoodGen {
				r.lastGoodSeq = 0
				r.lastGoodGen = hdr.Generation
				r.lastGoodGenSet = true
			}
		}
		payload, err := ReadRecord(r.current, r.w.maxRec)
		if errors.Is(err, io.EOF) {
			if r.curLive {
				// Live segment may have been sealed by a roll since we
				// opened it; if so, demote and fall through to drain the
				// handle. Otherwise return "no record available" and let
				// the caller (Next: turn into io.EOF; TryNext: ok=false)
				// decide whether to block.
				demoted, derr := r.maybeDemoteLiveLocked()
				if derr != nil {
					return Record{}, false, derr
				}
				if !demoted {
					return Record{}, false, nil
				}
				continue
			}
			// Sealed segment: end-of-data is final. Close and advance.
			_ = r.current.Close()
			r.current = nil
			continue
		}
		if errors.Is(err, ErrCRCMismatch) {
			// Coarse-range loss. We know ≥1 record in this segment is
			// bad; we cannot cheaply distinguish "one bad record then
			// good ones" from "everything past here is bad" without a
			// full re-scan, so emit a single-record range anchored at
			// the next expected sequence and let the transport coarsen
			// on receive (TODO: Task 18 — refine via avg-record-size or
			// segment-end seek). The bad segment is closed and the
			// reader advances to the next on the next Next call. Note:
			// when no records have ever been read in this generation,
			// lastGoodSeq=0 yields FromSequence=1 — a known coarse
			// undercount that the transport refines on receive.
			from := r.lastGoodSeq + 1
			to := from
			_ = r.current.Close()
			r.current = nil
			return Record{
				Kind:       RecordLoss,
				Generation: r.curHdr.Generation,
				Loss: LossRecord{
					FromSequence: from,
					ToSequence:   to,
					Generation:   r.curHdr.Generation,
					Reason:       "crc_corruption",
				},
			}, true, nil
		}
		if err != nil {
			return Record{}, false, fmt.Errorf("reader next: %w", err)
		}
		// Synthetic loss marker emitted by AppendLoss/overflow GC?
		if isLossMarker(payload) {
			loss, ok := decodeLossPayload(payload)
			if !ok {
				return Record{}, false, fmt.Errorf("reader: malformed loss marker payload (len=%d)", len(payload))
			}
			// Loss markers are NOT subject to the nextSeq filter — every
			// loss notice MUST flow to the transport so the receiver can
			// surface a gap. Filtering by sequence here would silently
			// suppress notices for ranges that predate the cursor.
			return Record{Kind: RecordLoss, Generation: loss.Generation, Loss: loss}, true, nil
		}
		seq, gen, ok := parseSeqGen(payload)
		if !ok {
			return Record{}, false, fmt.Errorf("reader: malformed seq/gen frame (len=%d)", len(payload))
		}
		// Update lastGoodSeq/Gen even for sub-cursor records so the loss
		// anchor tracks correctly across a future CRC mismatch.
		r.lastGoodSeq = seq
		r.lastGoodGen = gen
		r.lastGoodGenSet = true
		if seq < r.nextSeq {
			// Caller asked for a cursor strictly past this seq. Drop on
			// the floor and continue the loop to the next record.
			continue
		}
		r.lastEmittedSeq = seq
		return Record{Kind: RecordData, Sequence: seq, Generation: gen, Payload: payload[12:]}, true, nil
	}
}

// Close releases this reader's file handle (if any) and removes it from the
// WAL's reader set so notifyReaders no longer wakes it. Idempotent — repeated
// calls return nil after the first.
func (r *Reader) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	var closeErr error
	if r.current != nil {
		closeErr = r.current.Close()
		r.current = nil
	}
	r.mu.Unlock()

	// Drop ourselves from the WAL's reader set so notifyReaders doesn't keep
	// trying to wake a closed reader. Take w.mu without holding r.mu to
	// preserve the lock order (callers of notifyReaders already hold w.mu;
	// holding r.mu here too would invert the order if WAL.Close ever called
	// into reader.Close).
	r.w.mu.Lock()
	for i, other := range r.w.readers {
		if other == r {
			r.w.readers = append(r.w.readers[:i], r.w.readers[i+1:]...)
			break
		}
	}
	r.w.mu.Unlock()
	return closeErr
}

// closeFromWALLocked is invoked by WAL.Close while holding w.mu. It marks the
// reader closed and releases the file handle. Caller MUST NOT remove the
// reader from w.readers — WAL.Close is iterating that slice already and will
// reset it.
func (r *Reader) closeFromWALLocked() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	if r.current != nil {
		_ = r.current.Close()
		r.current = nil
	}
}
