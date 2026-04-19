package wal

import (
	"errors"
	"fmt"
	"io"
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
	curLive  bool // true if `current` is an .INPROGRESS file (re-tail on EOF)
	// nextScanIdx is the smallest segment index NOT yet enqueued in
	// `segments` from a previous scan. When `segments` empties and `current`
	// is nil, Next re-reads the directory and adds segments with idx >=
	// nextScanIdx, so appends made after NewReader are picked up without a
	// reopen.
	nextScanIdx uint64
	// lastGoodSeq is the highest user sequence successfully decoded from the
	// CURRENT segment so far. Used to anchor the FromSequence of a loss
	// record synthesized from ErrCRCMismatch; a value of zero before the
	// first successful read in a segment means the loss range starts at
	// seq=1, deferring tighter refinement to the transport layer (Task 18+).
	lastGoodSeq uint64
	closed      bool
}

// NewReader returns a Reader that will surface records starting at the first
// record with sequence >= start. Records that predate start in the on-disk
// stream are still returned; the start parameter is reserved for a future
// fast-forward optimization (Task 16+) and is currently informational.
func (w *WAL) NewReader(start uint64) (*Reader, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil, ErrClosed
	}
	r := &Reader{w: w, notify: make(chan struct{}, 1)}
	if err := r.rescanLocked(); err != nil {
		return nil, err
	}
	w.readers = append(w.readers, r)
	_ = start // reserved for future fast-forward; see Task 16+.
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

// Next returns the next available record. Returns io.EOF when the reader is
// caught up; the caller should wait on Notify and call Next again. Returns
// ErrReaderClosed if Close (or WAL.Close) has run.
func (r *Reader) Next() (Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return Record{}, ErrReaderClosed
	}
	for {
		if r.current == nil {
			if len(r.segments) == 0 {
				// Re-scan for any new segments produced by Append since
				// the last walk; if still empty, we are caught up.
				if err := r.rescanLocked(); err != nil {
					return Record{}, err
				}
				if len(r.segments) == 0 {
					return Record{}, io.EOF
				}
			}
			next := r.segments[0]
			r.segments = r.segments[1:]
			path := filepath.Join(r.w.segDir, next.name)
			f, err := os.Open(path)
			if err != nil {
				return Record{}, err
			}
			hdr, err := ReadSegmentHeader(f)
			if err != nil {
				_ = f.Close()
				return Record{}, err
			}
			r.current = f
			r.curHdr = hdr
			r.curLive = strings.HasSuffix(next.name, inprogressSuffix)
			// New segment — reset the in-segment last-good cursor; the
			// loss-range for a fresh segment with no successful reads
			// starts from 0 (transport-side refinement is Task 18+).
			r.lastGoodSeq = 0
		}
		payload, err := ReadRecord(r.current, r.w.maxRec)
		if errors.Is(err, io.EOF) {
			if r.curLive {
				// Live segment: more bytes may arrive on a future
				// Append. Keep the handle open and surface EOF so the
				// caller can wait on Notify; the next Next call retries
				// ReadRecord against the same handle.
				return Record{}, io.EOF
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
			// reader advances to the next on the next Next call.
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
			}, nil
		}
		if err != nil {
			return Record{}, fmt.Errorf("reader next: %w", err)
		}
		// Synthetic loss marker emitted by AppendLoss/overflow GC?
		if isLossMarker(payload) {
			loss, ok := decodeLossPayload(payload)
			if !ok {
				return Record{}, fmt.Errorf("reader: malformed loss marker payload (len=%d)", len(payload))
			}
			return Record{Kind: RecordLoss, Generation: loss.Generation, Loss: loss}, nil
		}
		seq, gen, ok := parseSeqGen(payload)
		if !ok {
			return Record{}, fmt.Errorf("reader: malformed seq/gen frame (len=%d)", len(payload))
		}
		r.lastGoodSeq = seq
		return Record{Kind: RecordData, Sequence: seq, Generation: gen, Payload: payload[12:]}, nil
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
