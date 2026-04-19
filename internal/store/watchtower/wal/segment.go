package wal

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrSegmentClosed is returned by WriteRecord, Sync, and Seal when called
// after Close or Seal. Closing or sealing a segment is a one-way transition;
// further writes/syncs are a programming error but are reported as a sentinel
// rather than a panic so callers can recover gracefully.
var ErrSegmentClosed = errors.New("wal: segment closed")

// Segment represents one WAL segment file. The on-disk lifecycle is:
//
//	0000000042.seg.INPROGRESS   (live, append-only)
//	   ↓ Seal()
//	0000000042.seg              (sealed, read-only)
//
// Concurrency: NOT safe for concurrent use; the WAL serializes Append calls.
type Segment struct {
	dir            string
	index          uint64
	gen            uint32
	path           string
	file           *os.File
	writer         *bufio.Writer
	bytes          int64
	maxRecordBytes int
	closed         bool
}

const segmentExt = ".seg"
const inProgressSuffix = ".INPROGRESS"

// segmentName formats an index as a 10-digit zero-padded string. The padding
// keeps lexical sort = numeric sort up to ~10 billion segments.
func segmentName(index uint64) string {
	return fmt.Sprintf("%010d%s", index, segmentExt)
}

// validateMaxRecordBytes enforces the same (0, MaxFramedPayload] bound the
// framing layer uses, so we reject obviously-invalid configurations at
// segment-open time rather than waiting for the first WriteRecord call.
func validateMaxRecordBytes(maxRecordBytes int) error {
	if maxRecordBytes <= 0 {
		return fmt.Errorf("wal: maxRecordBytes must be > 0, got %d", maxRecordBytes)
	}
	if uint64(maxRecordBytes) > MaxFramedPayload {
		return fmt.Errorf("wal: maxRecordBytes %d exceeds protocol cap %d", maxRecordBytes, uint64(MaxFramedPayload))
	}
	return nil
}

// OpenSegment creates a new .INPROGRESS segment and writes its 16-byte header.
// The header is fsync'd so a crash mid-creation leaves either no segment or a
// segment whose header is durable. Spec §"Lifecycle".
//
// maxRecordBytes is forwarded to every WriteRecord call; it must be in
// (0, MaxFramedPayload]. Callers typically derive this from WAL.SegmentSize.
func OpenSegment(dir string, index uint64, hdr SegmentHeader, maxRecordBytes int) (*Segment, error) {
	if err := validateMaxRecordBytes(maxRecordBytes); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, segmentName(index)+inProgressSuffix)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open segment: %w", err)
	}
	w := bufio.NewWriter(f)
	if err := WriteSegmentHeader(w, hdr); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("flush segment header: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("fsync segment header: %w", err)
	}
	if err := syncDir(dir); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("fsync segments dir: %w", err)
	}
	return &Segment{
		dir:            dir,
		index:          index,
		gen:            hdr.Generation,
		path:           path,
		file:           f,
		writer:         w,
		bytes:          int64(SegmentHeaderSize),
		maxRecordBytes: maxRecordBytes,
	}, nil
}

// ReopenSegment reopens an existing .INPROGRESS segment for append. Used on
// startup recovery: scan segments dir, find the .INPROGRESS file, reopen it.
//
// Replay all existing records first via the framing-layer ReadRecord before
// further appends (caller's responsibility; this constructor positions the
// writer at EOF).
//
// maxRecordBytes is the per-record cap to enforce on subsequent appends and
// must be in (0, MaxFramedPayload].
func ReopenSegment(path string, maxRecordBytes int) (*Segment, error) {
	if err := validateMaxRecordBytes(maxRecordBytes); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("reopen segment: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if st.Size() < int64(SegmentHeaderSize) {
		_ = f.Close()
		return nil, fmt.Errorf("segment too short: %d bytes", st.Size())
	}
	hdr, err := ReadSegmentHeader(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		_ = f.Close()
		return nil, err
	}
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	// Strip the .seg.INPROGRESS suffix and parse the remaining numeric prefix
	// as a uint64. fmt.Sscanf("%010d", ...) only accepts up to 10 digits and
	// would fail to recover segments past index 9_999_999_999.
	const suffix = segmentExt + inProgressSuffix
	if !strings.HasSuffix(base, suffix) {
		_ = f.Close()
		return nil, fmt.Errorf("not an INPROGRESS segment file: %q", base)
	}
	prefix := strings.TrimSuffix(base, suffix)
	index, err := strconv.ParseUint(prefix, 10, 64)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("parse segment name %q: %w", base, err)
	}
	return &Segment{
		dir:            dir,
		index:          index,
		gen:            hdr.Generation,
		path:           path,
		file:           f,
		writer:         bufio.NewWriter(f),
		bytes:          st.Size(),
		maxRecordBytes: maxRecordBytes,
	}, nil
}

// Path returns the on-disk path of this segment (with .INPROGRESS suffix
// while live, sealed name after Seal()).
func (s *Segment) Path() string { return s.path }

// Generation returns the segment's generation tag.
func (s *Segment) Generation() uint32 { return s.gen }

// Index returns the segment's numeric index.
func (s *Segment) Index() uint64 { return s.index }

// Bytes returns the current on-disk byte count (header + records).
func (s *Segment) Bytes() int64 { return s.bytes }

// WriteRecord appends one length+CRC32C-framed record. Buffered; caller must
// call Sync() (or Seal(), which syncs as part of its work) for durability.
// Returns ErrSegmentClosed if called after Close or Seal.
func (s *Segment) WriteRecord(payload []byte) error {
	if s.closed {
		return ErrSegmentClosed
	}
	startBytes := s.bytes
	if err := WriteRecord(s.writer, payload, s.maxRecordBytes); err != nil {
		return err
	}
	s.bytes = startBytes + int64(8+len(payload))
	return nil
}

// Sync flushes the writer and fsyncs the segment file. Returns
// ErrSegmentClosed if called after Close or Seal.
func (s *Segment) Sync() error {
	if s.closed {
		return ErrSegmentClosed
	}
	if err := s.writer.Flush(); err != nil {
		return fmt.Errorf("flush writer: %w", err)
	}
	return s.file.Sync()
}

// Seal flushes, fsyncs, truncates to actual length, renames .INPROGRESS to
// .seg, and fsyncs the parent directory. Returns the sealed path.
//
// After Seal, the Segment is no longer writable; further WriteRecord, Sync,
// or Seal calls return ErrSegmentClosed.
func (s *Segment) Seal() (string, error) {
	if s.closed {
		return "", ErrSegmentClosed
	}
	if err := s.Sync(); err != nil {
		return "", err
	}
	if err := s.file.Truncate(s.bytes); err != nil {
		return "", fmt.Errorf("truncate sealed segment: %w", err)
	}
	if err := s.file.Sync(); err != nil {
		return "", fmt.Errorf("fsync truncated segment: %w", err)
	}
	if err := s.file.Close(); err != nil {
		return "", fmt.Errorf("close sealed segment: %w", err)
	}
	sealed := filepath.Join(s.dir, segmentName(s.index))
	if err := atomicRename(s.path, sealed); err != nil {
		return "", fmt.Errorf("rename sealed segment: %w", err)
	}
	if err := syncDir(s.dir); err != nil {
		return "", fmt.Errorf("fsync segments dir after seal: %w", err)
	}
	s.path = sealed
	s.file = nil
	s.writer = nil
	s.closed = true
	return sealed, nil
}

// Close flushes and closes the underlying file WITHOUT renaming. Used on a
// graceful shutdown that may be reopened later. After Close, the .INPROGRESS
// file remains on disk for the next process to ReopenSegment. Idempotent:
// repeated calls return nil. Subsequent WriteRecord/Sync/Seal calls return
// ErrSegmentClosed.
func (s *Segment) Close() error {
	if s.closed {
		return nil
	}
	if err := s.Sync(); err != nil {
		return err
	}
	err := s.file.Close()
	s.file = nil
	s.writer = nil
	s.closed = true
	return err
}
