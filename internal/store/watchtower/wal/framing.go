// Package wal implements the WTP write-ahead log: framed records inside
// generation-tagged segment files, with CRC32C-Castagnoli per record and an
// atomic .INPROGRESS → .seg seal. Spec §"WAL Package".
package wal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
)

// SegmentHeaderSize is the fixed 16-byte segment header at the start of
// every segment file. Spec §"Segment header (16 bytes)".
const SegmentHeaderSize = 16

// SegmentMagic identifies a WTP1 segment file.
var SegmentMagic = []byte("WTP1")

// SegmentVersion is the current segment header version.
const SegmentVersion uint16 = 1

// FlagGenInit indicates the segment was opened due to a generation roll.
const FlagGenInit uint16 = 0x0001

// knownFlagsMask is the union of all defined flag bits. Spec §"Segment
// header" states "bit 0: gen_init, others reserved 0", so any bit outside
// this mask is a reserved flag bit and must be zero on both write and read.
const knownFlagsMask uint16 = FlagGenInit

// SegmentHeader is the parsed representation of a 16-byte segment header.
type SegmentHeader struct {
	Version    uint16
	Flags      uint16
	Generation uint32
}

// WriteSegmentHeader emits a 16-byte header to w. Reserved bytes are zero.
// Returns an error if h.Flags has any reserved bit set, so a malformed
// in-memory header never reaches disk.
func WriteSegmentHeader(w io.Writer, h SegmentHeader) error {
	if h.Flags&^knownFlagsMask != 0 {
		return fmt.Errorf("reserved flag bits set: %#x", h.Flags)
	}
	buf := make([]byte, SegmentHeaderSize)
	copy(buf[0:4], SegmentMagic)
	binary.BigEndian.PutUint16(buf[4:6], h.Version)
	binary.BigEndian.PutUint16(buf[6:8], h.Flags)
	binary.BigEndian.PutUint32(buf[8:12], h.Generation)
	// buf[12:16] reserved, all zero
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("write segment header: %w", err)
	}
	return nil
}

// ReadSegmentHeader parses a 16-byte header from r. Rejects unknown magic,
// unknown version, non-zero reserved flag bits, and non-zero reserved bytes.
func ReadSegmentHeader(r io.Reader) (SegmentHeader, error) {
	buf := make([]byte, SegmentHeaderSize)
	if _, err := io.ReadFull(r, buf); err != nil {
		return SegmentHeader{}, fmt.Errorf("read segment header: %w", err)
	}
	if string(buf[0:4]) != string(SegmentMagic) {
		return SegmentHeader{}, fmt.Errorf("bad magic: got %x want %x", buf[0:4], SegmentMagic)
	}
	h := SegmentHeader{
		Version:    binary.BigEndian.Uint16(buf[4:6]),
		Flags:      binary.BigEndian.Uint16(buf[6:8]),
		Generation: binary.BigEndian.Uint32(buf[8:12]),
	}
	if h.Version != SegmentVersion {
		return SegmentHeader{}, fmt.Errorf("unsupported segment version %d (want %d)", h.Version, SegmentVersion)
	}
	if h.Flags&^knownFlagsMask != 0 {
		return SegmentHeader{}, fmt.Errorf("reserved flag bits set: %#x", h.Flags)
	}
	for _, b := range buf[12:16] {
		if b != 0 {
			return SegmentHeader{}, fmt.Errorf("reserved bytes nonzero: %x", buf[12:16])
		}
	}
	return h, nil
}

// crcTable is the Castagnoli polynomial table used for record CRCs.
var crcTable = crc32.MakeTable(crc32.Castagnoli)

// MaxFramedPayload is the largest payload size the on-disk frame format can
// represent. The frame's length field is a uint32 and encodes
// len(payload)+4 (payload bytes plus the 4-byte CRC), so the absolute
// upper bound on a single record's payload is math.MaxUint32 - 4. This is
// a protocol-level hard cap that constrains every caller, regardless of
// how WAL.SegmentSize is configured. The constant is left untyped so 32-bit
// platforms (where int < uint32) still compile; comparisons widen via uint64.
const MaxFramedPayload = math.MaxUint32 - 4

// ErrCRCMismatch is returned by ReadRecord when the on-disk CRC does not
// match the recomputed CRC of the payload bytes.
var ErrCRCMismatch = errors.New("wal: record CRC mismatch")

// ErrCorruptFrame is returned by ReadRecord when the on-disk frame header is
// structurally invalid in a way no valid frame ever produced — currently
// only length < 4 (the length field encodes len(payload)+4, so values below
// 4 are impossible for any real record). Recovery treats this the same as
// ErrCRCMismatch or io.ErrUnexpectedEOF: stop scanning and truncate the
// live segment back to the last known-good offset before reopening for
// append. Wrapping is preserved via %w so callers can detect the class via
// errors.Is.
//
// An over-bound payload size (payloadLen > maxPayload) deliberately does
// NOT wrap this sentinel: it most often indicates a configuration mismatch
// (operator restarted with a smaller wal.segment_size than wrote the
// segment) rather than corruption, and silently truncating valid records
// in that case would drop queued data. Recovery surfaces that case as a
// hard open error instead.
var ErrCorruptFrame = errors.New("wal: corrupt record frame")

// WriteRecord writes a length-prefixed, CRC32C-protected record to w.
//
// Frame layout:
//   offset  size      field
//   0       4         length     (uint32 BE; bytes after this field, excluding CRC, including payload)
//   4       4         crc32c     (Castagnoli, computed over payload)
//   8       length-4  payload
//
// Note: the length field encodes len(payload)+4 (the payload bytes plus the
// 4-byte CRC). This matches spec §"Record framing".
//
// maxPayload is the largest payload (in bytes) the caller will allow in a
// single record. The caller — typically the segment writer — derives this
// from the configured WAL.SegmentSize so deployments with larger segments
// can still emit larger records without lifting a hard-coded ceiling here.
// maxPayload must be in (0, MaxFramedPayload]; values outside that range
// are rejected so a 64-bit caller bound cannot wrap the on-disk uint32
// length field.
func WriteRecord(w io.Writer, payload []byte, maxPayload int) error {
	if maxPayload <= 0 {
		return fmt.Errorf("wal: maxPayload must be > 0, got %d", maxPayload)
	}
	if uint64(maxPayload) > MaxFramedPayload {
		return fmt.Errorf("wal: maxPayload %d exceeds protocol cap %d", maxPayload, uint64(MaxFramedPayload))
	}
	if len(payload) == 0 {
		return errors.New("wal: empty payload")
	}
	if len(payload) > maxPayload {
		return fmt.Errorf("wal: payload size %d exceeds maxPayload %d", len(payload), maxPayload)
	}
	header := make([]byte, 8)
	binary.BigEndian.PutUint32(header[0:4], uint32(len(payload)+4))
	binary.BigEndian.PutUint32(header[4:8], crc32.Checksum(payload, crcTable))
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("write record header: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write record payload: %w", err)
	}
	return nil
}

// ReadRecord reads one length-prefixed CRC32C record from r and returns the
// payload. Returns ErrCRCMismatch on bad CRC, ErrCorruptFrame on a
// structurally impossible frame header (length < 4), an unwrapped error on
// payload size exceeding maxPayload (treated as a configuration mismatch
// rather than corruption — see ErrCorruptFrame's docstring),
// io.ErrUnexpectedEOF on truncation, io.EOF when r is at the end of its
// data.
//
// maxPayload bounds the declared payload size before any allocation, so a
// corrupted on-disk length cannot drive ReadRecord into an unbounded
// allocation. The caller — typically the segment reader — derives this
// from the actual segment file size or the configured WAL.SegmentSize.
// maxPayload must be in (0, MaxFramedPayload].
func ReadRecord(r io.Reader, maxPayload int) ([]byte, error) {
	if maxPayload <= 0 {
		return nil, fmt.Errorf("wal: maxPayload must be > 0, got %d", maxPayload)
	}
	if uint64(maxPayload) > MaxFramedPayload {
		return nil, fmt.Errorf("wal: maxPayload %d exceeds protocol cap %d", maxPayload, uint64(MaxFramedPayload))
	}
	header := make([]byte, 8)
	n, err := io.ReadFull(r, header)
	if err != nil {
		if err == io.EOF && n == 0 {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("read record header: %w", err)
	}
	length := binary.BigEndian.Uint32(header[0:4])
	expectedCRC := binary.BigEndian.Uint32(header[4:8])
	if length < 4 {
		return nil, fmt.Errorf("%w: invalid record length %d", ErrCorruptFrame, length)
	}
	payloadLen := length - 4
	if uint64(payloadLen) > uint64(maxPayload) {
		// Deliberately NOT wrapped with ErrCorruptFrame: an over-bound
		// length most often signals a configuration mismatch (operator
		// reopened the WAL with a smaller wal.segment_size than what
		// wrote the segment), and treating it as truncatable corruption
		// during recovery would silently chop a perfectly-valid file.
		// Recovery must surface this as a hard open error instead.
		return nil, fmt.Errorf("wal: record payload size %d exceeds maxPayload %d", payloadLen, maxPayload)
	}
	// Stream the payload into a growable buffer rather than pre-allocating
	// `payloadLen` bytes up front. A corrupted on-disk length can claim up
	// to MaxFramedPayload (~4 GiB) and pass the bound check above when a
	// caller permits the protocol cap, so a make([]byte, payloadLen) here
	// would let one bad header OOM the replay process. io.CopyN+bytes.Buffer
	// grows allocation in step with bytes the underlying reader actually
	// produces, so a header that overstates a record's true length fails
	// with a read error long before allocation reaches the claimed size.
	var payloadBuf bytes.Buffer
	if got, err := io.CopyN(&payloadBuf, r, int64(payloadLen)); err != nil {
		// io.CopyN returns io.EOF on a short read; translate to
		// io.ErrUnexpectedEOF to preserve the truncated-payload contract
		// callers used to get from io.ReadFull (errors.Is-detectable).
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, fmt.Errorf("read record payload (got %d of %d bytes): %w", got, payloadLen, err)
	}
	payload := payloadBuf.Bytes()
	if crc32.Checksum(payload, crcTable) != expectedCRC {
		return nil, ErrCRCMismatch
	}
	return payload, nil
}
