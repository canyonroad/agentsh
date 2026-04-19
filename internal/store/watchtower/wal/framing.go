// Package wal implements the WTP write-ahead log: framed records inside
// generation-tagged segment files, with CRC32C-Castagnoli per record and an
// atomic .INPROGRESS → .seg seal. Spec §"WAL Package".
package wal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
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

// ErrCRCMismatch is returned by ReadRecord when the on-disk CRC does not
// match the recomputed CRC of the payload bytes.
var ErrCRCMismatch = errors.New("wal: record CRC mismatch")

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
// maxPayload must be > 0; values <= 0 are an error so callers cannot
// accidentally bypass the bound.
func WriteRecord(w io.Writer, payload []byte, maxPayload int) error {
	if maxPayload <= 0 {
		return fmt.Errorf("wal: maxPayload must be > 0, got %d", maxPayload)
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
// payload. Returns ErrCRCMismatch on bad CRC, io.ErrUnexpectedEOF on
// truncation, io.EOF when r is at the end of its data.
//
// maxPayload bounds the declared payload size before any allocation, so a
// corrupted on-disk length cannot drive ReadRecord into an unbounded
// allocation. The caller — typically the segment reader — derives this
// from the actual segment file size or the configured WAL.SegmentSize.
// maxPayload must be > 0.
func ReadRecord(r io.Reader, maxPayload int) ([]byte, error) {
	if maxPayload <= 0 {
		return nil, fmt.Errorf("wal: maxPayload must be > 0, got %d", maxPayload)
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
		return nil, fmt.Errorf("invalid record length %d", length)
	}
	payloadLen := length - 4
	if uint64(payloadLen) > uint64(maxPayload) {
		return nil, fmt.Errorf("wal: record payload size %d exceeds maxPayload %d", payloadLen, maxPayload)
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("read record payload: %w", err)
	}
	if crc32.Checksum(payload, crcTable) != expectedCRC {
		return nil, ErrCRCMismatch
	}
	return payload, nil
}
