package wal

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestSegmentHeader_RoundTrip(t *testing.T) {
	hdr := SegmentHeader{Version: 1, Flags: FlagGenInit, Generation: 7}
	var buf bytes.Buffer
	if err := WriteSegmentHeader(&buf, hdr); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != SegmentHeaderSize {
		t.Errorf("header size = %d, want %d", buf.Len(), SegmentHeaderSize)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("WTP1")) {
		t.Errorf("missing WTP1 magic: %x", buf.Bytes())
	}
	got, err := ReadSegmentHeader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if got != hdr {
		t.Errorf("round trip mismatch: got=%+v want=%+v", got, hdr)
	}
}

func TestSegmentHeader_RejectsBadMagic(t *testing.T) {
	bad := append([]byte("XXXX"), make([]byte, SegmentHeaderSize-4)...)
	_, err := ReadSegmentHeader(bytes.NewReader(bad))
	if err == nil {
		t.Fatal("expected magic-rejection error")
	}
}

func TestSegmentHeader_RejectsUnknownVersion(t *testing.T) {
	hdr := SegmentHeader{Version: 99, Flags: 0, Generation: 0}
	var buf bytes.Buffer
	if err := WriteSegmentHeader(&buf, hdr); err != nil {
		t.Fatal(err)
	}
	_, err := ReadSegmentHeader(bytes.NewReader(buf.Bytes()))
	if err == nil {
		t.Fatal("expected version-rejection error")
	}
}

func TestSegmentHeader_RejectsReservedBits(t *testing.T) {
	// Construct a raw header that passes magic + version checks but has
	// non-zero reserved bytes, so the test actually exercises the
	// reserved-bytes branch (not the version branch).
	raw := make([]byte, SegmentHeaderSize)
	copy(raw, "WTP1")
	binary.BigEndian.PutUint16(raw[4:6], SegmentVersion)
	// reserved (offset 12..16) intentionally non-zero
	raw[12] = 0x42
	_, err := ReadSegmentHeader(bytes.NewReader(raw))
	if err == nil {
		t.Fatal("expected reserved-nonzero rejection")
	}
}

func TestSegmentHeader_RejectsReservedFlagBitsOnRead(t *testing.T) {
	// A header that passes magic + version checks but has a reserved
	// flag bit set must be rejected.
	raw := make([]byte, SegmentHeaderSize)
	copy(raw, "WTP1")
	binary.BigEndian.PutUint16(raw[4:6], SegmentVersion)
	binary.BigEndian.PutUint16(raw[6:8], 0x0002) // bit 1 reserved
	_, err := ReadSegmentHeader(bytes.NewReader(raw))
	if err == nil {
		t.Fatal("expected reserved-flag-bits rejection")
	}
}

func TestSegmentHeader_RejectsReservedFlagBitsOnWrite(t *testing.T) {
	hdr := SegmentHeader{Version: SegmentVersion, Flags: 0x8000, Generation: 1}
	var buf bytes.Buffer
	if err := WriteSegmentHeader(&buf, hdr); err == nil {
		t.Fatal("expected write to reject reserved flag bits")
	}
}

func TestRecordFraming_RoundTrip(t *testing.T) {
	payload := []byte("hello WTP record framing")
	var buf bytes.Buffer
	if err := WriteRecord(&buf, payload); err != nil {
		t.Fatal(err)
	}
	got, err := ReadRecord(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload mismatch: got=%q want=%q", got, payload)
	}
}

func TestRecordFraming_DetectsCorruption(t *testing.T) {
	payload := []byte("corrupt me")
	var buf bytes.Buffer
	if err := WriteRecord(&buf, payload); err != nil {
		t.Fatal(err)
	}
	frame := buf.Bytes()
	// Flip a payload byte (first byte after length+crc).
	frame[8] ^= 0xFF
	_, err := ReadRecord(bytes.NewReader(frame))
	if err != ErrCRCMismatch {
		t.Errorf("err = %v, want ErrCRCMismatch", err)
	}
}

func TestRecordFraming_RejectsTruncatedHeader(t *testing.T) {
	_, err := ReadRecord(bytes.NewReader([]byte{0, 1, 2}))
	if err == nil {
		t.Fatal("expected truncated-header error")
	}
}

func TestRecordFraming_RejectsTruncatedPayload(t *testing.T) {
	payload := []byte("abc")
	var buf bytes.Buffer
	if err := WriteRecord(&buf, payload); err != nil {
		t.Fatal(err)
	}
	frame := buf.Bytes()
	// Truncate the payload.
	frame = frame[:len(frame)-1]
	_, err := ReadRecord(bytes.NewReader(frame))
	if err == nil {
		t.Fatal("expected truncated-payload error")
	}
}

func TestRecordFraming_ReadRejectsOversizedLength(t *testing.T) {
	// Synthesize a header that claims a payload larger than MaxRecordSize.
	// Use a sentinel CRC; ReadRecord must reject before allocating or
	// reading the (nonexistent) payload bytes.
	header := make([]byte, 8)
	binary.BigEndian.PutUint32(header[0:4], MaxRecordSize+5) // payloadLen = MaxRecordSize+1
	binary.BigEndian.PutUint32(header[4:8], 0)
	_, err := ReadRecord(bytes.NewReader(header))
	if err == nil {
		t.Fatal("expected oversized-length rejection")
	}
}

func TestRecordFraming_WriteRejectsOversizedPayload(t *testing.T) {
	payload := make([]byte, MaxRecordSize+1)
	var buf bytes.Buffer
	if err := WriteRecord(&buf, payload); err == nil {
		t.Fatal("expected oversized-payload rejection")
	}
}
