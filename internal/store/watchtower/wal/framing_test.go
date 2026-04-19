package wal

import (
	"bytes"
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
	// Construct a raw header with non-zero reserved bits.
	raw := make([]byte, SegmentHeaderSize)
	copy(raw, "WTP1")
	raw[4] = 0x01 // version low byte
	// reserved (offset 12..16) intentionally non-zero
	raw[12] = 0x42
	_, err := ReadSegmentHeader(bytes.NewReader(raw))
	if err == nil {
		t.Fatal("expected reserved-nonzero rejection")
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
