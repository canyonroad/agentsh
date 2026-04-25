package wal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"testing"
)

// testMaxPayload is the bound passed to ReadRecord/WriteRecord in tests
// that don't care about the configured WAL.SegmentSize. Sized to match the
// spec default WAL.SegmentSize so it covers realistic record shapes.
const testMaxPayload = 16 * 1024 * 1024

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
	if err := WriteRecord(&buf, payload, testMaxPayload); err != nil {
		t.Fatal(err)
	}
	got, err := ReadRecord(&buf, testMaxPayload)
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
	if err := WriteRecord(&buf, payload, testMaxPayload); err != nil {
		t.Fatal(err)
	}
	frame := buf.Bytes()
	// Flip a payload byte (first byte after length+crc).
	frame[8] ^= 0xFF
	_, err := ReadRecord(bytes.NewReader(frame), testMaxPayload)
	if err != ErrCRCMismatch {
		t.Errorf("err = %v, want ErrCRCMismatch", err)
	}
}

func TestRecordFraming_RejectsTruncatedHeader(t *testing.T) {
	_, err := ReadRecord(bytes.NewReader([]byte{0, 1, 2}), testMaxPayload)
	if err == nil {
		t.Fatal("expected truncated-header error")
	}
}

func TestRecordFraming_RejectsTruncatedPayload(t *testing.T) {
	payload := []byte("abc")
	var buf bytes.Buffer
	if err := WriteRecord(&buf, payload, testMaxPayload); err != nil {
		t.Fatal(err)
	}
	frame := buf.Bytes()
	// Truncate the payload.
	frame = frame[:len(frame)-1]
	_, err := ReadRecord(bytes.NewReader(frame), testMaxPayload)
	if err == nil {
		t.Fatal("expected truncated-payload error")
	}
	// The contract documented on ReadRecord is io.ErrUnexpectedEOF for
	// truncation (so callers can distinguish a clean stream end from a
	// corrupted/short record). Assert via errors.Is to guard against
	// regressions in the read path.
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v, want errors.Is io.ErrUnexpectedEOF", err)
	}
}

func TestRecordFraming_ReadRejectsOversizedLength(t *testing.T) {
	// Synthesize a header that claims a payload larger than the caller's
	// declared maxPayload. Use a sentinel CRC; ReadRecord must reject
	// before allocating or reading the (nonexistent) payload bytes.
	const callerMax = 1024
	header := make([]byte, 8)
	binary.BigEndian.PutUint32(header[0:4], callerMax+5) // payloadLen = callerMax+1
	binary.BigEndian.PutUint32(header[4:8], 0)
	_, err := ReadRecord(bytes.NewReader(header), callerMax)
	if err == nil {
		t.Fatal("expected oversized-length rejection")
	}
}

func TestRecordFraming_WriteRejectsOversizedPayload(t *testing.T) {
	const callerMax = 1024
	payload := make([]byte, callerMax+1)
	var buf bytes.Buffer
	if err := WriteRecord(&buf, payload, callerMax); err == nil {
		t.Fatal("expected oversized-payload rejection")
	}
}

// TestRecordFraming_HonorsLargeConfiguredMax demonstrates that the framing
// layer does not impose a hidden 16 MiB ceiling: a deployment that
// configures WAL.SegmentSize > 16 MiB can pass a larger maxPayload and
// successfully round-trip a record that would have been rejected by a
// hard-coded constant.
func TestRecordFraming_HonorsLargeConfiguredMax(t *testing.T) {
	const largeMax = 64 * 1024 * 1024 // 64 MiB; well above default 16 MiB
	const payloadSize = 17 * 1024 * 1024
	payload := bytes.Repeat([]byte{0xA5}, payloadSize)

	var buf bytes.Buffer
	if err := WriteRecord(&buf, payload, largeMax); err != nil {
		t.Fatalf("WriteRecord with maxPayload=64MiB rejected a %d-byte payload: %v", payloadSize, err)
	}
	got, err := ReadRecord(&buf, largeMax)
	if err != nil {
		t.Fatalf("ReadRecord with maxPayload=64MiB failed on a %d-byte payload: %v", payloadSize, err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round-trip mismatch on large payload: len(got)=%d len(want)=%d", len(got), len(payload))
	}
}

func TestRecordFraming_RejectsNonPositiveMaxPayload(t *testing.T) {
	cases := []int{0, -1, -1024}
	for _, m := range cases {
		var buf bytes.Buffer
		if err := WriteRecord(&buf, []byte("x"), m); err == nil {
			t.Errorf("WriteRecord(maxPayload=%d) expected error, got nil", m)
		}
		if _, err := ReadRecord(bytes.NewReader([]byte{0, 0, 0, 5, 0, 0, 0, 0, 'x'}), m); err == nil {
			t.Errorf("ReadRecord(maxPayload=%d) expected error, got nil", m)
		}
	}
}

// TestRecordFraming_RejectsMaxPayloadAboveProtocolCap guards the on-disk
// length field. The frame's length is uint32 and encodes len(payload)+4,
// so the protocol cannot represent payloads above MaxFramedPayload. A
// caller that supplies maxPayload > MaxFramedPayload is rejected before
// any cast can wrap the on-disk length and silently corrupt a frame.
func TestRecordFraming_RejectsMaxPayloadAboveProtocolCap(t *testing.T) {
	// Use a runtime variable (not a const) so the int() conversion below
	// is evaluated at runtime; a const would overflow at compile time on
	// 32-bit platforms before the t.Skip branch could run.
	aboveCap := uint64(MaxFramedPayload) + 1
	if aboveCap > uint64(math.MaxInt) {
		t.Skip("32-bit platform: int cannot exceed MaxFramedPayload")
	}
	above := int(aboveCap)
	var buf bytes.Buffer
	if err := WriteRecord(&buf, []byte("x"), above); err == nil {
		t.Fatalf("WriteRecord(maxPayload=%d) expected error, got nil", above)
	}
	if _, err := ReadRecord(bytes.NewReader([]byte{0, 0, 0, 5, 0, 0, 0, 0, 'x'}), above); err == nil {
		t.Fatalf("ReadRecord(maxPayload=%d) expected error, got nil", above)
	}
}

// TestRecordFraming_AcceptsMaxPayloadAtProtocolCap exercises the boundary:
// a caller that supplies exactly MaxFramedPayload must be accepted. We
// don't actually allocate that much; we just confirm the bound check
// passes for a tiny payload under that ceiling.
func TestRecordFraming_AcceptsMaxPayloadAtProtocolCap(t *testing.T) {
	// Runtime variable, not const, so int() is evaluated at runtime; see
	// the sibling test for the 32-bit reasoning.
	capValue := uint64(MaxFramedPayload)
	if capValue > uint64(math.MaxInt) {
		t.Skip("32-bit platform: int cannot represent MaxFramedPayload")
	}
	cap := int(capValue)
	var buf bytes.Buffer
	if err := WriteRecord(&buf, []byte("x"), cap); err != nil {
		t.Fatalf("WriteRecord(maxPayload=MaxFramedPayload) returned error: %v", err)
	}
	if _, err := ReadRecord(&buf, cap); err != nil {
		t.Fatalf("ReadRecord(maxPayload=MaxFramedPayload) returned error: %v", err)
	}
}

// TestRecordFraming_BoundsAllocationOnCorruptedLength is a regression test
// for the OOM-on-corruption path: even when the caller permits payloads
// up to MaxFramedPayload, a header that overstates a record's true length
// (e.g. claims math.MaxUint32 when only a handful of bytes follow) must
// fail with a read error long before allocation tracks the claimed size.
// ReadRecord streams the payload via io.CopyN, so memory use is bounded
// by what the underlying reader actually produces — not by the on-disk
// length field.
func TestRecordFraming_BoundsAllocationOnCorruptedLength(t *testing.T) {
	capValue := uint64(MaxFramedPayload)
	if capValue > uint64(math.MaxInt) {
		t.Skip("32-bit platform: int cannot represent MaxFramedPayload")
	}
	cap := int(capValue)
	header := make([]byte, 8)
	binary.BigEndian.PutUint32(header[0:4], math.MaxUint32) // claims payloadLen == MaxFramedPayload
	binary.BigEndian.PutUint32(header[4:8], 0)              // CRC: doesn't matter, we should fail before checking
	body := []byte{'a', 'b', 'c'}                           // far short of the claimed ~4 GiB
	frame := append(header, body...)
	_, err := ReadRecord(bytes.NewReader(frame), cap)
	if err == nil {
		t.Fatal("expected read failure when claimed length far exceeds available bytes")
	}
}
