package wal

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWAL_CRCFailureEmitsCoarseLossRange is one of the four spec-required
// high-risk integrity tests. After flipping a payload byte in a SEALED
// segment (recovery doesn't rewrite sealed files, so the corruption survives
// to the Reader), Reader.Next must surface a RecordLoss with
// Reason="crc_corruption" rather than crashing or silently skipping.
//
// Sizing rationale: SegmentSize=64 with payload=2 yields 22-byte records and
// segment-header=16, so two records (38, then 60 bytes) fit but a third would
// push past 64 → seal. Five appends therefore produce two sealed segments
// plus one live INPROGRESS, leaving a sealed file we can corrupt safely.
func TestWAL_CRCFailureEmitsCoarseLossRange(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 64, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	for i := int64(0); i < 5; i++ {
		if _, err := w.Append(i, 0, []byte{byte(i), 'X'}); err != nil {
			t.Fatalf("append seq=%d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// Find a SEALED segment to corrupt. Recovery scans only the live segment
	// and truncates its corrupt tail — corrupting INPROGRESS would silently
	// vanish on reopen and the reader would never see the bad CRC.
	entries, err := os.ReadDir(filepath.Join(dir, "segments"))
	if err != nil {
		t.Fatal(err)
	}
	var sealed string
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".INPROGRESS") {
			continue
		}
		if strings.HasSuffix(name, ".seg") {
			sealed = name
			break
		}
	}
	if sealed == "" {
		t.Fatalf("no sealed .seg file to corrupt; entries=%v", entries)
	}
	path := filepath.Join(dir, "segments", sealed)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte inside record 1 of this segment (offset 16 + 22 + 8 = 46
	// is the first payload byte of the 2nd record). Any payload-region
	// flip invalidates CRC.
	const corruptOff = SegmentHeaderSize + 30
	if len(data) <= corruptOff {
		t.Fatalf("segment %s too short (%d bytes) to corrupt at off=%d", sealed, len(data), corruptOff)
	}
	data[corruptOff] ^= 0xFF
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	w2, err := Open(Options{Dir: dir, SegmentSize: 64, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	r, err := w2.NewReader(0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	var sawLoss, sawDataBeforeLoss bool
	var lossRec Record
	for i := 0; i < 10; i++ {
		rec, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Next iter=%d: %v", i, err)
		}
		if rec.Kind == RecordLoss && !sawLoss {
			sawLoss = true
			lossRec = rec
		}
		if rec.Kind == RecordData && !sawLoss {
			sawDataBeforeLoss = true
		}
	}
	if !sawLoss {
		t.Fatalf("Reader did not surface RecordLoss after CRC corruption in %s", sealed)
	}
	if lossRec.Loss.Reason != "crc_corruption" {
		t.Errorf("Loss.Reason = %q, want %q", lossRec.Loss.Reason, "crc_corruption")
	}
	if !sawDataBeforeLoss {
		t.Errorf("expected at least one RecordData from earlier sealed segments before the loss; saw none")
	}
}

// TestReader_SurfacesAppendedLossMarker exercises the round-1/round-2 Task 13
// behavior end-to-end via the Reader: a synthetic TransportLoss record written
// by AppendLoss must surface as Kind=RecordLoss with the original LossRecord
// fields preserved (FromSequence, ToSequence, Generation, Reason).
func TestReader_SurfacesAppendedLossMarker(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.Append(0, 0, []byte("a")); err != nil {
		t.Fatal(err)
	}
	want := LossRecord{FromSequence: 7, ToSequence: 11, Generation: 3, Reason: "overflow"}
	if err := w.AppendLoss(want); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(1, 0, []byte("b")); err != nil {
		t.Fatal(err)
	}
	r, err := w.NewReader(0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var got []Record
	for i := 0; i < 5; i++ {
		rec, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Next %d: %v", i, err)
		}
		got = append(got, rec)
	}
	var sawLoss bool
	for _, rec := range got {
		if rec.Kind == RecordLoss {
			sawLoss = true
			if rec.Loss != want {
				t.Errorf("loss roundtrip mismatch: got %+v, want %+v", rec.Loss, want)
			}
		}
	}
	if !sawLoss {
		t.Errorf("expected RecordLoss in stream; got %+v", got)
	}
}
