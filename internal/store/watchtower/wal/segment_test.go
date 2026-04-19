package wal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testSegmentMax matches the default WAL.SegmentSize (16 MiB) so segment
// tests exercise WriteRecord/ReadRecord with realistic per-record bounds.
const testSegmentMax = 16 * 1024 * 1024

func TestSegment_OpenWriteSeal(t *testing.T) {
	dir := t.TempDir()
	seg, err := OpenSegment(dir, 0, SegmentHeader{Version: SegmentVersion, Flags: FlagGenInit, Generation: 7}, testSegmentMax)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(seg.Path(), ".INPROGRESS") {
		t.Errorf("expected .INPROGRESS suffix, got %q", seg.Path())
	}
	// Capture the .INPROGRESS path before Seal() rewrites s.path to the
	// sealed name, so we can prove the live file is gone after the rename.
	inProgressPath := seg.Path()
	if err := seg.WriteRecord([]byte("rec-1")); err != nil {
		t.Fatal(err)
	}
	if err := seg.WriteRecord([]byte("rec-2")); err != nil {
		t.Fatal(err)
	}
	sealedPath, err := seg.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(sealedPath, ".INPROGRESS") {
		t.Errorf("seal did not rename: %q", sealedPath)
	}
	if _, err := os.Stat(inProgressPath); !os.IsNotExist(err) {
		t.Errorf(".INPROGRESS still exists after seal: %v", err)
	}
	if _, err := os.Stat(sealedPath); err != nil {
		t.Errorf("sealed file missing: %v", err)
	}
	// After Seal, Segment.Path() must reflect the sealed name (the rename
	// is the externally-observable contract of Seal).
	if seg.Path() != sealedPath {
		t.Errorf("Path() after Seal = %q, want %q", seg.Path(), sealedPath)
	}
}

func TestSegment_RecoversInProgress(t *testing.T) {
	dir := t.TempDir()
	seg, err := OpenSegment(dir, 0, SegmentHeader{Version: SegmentVersion, Flags: FlagGenInit, Generation: 0}, testSegmentMax)
	if err != nil {
		t.Fatal(err)
	}
	if err := seg.WriteRecord([]byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := seg.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen the same segment for append (recovery path).
	seg2, err := ReopenSegment(filepath.Join(dir, "0000000000.seg.INPROGRESS"), testSegmentMax)
	if err != nil {
		t.Fatal(err)
	}
	if err := seg2.WriteRecord([]byte("second")); err != nil {
		t.Fatal(err)
	}
	sealed, err := seg2.Seal()
	if err != nil {
		t.Fatal(err)
	}
	// Read back and verify both records present.
	f, err := os.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := ReadSegmentHeader(f); err != nil {
		t.Fatal(err)
	}
	r1, err := ReadRecord(f, testSegmentMax)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := ReadRecord(f, testSegmentMax)
	if err != nil {
		t.Fatal(err)
	}
	if string(r1) != "first" || string(r2) != "second" {
		t.Errorf("records not preserved: %q, %q", r1, r2)
	}
}

func TestSegment_FilenamePadding(t *testing.T) {
	dir := t.TempDir()
	seg, err := OpenSegment(dir, 42, SegmentHeader{Version: SegmentVersion, Flags: 0, Generation: 0}, testSegmentMax)
	if err != nil {
		t.Fatal(err)
	}
	defer seg.Close()
	want := filepath.Join(dir, "0000000042.seg.INPROGRESS")
	if seg.Path() != want {
		t.Errorf("filename = %q, want %q", seg.Path(), want)
	}
}
