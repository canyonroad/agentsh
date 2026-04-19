package wal

import (
	"errors"
	"fmt"
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

// TestSegment_OperationsAfterSealReturnError pins the API contract from the
// Seal() doc comment: post-Seal WriteRecord/Sync/Seal must return
// ErrSegmentClosed rather than panicking on a nil file/writer. Close after
// Seal is idempotent (returns nil).
func TestSegment_OperationsAfterSealReturnError(t *testing.T) {
	dir := t.TempDir()
	seg, err := OpenSegment(dir, 0, SegmentHeader{Version: SegmentVersion, Flags: 0, Generation: 0}, testSegmentMax)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seg.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := seg.WriteRecord([]byte("late")); !errors.Is(err, ErrSegmentClosed) {
		t.Errorf("WriteRecord after Seal err = %v, want ErrSegmentClosed", err)
	}
	if err := seg.Sync(); !errors.Is(err, ErrSegmentClosed) {
		t.Errorf("Sync after Seal err = %v, want ErrSegmentClosed", err)
	}
	if _, err := seg.Seal(); !errors.Is(err, ErrSegmentClosed) {
		t.Errorf("Seal after Seal err = %v, want ErrSegmentClosed", err)
	}
	if err := seg.Close(); err != nil {
		t.Errorf("Close after Seal err = %v, want nil (idempotent)", err)
	}
}

// TestSegment_OperationsAfterCloseReturnError mirrors the post-Seal contract
// for the Close path: WriteRecord/Sync/Seal after Close return
// ErrSegmentClosed; a second Close is a no-op.
func TestSegment_OperationsAfterCloseReturnError(t *testing.T) {
	dir := t.TempDir()
	seg, err := OpenSegment(dir, 0, SegmentHeader{Version: SegmentVersion, Flags: 0, Generation: 0}, testSegmentMax)
	if err != nil {
		t.Fatal(err)
	}
	if err := seg.Close(); err != nil {
		t.Fatal(err)
	}
	if err := seg.WriteRecord([]byte("late")); !errors.Is(err, ErrSegmentClosed) {
		t.Errorf("WriteRecord after Close err = %v, want ErrSegmentClosed", err)
	}
	if err := seg.Sync(); !errors.Is(err, ErrSegmentClosed) {
		t.Errorf("Sync after Close err = %v, want ErrSegmentClosed", err)
	}
	if _, err := seg.Seal(); !errors.Is(err, ErrSegmentClosed) {
		t.Errorf("Seal after Close err = %v, want ErrSegmentClosed", err)
	}
	if err := seg.Close(); err != nil {
		t.Errorf("Close after Close err = %v, want nil (idempotent)", err)
	}
}

// TestSegment_RoundTripLargeIndex covers the recovery path for indices past
// 9_999_999_999 — the previous fmt.Sscanf("%010d") parser silently capped at
// 10 digits, so an 11-digit segment could be created but never reopened.
func TestSegment_RoundTripLargeIndex(t *testing.T) {
	dir := t.TempDir()
	const largeIndex uint64 = 12_345_678_901
	seg, err := OpenSegment(dir, largeIndex, SegmentHeader{Version: SegmentVersion, Flags: 0, Generation: 1}, testSegmentMax)
	if err != nil {
		t.Fatal(err)
	}
	if err := seg.WriteRecord([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := seg.Close(); err != nil {
		t.Fatal(err)
	}

	want := fmt.Sprintf("%010d.seg.INPROGRESS", largeIndex)
	if filepath.Base(seg.Path()) != want {
		t.Fatalf("Path() base = %q, want %q", filepath.Base(seg.Path()), want)
	}

	reopened, err := ReopenSegment(seg.Path(), testSegmentMax)
	if err != nil {
		t.Fatalf("ReopenSegment failed for 11-digit index: %v", err)
	}
	defer reopened.Close()
	if reopened.Index() != largeIndex {
		t.Errorf("Index() = %d, want %d", reopened.Index(), largeIndex)
	}
}
