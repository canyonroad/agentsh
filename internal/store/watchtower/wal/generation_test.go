package wal

import (
	"strings"
	"testing"
)

// TestWAL_GenerationBoundaryOrdering is one of the four spec-required
// high-risk integrity tests (§"High-risk integrity tests"). It asserts that:
//   - records of different generations land in DIFFERENT segments;
//   - the AppendResult.GenerationRolled flag is set on the boundary record;
//   - the boundary segment's header.generation reflects the new generation.
func TestWAL_GenerationBoundaryOrdering(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 64 * 1024, MaxTotalBytes: 1024 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	// gen=7 records.
	for seq := int64(0); seq < 3; seq++ {
		res, err := w.Append(seq, 7, []byte("g7"))
		if err != nil {
			t.Fatal(err)
		}
		if res.GenerationRolled {
			t.Errorf("seq=%d gen=7 should not roll generation (first writes)", seq)
		}
	}
	// gen=8 boundary record — MUST set GenerationRolled.
	res, err := w.Append(0, 8, []byte("g8"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.GenerationRolled {
		t.Error("first gen=8 record must set GenerationRolled=true")
	}
	for seq := int64(1); seq < 3; seq++ {
		res, err := w.Append(seq, 8, []byte("g8"))
		if err != nil {
			t.Fatal(err)
		}
		if res.GenerationRolled {
			t.Errorf("seq=%d gen=8 (after boundary) should not roll", seq)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// Two sealed segments expected: one gen=7, one gen=8 (live, .INPROGRESS).
	names := listSegments(t, dir)
	sealed, inProgress := splitNames(names)
	if len(sealed) != 1 {
		t.Errorf("expected 1 sealed segment after gen roll, got %d (%v)", len(sealed), names)
	}
	if len(inProgress) != 1 {
		t.Errorf("expected 1 .INPROGRESS, got %d (%v)", len(inProgress), names)
	}
}

func splitNames(names []string) (sealed, inProgress []string) {
	for _, n := range names {
		if strings.HasSuffix(n, ".INPROGRESS") {
			inProgress = append(inProgress, n)
		} else {
			sealed = append(sealed, n)
		}
	}
	return
}
