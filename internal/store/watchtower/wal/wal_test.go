package wal

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestWAL_OpenEmptyDir(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if w.HighWatermark() != 0 || w.HighGeneration() != 0 {
		t.Errorf("fresh WAL hw = (%d,%d), want (0,0)", w.HighWatermark(), w.HighGeneration())
	}
}

func TestWAL_AppendThenReplay(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	for i := uint64(0); i < 5; i++ {
		_, err := w.Append(int64(i), 0, []byte("payload"))
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// Reopen and verify high-watermark recovered.
	w2, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	if w2.HighWatermark() != 4 {
		t.Errorf("recovered HighWatermark = %d, want 4", w2.HighWatermark())
	}
}

func TestWAL_RejectsClosedAppend(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = w.Append(0, 0, []byte("x"))
	if err == nil {
		t.Fatal("expected closed error")
	}
	if !IsClean(err) {
		t.Errorf("Closed-write error must be Clean (no I/O attempted)")
	}
}

func TestWAL_RejectsOversizedPayload(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 1024, MaxTotalBytes: 8 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	big := make([]byte, 2048)
	_, err = w.Append(0, 0, big)
	if err == nil {
		t.Fatal("expected oversized error")
	}
	if !IsClean(err) {
		t.Errorf("Oversized payload error must be Clean (validated pre-I/O)")
	}
}

func listSegments(t *testing.T, dir string) []string {
	t.Helper()
	d := filepath.Join(dir, "segments")
	entries, err := os.ReadDir(d)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}
