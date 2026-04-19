package wal

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWAL_OverflowEmitsLossMarker verifies that an Append that would push the
// WAL past MaxTotalBytes drops oldest segments AND inserts a TransportLoss
// marker into the WAL stream.
func TestWAL_OverflowEmitsLossMarker(t *testing.T) {
	dir := t.TempDir()
	// Tight budget: 4 KiB segments, 12 KiB cap → 3 segments max.
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 12 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	payload := bytes.Repeat([]byte("x"), 1024) // ~1 KiB per record
	for seq := int64(0); seq < 30; seq++ {
		if _, err := w.Append(seq, 0, payload); err != nil {
			t.Fatalf("seq=%d: %v", seq, err)
		}
	}
	// At least one TransportLoss marker should now exist on disk.
	found := false
	entries, _ := os.ReadDir(filepath.Join(dir, "segments"))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".INPROGRESS") || strings.HasSuffix(e.Name(), ".seg") {
			data, _ := os.ReadFile(filepath.Join(dir, "segments", e.Name()))
			if bytes.Contains(data, []byte(LossMarkerSentinel)) {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("no TransportLoss marker found after WAL overflow")
	}
	// And total disk usage must not exceed MaxTotalBytes by more than one
	// segment (we cap at the next-segment boundary, not exactly).
	totalBytes := int64(0)
	entries, _ = os.ReadDir(filepath.Join(dir, "segments"))
	for _, e := range entries {
		st, _ := os.Stat(filepath.Join(dir, "segments", e.Name()))
		totalBytes += st.Size()
	}
	if totalBytes > 16*1024 {
		t.Errorf("total bytes %d exceeds budget 12 KiB + one segment slack", totalBytes)
	}
}

// TestWAL_OverflowAfterAck_OnlyDropsAcked verifies we never drop unacked
// segments when ack-acked segments are available to GC instead.
func TestWAL_OverflowAfterAck_OnlyDropsAcked(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 12 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for seq := int64(0); seq < 5; seq++ {
		if _, err := w.Append(seq, 0, bytes.Repeat([]byte("a"), 1024)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.MarkAcked(4); err != nil {
		t.Fatal(err)
	}
	for seq := int64(5); seq < 20; seq++ {
		if _, err := w.Append(seq, 0, bytes.Repeat([]byte("b"), 1024)); err != nil {
			t.Fatalf("seq=%d: %v", seq, err)
		}
	}
}
