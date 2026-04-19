package wal

import (
	"io"
	"testing"
	"time"
)

func TestReader_AppendNotifyNext(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	r, err := w.NewReader(0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := w.Append(0, 0, []byte("first")); err != nil {
		t.Fatal(err)
	}
	// Notify may have already coalesced — drain non-blocking and proceed.
	select {
	case <-r.Notify():
	default:
	}
	rec, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if rec.Kind != RecordData || rec.Sequence != 0 || string(rec.Payload) != "first" {
		t.Errorf("rec = %+v, want kind=Data seq=0 payload=first", rec)
	}
}

func TestReader_StreamsSequentially(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := int64(0); i < 5; i++ {
		if _, err := w.Append(i, 0, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	r, err := w.NewReader(0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for i := uint64(0); i < 5; i++ {
		rec, err := r.Next()
		if err != nil {
			t.Fatalf("seq=%d: %v", i, err)
		}
		if rec.Kind != RecordData {
			t.Fatalf("seq=%d kind=%v, want RecordData", i, rec.Kind)
		}
		if rec.Sequence != i {
			t.Errorf("got seq=%d, want %d", rec.Sequence, i)
		}
	}
}

// TestReader_BlocksUntilNotifyAfterEOF asserts the Notify/Next contract: after
// Next returns io.EOF, the reader must wait on Notify before re-trying. A new
// Append must wake the channel within a short timeout, and the next Next call
// must return the new record.
func TestReader_BlocksUntilNotifyAfterEOF(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(Options{Dir: dir, SegmentSize: 4 * 1024, MaxTotalBytes: 64 * 1024, SyncMode: SyncImmediate})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	r, err := w.NewReader(0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// Drain to EOF — empty WAL.
	for {
		_, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("unexpected: %v", err)
		}
	}
	// Drain the notify channel if it has anything (state is fresh; should be empty).
	select {
	case <-r.Notify():
	default:
	}
	// Now append and verify Notify fires within 1s.
	if _, err := w.Append(0, 0, []byte("late")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-r.Notify():
	case <-time.After(time.Second):
		t.Fatal("Notify did not fire after Append within 1s")
	}
	rec, err := r.Next()
	if err != nil {
		t.Fatalf("Next after notify: %v", err)
	}
	if rec.Kind != RecordData || rec.Sequence != 0 || string(rec.Payload) != "late" {
		t.Errorf("unexpected post-notify record: %+v", rec)
	}
}
