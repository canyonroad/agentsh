package transport_test

import (
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
)

func mkRec(seq uint64, gen uint32, sz int) wal.Record {
	return wal.Record{
		Sequence:   seq,
		Generation: gen,
		Payload:    make([]byte, sz),
	}
}

// 1. Single generation per batch.
func TestBatcher_NeverMixesGenerations(t *testing.T) {
	b := transport.NewBatcher(transport.BatcherOptions{
		MaxRecords: 100, MaxBytes: 1 << 20, MaxAge: time.Second,
	})

	flushed := b.Add(mkRec(1, 1, 64))
	if flushed != nil {
		t.Fatalf("unexpected early flush")
	}
	flushed = b.Add(mkRec(2, 2, 64)) // generation rolled
	if flushed == nil {
		t.Fatalf("expected flush at generation boundary")
	}
	if got := flushed.Records[0].Generation; got != 1 {
		t.Fatalf("first batch gen: got %d, want 1", got)
	}
	if len(flushed.Records) != 1 {
		t.Fatalf("first batch len: got %d, want 1", len(flushed.Records))
	}
}

// 2. Sequence-contiguous (gap forces flush).
func TestBatcher_FlushOnSequenceGap(t *testing.T) {
	b := transport.NewBatcher(transport.BatcherOptions{
		MaxRecords: 100, MaxBytes: 1 << 20, MaxAge: time.Second,
	})
	if b.Add(mkRec(1, 1, 64)) != nil {
		t.Fatal("unexpected early flush")
	}
	flushed := b.Add(mkRec(3, 1, 64)) // skipped seq 2
	if flushed == nil {
		t.Fatal("expected flush on sequence gap")
	}
	if flushed.Records[0].Sequence != 1 {
		t.Fatalf("first batch seq: got %d, want 1", flushed.Records[0].Sequence)
	}
}

// 3. Flush at MaxRecords.
func TestBatcher_FlushAtMaxRecords(t *testing.T) {
	b := transport.NewBatcher(transport.BatcherOptions{
		MaxRecords: 2, MaxBytes: 1 << 20, MaxAge: time.Second,
	})
	if b.Add(mkRec(1, 1, 32)) != nil {
		t.Fatal("unexpected early flush")
	}
	flushed := b.Add(mkRec(2, 1, 32))
	if flushed == nil {
		t.Fatal("expected flush at MaxRecords")
	}
	if len(flushed.Records) != 2 {
		t.Fatalf("len: got %d, want 2", len(flushed.Records))
	}
}

// 4. Flush at MaxBytes (oversize record still produces the batch).
func TestBatcher_FlushAtMaxBytes(t *testing.T) {
	b := transport.NewBatcher(transport.BatcherOptions{
		MaxRecords: 100, MaxBytes: 100, MaxAge: time.Second,
	})
	if b.Add(mkRec(1, 1, 60)) != nil {
		t.Fatal("unexpected early flush")
	}
	flushed := b.Add(mkRec(2, 1, 60)) // 60+60 > 100
	if flushed == nil {
		t.Fatal("expected flush at MaxBytes")
	}
	if len(flushed.Records) != 1 {
		t.Fatalf("len: got %d, want 1", len(flushed.Records))
	}
}

// 5. Flush on MaxAge via Tick().
func TestBatcher_FlushOnMaxAge(t *testing.T) {
	b := transport.NewBatcher(transport.BatcherOptions{
		MaxRecords: 100, MaxBytes: 1 << 20, MaxAge: 50 * time.Millisecond,
	})
	if b.Add(mkRec(1, 1, 64)) != nil {
		t.Fatal("unexpected early flush")
	}
	if got := b.Tick(time.Now()); got != nil {
		t.Fatal("did not expect flush at t=0")
	}
	got := b.Tick(time.Now().Add(100 * time.Millisecond))
	if got == nil {
		t.Fatal("expected flush after MaxAge elapsed")
	}
}

// 6. Never block on stream — caller stops Add() once inflight is full.
//    Batcher itself has no stream coupling; the state machine enforces this.
//    We test that the state machine respects window full in Task 18.
