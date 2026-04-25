package transport

import (
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
)

// BatcherOptions configures Batcher flush thresholds.
type BatcherOptions struct {
	MaxRecords int
	MaxBytes   int
	MaxAge     time.Duration
}

// Batch is a snapshot of records to send.
type Batch struct {
	Records []wal.Record
}

// Batcher accumulates WAL records into size/time-bounded batches. It is
// not goroutine-safe; the transport's main loop is the sole caller.
type Batcher struct {
	opts        BatcherOptions
	pending     []wal.Record
	pendingSize int
	firstSeq    uint64
	lastSeq     uint64
	gen         uint32
	startedAt   time.Time
}

// NewBatcher returns an empty batcher.
func NewBatcher(opts BatcherOptions) *Batcher { return &Batcher{opts: opts} }

// Add inserts rec into the pending batch. If the addition would violate the
// generation, sequence-contiguity, or MaxBytes invariants, the existing
// pending batch is flushed and returned, and rec becomes the first record
// of the next batch. If the addition fills the batch to MaxRecords, rec is
// included in the flushed batch (post-append flush).
//
// MaxRecords vs. MaxBytes asymmetry: the MaxBytes check is pre-append
// ("would adding rec push us over?") so the offending oversize record
// starts the next batch. The MaxRecords check is post-append ("did rec
// fill us to the limit?") so a batch closing on MaxRecords contains
// exactly MaxRecords records — matching the invariant test expectations.
func (b *Batcher) Add(rec wal.Record) *Batch {
	if len(b.pending) == 0 {
		b.start(rec)
		// MaxRecords == 1 closes the batch on the very first add.
		if len(b.pending) >= b.opts.MaxRecords {
			return b.flush()
		}
		return nil
	}

	switch {
	case rec.Generation != b.gen:
		return b.flushAndStart(rec)
	case rec.Sequence != b.lastSeq+1:
		return b.flushAndStart(rec)
	case b.pendingSize+len(rec.Payload) > b.opts.MaxBytes:
		return b.flushAndStart(rec)
	}

	b.pending = append(b.pending, rec)
	b.pendingSize += len(rec.Payload)
	b.lastSeq = rec.Sequence
	if len(b.pending) >= b.opts.MaxRecords {
		return b.flush()
	}
	return nil
}

// Tick checks whether the pending batch has exceeded MaxAge. If so it is
// flushed.
func (b *Batcher) Tick(now time.Time) *Batch {
	if len(b.pending) == 0 {
		return nil
	}
	if now.Sub(b.startedAt) < b.opts.MaxAge {
		return nil
	}
	return b.flush()
}

// Drain returns any in-flight pending records (used at Shutdown).
func (b *Batcher) Drain() *Batch {
	if len(b.pending) == 0 {
		return nil
	}
	return b.flush()
}

func (b *Batcher) start(rec wal.Record) {
	b.pending = []wal.Record{rec}
	b.pendingSize = len(rec.Payload)
	b.firstSeq = rec.Sequence
	b.lastSeq = rec.Sequence
	b.gen = rec.Generation
	b.startedAt = time.Now()
}

func (b *Batcher) flush() *Batch {
	out := &Batch{Records: b.pending}
	b.pending = nil
	b.pendingSize = 0
	b.firstSeq, b.lastSeq, b.gen = 0, 0, 0
	return out
}

func (b *Batcher) flushAndStart(rec wal.Record) *Batch {
	out := b.flush()
	b.start(rec)
	return out
}
