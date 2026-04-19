package transport

import (
	"context"
	"fmt"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
)

// ReplayerOptions controls replay batching. Both bounds are advisory and
// trigger a return from NextBatch only after at least one record has been
// added (a single record larger than MaxBatchBytes will still ship, alone,
// rather than stall the replay).
type ReplayerOptions struct {
	// MaxBatchRecords caps the number of records returned per NextBatch
	// call. Zero is treated as "no record-count cap"; callers should set
	// a sensible bound (e.g. 100) to keep batches snappy.
	MaxBatchRecords int
	// MaxBatchBytes caps the cumulative payload bytes returned per
	// NextBatch call. Zero is treated as "no byte cap". The cap is
	// checked after each record is added, so a batch may overshoot by
	// the size of one record.
	MaxBatchBytes int
}

// ReplayBatch is a chunk of WAL records returned by Replayer.NextBatch. The
// Records slice holds RecordData and RecordLoss entries in the order the
// Reader surfaced them; loss markers MUST be propagated to the receiver
// even if they fall before the entry-time tail watermark.
type ReplayBatch struct {
	Records []wal.Record
}

// Replayer drains a wal.Reader up to a captured entry-time tail watermark
// and emits records in size-bounded batches. Records appended to the WAL
// after NewReplayer is called belong to the Live state (Task 17), not the
// Replaying state, so the watermark is sampled exactly once at construction.
//
// The Replayer is not safe for concurrent NextBatch calls — callers MUST
// drive it from a single goroutine (typically the transport's run loop).
type Replayer struct {
	rdr     *wal.Reader
	opts    ReplayerOptions
	tailSeq uint64
}

// NewReplayer captures the current WAL high-water sequence as the replay
// target. Records with sequence > tailSeq are not the Replayer's concern;
// the Live state picks them up.
func NewReplayer(rdr *wal.Reader, opts ReplayerOptions) *Replayer {
	return &Replayer{
		rdr:     rdr,
		opts:    opts,
		tailSeq: rdr.WALHighWaterSequence(),
	}
}

// TailSequence returns the entry-time tail watermark this Replayer is
// draining toward. Surfaced for diagnostics and tests; the live transport
// uses it implicitly via the done flag from NextBatch.
func (r *Replayer) TailSequence() uint64 { return r.tailSeq }

// NextBatch pulls records from the underlying Reader without blocking and
// returns the next batch alongside a done flag. done=true means the replay
// has reached the entry-time tail watermark and the caller should advance
// to the Live state. ctx is honoured between record reads — if it is
// cancelled, NextBatch returns its error.
//
// Termination rules (in order):
//
//  1. ctx cancelled → return (current-partial-batch, false, ctx.Err()).
//  2. A record's Sequence reaches or passes tailSeq → include it in the
//     batch, then return done=true.
//  3. Reader is currently caught up (TryNext ok=false) → return done=true.
//     This is safe because tailSeq was captured under the WAL lock at
//     NewReplayer time, so every record with seq <= tailSeq is already on
//     disk and will be reachable via TryNext; ok=false therefore means
//     "everything ≤ tailSeq has been seen (either emitted or filtered)."
//  4. Batch caps hit (records or bytes) → return done=false, partial batch.
//
// Loss records (RecordLoss) are appended verbatim and do not advance the
// done check — only RecordData seqs are compared against tailSeq.
func (r *Replayer) NextBatch(ctx context.Context) (ReplayBatch, bool, error) {
	batch := ReplayBatch{}
	bytes := 0
	for {
		if err := ctx.Err(); err != nil {
			return batch, false, err
		}
		if r.opts.MaxBatchRecords > 0 && len(batch.Records) >= r.opts.MaxBatchRecords {
			return batch, false, nil
		}
		if r.opts.MaxBatchBytes > 0 && bytes >= r.opts.MaxBatchBytes && len(batch.Records) > 0 {
			return batch, false, nil
		}
		rec, ok, err := r.rdr.TryNext()
		if err != nil {
			return batch, false, fmt.Errorf("replayer: reader.TryNext: %w", err)
		}
		if !ok {
			// Reader is caught up to the live tail. Since tailSeq was
			// snapshotted under the WAL lock at construction time, every
			// record with seq <= tailSeq has been visible to the reader by
			// now (whether emitted, filtered by start, or surfaced as a
			// loss marker). Replay is done.
			return batch, true, nil
		}
		batch.Records = append(batch.Records, rec)
		if rec.Kind == wal.RecordData {
			bytes += len(rec.Payload)
			if rec.Sequence >= r.tailSeq {
				return batch, true, nil
			}
		}
	}
}
