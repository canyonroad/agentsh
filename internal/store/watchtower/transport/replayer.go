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
	rdr *wal.Reader
	opts ReplayerOptions
	// tailSeq is a MINIMUM bound on what replay surfaces, not a hard stop.
	// It is the WAL high-water sequence captured under the WAL lock at
	// NewReplayer time, so every record with seq <= tailSeq was already on
	// disk by then and will be visible to the underlying Reader. After
	// replay completes (TryNext returns ok=false), the Reader has surfaced
	// every record with seq <= tailSeq, plus any records appended after
	// construction that happened to be visible at the moment of catch-up.
	// Those extra Live-era records are appended to the final batch — that
	// is harmless because the server treats EventBatch records identically
	// regardless of which state-machine state delivered them. In steady-
	// state high throughput the batch caps (MaxBatchRecords/MaxBatchBytes)
	// bound the loop so the Replayer cannot starve the run loop just
	// because new records keep arriving.
	tailSeq uint64
}

// NewReplayer captures the current WAL high-water sequence as a minimum-
// replay watermark. Every record with seq <= tailSeq is guaranteed to be
// surfaced before NextBatch returns done=true (the Reader will always reach
// it because tailSeq was sampled under the WAL lock). Records appended
// after this point may also surface in the final batch; the Live state
// handler picks up where Replayer leaves off without overlap because the
// underlying Reader is shared.
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
// returns the next batch alongside a done flag. done=true means the Reader
// is currently caught up and the caller should advance to the Live state.
// ctx is honoured between record reads — if it is cancelled, NextBatch
// returns its error.
//
// Termination rules (in order):
//
//  1. ctx cancelled → return (current-partial-batch, false, ctx.Err()).
//  2. Reader is currently caught up (TryNext ok=false) → return done=true.
//     This is the SOLE done signal. tailSeq was captured under the WAL
//     lock at NewReplayer time, so every record with seq <= tailSeq was
//     on disk by then and the Reader will have surfaced it (either as a
//     RecordData yield or, for filtered-by-start records, dropped on the
//     floor inside Reader.nextLocked) by the time TryNext returns
//     ok=false. Live records appended after construction that happen to
//     be visible at the moment of catch-up are appended to this final
//     batch — harmless because the server treats EventBatch records
//     identically regardless of which state-machine state delivered them.
//  3. Batch caps hit (records or bytes) → return done=false, partial batch.
//
// IMPORTANT: there is NO early-exit on `rec.Sequence >= tailSeq`. An
// earlier draft had one, but it raced with overflow GC: while the
// replayer drains, GC can drop a segment containing replay-era seqs and
// append a compensating loss marker AT THE WAL TAIL whose Loss.ToSequence
// is <= tailSeq but whose WAL position is beyond tailSeq. With an
// early-exit on RecordData reaching tailSeq, that trailing loss marker
// would never surface and the receiver would silently miss the gap
// notice. Termination MUST be driven by the Reader's caught-up signal
// alone.
//
// Loss records (RecordLoss) are appended verbatim and contribute neither
// to the byte cap accounting nor to a "this record is past tailSeq"
// check (there is none — see above).
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
			// loss marker). Replay is done — even trailing loss markers
			// that overflow GC may have appended after entry are surfaced
			// on this same iteration before we observe ok=false, because
			// they were durably written before the TryNext that returned
			// ok=false.
			return batch, true, nil
		}
		batch.Records = append(batch.Records, rec)
		if rec.Kind == wal.RecordData {
			bytes += len(rec.Payload)
		}
	}
}
