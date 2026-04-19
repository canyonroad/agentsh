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
	rdr  *wal.Reader
	opts ReplayerOptions
	// tailSeq is a HARD upper bound on RecordData surfaced during replay.
	// It is the WAL high-water sequence captured under the WAL lock at
	// NewReplayer time, so every record with seq <= tailSeq was already
	// on disk by then and will be visible to the underlying Reader. The
	// spec at docs/superpowers/specs/2026-04-18-wtp-client-design.md:586
	// defines replay as the finite (ack_hw, wal_hw_at_entry] window
	// before advancing to live; without a hard stop, sustained appends
	// would prevent TryNext from ever returning ok=false and replay
	// would never terminate.
	//
	// Loss markers (RecordLoss) are NOT subject to this hard stop — they
	// always surface so the receiver can record the gap. See NextBatch
	// for the trailing-loss-marker race that this carve-out addresses.
	tailSeq uint64
	// lastReplayedSeq tracks the highest RecordData.Sequence surfaced by
	// NextBatch so far. Initialized to zero; updated whenever a RecordData
	// is appended to a batch. Task 22 (Store integration) consumes this
	// value via LastReplayedSequence() to position the Live-state Reader
	// at max(lastReplayedSeq+1, ackHW+1) — see LastReplayedSequence for
	// the rationale.
	lastReplayedSeq uint64
}

// NewReplayer captures the current WAL high-water sequence as a hard upper
// bound on RecordData surfaced during replay. Every RecordData with
// seq <= tailSeq is guaranteed to be surfaced before NextBatch returns
// done=true (the Reader will always reach it because tailSeq was sampled
// under the WAL lock). Records appended after this point belong to the Live
// state and MUST NOT extend replay; the boundary record (the first
// RecordData with seq > tailSeq) is included in the final batch as a side
// effect of having been read from the Reader (we cannot push it back), but
// no further over-tail records are pulled.
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

// LastReplayedSequence returns the highest RecordData.Sequence surfaced by
// NextBatch so far. Zero before the first RecordData is emitted.
//
// Task 22 (Store integration) consumes this value to position the Live
// Reader at max(lastReplayedSeq+1, ackHW+1). The max() is required for
// two reasons:
//
//  1. Avoid duplicate RecordData sends: replay may have over-shot tailSeq
//     by ONE record (the boundary record per NextBatch's hard-stop rule),
//     so Live MUST start at lastReplayedSeq+1, not ackHW+1.
//  2. Still pass over the trailing-loss-marker WAL position: loss markers
//     bypass the Reader's nextSeq filter (see wal/reader.go nextLocked
//     near the isLossMarker branch), so Live's Reader will encounter and
//     surface any trailing loss marker that overflow GC appended at the
//     WAL tail mid-replay even though Live's start cursor is past the
//     marker's covered seq range.
//
// Without this contract, the trailing-loss-marker race that motivated
// the round-1 drain-until-ok=false fix would re-emerge as silent gap
// loss in the Live state.
func (r *Replayer) LastReplayedSequence() uint64 { return r.lastReplayedSeq }

// NextBatch pulls records from the underlying Reader without blocking and
// returns the next batch alongside a done flag. done=true means replay is
// complete and the caller should advance to the Live state. ctx is honoured
// between record reads — if it is cancelled, NextBatch returns its error.
//
// Termination rules (in order):
//
//  1. ctx cancelled → return (current-partial-batch, false, ctx.Err()).
//  2. RecordData with seq > tailSeq read → append the boundary record and
//     return done=true. tailSeq is a HARD upper bound: per spec
//     2026-04-18-wtp-client-design.md:586, replay is the finite
//     (ack_hw, wal_hw_at_entry] window before advancing to live. Without
//     this hard stop, sustained appends would prevent TryNext from ever
//     returning ok=false and replay would never terminate. The boundary
//     record is included because we have already read it from the Reader
//     and cannot push it back; the server treats EventBatch records
//     identically regardless of which state-machine state delivered them.
//  3. Reader is currently caught up (TryNext ok=false) → return done=true.
//  4. Batch caps hit (records or bytes) → return done=false, partial batch.
//
// Trailing-loss-marker race (documented for Task 17/22 Live state). While
// replay drains, overflow GC can drop a segment containing replay-era seqs
// and append a compensating loss marker AT THE WAL TAIL, with
// Loss.ToSequence <= tailSeq but a WAL position strictly beyond tailSeq.
// Two outcomes are possible:
//
//   - The Reader surfaces the loss marker BEFORE any over-tail RecordData.
//     NextBatch appends it to the batch (loss markers always surface and
//     do not contribute to the seq-vs-tailSeq check) and replay continues
//     normally.
//   - The Reader surfaces an over-tail RecordData first, NextBatch returns
//     done=true with the boundary record included, and the trailing loss
//     marker has not yet been seen. The Live state handler is responsible
//     for surfacing it: Live MUST open its Reader at
//     max(lastReplayedSeq+1, ackHW+1) — loss markers bypass the Reader's
//     nextSeq filter (see wal/reader.go nextLocked near the isLossMarker
//     branch), so the trailing marker WILL surface through Live's Reader
//     even though its covered seq range is past Live's start cursor.
//
// Loss records (RecordLoss) are appended verbatim and contribute neither
// to the byte cap accounting nor to the seq-vs-tailSeq check above.
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
			// Reader is caught up to the live tail — replay is done.
			// tailSeq was snapshotted under the WAL lock at construction,
			// so every record with seq <= tailSeq has been visible to the
			// reader by now (whether emitted, filtered by start, or
			// surfaced as a loss marker).
			return batch, true, nil
		}
		if rec.Kind == wal.RecordData && rec.Sequence > r.tailSeq {
			batch.Records = append(batch.Records, rec)
			r.lastReplayedSeq = rec.Sequence
			return batch, true, nil
		}
		batch.Records = append(batch.Records, rec)
		if rec.Kind == wal.RecordData {
			bytes += len(rec.Payload)
			r.lastReplayedSeq = rec.Sequence
		}
	}
}
