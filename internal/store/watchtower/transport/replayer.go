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
	// tail is a HARD upper bound on RecordData surfaced during replay,
	// expressed as a (Generation, Sequence) tuple compared lexicographically:
	// a record with (rec.Generation, rec.Sequence) > tail is the boundary
	// record that ends replay (it is included in the final batch as a
	// side effect of having been read from the Reader — we cannot push it
	// back). Per Task 14b, the Reader is also generation-scoped via
	// ReaderOptions.Generation, so in steady state every record surfaced
	// has rec.Generation == tail.Generation; the lex compare degenerates
	// to a seq compare. The tuple shape is retained to keep the
	// generation context explicit on the call sites that consume the tail
	// (Tail / LastReplayedSequence) and to fail-fast if a future Reader
	// regression surfaces an other-generation record.
	//
	// The Sequence component is the per-generation data-bearing high-water
	// captured under the WAL lock at NewReplayer time via
	// wal.WrittenDataHighWater(rdr.Generation()): every RecordData with
	// (gen=rdr.Generation(), seq <= tail.Sequence) was already on disk
	// by then and will be visible to the underlying Reader. The spec at
	// docs/superpowers/specs/2026-04-18-wtp-client-design.md:586 defines
	// replay as the finite (ack_hw, wal_hw_at_entry] window before
	// advancing to live; without a hard stop, sustained appends would
	// prevent TryNext from ever returning ok=false and replay would
	// never terminate.
	//
	// Loss markers (RecordLoss) are NOT subject to this hard stop — they
	// always surface so the receiver can record the gap. See NextBatch
	// for the trailing-loss-marker race that this carve-out addresses.
	tail Watermark
	// lastReplayed tracks the highest RecordData (Generation, Sequence)
	// surfaced by NextBatch so far, lexicographically. Initialized to the
	// zero Watermark; updated whenever a RecordData is appended to a batch.
	// Task 22 (Store integration) consumes this value via
	// LastReplayedSequence() to position the Live-state Reader at
	// max(lastReplayed.seq+1, ackHW+1) — see LastReplayedSequence for the
	// rationale.
	lastReplayed Watermark
}

// Watermark is a (Generation, Sequence) pair used by the Replayer to
// express the entry-time tail bound and the running last-replayed cursor.
// Compared lexicographically: (g1, s1) > (g2, s2) iff g1>g2 || (g1==g2 &&
// s1>s2). The Generation field type mirrors wal.Reader.Generation /
// SegmentHeader.Generation / Record.Generation exactly (uint32) so callers
// pass the value through without widening.
type Watermark struct {
	Generation uint32
	Sequence   uint64
}

// NewReplayer captures the current per-generation data-bearing high-water
// (via wal.WrittenDataHighWater(rdr.Generation())) as a hard upper bound
// on RecordData surfaced during replay. Every RecordData with
// (gen=rdr.Generation(), seq <= tail.Sequence) is guaranteed to be
// surfaced before NextBatch returns done=true (the Reader will always
// reach it because the watermark was sampled under the WAL lock).
// Records appended after this point belong to the Live state and MUST NOT
// extend replay; the boundary record (the first RecordData with
// (gen,seq) > tail) is included in the final batch as a side effect of
// having been read from the Reader (we cannot push it back), but no
// further over-tail records are pulled.
//
// Returns an error only if WrittenDataHighWater itself fails (the WAL is
// closed). If no RecordData has ever been written for rdr.Generation()
// (ok=false from WrittenDataHighWater — e.g. a fresh generation that
// only has a segment header), tail.Sequence is 0 and replay drains
// loss markers + any boundary record without surfacing a phantom highest
// seq.
func NewReplayer(rdr *wal.Reader, opts ReplayerOptions) (*Replayer, error) {
	gen := rdr.Generation()
	hw, _, err := rdr.WrittenDataHighWater()
	if err != nil {
		return nil, fmt.Errorf("replayer: WrittenDataHighWater(gen=%d): %w", gen, err)
	}
	return &Replayer{
		rdr:  rdr,
		opts: opts,
		tail: Watermark{Generation: gen, Sequence: hw},
	}, nil
}

// Tail returns the entry-time per-generation tail watermark this Replayer
// is draining toward, as a (Generation, Sequence) tuple. Surfaced for
// diagnostics and tests; the live transport uses it implicitly via the
// done flag from NextBatch.
func (r *Replayer) Tail() (uint32, uint64) { return r.tail.Generation, r.tail.Sequence }

// LastReplayedSequence returns the highest RecordData (Generation,
// Sequence) surfaced by NextBatch so far, as a tuple. Zero before the
// first RecordData is emitted. Per Task 14b the Reader is
// generation-scoped, so the Generation component will equal the Reader's
// pinned generation in steady state; it is returned anyway so callers
// can carry the full tuple through to Live without re-deriving it.
//
// Task 22 (Store integration) consumes this value to position the Live
// Reader at max(lastReplayed.seq+1, ackHW+1). The max() is required for
// two reasons:
//
//  1. Avoid duplicate RecordData sends: replay may have over-shot
//     tail.Sequence by ONE record (the boundary record per NextBatch's
//     hard-stop rule), so Live MUST start at lastReplayed.seq+1, not
//     ackHW+1.
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
func (r *Replayer) LastReplayedSequence() (uint32, uint64) {
	return r.lastReplayed.Generation, r.lastReplayed.Sequence
}

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
		if rec.Kind == wal.RecordData && watermarkLess(r.tail, Watermark{Generation: rec.Generation, Sequence: rec.Sequence}) {
			batch.Records = append(batch.Records, rec)
			r.lastReplayed = Watermark{Generation: rec.Generation, Sequence: rec.Sequence}
			return batch, true, nil
		}
		batch.Records = append(batch.Records, rec)
		if rec.Kind == wal.RecordData {
			bytes += len(rec.Payload)
			r.lastReplayed = Watermark{Generation: rec.Generation, Sequence: rec.Sequence}
		}
	}
}

// watermarkLess returns true iff a < b under lex order on (Generation,
// Sequence). Used by the NextBatch hard-stop check: a record at
// (rec.Gen, rec.Seq) is past the tail iff watermarkLess(tail, recWM).
// In steady state the Reader is generation-scoped (Task 14b) so all
// records have rec.Generation == tail.Generation and the compare reduces
// to seq>tail.Sequence; the lex form is retained so a future Reader
// regression that surfaces an other-generation record fails fast at the
// boundary check rather than silently pulling extra records.
func watermarkLess(a, b Watermark) bool {
	if a.Generation != b.Generation {
		return a.Generation < b.Generation
	}
	return a.Sequence < b.Sequence
}
