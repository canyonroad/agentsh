package watchtower

import (
	"errors"
	"fmt"
	"io"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store/watchtower/chain"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"google.golang.org/protobuf/proto"
)

// restoreChainFromWAL rebuilds the audit.SinkChain's internal state so
// it matches what was in memory when the prior process committed its
// last WAL record. Call once, immediately after wal.Open, before the
// Store begins accepting appends.
//
// The audit.SinkChain does not persist its prev_hash across restarts
// (by design — tokens are chain-bound to an in-memory instance). Each
// Store therefore starts with a fresh chain at prev_hash="". If the
// WAL already contains committed records, the next AppendEvent would
// stamp IntegrityRecord.PrevHash="" even though the prior record had
// advanced the chain — breaking cross-restart integrity continuity.
//
// Approach: read the last committed WAL record, reconstruct its
// canonical IntegrityRecord, and replay it through an ephemeral chain
// seeded at the record's own PrevHash/Generation. Commit on the
// ephemeral chain yields the post-record state (Generation,
// PrevHash=entry_hash). Restore that state onto the production chain.
//
// No-op when the WAL is empty (HighGeneration() == 0 AND no data in
// any generation) — the fresh-chain default is already correct.
func restoreChainFromWAL(innerChain *audit.SinkChain, w *wal.WAL, opts Options) error {
	lastGen := w.HighGeneration()
	if lastGen == 0 && w.HighWatermark() == 0 {
		// Empty WAL; nothing to restore.
		return nil
	}

	// Walk down from the highest generation to the lowest to find the
	// most recent generation that actually carries data records
	// (header-only or loss-only segments don't advance the chain).
	// The loop bounds are small in practice — generation rolls are
	// rare events and WAL GC drops very old ones.
	var (
		targetGen uint32
		targetSeq uint64
		found     bool
	)
	for g := lastGen; g > 0; g-- {
		seq, ok, err := w.WrittenDataHighWater(g)
		if err != nil {
			return fmt.Errorf("WrittenDataHighWater(gen=%d): %w", g, err)
		}
		if ok {
			targetGen, targetSeq, found = g, seq, true
			break
		}
	}
	if !found {
		// No data-carrying record exists anywhere in the WAL;
		// fresh-chain default is correct.
		return nil
	}

	rdr, err := w.NewReader(wal.ReaderOptions{Generation: targetGen, Start: targetSeq})
	if err != nil {
		return fmt.Errorf("wal.NewReader(gen=%d, start=%d): %w", targetGen, targetSeq, err)
	}
	defer rdr.Close()

	// Advance to the last data record at targetSeq. Loss markers and
	// later records (if any) are skipped — we want the
	// highest-(gen,seq) data record.
	var lastRec *wal.Record
	for {
		rec, err := rdr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("wal.Reader.Next: %w", err)
		}
		recCopy := rec
		lastRec = &recCopy
	}
	if lastRec == nil {
		// Reader yielded no records despite WrittenDataHighWater
		// reporting one. This is a WAL-scan inconsistency; treat
		// as non-fatal and fall back to fresh chain.
		return nil
	}

	ce := &wtpv1.CompactEvent{}
	if err := proto.Unmarshal(lastRec.Payload, ce); err != nil {
		return fmt.Errorf("unmarshal last WAL record: %w", err)
	}
	ir := ce.GetIntegrity()
	if ir == nil {
		// Records pre-dating the integrity format (or corrupted)
		// don't carry an IntegrityRecord. Fall back to fresh chain
		// rather than invent a prev_hash.
		return nil
	}

	// Reconstruct the canonical IntegrityRecord that was hashed into
	// the chain when the prior process committed this record.
	canonIR, err := chain.EncodeCanonical(chain.IntegrityRecord{
		FormatVersion:  ir.GetFormatVersion(),
		Sequence:       ir.GetSequence(),
		Generation:     ir.GetGeneration(),
		PrevHash:       ir.GetPrevHash(),
		EventHash:      ir.GetEventHash(),
		ContextDigest:  ir.GetContextDigest(),
		KeyFingerprint: ir.GetKeyFingerprint(),
	})
	if err != nil {
		return fmt.Errorf("EncodeCanonical(lastRecord): %w", err)
	}

	// Replay on an ephemeral chain to derive post-commit state.
	// Using a separate instance keeps the production chain untouched
	// until we know the restore succeeded; on error we return and
	// the production chain stays at the fresh default (which Close
	// will then roll back above).
	temp, err := audit.NewSinkChain(opts.HMACSecret, opts.HMACAlgorithm)
	if err != nil {
		return fmt.Errorf("ephemeral NewSinkChain: %w", err)
	}
	// Seed the ephemeral chain with the last record's pre-commit
	// state (its on-disk PrevHash + Generation). Compute+Commit
	// then advances to the post-commit state.
	if err := temp.Restore(ir.GetGeneration(), ir.GetPrevHash(), false); err != nil {
		return fmt.Errorf("ephemeral Restore: %w", err)
	}
	cr, err := temp.Compute(int(ir.GetFormatVersion()), int64(ir.GetSequence()), ir.GetGeneration(), canonIR)
	if err != nil {
		return fmt.Errorf("ephemeral Compute: %w", err)
	}
	if err := temp.Commit(cr); err != nil {
		return fmt.Errorf("ephemeral Commit: %w", err)
	}

	// Transfer the replayed state to the production chain. Fatal=false
	// because a successful restart is the non-fatal case; if the prior
	// process latched fatal, recovery is expected to quarantine the
	// WAL out of the way (Task 14a identity quarantine) rather than
	// hand a latched chain to the new process.
	state := temp.State()
	if err := innerChain.Restore(state.Generation, state.PrevHash, false); err != nil {
		return fmt.Errorf("production Restore: %w", err)
	}
	return nil
}
