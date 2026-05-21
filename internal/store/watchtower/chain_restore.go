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
// Approach: walk every committed WAL record in order, replaying each
// through an ephemeral chain (Compute+Commit). The final ephemeral
// chain state is the post-last-commit HMAC prev_hash; restore that
// onto the production chain.
//
// The old approach (seed the ephemeral chain from the last record's
// IntegrityRecord.PrevHash, replay one record) assumed the wire
// PrevHash field carried the HMAC chain's prev_hash. That assumption
// was broken when IntegrityRecord.PrevHash was repurposed to carry
// the previous event's event_hash per Watchtower spec §3.1.5 (wire
// chain). The HMAC chain hash now must be re-derived from scratch.
//
// Generation 0 IS in scope for the scan: the common "no generation
// roll has happened yet" case has every record in gen=0, and an early-
// restart before the first roll MUST still restore continuity.
//
// Loss markers (wal.RecordLoss) are ignored when replaying: loss
// markers advance the WAL tail but do NOT advance the audit chain.
func restoreChainFromWAL(innerChain *audit.SinkChain, w *wal.WAL, opts Options) (lastEventHash string, lastEventGen uint32, err error) {
	lastGen := w.HighGeneration()

	// Find the highest generation that carries data records.
	var (
		targetGen uint32
		found     bool
	)
	for g := int64(lastGen); g >= 0; g-- {
		_, ok, scanErr := w.WrittenDataHighWater(uint32(g))
		if scanErr != nil {
			return "", 0, fmt.Errorf("WrittenDataHighWater(gen=%d): %w", g, scanErr)
		}
		if ok {
			targetGen, found = uint32(g), true
			break
		}
	}
	if !found {
		// No data-carrying record exists anywhere in the WAL;
		// fresh-chain default is correct.
		return "", 0, nil
	}

	// Build an ephemeral chain seeded at gen=targetGen, prev_hash="".
	// Replaying every record in order advances it to the post-commit
	// state of the last record.
	temp, err := audit.NewSinkChain(opts.HMACSecret, opts.HMACAlgorithm)
	if err != nil {
		return "", 0, fmt.Errorf("ephemeral NewSinkChain: %w", err)
	}
	if err := temp.Restore(targetGen, "", false); err != nil {
		return "", 0, fmt.Errorf("ephemeral Restore(gen=%d, prev=\"\"): %w", targetGen, err)
	}

	rdr, err := w.NewReader(wal.ReaderOptions{Generation: targetGen, Start: 0})
	if err != nil {
		return "", 0, fmt.Errorf("wal.NewReader(gen=%d, start=0): %w", targetGen, err)
	}
	defer rdr.Close()

	var (
		replayed         int
		lastSeenEventHash string
		lastSeenGen      uint32
	)
	for {
		rec, err := rdr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", 0, fmt.Errorf("wal.Reader.Next: %w", err)
		}
		if rec.Kind != wal.RecordData {
			continue
		}

		ce := &wtpv1.CompactEvent{}
		if err := proto.Unmarshal(rec.Payload, ce); err != nil {
			return "", 0, fmt.Errorf("unmarshal WAL record (seq=%d): %w", rec.Sequence, err)
		}
		ir := ce.GetIntegrity()
		if ir == nil {
			// Records pre-dating the integrity format don't carry an
			// IntegrityRecord. Skip them (can't reproduce a hash chain
			// link without inputs).
			continue
		}
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
			return "", 0, fmt.Errorf("EncodeCanonical(seq=%d): %w", ir.GetSequence(), err)
		}
		cr, err := temp.Compute(int(ir.GetFormatVersion()), int64(ir.GetSequence()), ir.GetGeneration(), canonIR)
		if err != nil {
			return "", 0, fmt.Errorf("ephemeral Compute(seq=%d): %w", ir.GetSequence(), err)
		}
		if err := temp.Commit(cr); err != nil {
			return "", 0, fmt.Errorf("ephemeral Commit(seq=%d): %w", ir.GetSequence(), err)
		}
		// Track the most recent event_hash + generation seen so the
		// caller can seed the wire-chain anchor (Store.lastEventHash /
		// lastEventGen) post-restore. The wire chain feeds
		// IntegrityRecord.PrevHash on the next AppendEvent per
		// Watchtower spec §3.1.5.
		lastSeenEventHash = ir.GetEventHash()
		lastSeenGen = ir.GetGeneration()
		replayed++
	}
	if replayed == 0 {
		// Reader yielded no records despite WrittenDataHighWater
		// reporting one. Fall back to fresh chain.
		return "", 0, nil
	}

	// Transfer the replayed state to the production chain.
	state := temp.State()
	if err := innerChain.Restore(state.Generation, state.PrevHash, false); err != nil {
		return "", 0, fmt.Errorf("production Restore: %w", err)
	}
	return lastSeenEventHash, lastSeenGen, nil
}
