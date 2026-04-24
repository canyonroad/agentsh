package watchtower

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	"github.com/agentsh/agentsh/pkg/types"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"google.golang.org/protobuf/proto"
)

// errFatalLatch is returned when AppendEvent is called after a prior
// ambiguous WAL failure (or terminal chain.Commit failure) latched the
// store into a fatal state. No further writes can proceed safely — the
// caller MUST Close and reopen the store to resume.
var errFatalLatch = errors.New("watchtower: store fatal — refusing append")

// AppendEvent encodes ev, computes its integrity record, writes the WAL
// frame, and only then commits the chain advance (Compute → Append →
// Commit). Transactional invariants:
//
//   - On CLEAN WAL failure (no I/O attempted, or I/O rejected before any
//     on-disk mutation), the chain does NOT advance — PeekPrevHash
//     returns the same value as before the call. The next AppendEvent
//     sees the original prev_hash.
//
//   - On AMBIGUOUS WAL failure (I/O attempted, on-disk state may or may
//     not have mutated), the store latches fatal and every subsequent
//     AppendEvent returns errFatalLatch. The audit chain is also
//     latched (Fatal) so any surviving ComputeResult tokens from other
//     goroutines stop advancing.
//
//   - On CLEAN chain Compute failure (e.g., chain.ErrInvalidUTF8), the
//     WAL is NOT touched and the chain does not advance; the error
//     propagates to the caller.
//
//   - On successful Append, Commit is called; if Commit returns a
//     terminal chain error (stale result, cross-chain, backwards-
//     generation, latched), the store latches fatal.
//
// NOTE: this is Task 23's happy-path + failure-latch core. The full
// spec additionally routes compact.ErrInvalidMapper / ErrInvalidTimestamp
// / mapper-wrapped / ErrInvalidUTF8 / sequence-overflow errors through
// per-class drop counters (wtp_dropped_invalid_*_total) instead of
// propagating — that wiring is follow-up work alongside the Task 22a
// counter surface and is not required for the Task 24 integrity tests.
func (s *Store) AppendEvent(ctx context.Context, ev types.Event) error {
	// Serialize the full Compute → Append → Commit transaction. The
	// composite store fans events out to sinks under RLock, so two
	// callers can reach AppendEvent concurrently; without this mutex
	// they would race on the shared prev_hash and one would lose at
	// Commit with a stale-token error, turning normal concurrent
	// traffic into a fatal latch. See Store.appendMu's docstring for
	// the full rationale.
	s.appendMu.Lock()
	defer s.appendMu.Unlock()

	if s.isFatal() {
		return errFatalLatch
	}
	if ev.Chain == nil {
		return fmt.Errorf("watchtower: ev.Chain is required")
	}
	if ev.Chain.Sequence > math.MaxInt64 {
		return fmt.Errorf("watchtower: ev.Chain.Sequence %d overflows int64", ev.Chain.Sequence)
	}

	ce, err := compact.Encode(s.opts.Mapper, ev)
	if err != nil {
		return fmt.Errorf("compact.Encode: %w", err)
	}

	payload, err := proto.Marshal(ce)
	if err != nil {
		return fmt.Errorf("marshal compact event: %w", err)
	}

	// Compute is pure — reads the chain's in-memory state but does not
	// advance it. The returned *audit.ComputeResult is the token we'll
	// pass to Commit after the WAL write succeeds.
	cr, err := s.sink.Compute(audit.IntegrityFormatVersion, int64(ev.Chain.Sequence), ev.Chain.Generation, payload)
	if err != nil {
		return fmt.Errorf("chain compute: %w", err)
	}

	ce.Integrity = s.buildIntegrityRecord(cr, ev.Chain)
	final, err := proto.Marshal(ce)
	if err != nil {
		return fmt.Errorf("marshal final: %w", err)
	}

	if _, err := s.w.Append(int64(ev.Chain.Sequence), ev.Chain.Generation, final); err != nil {
		// Ambiguous: on-disk state may be partially mutated; latch
		// fatal across BOTH the audit chain (so concurrent writers
		// stop) and the store (so subsequent calls bail fast).
		if wal.IsAmbiguous(err) {
			s.sink.Fatal(err)
			s.latchFatal(err)
		}
		// Clean OR ambiguous — either way, do NOT call Commit. The
		// audit chain therefore does not advance; PeekPrevHash
		// returns the pre-call value on the next read.
		return fmt.Errorf("wal append: %w", err)
	}

	// WAL committed; advance the audit chain. Commit failures here are
	// terminal chain-level errors (stale, cross-chain, backwards-gen,
	// latched fatal from a concurrent writer) — latch the store fatal
	// and surface the cause.
	if err := s.sink.Commit(cr); err != nil {
		s.latchFatal(err)
		return fmt.Errorf("chain commit: %w", err)
	}
	return nil
}

// buildIntegrityRecord assembles the WTP-side IntegrityRecord from the
// audit.ComputeResult's entry/prev hashes plus the Store-owned
// identifiers (key fingerprint, sequence, generation, format version).
// context_digest is left empty for the minimal Task 23 scope; binding
// it requires the SessionInit-time context digest, which is follow-up
// work alongside the full transport integration.
func (s *Store) buildIntegrityRecord(cr *audit.ComputeResult, cs *types.ChainState) *wtpv1.IntegrityRecord {
	return &wtpv1.IntegrityRecord{
		FormatVersion:  uint32(audit.IntegrityFormatVersion),
		Sequence:       cs.Sequence,
		Generation:     cs.Generation,
		PrevHash:       cr.PrevHash(),
		EventHash:      cr.EntryHash(),
		KeyFingerprint: s.opts.KeyFingerprint,
	}
}

// isFatal reports whether AppendEvent has been latched into the fatal
// state by a prior ambiguous WAL failure or terminal Commit error.
func (s *Store) isFatal() bool {
	return s.fatalLatched.Load()
}

// latchFatal latches the store fatal if not already latched. The first
// latching caller's error is stored for diagnostic retrieval via Err();
// subsequent calls are no-ops.
func (s *Store) latchFatal(err error) {
	if s.fatalLatched.CompareAndSwap(false, true) {
		if err != nil {
			s.fatalErr.Store(err)
		}
	}
}
