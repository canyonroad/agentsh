package watchtower

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store/watchtower/chain"
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

// deterministicMarshal is the proto.MarshalOptions used to produce the
// byte-stable canonical CompactEvent bytes that feed into
// chain.ComputeEventHash. proto3's deterministic serialisation emits
// fields in tag order with fixed wire-format rules, so the hash is
// stable across Go build + proto-compiler versions that honour the
// option. This is the same property audit.IntegrityChain relies on for
// its canonical JSON payload; for WTP's proto-wire form we trade a
// custom JSON canonicaliser for the proto-native deterministic flag.
var deterministicMarshal = proto.MarshalOptions{Deterministic: true}

// AppendEvent encodes ev, canonicalises the CompactEvent to derive
// event_hash, builds the WTP IntegrityRecord, canonical-encodes it,
// feeds it to the sink's HMAC chain, writes the final frame to the
// WAL, and only then commits the chain advance. The Compute → Append →
// Commit transaction is atomic with respect to concurrent appenders
// (Store.appendMu).
//
// Transactional invariants:
//
//   - On CLEAN WAL failure (no I/O attempted, or rejected before any
//     on-disk mutation), the chain does NOT advance — PeekPrevHash
//     returns the same value as before the call. The next AppendEvent
//     re-signs from the same prev_hash.
//
//   - On AMBIGUOUS WAL failure (I/O attempted, on-disk state may have
//     mutated), the store latches fatal — every subsequent
//     AppendEvent returns errFatalLatch. The audit chain is also
//     latched (Fatal) so any surviving ComputeResult tokens from
//     other goroutines stop advancing.
//
//   - On CLEAN chain compute failure (e.g., chain.ErrInvalidUTF8), the
//     WAL is NOT touched and the chain does not advance; the error
//     propagates to the caller.
//
//   - On terminal Commit failure (stale result, cross-chain,
//     backwards-generation, latched fatal), the store latches fatal.
//
// SCOPE NOTE: this is Task 23's core transactional path. The full
// spec additionally routes compact.ErrInvalidMapper /
// ErrInvalidTimestamp / mapper-wrapped / sequence-overflow /
// chain.ErrInvalidUTF8 through per-class drop counters
// (wtp_dropped_invalid_*_total) with structured WARN logs. That
// counter-wiring layer is follow-up work alongside the Task 22a
// sink-failure counter surface; today those errors propagate to the
// caller as wrapped errors.
func (s *Store) AppendEvent(ctx context.Context, ev types.Event) error {
	// Serialise the full Compute → Append → Commit transaction. The
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

	// 1. Canonical CompactEvent bytes (WITHOUT Integrity set) feed the
	//    event_hash. Every other chain implementation verifying this
	//    record MUST arrive at the same bytes, so deterministic proto
	//    serialisation is a contract surface: changing the option (or
	//    mutating Integrity before this point) would break
	//    cross-implementation verification.
	canonicalEvent, err := deterministicMarshal.Marshal(ce)
	if err != nil {
		return fmt.Errorf("marshal canonical compact event: %w", err)
	}
	eventHash := chain.ComputeEventHash(canonicalEvent)

	// 2. Build the WTP IntegrityRecord. prev_hash comes from the
	//    sink's CURRENT state (pre-advance) — the audit chain
	//    advances only after Commit. Reading via PeekPrevHash keeps
	//    the two in lock-step: the chain's Compute call below re-
	//    derives this same prev_hash from its internal state, and
	//    cr.PrevHash() matches the value we stamped here.
	integrityRec := chain.IntegrityRecord{
		FormatVersion:  uint32(audit.IntegrityFormatVersion),
		Sequence:       ev.Chain.Sequence,
		Generation:     ev.Chain.Generation,
		PrevHash:       s.sink.PeekPrevHash(),
		EventHash:      eventHash,
		ContextDigest:  s.contextDigest,
		KeyFingerprint: s.opts.KeyFingerprint,
	}
	canonicalIntegrity, err := chain.EncodeCanonical(integrityRec)
	if err != nil {
		// chain.ErrInvalidUTF8 propagates here for any peer-derived
		// field that slipped through upstream validation. Task 23
		// follow-up wires this into wtp_dropped_invalid_utf8_total;
		// today it surfaces to the caller.
		return fmt.Errorf("chain.EncodeCanonical: %w", err)
	}

	// 3. Feed the canonical IntegrityRecord to the HMAC chain. Compute
	//    is pure — it reads the chain's prev_hash but does not
	//    advance. The returned *audit.ComputeResult is the commit
	//    token.
	cr, err := s.sink.Compute(audit.IntegrityFormatVersion, int64(ev.Chain.Sequence), ev.Chain.Generation, canonicalIntegrity)
	if err != nil {
		return fmt.Errorf("chain compute: %w", err)
	}

	// 4. Attach the full IntegrityRecord to the CompactEvent and
	//    marshal the wire-final bytes for the WAL. Both
	//    cross-implementation verifiers and local replay use the
	//    proto-native form stored on disk; the canonical JSON form
	//    only exists to feed the HMAC chain.
	ce.Integrity = &wtpv1.IntegrityRecord{
		FormatVersion:  integrityRec.FormatVersion,
		Sequence:       integrityRec.Sequence,
		Generation:     integrityRec.Generation,
		PrevHash:       integrityRec.PrevHash,
		EventHash:      integrityRec.EventHash,
		ContextDigest:  integrityRec.ContextDigest,
		KeyFingerprint: integrityRec.KeyFingerprint,
	}
	final, err := proto.Marshal(ce)
	if err != nil {
		return fmt.Errorf("marshal final compact event: %w", err)
	}

	// 5. Append to WAL. Ambiguous failures latch BOTH the audit
	//    chain (so concurrent writers stop) AND the Store (so
	//    subsequent appends bail fast). On clean failure the chain
	//    does NOT advance because we never call Commit.
	if _, err := s.w.Append(int64(ev.Chain.Sequence), ev.Chain.Generation, final); err != nil {
		if wal.IsAmbiguous(err) {
			s.sink.Fatal(err)
			s.latchFatal(err)
		}
		return fmt.Errorf("wal append: %w", err)
	}

	// 6. Commit advances the audit chain. A Commit error is terminal
	//    (stale, cross-chain, backwards-gen, latched fatal) so we
	//    latch the store fatal and surface the cause.
	if err := s.sink.Commit(cr); err != nil {
		s.latchFatal(err)
		return fmt.Errorf("chain commit: %w", err)
	}
	return nil
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
