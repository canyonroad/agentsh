package watchtower

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store/watchtower/chain"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	"github.com/agentsh/agentsh/pkg/types"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"google.golang.org/protobuf/proto"
)

// errStoreClosing is returned by AppendEvent when Close has begun
// draining the store. Appends that had already acquired appendMu
// before Close ran complete normally; appends arriving after bail
// with this error so Close's transport-drain window is not polluted
// by late records.
var errStoreClosing = errors.New("watchtower: store closing — refusing append")

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

	// Close-gate: reject new appends once shutdown has begun. Close
	// acquires appendMu AFTER setting closing=true, so any append
	// that had already taken the mutex completes normally; late
	// arrivals bail here. Checked under appendMu so the observable
	// ordering is: (a) all pre-Close appends fully commit before
	// Close's appendMu.Lock() returns, (b) all post-Close appends
	// see closing=true and bail.
	if s.closing.Load() {
		return errStoreClosing
	}
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

	// 2. Build the WTP IntegrityRecord. prev_hash MUST match what
	//    sink.Compute will use internally on the next call:
	//      - if ev.Chain.Generation == chain.Generation, prev_hash is
	//        the chain's current prev_hash;
	//      - if ev.Chain.Generation != chain.Generation (generation
	//        roll), prev_hash resets to "" — matching
	//        audit.SinkChain.Compute's rollover rule.
	//    Reading state here and mirroring that rule keeps
	//    IntegrityRecord.PrevHash in lock-step with the HMAC the
	//    chain will produce; otherwise a first-record-of-new-
	//    generation would serialise the prior generation's hash and
	//    break cross-implementation replay / verification.
	state := s.sink.State()
	var prevForRecord string
	if ev.Chain.Generation == state.Generation {
		prevForRecord = state.PrevHash
	}
	integrityRec := chain.IntegrityRecord{
		FormatVersion:  uint32(audit.IntegrityFormatVersion),
		Sequence:       ev.Chain.Sequence,
		Generation:     ev.Chain.Generation,
		PrevHash:       prevForRecord,
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

// recordSequenceOverflow increments wtp_dropped_sequence_overflow_total
// and emits a structured WARN. Called from AppendEvent's
// ev.Chain.Sequence > math.MaxInt64 branch BEFORE the existing error
// return so the counter increments exactly once per drop and the WARN
// gives operators triage context (which (gen, seq) was rejected).
//
// No underlying err is logged because this is our own range check, not
// a wrapped sentinel — the message is deterministic from event_seq.
func (s *Store) recordSequenceOverflow(ev types.Event) {
	s.metrics.IncDroppedSequenceOverflow(1)
	s.opts.Logger.LogAttrs(context.Background(), slog.LevelWarn,
		"wtp: dropping event before WAL append",
		slog.String("reason", "sequence_overflow"),
		slog.Uint64("event_seq", ev.Chain.Sequence),
		slog.Uint64("event_gen", uint64(ev.Chain.Generation)),
		slog.String("session_id", s.opts.SessionID),
		slog.String("agent_id", s.opts.AgentID))
}
