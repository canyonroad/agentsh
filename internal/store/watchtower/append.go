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
// Per-class drop counters: every reject path (sequence overflow,
// compact.Encode classification, chain.EncodeCanonical) increments
// the matching wtp_dropped_invalid_*_total counter and emits a
// structured WARN with reason/event_seq/event_gen/session_id/agent_id
// before the wrapped error is returned. See recordSequenceOverflow,
// recordCompactEncodeFailure, recordCanonicalFailure below.
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
		s.recordSequenceOverflow(ev)
		return fmt.Errorf("watchtower: ev.Chain.Sequence %d overflows int64", ev.Chain.Sequence)
	}

	ce, err := compact.Encode(s.opts.Mapper, ev)
	if err != nil {
		s.recordCompactEncodeFailure(err, ev)
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
		s.recordCanonicalFailure(err, ev)
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

// recordCompactEncodeFailure inspects err for the compact.Encode
// sentinels and routes the drop to the matching counter + WARN.
// Called from AppendEvent's compact.Encode error branch BEFORE the
// existing error return.
//
// Classification priority (errors.Is order — MUST stay in this order):
//   - compact.ErrMapperFailure    → IncDroppedMapperFailure / "mapper_failure"
//   - compact.ErrInvalidMapper    → IncDroppedInvalidMapper / "invalid_mapper"
//   - compact.ErrInvalidTimestamp → IncDroppedInvalidTimestamp / "invalid_timestamp"
//   - (fallthrough)               → IncDroppedMapperFailure / "mapper_failure"
//
// ErrMapperFailure is checked FIRST because compact.Encode wraps every
// mapper-side error with it via `fmt.Errorf("%w: %w", ErrMapperFailure,
// err)`; without that priority, a Mapper that happened to return
// ErrInvalidMapper or ErrInvalidTimestamp from inside Map would have
// its drop misclassified as a validation-gate hit (roborev #6177
// Medium). The fallthrough remains for any future encoder error path
// that does not wrap with ErrMapperFailure or one of the other
// sentinels. The compact.ErrMissingChain sentinel is unreachable from
// AppendEvent because the ev.Chain == nil check earlier in the
// function bails before compact.Encode runs; if a future change makes
// it reachable, it falls into the mapper_failure catch-all and
// surfaces in logs.
func (s *Store) recordCompactEncodeFailure(err error, ev types.Event) {
	var reason string
	switch {
	case errors.Is(err, compact.ErrMapperFailure):
		s.metrics.IncDroppedMapperFailure(1)
		reason = "mapper_failure"
	case errors.Is(err, compact.ErrInvalidMapper):
		s.metrics.IncDroppedInvalidMapper(1)
		reason = "invalid_mapper"
	case errors.Is(err, compact.ErrInvalidTimestamp):
		s.metrics.IncDroppedInvalidTimestamp(1)
		reason = "invalid_timestamp"
	default:
		s.metrics.IncDroppedMapperFailure(1)
		reason = "mapper_failure"
	}
	s.opts.Logger.LogAttrs(context.Background(), slog.LevelWarn,
		"wtp: dropping event before WAL append",
		slog.String("reason", reason),
		slog.String("err", err.Error()),
		slog.Uint64("event_seq", ev.Chain.Sequence),
		slog.Uint64("event_gen", uint64(ev.Chain.Generation)),
		slog.String("session_id", s.opts.SessionID),
		slog.String("agent_id", s.opts.AgentID))
}

// recordCanonicalFailure increments wtp_dropped_invalid_utf8_total
// and emits a structured WARN. Called from AppendEvent's
// chain.EncodeCanonical error branch BEFORE the existing error
// return.
//
// chain.EncodeCanonical's only error sentinel today is
// chain.ErrInvalidUTF8 — the function returns that or nil. This
// helper unconditionally classifies as invalid_utf8 rather than
// errors.Is-checking, so a future expansion of EncodeCanonical's
// error surface will fall through here and surface as invalid_utf8
// until the helper is updated. That posture is deliberate: it keeps
// the call site one line and matches the today-only contract; if a
// new sentinel is added, the helper grows a switch like
// recordCompactEncodeFailure.
func (s *Store) recordCanonicalFailure(err error, ev types.Event) {
	s.metrics.IncDroppedInvalidUTF8(1)
	s.opts.Logger.LogAttrs(context.Background(), slog.LevelWarn,
		"wtp: dropping event before WAL append",
		slog.String("reason", "invalid_utf8"),
		slog.String("err", err.Error()),
		slog.Uint64("event_seq", ev.Chain.Sequence),
		slog.Uint64("event_gen", uint64(ev.Chain.Generation)),
		slog.String("session_id", s.opts.SessionID),
		slog.String("agent_id", s.opts.AgentID))
}
