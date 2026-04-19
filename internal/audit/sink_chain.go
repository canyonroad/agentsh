package audit

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

// SinkChain owns prev_hash for one sink. Each chained sink holds one.
// Compute is pure (no mutation); Commit advances prev_hash; Fatal latches
// the chain after an ambiguous durable-write failure.
//
// The same (formatVersion, sequence, prevHash, payload) under different
// keys produces different entryHash values — that is the entire point of
// per-sink chaining.
//
// Concurrency model: single-owner serialized use. SinkChain is mutex-safe,
// and concurrent Compute calls (with no intervening Commit) are pure and
// return identical results — they do not corrupt state. However, callers
// MUST NOT interleave Compute/Commit pairs across goroutines: Commit
// consumes a typed *ComputeResult and validates the result's generation
// against the chain's current generation, but the (sequence, generation)
// tuple alone does not identify which Compute call produced it within the
// same generation. The expected pattern is a single owner that issues
// Compute → durable write → Commit (or Fatal) in sequence per event.
//
// Compute/Commit token contract: Compute returns a *ComputeResult that
// callers MUST pass to Commit unchanged. The unexported fields on
// ComputeResult let Commit verify the result really came from Compute on
// this chain. Callers cannot construct a ComputeResult literal because
// the unexported fields make that impossible from outside the audit
// package; this prevents Commit from accepting a fabricated EntryHash
// that Compute would never have produced.
//
// Contract — what SinkChain enforces:
//
//   - Commit(nil) returns an error and does NOT latch fatal (the chain is
//     unmodified; this is a caller bug, not an integrity divergence).
//   - Commit on a chain that was previously latched Fatal (via Fatal or via
//     a prior backwards/stale Commit) returns ErrFatalIntegrity. The chain
//     stays latched.
//   - Commit with a result whose generation < c.generation latches fatal
//     and returns an error wrapping ErrBackwardsGeneration. This indicates
//     the durable write succeeded for an entry whose generation is no
//     longer current; accepting it would silently corrupt subsequent
//     Compute results.
//   - Commit with a result whose generation == c.generation but whose
//     PrevHash != c.prevHash latches fatal and returns an error wrapping
//     ErrStaleResult. The result was computed against a chain head that has
//     since been advanced by a successful prior Commit; accepting it would
//     silently fork the chain.
//   - Commit with a result whose generation > c.generation (rollover)
//     requires PrevHash == "" (because Compute always uses prev="" when
//     rolling). A non-empty PrevHash on a rollover result latches fatal
//     and returns an error wrapping ErrStaleResult. This branch is
//     defense-in-depth: normal callers cannot construct such a result via
//     the public Compute API.
//
// Contract — what remains the caller's responsibility:
//
//   - Serialize Compute → durable write → Commit per record. SinkChain
//     does NOT detect concurrent overlapping Compute/Commit pairs from
//     multiple goroutines; the (sequence, generation) tuple is not a
//     unique identifier within a generation.
//   - Do not concurrently Compute+Commit across goroutines. Commit only
//     validates the result against the chain's CURRENT prev_hash; if two
//     goroutines race a Compute → Commit pair, the second Commit will
//     either appear stale (good — caught) or appear fresh (bad — silently
//     accepted) depending on interleaving. The single-owner pattern is
//     the only safe one.
//   - Only call Commit with a result whose durable write actually
//     succeeded. SinkChain has no knowledge of durable state; Commit on a
//     result whose write failed silently advances the in-memory chain
//     past an entry that does not exist in storage.
//
// Recovery — a fatal latch makes the SinkChain instance unusable:
//
//   - All subsequent Compute calls return ErrFatalIntegrity.
//   - All subsequent Commit calls return ErrFatalIntegrity.
//   - The latch survives State()/Restore() round-trips (Fatal is part of
//     SinkChainState).
//   - The instance must be recreated via NewSinkChain (and a fresh
//     generation established externally — typically by rotating the
//     chain key and bumping the SequenceAllocator's generation, then
//     wiring a fresh SinkChain into the sink). There is no in-place
//     reset method by design: a fatal latch indicates an integrity
//     event the operator must observe.
type SinkChain struct {
	mu         sync.Mutex
	key        []byte
	algorithm  string
	generation uint32
	prevHash   string
	fatal      bool
}

// SinkChainState is the persistent state of a SinkChain. The spec calls
// this ChainState; renamed here to avoid colliding with the existing
// audit.ChainState used by IntegrityChain.State().
//
// Fatal is included so persistence round-trips preserve the latch — a
// chain that latched Fatal before a restart must come back latched after
// Restore, otherwise the safety model is defeated.
type SinkChainState struct {
	Generation uint32
	PrevHash   string
	Fatal      bool
}

// ComputeResult is the typed output of SinkChain.Compute. It is the only
// value Commit will accept. The exported fields are inspectable; the
// unexported fields let Commit verify it really came out of Compute and
// that no impossible state transition is being requested.
//
// Callers MUST NOT construct ComputeResult literals — only Compute returns
// valid ones. The unexported fields make literal construction impossible
// outside the audit package; that is load-bearing for the chain-state
// invariants Commit enforces.
type ComputeResult struct {
	// EntryHash is the HMAC of (formatVersion | sequence | prevHash |
	// payload) under the chain's key. Inspectable — callers serialize this
	// into the entry's integrity metadata.
	EntryHash string

	// PrevHash is the prev_hash that was hashed into EntryHash. For the
	// first entry of a chain (or the first entry after a generation
	// rollover) this is the empty string. Inspectable — callers serialize
	// this into the entry's integrity metadata.
	PrevHash string

	// sequence and generation are unexported so external packages cannot
	// fabricate a ComputeResult with arbitrary state. Commit reads these
	// to enforce chain-state invariants (e.g., backwards-generation Commit
	// is a caller bug and latches fatal).
	sequence   int64
	generation uint32
}

// ErrFatalIntegrity is returned by Compute after Fatal has been called,
// and by Commit when called on a chain that was latched Fatal (either by
// Fatal itself or by a backwards-generation Commit). The chain cannot be
// reused; the sink must be reinitialized (e.g., via generation rotation).
var ErrFatalIntegrity = errors.New("integrity chain latched fatal; sink must be reinitialized")

// ErrMissingChainState is returned by chained sinks when an event arrives
// without ev.Chain set (i.e., composite did not stamp it). Production
// configurations with chained sinks must always run inside a composite
// with a SequenceAllocator.
var ErrMissingChainState = errors.New("event missing Chain field; composite did not stamp it")

// ErrInvalidChainState is returned by Restore when the supplied state
// violates SinkChain invariants (e.g., prevHash is neither empty nor a
// hex string of the algorithm's expected length). The chain is not
// modified on rejected restore.
var ErrInvalidChainState = errors.New("invalid sink chain state")

// ErrBackwardsGeneration is wrapped by Commit when the result's generation
// is older than the chain's current generation. Latches the chain fatal:
// the durable write succeeded for an entry whose generation is no longer
// current, so silently accepting it would leave in-memory prev_hash
// lagging the durable state and corrupt subsequent Compute results.
var ErrBackwardsGeneration = errors.New("backwards-generation Commit: chain latched fatal")

// ErrStaleResult is wrapped by Commit when the result was computed against
// an obsolete chain head. Two cases:
//
//   - same-generation: result.PrevHash != c.prevHash (a prior Commit
//     advanced prev_hash between this result's Compute and Commit).
//   - rollover: result.generation > c.generation but result.PrevHash != ""
//     (rollover results MUST have empty PrevHash; this branch is
//     defense-in-depth).
//
// In either case the chain latches fatal: silently accepting the stale
// result would fork the chain.
var ErrStaleResult = errors.New("stale ComputeResult: caller committed against an obsolete chain head; chain latched fatal")

// NewSinkChain creates a new chain keyed by `key` (must be >= MinKeyLength).
// Supported algorithms: "hmac-sha256" (default), "hmac-sha512".
func NewSinkChain(key []byte, algorithm string) (*SinkChain, error) {
	if len(key) < MinKeyLength {
		return nil, fmt.Errorf("key too short: got %d bytes, need at least %d", len(key), MinKeyLength)
	}
	if algorithm == "" {
		algorithm = "hmac-sha256"
	}
	switch algorithm {
	case "hmac-sha256", "hmac-sha512":
		// supported
	default:
		return nil, fmt.Errorf("unsupported algorithm %q: use hmac-sha256 or hmac-sha512", algorithm)
	}
	return &SinkChain{key: key, algorithm: algorithm}, nil
}

// Compute computes the HMAC of (formatVersion, sequence, prev_hash, payload)
// using the chain's key and returns it as a *ComputeResult. Compute is
// PURE: it does not mutate prev_hash. The caller must follow with Commit
// (passing the returned *ComputeResult) on durable-write success or
// discard the result on durable-write failure.
//
// If `generation` differs from the chain's current generation, prev_hash
// is treated as "" for this Compute (chain rolls automatically). The
// transition is committed only when Commit is called with a result whose
// generation is the new generation.
//
// Returns ErrFatalIntegrity if Fatal was previously called.
func (c *SinkChain) Compute(formatVersion int, sequence int64, generation uint32, payload []byte) (*ComputeResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fatal {
		return nil, ErrFatalIntegrity
	}
	prev := c.prevHash
	if generation != c.generation {
		prev = ""
	}
	hash, err := computeIntegrityHash(c.key, c.algorithm, formatVersion, sequence, prev, payload)
	if err != nil {
		return nil, err
	}
	return &ComputeResult{
		EntryHash:  hash,
		PrevHash:   prev,
		sequence:   sequence,
		generation: generation,
	}, nil
}

// Commit advances prev_hash using the result of a previous Compute on this
// chain. Must be called exactly once per successful Compute, after the
// durable write succeeds. On ambiguous failure (write may or may not have
// landed), the caller MUST call Fatal instead; Commit and Fatal are
// mutually exclusive per Compute.
//
// Returns an error if `result` is nil (caller bug; chain is not modified).
//
// Returns ErrFatalIntegrity if the chain was previously latched Fatal —
// either by an explicit Fatal call, by a prior backwards-generation
// Commit, or by a prior stale-result Commit. The chain stays latched.
//
// Returns an error wrapping ErrBackwardsGeneration AND latches the chain
// Fatal if the result's generation is older than the chain's current
// generation. Accepting it would leave in-memory prev_hash lagging the
// durable state and silently corrupt subsequent Compute results.
//
// Returns an error wrapping ErrStaleResult AND latches the chain Fatal in
// two cases that both indicate the result was computed against an
// obsolete chain head:
//
//   - result.generation == c.generation and result.PrevHash != c.prevHash:
//     a prior Commit advanced prev_hash between this result's Compute and
//     Commit. Silently accepting would fork the chain.
//   - result.generation > c.generation and result.PrevHash != "": rollover
//     results MUST have empty PrevHash (Compute always sets prev="" on
//     rollover). A non-empty PrevHash here means the result was forged or
//     computed against mismatched state. Defense-in-depth: normal callers
//     cannot construct this via the public API.
func (c *SinkChain) Commit(result *ComputeResult) error {
	if result == nil {
		return errors.New("nil ComputeResult")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fatal {
		return ErrFatalIntegrity
	}
	if result.generation < c.generation {
		c.fatal = true
		return fmt.Errorf("%w: result.generation=%d < c.generation=%d",
			ErrBackwardsGeneration, result.generation, c.generation)
	}
	// Stale-token detection — fatal latch.
	// Two cases:
	//   * result.generation == c.generation: result.PrevHash MUST equal
	//     c.prevHash. Mismatch means the caller computed against an older
	//     chain head and is replaying a stale token.
	//   * result.generation > c.generation: this is a rollover commit. The
	//     result MUST have PrevHash == "" because Compute used "" for the
	//     rolled gen. Anything else means the result was forged or computed
	//     against mismatched state.
	if result.generation == c.generation {
		if result.PrevHash != c.prevHash {
			c.fatal = true
			return fmt.Errorf("%w: result.prev_hash=%q, current prev_hash=%q",
				ErrStaleResult, result.PrevHash, c.prevHash)
		}
	} else { // result.generation > c.generation (rollover)
		if result.PrevHash != "" {
			c.fatal = true
			return fmt.Errorf("%w: rollover commit must have empty prev_hash; got %q",
				ErrStaleResult, result.PrevHash)
		}
	}
	c.generation = result.generation
	c.prevHash = result.EntryHash
	return nil
}

// Fatal latches the chain in an unrecoverable state. All subsequent Compute
// calls return ErrFatalIntegrity. Used when a durable write returned an
// ambiguous error (timeout, partial write detection) — we cannot know whether
// the entry was persisted, so we cannot safely continue chaining.
func (c *SinkChain) Fatal(reason error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fatal = true
	_ = reason // reserved for future telemetry; intentionally unused
}

// State returns the (generation, prev_hash, fatal) for persistence.
func (c *SinkChain) State() SinkChainState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return SinkChainState{Generation: c.generation, PrevHash: c.prevHash, Fatal: c.fatal}
}

// Restore rehydrates chain state after restart. Returns ErrInvalidChainState
// if `prevHash` is neither empty (genesis) nor a hex string whose decoded
// length matches the chain's algorithm output (32 bytes for hmac-sha256,
// 64 bytes for hmac-sha512). The chain is not modified on rejected restore.
//
// If `fatal` is true, the chain comes back latched: subsequent Compute calls
// return ErrFatalIntegrity. This is required so persistence round-trips
// preserve the safety latch across restarts.
func (c *SinkChain) Restore(generation uint32, prevHash string, fatal bool) error {
	if err := validatePrevHash(c.algorithm, prevHash); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.generation = generation
	c.prevHash = prevHash
	c.fatal = fatal
	return nil
}

// validatePrevHash returns nil if prevHash is empty (genesis) or a valid
// hex string of the algorithm's expected output length. Otherwise it
// returns an error wrapping ErrInvalidChainState.
func validatePrevHash(algorithm, prevHash string) error {
	if prevHash == "" {
		return nil
	}
	var wantBytes int
	switch algorithm {
	case "hmac-sha512":
		wantBytes = 64
	default: // hmac-sha256 (also default when algorithm == "")
		wantBytes = 32
	}
	wantHex := wantBytes * 2
	if len(prevHash) != wantHex {
		return fmt.Errorf("%w: prevHash length %d, want %d hex chars for %s", ErrInvalidChainState, len(prevHash), wantHex, algorithm)
	}
	if _, err := hex.DecodeString(prevHash); err != nil {
		return fmt.Errorf("%w: prevHash is not valid hex: %v", ErrInvalidChainState, err)
	}
	return nil
}
