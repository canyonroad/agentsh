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
// callers MUST pass to Commit unchanged. ComputeResult is opaque
// (unexported fields, accessor methods) and chain-bound — only the
// SinkChain instance that produced the result can commit it. The
// unexported fields make literal construction or post-Compute mutation
// impossible from outside the audit package. Callers that need to persist
// the integrity metadata alongside the payload use EntryHash() and
// PrevHash(); see the lifecycle note below.
//
// Enforced invariants on Commit:
//   - nil ComputeResult → error (no latch).
//   - Post-Fatal Commit → ErrFatalIntegrity (no further latch).
//   - Cross-chain ComputeResult (one produced by a different SinkChain
//     instance) → ErrCrossChainResult, latches fatal on this chain.
//   - Backwards generation → ErrBackwardsGeneration, latches fatal.
//   - Stale prev_hash within the current generation, or non-empty prev_hash
//     on a rollover commit → ErrStaleResult, latches fatal.
//   - Otherwise, generation and prev_hash advance.
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
// Lifecycle / serialization boundary:
//
// A ComputeResult is bound to the in-memory SinkChain instance that
// produced it (chain-bound by pointer identity). It cannot be durably
// stored and committed later: a SinkChain reconstructed via NewSinkChain
// + Restore is a new instance and will reject prior tokens with
// ErrCrossChainResult. This is intentional — Compute and Commit are
// designed to be co-located in a single process, with the durable write
// of the integrity metadata happening between them.
//
// EntryHash() and PrevHash() exist so that callers can persist the
// integrity metadata alongside the payload for later VerifyHash. They are
// NOT the input shape for reconstructing a Commit token across process
// boundaries — there is no such API and no such need; the chain itself
// remembers what it has committed via prev_hash, and VerifyHash
// re-derives entry hashes from the persisted metadata.
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

// ComputeResult is the opaque, chain-bound output of SinkChain.Compute. It is
// the only value Commit will accept, and only the SinkChain instance that
// produced it can commit it. Fields are unexported so callers cannot mutate
// or fabricate one outside the audit package.
//
// Use EntryHash() and PrevHash() to inspect the values for serialization.
//
// Lifecycle / serialization boundary:
//
// A ComputeResult is bound to the in-memory SinkChain instance that
// produced it (chain-bound by pointer identity). It cannot be durably
// stored and committed later: a SinkChain reconstructed via NewSinkChain
// + Restore is a new instance and will reject prior tokens with
// ErrCrossChainResult. This is intentional — Compute and Commit are
// designed to be co-located in a single process, with the durable write
// of the integrity metadata happening between them.
//
// EntryHash() and PrevHash() exist so that callers can persist the
// integrity metadata alongside the payload for later VerifyHash. They are
// NOT the input shape for reconstructing a Commit token across process
// boundaries — there is no such API and no such need; the chain itself
// remembers what it has committed via prev_hash, and VerifyHash
// re-derives entry hashes from the persisted metadata.
type ComputeResult struct {
	entryHash  string
	prevHash   string
	sequence   int64
	generation uint32
	chain      *SinkChain // identity-bound; Commit verifies result.chain == c
}

// EntryHash returns the HMAC entry hash that should be persisted alongside
// the payload for later integrity verification.
func (r *ComputeResult) EntryHash() string { return r.entryHash }

// PrevHash returns the prev_hash the entry was chained against. For the
// genesis entry of a chain or generation, this is "".
func (r *ComputeResult) PrevHash() string { return r.prevHash }

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

// ErrCrossChainResult is wrapped by Commit when the supplied ComputeResult
// was produced by a different SinkChain instance. The misuse latches fatal
// on the receiving chain so the programming error becomes loud rather than
// silently corrupting state. The chain that produced the result is
// unaffected.
var ErrCrossChainResult = errors.New("ComputeResult bound to a different SinkChain")

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
// The returned *ComputeResult is bound to this SinkChain instance — only
// Commit on this same chain will accept it. Cross-chain commits fail with
// ErrCrossChainResult and latch the receiving chain fatal.
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
		entryHash:  hash,
		prevHash:   prev,
		sequence:   sequence,
		generation: generation,
		chain:      c,
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
// Commit, by a prior stale-result Commit, or by a prior cross-chain
// Commit. The chain stays latched.
//
// Returns an error wrapping ErrCrossChainResult AND latches the chain
// Fatal if the supplied ComputeResult was produced by a different
// SinkChain instance. The cross-chain check runs BEFORE
// generation/prev_hash validation so that mixing tokens between chains is
// always reported as a cross-chain error rather than as a downstream
// invariant violation.
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
	// Cross-chain check runs first so that mixing tokens between chains
	// always surfaces as ErrCrossChainResult, not as a downstream
	// generation/prev_hash invariant violation.
	if result.chain != c {
		c.fatal = true
		return fmt.Errorf("%w", ErrCrossChainResult)
	}
	if result.generation < c.generation {
		c.fatal = true
		return fmt.Errorf("%w: result.generation=%d < c.generation=%d",
			ErrBackwardsGeneration, result.generation, c.generation)
	}
	// Stale-token detection — fatal latch.
	// Two cases:
	//   * result.generation == c.generation: result.prevHash MUST equal
	//     c.prevHash. Mismatch means the caller computed against an older
	//     chain head and is replaying a stale token.
	//   * result.generation > c.generation: this is a rollover commit. The
	//     result MUST have prevHash == "" because Compute used "" for the
	//     rolled gen. Anything else means the result was forged or computed
	//     against mismatched state.
	if result.generation == c.generation {
		if result.prevHash != c.prevHash {
			c.fatal = true
			return fmt.Errorf("%w: result.prev_hash=%q, current prev_hash=%q",
				ErrStaleResult, result.prevHash, c.prevHash)
		}
	} else { // result.generation > c.generation (rollover)
		if result.prevHash != "" {
			c.fatal = true
			return fmt.Errorf("%w: rollover commit must have empty prev_hash; got %q",
				ErrStaleResult, result.prevHash)
		}
	}
	c.generation = result.generation
	c.prevHash = result.entryHash
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

// keyAndAlgorithm exposes the chain's key and algorithm for legacy
// IntegrityChain delegation. NOT part of the public Phase 0 contract;
// future code should use Compute and never reach for raw key material.
func (c *SinkChain) keyAndAlgorithm() ([]byte, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.key, c.algorithm
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
