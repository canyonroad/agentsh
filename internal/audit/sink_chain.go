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
// carries no token identifying which Compute it finalizes, so a stale or
// reordered Commit can overwrite prev_hash with a hash that does not
// correspond to the most recent Compute. The expected pattern is a single
// owner that issues Compute → durable write → Commit (or Fatal) in
// sequence per event.
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

// ErrFatalIntegrity is returned by Compute after Fatal has been called.
// The chain cannot be reused; the sink must be reinitialized (e.g., via
// generation rotation).
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
// using the chain's key. Compute is PURE: it does not mutate prev_hash. The
// caller must follow with Commit on durable-write success or discard the
// result on durable-write failure.
//
// If `generation` differs from the chain's current generation, prev_hash
// is treated as "" for this Compute (chain rolls automatically). The
// transition is committed only when Commit is called with the new generation.
//
// Returns ErrFatalIntegrity if Fatal was previously called.
func (c *SinkChain) Compute(formatVersion int, sequence int64, generation uint32, payload []byte) (entryHash string, prevHash string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fatal {
		return "", "", ErrFatalIntegrity
	}
	prev := c.prevHash
	if generation != c.generation {
		prev = ""
	}
	hash, err := computeIntegrityHash(c.key, c.algorithm, formatVersion, sequence, prev, payload)
	if err != nil {
		return "", "", err
	}
	return hash, prev, nil
}

// Commit advances prev_hash to entryHash and records the generation. Must be
// called exactly once per successful Compute, after the durable write
// succeeds. On ambiguous failure (write may or may not have landed), the
// caller MUST call Fatal instead; Commit and Fatal are mutually exclusive
// per Compute.
//
// Commit silently no-ops in two cases: (1) the chain has been latched Fatal,
// and (2) `generation` is older than the chain's current generation —
// rolling backwards across a generation boundary would re-use prior
// (sequence, generation) tuples and corrupt the chain. The latter is a
// caller programming error and is treated as ignorable rather than fatal.
func (c *SinkChain) Commit(generation uint32, entryHash string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fatal {
		return
	}
	if generation < c.generation {
		return
	}
	c.generation = generation
	c.prevHash = entryHash
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
