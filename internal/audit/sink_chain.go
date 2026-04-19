package audit

import (
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
// Concurrency-safe. Compute+Commit pairs must be issued by a single
// goroutine in order; concurrent Compute calls with interleaved Commits
// is supported but each Commit applies to the most recent Compute that
// observed the same prev_hash.
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
type SinkChainState struct {
	Generation uint32
	PrevHash   string
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
func (c *SinkChain) Commit(generation uint32, entryHash string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fatal {
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

// State returns the (generation, prev_hash) for persistence.
func (c *SinkChain) State() SinkChainState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return SinkChainState{Generation: c.generation, PrevHash: c.prevHash}
}

// Restore rehydrates chain state after restart.
func (c *SinkChain) Restore(generation uint32, prevHash string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.generation = generation
	c.prevHash = prevHash
}
