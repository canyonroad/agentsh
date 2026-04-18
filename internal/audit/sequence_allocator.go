package audit

import (
	"math"
	"sync"
)

// SequenceAllocator owns the shared (sequence, generation) tuple. It has no
// hash state. Composite holds exactly one allocator and stamps every event
// with the next allocated tuple before fanning out to chained sinks.
//
// Sequence is monotonically increasing within a generation, starting at 0.
// Generation is incremented by NextGeneration() and resets sequence so the
// next Next() returns (0, new_generation).
//
// Concurrency-safe.
type SequenceAllocator struct {
	mu         sync.Mutex
	sequence   int64  // last returned sequence; -1 means "none yet"
	generation uint32 // current generation
}

// AllocatorState captures the allocator's persistent state. Snapshot via
// State() and rehydrate with Restore() across restarts.
type AllocatorState struct {
	Sequence   int64
	Generation uint32
}

// NewSequenceAllocator creates an allocator whose first Next() returns (0, 0).
func NewSequenceAllocator() *SequenceAllocator {
	return &SequenceAllocator{sequence: -1}
}

// Next returns the next (sequence, generation) and advances the counter.
// Returns ErrSequenceOverflow when sequence == math.MaxInt64; the caller
// should treat this as fatal (it implies > 9.2e18 events in a single
// generation, so a generation rotation is the recovery path).
func (a *SequenceAllocator) Next() (sequence int64, generation uint32, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sequence == math.MaxInt64 {
		return 0, 0, ErrSequenceOverflow
	}
	a.sequence++
	return a.sequence, a.generation, nil
}

// NextGeneration increments generation and resets sequence so the next Next()
// returns (0, new_generation). Returns the new generation. Used by the
// composite owner when the chain key rotates.
func (a *SequenceAllocator) NextGeneration() uint32 {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.generation++
	a.sequence = -1
	return a.generation
}

// State returns the current (sequence, generation) for persistence. After
// Restore(state), the next Next() returns (state.Sequence + 1, state.Generation).
func (a *SequenceAllocator) State() AllocatorState {
	a.mu.Lock()
	defer a.mu.Unlock()
	return AllocatorState{Sequence: a.sequence, Generation: a.generation}
}

// Restore rehydrates allocator state after restart.
func (a *SequenceAllocator) Restore(state AllocatorState) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sequence = state.Sequence
	a.generation = state.Generation
}
