package audit

import (
	"errors"
	"math"
	"sync"
	"testing"
)

func TestSequenceAllocator_Next_ReturnsZeroFirst(t *testing.T) {
	a := NewSequenceAllocator()
	seq, gen, err := a.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if seq != 0 || gen != 0 {
		t.Fatalf("first Next() = (%d, %d), want (0, 0)", seq, gen)
	}
}

func TestSequenceAllocator_Next_Monotonic(t *testing.T) {
	a := NewSequenceAllocator()
	for i := int64(0); i < 100; i++ {
		seq, gen, err := a.Next()
		if err != nil {
			t.Fatalf("Next #%d: %v", i, err)
		}
		if seq != i {
			t.Fatalf("Next #%d returned seq=%d, want %d", i, seq, i)
		}
		if gen != 0 {
			t.Fatalf("Next #%d returned gen=%d, want 0", i, gen)
		}
	}
}

func TestSequenceAllocator_NextGeneration_ResetsSequence(t *testing.T) {
	a := NewSequenceAllocator()
	if _, _, err := a.Next(); err != nil {
		t.Fatalf("Next: %v", err)
	}
	if _, _, err := a.Next(); err != nil {
		t.Fatalf("Next: %v", err)
	}
	// State now: sequence=1, gen=0; next Next() would return (2, 0).

	newGen, err := a.NextGeneration()
	if err != nil {
		t.Fatalf("NextGeneration: %v", err)
	}
	if newGen != 1 {
		t.Fatalf("NextGeneration() = %d, want 1", newGen)
	}

	seq, gen, err := a.Next()
	if err != nil {
		t.Fatalf("Next after NextGeneration: %v", err)
	}
	if seq != 0 || gen != 1 {
		t.Fatalf("after rollover: Next() = (%d, %d), want (0, 1)", seq, gen)
	}
}

func TestSequenceAllocator_State_Restore_RoundTrip(t *testing.T) {
	a := NewSequenceAllocator()
	for i := 0; i < 5; i++ {
		if _, _, err := a.Next(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.NextGeneration(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Next(); err != nil {
		t.Fatal(err)
	}
	// State: sequence=0, gen=1.

	state := a.State()
	if state.Sequence != 0 || state.Generation != 1 {
		t.Fatalf("State() = %+v, want {Sequence:0 Generation:1}", state)
	}

	b := NewSequenceAllocator()
	if err := b.Restore(state); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	seq, gen, err := b.Next()
	if err != nil {
		t.Fatalf("Next after Restore: %v", err)
	}
	if seq != 1 || gen != 1 {
		t.Fatalf("after restore: Next() = (%d, %d), want (1, 1)", seq, gen)
	}
}

func TestSequenceAllocator_Overflow(t *testing.T) {
	a := NewSequenceAllocator()
	if err := a.Restore(AllocatorState{Sequence: math.MaxInt64, Generation: 0}); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	_, _, err := a.Next()
	if !errors.Is(err, ErrSequenceOverflow) {
		t.Fatalf("Next at MaxInt64: err = %v, want ErrSequenceOverflow", err)
	}
}

func TestSequenceAllocator_ConcurrentNext_NoDuplicates(t *testing.T) {
	a := NewSequenceAllocator()
	const workers = 8
	const perWorker = 1000

	var wg sync.WaitGroup
	results := make(chan int64, workers*perWorker)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				seq, _, err := a.Next()
				if err != nil {
					t.Errorf("Next: %v", err)
					return
				}
				results <- seq
			}
		}()
	}
	wg.Wait()
	close(results)

	seen := make(map[int64]bool, workers*perWorker)
	for s := range results {
		if seen[s] {
			t.Fatalf("duplicate sequence: %d", s)
		}
		seen[s] = true
	}
	if len(seen) != workers*perWorker {
		t.Fatalf("got %d unique sequences, want %d", len(seen), workers*perWorker)
	}
}

func TestSequenceAllocator_NextGeneration_Overflow(t *testing.T) {
	a := NewSequenceAllocator()
	if err := a.Restore(AllocatorState{Sequence: -1, Generation: math.MaxUint32}); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	_, err := a.NextGeneration()
	if !errors.Is(err, ErrGenerationOverflow) {
		t.Fatalf("NextGeneration at MaxUint32: err = %v, want ErrGenerationOverflow", err)
	}

	// Allocator must not be mutated by a rejected NextGeneration.
	state := a.State()
	if state.Generation != math.MaxUint32 {
		t.Fatalf("Generation mutated after rejected NextGeneration: got %d, want MaxUint32", state.Generation)
	}
	if state.Sequence != -1 {
		t.Fatalf("Sequence mutated after rejected NextGeneration: got %d, want -1", state.Sequence)
	}

	// Sequences in the current (max) generation must still allocate cleanly.
	seq, gen, err := a.Next()
	if err != nil {
		t.Fatalf("Next after rejected NextGeneration: %v", err)
	}
	if seq != 0 || gen != math.MaxUint32 {
		t.Fatalf("Next at max generation: got (%d, %d), want (0, MaxUint32)", seq, gen)
	}
}

func TestSequenceAllocator_Restore_RejectsInvalidSequence(t *testing.T) {
	a := NewSequenceAllocator()
	// Allocate one tuple so we have non-default state to verify we don't perturb on reject.
	if _, _, err := a.Next(); err != nil {
		t.Fatalf("Next: %v", err)
	}
	pre := a.State()

	for _, bad := range []int64{-2, -100, math.MinInt64} {
		err := a.Restore(AllocatorState{Sequence: bad, Generation: 5})
		if !errors.Is(err, ErrInvalidAllocatorState) {
			t.Fatalf("Restore(Sequence=%d): err = %v, want ErrInvalidAllocatorState", bad, err)
		}
	}

	// Allocator must be unchanged after rejected restores.
	post := a.State()
	if post != pre {
		t.Fatalf("allocator mutated by rejected Restore: pre=%+v, post=%+v", pre, post)
	}

	// Boundary: Sequence == -1 is the valid minimum (means "no Next() yet").
	if err := a.Restore(AllocatorState{Sequence: -1, Generation: 9}); err != nil {
		t.Fatalf("Restore(Sequence=-1): %v", err)
	}
	seq, gen, err := a.Next()
	if err != nil {
		t.Fatalf("Next after Restore(-1, 9): %v", err)
	}
	if seq != 0 || gen != 9 {
		t.Fatalf("after Restore(-1, 9): Next() = (%d, %d), want (0, 9)", seq, gen)
	}
}
