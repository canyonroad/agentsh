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

	newGen := a.NextGeneration()
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
	a.NextGeneration()
	if _, _, err := a.Next(); err != nil {
		t.Fatal(err)
	}
	// State: sequence=0, gen=1.

	state := a.State()
	if state.Sequence != 0 || state.Generation != 1 {
		t.Fatalf("State() = %+v, want {Sequence:0 Generation:1}", state)
	}

	b := NewSequenceAllocator()
	b.Restore(state)
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
	a.Restore(AllocatorState{Sequence: math.MaxInt64, Generation: 0})

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
