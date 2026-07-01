package session

import (
	"sync"
	"sync/atomic"
	"testing"
)

// TestCurrentCommandAttribution_AtomicSnapshot asserts the combined getter
// returns a consistent (commandID, pid) pair: it never mixes data from two
// different commands.
//
// The writer sets the pair atomically (under s.mu, via the unexported fields
// this same-package test can reach) so the only writer states ever created
// are (cmd-A, 1) and (cmd-B, 2). A two-call getter — reading commandID then
// pid in two separate locks — can observe the torn cross-transition pair
// ("cmd-A", 2) or ("cmd-B", 1); a single-lock combined getter cannot. This
// makes the test a reliable discriminator, not a probabilistic one. Run with
// -race so any unsynchronized field access also fails the detector.
func TestCurrentCommandAttribution_AtomicSnapshot(t *testing.T) {
	s := &Session{ID: "attribution-test"}

	const cycles = 1000000
	const readers = 8

	var stop atomic.Bool
	var bad atomic.Int64
	var wg sync.WaitGroup
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				cid, pid := s.CurrentCommandAttribution()
				// Writer only ever creates (cmd-A,1) and (cmd-B,2); these mixed
				// pairs can only come from a torn two-call read.
				if (cid == "cmd-A" && pid == 2) || (cid == "cmd-B" && pid == 1) {
					bad.Add(1)
				}
			}
		}()
	}

	// Writer flips the pair atomically between the two consistent states.
	for i := 0; i < cycles; i++ {
		s.mu.Lock()
		s.currentCommandID = "cmd-A"
		s.currentProcPID = 1
		s.mu.Unlock()
		s.mu.Lock()
		s.currentCommandID = "cmd-B"
		s.currentProcPID = 2
		s.mu.Unlock()
	}
	stop.Store(true)
	wg.Wait()

	if n := bad.Load(); n != 0 {
		t.Fatalf("observed %d torn (commandID, pid) snapshots; combined getter is not atomic", n)
	}
}
