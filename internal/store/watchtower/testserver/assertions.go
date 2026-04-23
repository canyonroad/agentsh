package testserver

import (
	"fmt"
	"time"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// WaitForBatch blocks until the server has recorded at least one
// EventBatch or deadline elapses. Returns the FIRST recorded batch on
// success (not a copy — callers MUST NOT mutate the returned proto).
// On timeout returns (nil, non-nil error).
//
// Polling interval is 5ms; callers should pick a deadline that
// accommodates the real-time latency of their scenario plus a
// comfortable margin for scheduler jitter.
func (s *Server) WaitForBatch(deadline time.Duration) (*wtpv1.EventBatch, error) {
	expire := time.After(deadline)
	for {
		bs := s.Batches()
		if len(bs) > 0 {
			return bs[0], nil
		}
		select {
		case <-expire:
			return nil, fmt.Errorf("WaitForBatch: timeout after %v with no EventBatch received", deadline)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// compactEventSequences flattens every CompactEvent in every batch
// recorded on the server into an ordered slice of seqs. Used by the
// assertions below; kept private because the wire invariants it
// depends on (uncompressed-only today) are testserver-internal.
//
// Only UncompressedEvents are surfaced — compressed EventBatches
// cannot be inspected at this layer without introducing a zstd /
// lz4 dependency. Tests that need sequence-level assertions MUST
// drive the transport in a configuration that produces uncompressed
// batches (which is the default for the MVP; compression is a
// Task-22+ concern).
func (s *Server) compactEventSequences() []uint64 {
	out := []uint64{}
	for _, b := range s.Batches() {
		u := b.GetUncompressed()
		if u == nil {
			continue
		}
		for _, ev := range u.GetEvents() {
			out = append(out, ev.GetSequence())
		}
	}
	return out
}

// AssertSequenceRange verifies the union of all received
// UncompressedEvents across all batches covers EXACTLY [first, last]
// with no gaps, no duplicates, and no out-of-range sequences.
// Returns nil if the assertion holds; otherwise a non-nil error
// identifying the first failure (deterministic order: out-of-range,
// duplicate, missing).
//
// Intended for happy-path tests that expect a known contiguous run.
// For "replay then live" tests that tolerate extra seqs past `last`,
// use AssertReplayObserved instead.
func (s *Server) AssertSequenceRange(first, last uint64) error {
	seen := map[uint64]bool{}
	for _, seq := range s.compactEventSequences() {
		if seq < first || seq > last {
			return fmt.Errorf("AssertSequenceRange[%d..%d]: observed seq %d outside expected range", first, last, seq)
		}
		if seen[seq] {
			return fmt.Errorf("AssertSequenceRange[%d..%d]: duplicate seq %d", first, last, seq)
		}
		seen[seq] = true
	}
	for seq := first; seq <= last; seq++ {
		if !seen[seq] {
			return fmt.Errorf("AssertSequenceRange[%d..%d]: missing seq %d", first, last, seq)
		}
		if seq == ^uint64(0) {
			// Defensive: last == math.MaxUint64 would underflow the
			// loop increment below.
			break
		}
	}
	return nil
}

// AssertReplayObserved verifies that every sequence in [first, last]
// was observed in some batch, allowing additional sequences outside
// the range (e.g. later Live-era records appended after the replay
// window). Does NOT check for duplicates — replay + live can
// legitimately overlap on the boundary record in some configurations.
//
// Intended for replay tests that prove "the replay window landed"
// without over-constraining what happens after it.
func (s *Server) AssertReplayObserved(first, last uint64) error {
	seen := map[uint64]bool{}
	for _, seq := range s.compactEventSequences() {
		seen[seq] = true
	}
	for seq := first; seq <= last; seq++ {
		if !seen[seq] {
			return fmt.Errorf("AssertReplayObserved[%d..%d]: missing seq %d in observed batches", first, last, seq)
		}
		if seq == ^uint64(0) {
			break
		}
	}
	return nil
}
