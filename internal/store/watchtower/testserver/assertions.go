package testserver

import (
	"errors"
	"fmt"
	"time"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"google.golang.org/protobuf/proto"
)

// ErrUnsupportedCompression is returned by the assertion helpers when
// the Server has recorded an EventBatch whose Body is not an
// UncompressedEvents oneof variant. The helpers CANNOT decode
// compressed batches without a compression-specific codec (zstd /
// lz4), which the MVP test harness does not carry as a dependency.
// Tests that need sequence-level assertions MUST drive the Transport
// in a configuration that produces uncompressed batches.
var ErrUnsupportedCompression = errors.New("testserver: recorded batch body is not UncompressedEvents; assertion helpers cannot decode compressed batches")

// ErrInvalidRange is returned by AssertSequenceRange and
// AssertReplayObserved when first > last. The helpers interpret the
// range as inclusive on both ends; first == last is a valid single-
// seq assertion. first > last almost always indicates a test-setup
// bug (swapped arguments), so the helpers fail fast rather than
// silently accepting any input.
var ErrInvalidRange = errors.New("testserver: invalid range (first > last)")

// WaitForFirstBatch blocks until the Server has recorded at least one
// EventBatch, then returns a DEEP COPY of the first batch (safe for
// callers to mutate). On deadline elapse returns (nil, non-nil err).
//
// Semantics: "first" means the earliest batch recorded across the
// Server's lifetime, NOT "the next batch after this call returns."
// Reused servers and multi-phase tests will unblock immediately on
// batches from earlier phases. Tests that need "wait for new data"
// semantics should snapshot len(srv.Batches()) before the phase and
// poll until it grows.
//
// Polling interval is 5ms; callers should pick a deadline that
// accommodates their scenario's real-time latency plus scheduler
// jitter. The returned deep copy isolates the caller's assertions
// from any later mutation of the Server's internal batch slice.
func (s *Server) WaitForFirstBatch(deadline time.Duration) (*wtpv1.EventBatch, error) {
	expire := time.After(deadline)
	for {
		bs := s.Batches()
		if len(bs) > 0 {
			// Clone so caller mutation does not corrupt later
			// assertions. proto.Clone is defined to return a
			// disjoint message tree.
			return proto.Clone(bs[0]).(*wtpv1.EventBatch), nil
		}
		select {
		case <-expire:
			return nil, fmt.Errorf("WaitForFirstBatch: timeout after %v with no EventBatch recorded", deadline)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// compactEventSequences flattens every UncompressedEvents' CompactEvent
// Sequence field across all recorded batches into an ordered slice.
// Returns ErrUnsupportedCompression if any recorded batch's Body is
// not an UncompressedEvents variant — the helpers cannot decode
// compressed bodies without additional codec dependencies, and
// silently skipping them would produce misleading "missing seq"
// diagnostics.
//
// Non-goal: this helper does NOT validate CompactEvent.generation,
// EventBatch.from_sequence / to_sequence, or the compression / body
// oneof consistency beyond the fail-fast check above. Tests that
// need those invariants must assert them explicitly from the
// Server.Batches snapshot.
func (s *Server) compactEventSequences() ([]uint64, error) {
	out := []uint64{}
	for i, b := range s.Batches() {
		u := b.GetUncompressed()
		if u == nil {
			return nil, fmt.Errorf("%w (batch index=%d, compression=%v)", ErrUnsupportedCompression, i, b.GetCompression())
		}
		for _, ev := range u.GetEvents() {
			out = append(out, ev.GetSequence())
		}
	}
	return out, nil
}

// AssertSequenceRange verifies the union of all received
// UncompressedEvents across all batches covers EXACTLY [first, last]
// (inclusive on both ends) with no gaps, no duplicates, and no out-
// of-range sequences.
//
// Returns nil iff the assertion holds. Otherwise a non-nil error
// with a deterministic diagnostic precedence:
//
//  1. ErrInvalidRange (wrapped, with helper-name prefix) if first > last.
//  2. ErrUnsupportedCompression (wrapped, with helper-name prefix) if
//     any recorded batch is not uncompressed.
//  3. Out-of-range seq (first observed seq <first or >last).
//  4. Duplicate seq.
//  5. Missing seq.
//
// All error messages start with "AssertSequenceRange[first..last]: "
// so callers can grep CI logs by the helper name. Sentinel-error
// branches (1, 2) wrap the package-level sentinel so callers can
// also use errors.Is to discriminate.
//
// Intended for happy-path tests expecting a known contiguous run.
// For replay tests that tolerate extra seqs past `last`, use
// AssertReplayObserved.
func (s *Server) AssertSequenceRange(first, last uint64) error {
	prefix := fmt.Sprintf("AssertSequenceRange[%d..%d]", first, last)
	if first > last {
		return fmt.Errorf("%s: %w (first=%d, last=%d)", prefix, ErrInvalidRange, first, last)
	}
	seqs, err := s.compactEventSequences()
	if err != nil {
		return fmt.Errorf("%s: %w", prefix, err)
	}
	seen := map[uint64]bool{}
	for _, seq := range seqs {
		if seq < first || seq > last {
			return fmt.Errorf("%s: observed seq %d outside expected range", prefix, seq)
		}
		if seen[seq] {
			return fmt.Errorf("%s: duplicate seq %d", prefix, seq)
		}
		seen[seq] = true
	}
	for seq := first; seq <= last; seq++ {
		if !seen[seq] {
			return fmt.Errorf("%s: missing seq %d", prefix, seq)
		}
		if seq == ^uint64(0) {
			// Defensive: last == math.MaxUint64 would underflow the
			// loop increment below. Unreachable under realistic
			// WAL-sourced sequences but guarded so the helper can
			// never infinite-loop on pathological input.
			break
		}
	}
	return nil
}

// AssertReplayObserved verifies that every sequence in [first, last]
// (inclusive) was observed in some batch. Unlike AssertSequenceRange,
// this helper tolerates additional sequences outside the range (e.g.
// later Live-era records appended after the replay window) AND
// tolerates duplicates (replay + live can legitimately overlap on
// the boundary record in some configurations).
//
// Error precedence mirrors AssertSequenceRange (with prefix
// "AssertReplayObserved[first..last]: "):
//
//  1. ErrInvalidRange (wrapped) if first > last.
//  2. ErrUnsupportedCompression (wrapped) if any recorded batch is
//     not uncompressed.
//  3. Missing seq in the [first, last] window.
//
// Intended for replay tests that prove "the replay window landed"
// without over-constraining what happens after it.
func (s *Server) AssertReplayObserved(first, last uint64) error {
	prefix := fmt.Sprintf("AssertReplayObserved[%d..%d]", first, last)
	if first > last {
		return fmt.Errorf("%s: %w (first=%d, last=%d)", prefix, ErrInvalidRange, first, last)
	}
	seqs, err := s.compactEventSequences()
	if err != nil {
		return fmt.Errorf("%s: %w", prefix, err)
	}
	seen := map[uint64]bool{}
	for _, seq := range seqs {
		seen[seq] = true
	}
	for seq := first; seq <= last; seq++ {
		if !seen[seq] {
			return fmt.Errorf("%s: missing seq %d in observed batches", prefix, seq)
		}
		if seq == ^uint64(0) {
			break
		}
	}
	return nil
}
