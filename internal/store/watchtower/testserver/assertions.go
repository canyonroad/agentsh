package testserver

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"time"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"
)

// ErrUnsupportedCompression is returned by the assertion helpers when
// the Server has recorded an EventBatch whose Compression enum value
// is one the helper does not know how to decode — typically
// COMPRESSION_UNSPECIFIED, or a future algorithm we have not been
// taught. COMPRESSION_NONE, COMPRESSION_ZSTD, and COMPRESSION_GZIP
// are all decoded transparently by the helpers; tests no longer need
// to drive the Transport in an uncompressed-only configuration to
// make sequence-level assertions work. Errors from the codecs
// themselves (malformed payload, proto unmarshal failure) are also
// wrapped in this sentinel so callers can use errors.Is to gate on
// "the helpers could not extract events from this batch."
var ErrUnsupportedCompression = errors.New("testserver: assertion helpers could not decode recorded batch body")

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

// decodeBatchEvents returns the CompactEvents inside an EventBatch,
// transparently decoding zstd or gzip compressed_payload as needed.
// Returns an error for any Compression value the helper does not
// recognize (UNSPECIFIED, or a future algo we have not been taught).
//
// The decompressed read is bounded by wtpv1.MaxDecompressedBatchBytes
// to mirror the production receiver's defensive cap; testserver tests
// that exercise oversized inputs can rely on the same boundary.
func decodeBatchEvents(b *wtpv1.EventBatch) ([]*wtpv1.CompactEvent, error) {
	switch b.GetCompression() {
	case wtpv1.Compression_COMPRESSION_NONE:
		u := b.GetUncompressed()
		if u == nil {
			return nil, errors.New("body is not UncompressedEvents")
		}
		return u.Events, nil
	case wtpv1.Compression_COMPRESSION_ZSTD:
		raw, err := zstdDecodeBounded(b.GetCompressedPayload(), wtpv1.MaxDecompressedBatchBytes)
		if err != nil {
			return nil, fmt.Errorf("zstd decode: %w", err)
		}
		var u wtpv1.UncompressedEvents
		if err := proto.Unmarshal(raw, &u); err != nil {
			return nil, fmt.Errorf("proto unmarshal: %w", err)
		}
		return u.Events, nil
	case wtpv1.Compression_COMPRESSION_GZIP:
		raw, err := gzipDecodeBounded(b.GetCompressedPayload(), wtpv1.MaxDecompressedBatchBytes)
		if err != nil {
			return nil, fmt.Errorf("gzip decode: %w", err)
		}
		var u wtpv1.UncompressedEvents
		if err := proto.Unmarshal(raw, &u); err != nil {
			return nil, fmt.Errorf("proto unmarshal: %w", err)
		}
		return u.Events, nil
	default:
		return nil, fmt.Errorf("compression=%v not handled", b.GetCompression())
	}
}

// zstdDecodeBounded decompresses the given zstd payload and returns
// up to max+1 bytes. The +1 is intentional: callers can detect a cap
// hit by observing len(out) > max rather than silently truncating at
// exactly the cap. The testserver call sites do not currently enforce
// the cap; production receivers will via the validator.
func zstdDecodeBounded(in []byte, max int) ([]byte, error) {
	r, err := zstd.NewReader(bytes.NewReader(in))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(io.LimitReader(r, int64(max)+1))
}

// gzipDecodeBounded decompresses the given gzip payload and returns
// up to max+1 bytes. See zstdDecodeBounded for the cap-detection
// rationale.
func gzipDecodeBounded(in []byte, max int) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(in))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(io.LimitReader(r, int64(max)+1))
}

// compactEventSequences flattens every UncompressedEvents' CompactEvent
// Sequence field across all recorded batches into an ordered slice.
// Compressed bodies (zstd, gzip) are decoded transparently via
// decodeBatchEvents. Returns ErrUnsupportedCompression (wrapping the
// underlying decode error) if any recorded batch uses a Compression
// enum value the helper does not recognize, or if a known codec
// fails to decode its payload — silently skipping such batches would
// produce misleading "missing seq" diagnostics.
//
// Non-goal: this helper does NOT validate CompactEvent.generation,
// EventBatch.from_sequence / to_sequence, or the compression / body
// oneof consistency beyond the fail-fast check above. Tests that
// need those invariants must assert them explicitly from the
// Server.Batches snapshot.
func (s *Server) compactEventSequences() ([]uint64, error) {
	out := []uint64{}
	for i, b := range s.Batches() {
		evs, err := decodeBatchEvents(b)
		if err != nil {
			return nil, fmt.Errorf("%w (batch index=%d, compression=%v): %v",
				ErrUnsupportedCompression, i, b.GetCompression(), err)
		}
		for _, ev := range evs {
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
