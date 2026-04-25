package compact

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/agentsh/agentsh/pkg/types"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// ErrInvalidMapper is returned when m is untyped nil or a typed-nil pointer
// implementation of Mapper. Encode performs this check defensively even though
// Store.New (Phase 10) will also reject invalid mappers — the nil-check is
// cheap and removes the temporal coupling on the future store layer.
var ErrInvalidMapper = errors.New("compact.Encode: mapper is required (nil or typed-nil pointer)")

// ErrMissingChain is returned by Encode when ev.Chain is nil — the composite
// store did not stamp the shared (sequence, generation). This is a programming
// error: a WTP sink must run inside the composite store.
var ErrMissingChain = errors.New("compact.Encode: ev.Chain is nil; composite did not stamp")

// ErrInvalidTimestamp is returned when ev.Timestamp is the zero value or
// represents an instant before the Unix epoch. Both cases would silently wrap
// when cast to uint64 nanoseconds, masking caller bugs in the hot path.
var ErrInvalidTimestamp = errors.New("compact.Encode: ev.Timestamp must be non-zero and ≥ Unix epoch")

// ErrMapperFailure is the OUTER sentinel that wraps every error
// returned from a Mapper's Map method. It distinguishes "Encode's own
// validation gates fired" (bare ErrInvalidMapper / ErrInvalidTimestamp
// returned from Encode's pre-call checks) from "the Mapper rejected
// the event" (the call into m.Map returned an error). Without this
// outer sentinel, a Mapper that happens to return ErrInvalidMapper or
// ErrInvalidTimestamp would be misclassified by downstream consumers
// using errors.Is to route drop-class metrics. Callers that classify
// the encoder's error MUST check ErrMapperFailure FIRST so a mapper-
// originated sentinel does not leak into the validation-gate
// counters; see watchtower.recordCompactEncodeFailure.
var ErrMapperFailure = errors.New("compact mapper")

// Encode projects an agentsh event into a wtpv1.CompactEvent, populating
// everything EXCEPT the IntegrityRecord. The IntegrityRecord is filled in by
// the WTP Store in the AppendEvent transactional pattern, AFTER chain.Compute
// returns the entry hash.
//
// Encode is independently safe to call. Store.New (Phase 10) provides
// additional rejection of invalid mappers at construction time, but Encode
// does not depend on it: the nil-check below mirrors the same contract on
// the hot path so the temporal coupling on the future store layer is
// eliminated. This is defense in depth, not redundancy.
//
// Preconditions:
//   - m must be a valid Mapper (non-nil, not typed-nil pointer). Returns
//     ErrInvalidMapper otherwise.
//   - ev.Chain must be non-nil; the composite store stamps this before
//     fanning out to sinks. Returns ErrMissingChain otherwise.
//   - ev.Timestamp must be non-zero and ≥ Unix epoch. Returns
//     ErrInvalidTimestamp otherwise.
//
// Error contract:
//   - errors.Is(err, ErrInvalidMapper) for nil/typed-nil pointer mapper
//   - errors.Is(err, ErrMissingChain) for missing chain
//   - errors.Is(err, ErrInvalidTimestamp) for invalid timestamp
//   - errors.Unwrap returns the mapper error when m.Map fails
func Encode(m Mapper, ev types.Event) (*wtpv1.CompactEvent, error) {
	if m == nil {
		return nil, ErrInvalidMapper
	}
	if rv := reflect.ValueOf(m); rv.Kind() == reflect.Ptr && rv.IsNil() {
		return nil, ErrInvalidMapper
	}
	if ev.Chain == nil {
		return nil, ErrMissingChain
	}
	if ev.Timestamp.IsZero() {
		return nil, ErrInvalidTimestamp
	}
	nanos := ev.Timestamp.UnixNano()
	if nanos < 0 {
		return nil, ErrInvalidTimestamp
	}
	mapped, err := m.Map(ev)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMapperFailure, err)
	}
	return &wtpv1.CompactEvent{
		Sequence:           ev.Chain.Sequence,
		Generation:         ev.Chain.Generation,
		TimestampUnixNanos: uint64(nanos),
		OcsfClassUid:       mapped.OCSFClassUID,
		OcsfActivityId:     mapped.OCSFActivityID,
		Payload:            mapped.Payload,
		// Integrity left nil; populated downstream by the chain step.
	}, nil
}
