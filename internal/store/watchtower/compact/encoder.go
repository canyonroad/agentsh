package compact

import (
	"errors"
	"fmt"

	"github.com/agentsh/agentsh/pkg/types"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// ErrMissingChain is returned by Encode when ev.Chain is nil — the composite
// store did not stamp the shared (sequence, generation). This is a programming
// error: a WTP sink must run inside the composite store.
var ErrMissingChain = errors.New("compact.Encode: ev.Chain is nil; composite did not stamp")

// ErrInvalidTimestamp is returned when ev.Timestamp is the zero value or
// represents an instant before the Unix epoch. Both cases would silently wrap
// when cast to uint64 nanoseconds, masking caller bugs in the hot path.
var ErrInvalidTimestamp = errors.New("compact.Encode: ev.Timestamp must be non-zero and ≥ Unix epoch")

// Encode projects an agentsh event into a wtpv1.CompactEvent, populating
// everything EXCEPT the IntegrityRecord. The IntegrityRecord is filled in by
// the WTP Store in the AppendEvent transactional pattern, AFTER chain.Compute
// returns the entry hash.
//
// Preconditions (caller's responsibility — see Store.New validate):
//   - m must be a valid Mapper (non-nil, not typed-nil pointer). Encode does
//     NOT re-validate; mapper validity is owned by Store.New.
//   - ev.Chain must be non-nil; the composite store stamps this before
//     fanning out to sinks. Returns ErrMissingChain otherwise.
//   - ev.Timestamp must be non-zero and ≥ Unix epoch. Returns
//     ErrInvalidTimestamp otherwise.
//
// Error contract:
//   - errors.Is(err, ErrMissingChain) for missing chain
//   - errors.Is(err, ErrInvalidTimestamp) for invalid timestamp
//   - errors.Unwrap returns the mapper error when m.Map fails
func Encode(m Mapper, ev types.Event) (*wtpv1.CompactEvent, error) {
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
		return nil, fmt.Errorf("compact mapper: %w", err)
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
