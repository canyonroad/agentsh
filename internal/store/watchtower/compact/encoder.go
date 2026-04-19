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

// Encode projects an agentsh event into a wtpv1.CompactEvent, populating
// everything EXCEPT the IntegrityRecord. The IntegrityRecord is filled in by
// the WTP Store in the AppendEvent transactional pattern, AFTER chain.Compute
// returns the entry hash.
func Encode(m Mapper, ev types.Event) (*wtpv1.CompactEvent, error) {
	if ev.Chain == nil {
		return nil, ErrMissingChain
	}
	mapped, err := m.Map(ev)
	if err != nil {
		return nil, fmt.Errorf("compact mapper: %w", err)
	}
	return &wtpv1.CompactEvent{
		Sequence:           ev.Chain.Sequence,
		Generation:         ev.Chain.Generation,
		TimestampUnixNanos: uint64(ev.Timestamp.UnixNano()),
		OcsfClassUid:       mapped.OCSFClassUID,
		OcsfActivityId:     mapped.OCSFActivityID,
		Payload:            mapped.Payload,
		// Integrity left nil; populated downstream by the chain step.
	}, nil
}
