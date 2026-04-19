// Package compact projects agentsh events into the WTP CompactEvent wire shape.
//
// The OCSF class/activity mapping is Phase 1 work and is injected via the
// Mapper interface. This package provides:
//   - The Mapper interface (production: injected from Phase 1).
//   - A StubMapper used by unit tests; production wiring REJECTS this stub
//     via Store validate() so it never escapes test code.
//   - The Encode function that combines a Mapper with the chain helpers and
//     produces a fully-populated wtpv1.CompactEvent.
package compact

import (
	"encoding/json"
	"fmt"

	"github.com/agentsh/agentsh/pkg/types"
)

// MappedEvent is the Mapper's output: a class/activity pair plus the
// pre-encoded OCSF payload for that class. The Encode function combines this
// with the chain integrity record to produce the final CompactEvent.
type MappedEvent struct {
	OCSFClassUID   uint32
	OCSFActivityID uint32
	Payload        []byte // protobuf-encoded class-specific payload
}

// Mapper projects an agentsh event into the OCSF class identifier and the
// pre-encoded class-specific payload bytes.
//
// Production: injected via watchtower.WithMapper(...) from Phase 1.
// Tests: use StubMapper or a per-test fake.
type Mapper interface {
	Map(types.Event) (MappedEvent, error)
}

// StubMapper is a placeholder Mapper that emits class=0/activity=0 with the
// raw events.Event JSON as payload. It exists to keep the WTP package's own
// unit tests independent of Phase 1; production wiring rejects it.
type StubMapper struct{}

func (StubMapper) Map(ev types.Event) (MappedEvent, error) {
	b, err := json.Marshal(ev)
	if err != nil {
		return MappedEvent{}, fmt.Errorf("stub mapper marshal: %w", err)
	}
	return MappedEvent{OCSFClassUID: 0, OCSFActivityID: 0, Payload: b}, nil
}

// IsStubMapper reports whether m is the StubMapper. Used by Store.validate()
// to reject test-only mappers in production.
func IsStubMapper(m Mapper) bool {
	_, ok := m.(StubMapper)
	return ok
}
