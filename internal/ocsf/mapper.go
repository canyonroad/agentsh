package ocsf

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/pkg/types"
)

// Mapper is the production OCSF v1.8.0 mapper. It implements
// compact.Mapper. The zero value is NOT usable — construct with New().
//
// Mapper is read-only after New(); Map() is safe for concurrent use.
type Mapper struct {
	registry map[string]Mapping
}

// New returns a Mapper backed by the package's static registry.
func New() *Mapper {
	return &Mapper{registry: registry}
}

// Map projects an agentsh event into a compact.MappedEvent.
//
// Returns ErrUnmappedType if ev.Type is not in the registry (or its
// UnmappedTypeError wrapper which carries the offending Type). Returns
// ErrMissingRequiredField if a Required FieldRule was absent or
// transform-rejected. Returns ErrProjectFailed if the projector
// panicked, returned an error, returned nil, or proto.Marshal failed.
//
// Determinism contract: for any two calls with logically equal `ev`,
// the returned Payload []byte is byte-identical. See
// TestMapDeterministic.
func (m *Mapper) Map(ev types.Event) (compact.MappedEvent, error) {
	rule, ok := m.registry[ev.Type]
	if !ok {
		return compact.MappedEvent{}, &UnmappedTypeError{Type: ev.Type}
	}

	allowed, err := projectFields(ev.Fields, rule.FieldsAllowlist)
	if err != nil {
		return compact.MappedEvent{}, err
	}

	msg, err := safeProject(rule.Project, ev, allowed)
	if err != nil {
		return compact.MappedEvent{}, err
	}

	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return compact.MappedEvent{}, fmt.Errorf("%w: marshal: %v", ErrProjectFailed, err)
	}

	return compact.MappedEvent{
		OCSFClassUID:   rule.ClassUID,
		OCSFActivityID: rule.ActivityID,
		Payload:        payload,
	}, nil
}

// Compile-time check: Mapper implements compact.Mapper.
var _ compact.Mapper = (*Mapper)(nil)
