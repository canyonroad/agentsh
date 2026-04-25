package compact

import (
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestStubMapper_MapsToZeroClass(t *testing.T) {
	ev := types.Event{
		ID:        "abc",
		Type:      "exec.start",
		SessionID: "sess1",
		Timestamp: time.Unix(1700000000, 123),
	}
	m := StubMapper{}
	out, err := m.Map(ev)
	if err != nil {
		t.Fatal(err)
	}
	if out.OCSFClassUID != 0 || out.OCSFActivityID != 0 {
		t.Errorf("StubMapper should produce class=0 activity=0, got class=%d activity=%d", out.OCSFClassUID, out.OCSFActivityID)
	}
	if len(out.Payload) == 0 {
		t.Error("StubMapper should set non-empty payload")
	}
}

func TestStubMapper_DeterministicForSameEvent(t *testing.T) {
	ev := types.Event{
		ID:        "abc",
		Type:      "exec.start",
		SessionID: "sess1",
		Timestamp: time.Unix(1700000000, 0),
	}
	m := StubMapper{}
	a, _ := m.Map(ev)
	b, _ := m.Map(ev)
	if string(a.Payload) != string(b.Payload) {
		t.Error("StubMapper should be deterministic")
	}
}

// TestIsStubMapper_DetectsValueAndPointer verifies the type switch in
// IsStubMapper accepts both StubMapper{} and *StubMapper, including a
// typed-nil pointer wrapped in the Mapper interface. The typed-nil case
// is critical: a caller passing (*StubMapper)(nil) would slip past a
// value-only check, but Store.validate() must reject it the same as a
// value form so the stub never escapes test code in production.
func TestIsStubMapper_DetectsValueAndPointer(t *testing.T) {
	if !IsStubMapper(StubMapper{}) {
		t.Error("value form must be detected")
	}
	if !IsStubMapper(&StubMapper{}) {
		t.Error("pointer form must be detected")
	}
	var typedNil *StubMapper
	if !IsStubMapper(typedNil) {
		t.Error("typed-nil pointer wrapped in Mapper interface must be detected")
	}
}

// TestIsStubMapper_RejectsUntypedNil verifies that IsStubMapper does NOT
// claim an untyped nil is the stub. validate() handles nil mappers
// separately with a clearer "mapper is required" error.
func TestIsStubMapper_RejectsUntypedNil(t *testing.T) {
	if IsStubMapper(nil) {
		t.Error("untyped nil must not be detected as the stub (validate() handles nil separately)")
	}
}

type fakeMapper struct{}

func (fakeMapper) Map(types.Event) (MappedEvent, error) { return MappedEvent{}, nil }

// TestIsStubMapper_RejectsOtherImplementations ensures the type switch
// does not over-match: any other Mapper implementation must return false
// so production callers' real mappers are not mistakenly rejected.
func TestIsStubMapper_RejectsOtherImplementations(t *testing.T) {
	if IsStubMapper(fakeMapper{}) {
		t.Error("non-stub Mapper must not be detected")
	}
}
