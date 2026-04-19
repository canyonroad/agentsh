package compact

import (
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestEncode_PopulatesCoreFields(t *testing.T) {
	ev := types.Event{
		Type:      "exec.start",
		Timestamp: time.Unix(1_700_000_000, 123),
		Chain:     &types.ChainState{Sequence: 42, Generation: 7},
	}
	got, err := Encode(StubMapper{}, ev)
	if err != nil {
		t.Fatal(err)
	}
	if got.Sequence != 42 {
		t.Errorf("Sequence = %d, want 42", got.Sequence)
	}
	if got.Generation != 7 {
		t.Errorf("Generation = %d, want 7", got.Generation)
	}
	if got.TimestampUnixNanos != uint64(time.Unix(1_700_000_000, 123).UnixNano()) {
		t.Errorf("TimestampUnixNanos wrong: %d", got.TimestampUnixNanos)
	}
	if got.OcsfClassUid != 0 || got.OcsfActivityId != 0 {
		t.Errorf("StubMapper class/activity not propagated")
	}
	if len(got.Payload) == 0 {
		t.Error("payload empty")
	}
	// Integrity is intentionally LEFT NIL by Encode — chain.Compute
	// populates it later in the AppendEvent transactional pattern.
	if got.Integrity != nil {
		t.Errorf("Encode must not populate Integrity (set by chain step)")
	}
}

func TestEncode_RejectsMissingChain(t *testing.T) {
	ev := types.Event{Type: "x", Timestamp: time.Now()}
	_, err := Encode(StubMapper{}, ev)
	if err == nil {
		t.Fatal("Encode must reject ev with nil Chain")
	}
}

func TestEncode_PropagatesMapperError(t *testing.T) {
	failing := failingMapper{}
	ev := types.Event{Type: "x", Timestamp: time.Now(), Chain: &types.ChainState{}}
	_, err := Encode(failing, ev)
	if err == nil {
		t.Fatal("Encode must propagate mapper error")
	}
}

type failingMapper struct{}

func (failingMapper) Map(types.Event) (MappedEvent, error) {
	return MappedEvent{}, errBoom
}

var errBoom = errFromString("boom")

type errFromString string

func (e errFromString) Error() string { return string(e) }
