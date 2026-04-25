package compact

import (
	"errors"
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
	if !errors.Is(err, ErrMissingChain) {
		t.Errorf("err = %v, want errors.Is(err, ErrMissingChain)", err)
	}
}

func TestEncode_RejectsNilMapper(t *testing.T) {
	ev := types.Event{
		Type:      "x",
		Timestamp: time.Unix(1_700_000_000, 0),
		Chain:     &types.ChainState{Sequence: 1, Generation: 1},
	}
	_, err := Encode(nil, ev)
	if err == nil {
		t.Fatal("Encode must reject untyped-nil mapper")
	}
	if !errors.Is(err, ErrInvalidMapper) {
		t.Errorf("err = %v, want errors.Is(err, ErrInvalidMapper)", err)
	}
}

func TestEncode_RejectsTypedNilPointerMapper(t *testing.T) {
	var m *StubMapper // typed-nil pointer; non-nil interface, nil dynamic value
	ev := types.Event{
		Type:      "x",
		Timestamp: time.Unix(1_700_000_000, 0),
		Chain:     &types.ChainState{Sequence: 1, Generation: 1},
	}
	_, err := Encode(m, ev)
	if err == nil {
		t.Fatal("Encode must reject typed-nil pointer mapper")
	}
	if !errors.Is(err, ErrInvalidMapper) {
		t.Errorf("err = %v, want errors.Is(err, ErrInvalidMapper)", err)
	}
}

func TestEncode_PropagatesMapperError(t *testing.T) {
	failing := failingMapper{}
	ev := types.Event{Type: "x", Timestamp: time.Now(), Chain: &types.ChainState{}}
	_, err := Encode(failing, ev)
	if err == nil {
		t.Fatal("Encode must propagate mapper error")
	}
	if !errors.Is(err, errBoom) {
		t.Errorf("err = %v, want wrapped errBoom", err)
	}
	// Pin the linear-unwrap contract preserved by mapperFailureErr
	// (roborev #6192 Low). errors.Unwrap must return the inner error
	// directly — a regression to multi-%w wrapping would have
	// errors.Unwrap return nil and silently break callers using linear
	// unwrapping.
	if got := errors.Unwrap(err); got != errBoom {
		t.Errorf("errors.Unwrap(err) = %v, want %v (linear unwrap broken)", got, errBoom)
	}
	// And errors.Is(_, ErrMapperFailure) must hold so drop-class
	// classifiers can route to the right counter.
	if !errors.Is(err, ErrMapperFailure) {
		t.Errorf("err = %v, want errors.Is(_, ErrMapperFailure)", err)
	}
}

func TestEncode_RejectsZeroTimestamp(t *testing.T) {
	ev := types.Event{
		Type:  "x",
		Chain: &types.ChainState{Sequence: 1, Generation: 1},
		// Timestamp deliberately left as the zero value.
	}
	_, err := Encode(StubMapper{}, ev)
	if err == nil {
		t.Fatal("Encode must reject zero timestamp")
	}
	if !errors.Is(err, ErrInvalidTimestamp) {
		t.Errorf("err = %v, want errors.Is(err, ErrInvalidTimestamp)", err)
	}
}

func TestEncode_RejectsPreEpochTimestamp(t *testing.T) {
	ev := types.Event{
		Type:      "x",
		Timestamp: time.Date(1969, time.December, 31, 23, 59, 59, 0, time.UTC),
		Chain:     &types.ChainState{Sequence: 1, Generation: 1},
	}
	_, err := Encode(StubMapper{}, ev)
	if err == nil {
		t.Fatal("Encode must reject pre-epoch timestamp")
	}
	if !errors.Is(err, ErrInvalidTimestamp) {
		t.Errorf("err = %v, want errors.Is(err, ErrInvalidTimestamp)", err)
	}
}

func TestEncode_AcceptsUnixEpoch(t *testing.T) {
	ev := types.Event{
		Type:      "x",
		Timestamp: time.Unix(0, 0),
		Chain:     &types.ChainState{Sequence: 1, Generation: 1},
	}
	got, err := Encode(StubMapper{}, ev)
	if err != nil {
		t.Fatalf("Encode must accept Unix epoch boundary: %v", err)
	}
	if got.TimestampUnixNanos != 0 {
		t.Errorf("TimestampUnixNanos = %d, want 0", got.TimestampUnixNanos)
	}
}

type failingMapper struct{}

func (failingMapper) Map(types.Event) (MappedEvent, error) {
	return MappedEvent{}, errBoom
}

var errBoom = errFromString("boom")

type errFromString string

func (e errFromString) Error() string { return string(e) }
