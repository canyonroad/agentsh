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
