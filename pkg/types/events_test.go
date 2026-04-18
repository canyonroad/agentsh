package types

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecveEvent_JSON(t *testing.T) {
	ev := Event{
		ID:        "evt-123",
		Type:      "execve",
		Timestamp: time.Now(),
		SessionID: "sess-456",
		PID:       1234,
		ParentPID: 1000,
		Depth:     2,
		Filename:  "/usr/bin/curl",
		Argv:      []string{"curl", "-X", "POST", "http://example.com"},
		Truncated: false,
		Policy: &PolicyInfo{
			Decision:          "deny",
			EffectiveDecision: "deny",
			Rule:              "block-curl-nested",
		},
		EffectiveAction: "blocked",
	}

	data, err := json.Marshal(ev)
	require.NoError(t, err)

	var decoded Event
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "execve", decoded.Type)
	assert.Equal(t, 2, decoded.Depth)
	assert.Equal(t, "/usr/bin/curl", decoded.Filename)
	assert.Equal(t, []string{"curl", "-X", "POST", "http://example.com"}, decoded.Argv)
	assert.Equal(t, 1234, decoded.PID)
	assert.Equal(t, 1000, decoded.ParentPID)
	assert.False(t, decoded.Truncated)
}

// TestEvent_ChainFieldNotMarshaled is a load-bearing safety test for the
// Phase 0 contract: the typed Chain field MUST NEVER appear in JSON output,
// because it carries internal sink coordination state, not user-visible data.
func TestEvent_ChainFieldNotMarshaled(t *testing.T) {
	ev := Event{
		ID:        "abc",
		Timestamp: time.Unix(1700000000, 0).UTC(),
		Type:      "file_open",
		SessionID: "sess-1",
		Chain:     NewChainState(42, 7),
	}

	out, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got := string(out)

	for _, banned := range []string{`"chain"`, `"Chain"`, `"sequence":42`, `"generation":7`} {
		if strings.Contains(got, banned) {
			t.Errorf("Event JSON must not contain %q; got %s", banned, got)
		}
	}
}

// TestEvent_ChainFieldIgnoredOnUnmarshal verifies that decoding JSON which
// happens to contain a "chain" key does not populate Event.Chain.
func TestEvent_ChainFieldIgnoredOnUnmarshal(t *testing.T) {
	raw := []byte(`{"id":"x","type":"file_open","session_id":"s","timestamp":"2024-01-02T03:04:05Z","chain":{"sequence":99,"generation":3}}`)
	var ev Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if ev.Chain != nil {
		t.Fatalf("Chain should remain nil after unmarshal, got %+v", ev.Chain)
	}
}

// TestChainState_Immutable verifies that the ChainState pointer aliased
// across sinks during composite fanout cannot be mutated by any sink.
// This is the structural guarantee that justifies sharing the pointer
// rather than deep-copying per sink.
func TestChainState_Immutable(t *testing.T) {
	c := NewChainState(100, 5)
	if c.Sequence() != 100 {
		t.Fatalf("Sequence(): got %d, want 100", c.Sequence())
	}
	if c.Generation() != 5 {
		t.Fatalf("Generation(): got %d, want 5", c.Generation())
	}

	// The struct fields are unexported; outside the types package this
	// test wouldn't even compile if a caller tried to write c.sequence = 0.
	// Inside the package we can demonstrate the read-only intent by
	// confirming that two readers see the same values regardless of order.
	c2 := c
	if c2.Sequence() != c.Sequence() || c2.Generation() != c.Generation() {
		t.Fatalf("aliased pointer reads diverged: c=%v c2=%v", c, c2)
	}
}
