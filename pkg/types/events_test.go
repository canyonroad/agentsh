package types

import (
	"encoding/json"
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
