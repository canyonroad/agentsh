package events

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSeccompBlockedEventJSON(t *testing.T) {
	evt := SeccompBlockedEvent{
		BaseEvent: BaseEvent{
			Type:      EventSeccompBlocked,
			Timestamp: "2024-01-15T10:30:00Z",
			SessionID: "sess_abc123",
		},
		PID:       12345,
		Comm:      "malicious-tool",
		Syscall:   "ptrace",
		SyscallNr: 101,
		Reason:    "blocked_by_policy",
		Action:    "killed",
	}

	data, err := json.Marshal(evt)
	require.NoError(t, err)
	require.Contains(t, string(data), `"type":"seccomp_blocked"`)
	require.Contains(t, string(data), `"syscall":"ptrace"`)
	require.Contains(t, string(data), `"action":"killed"`)
}
