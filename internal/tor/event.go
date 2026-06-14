package tor

import (
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

// BuildControlEvent constructs a tor_control audit event from a Verdict.
// Callers append+publish it via their session emitter.
func BuildControlEvent(sessionID, commandID string, pid int, v Verdict) types.Event {
	return types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "tor_control",
		SessionID: sessionID,
		CommandID: commandID,
		PID:       pid,
		Fields: map[string]any{
			"vector":   v.Vector,
			"mode":     v.Mode,
			"decision": v.Decision,
			"target":   v.Target,
			"rule":     "tor",
		},
	}
}
