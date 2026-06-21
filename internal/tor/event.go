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

// BuildGatewayEvent constructs a session-level tor_control event describing the
// Phase 3 onion-gateway wiring outcome. decision is "allow" (force-redirect
// armed) or "deny" (fail-closed). reason names the cause. enforced is false
// only when a fail-closed deny cannot actually be enforced (no live syscall
// enforcement subsystem for the session).
func BuildGatewayEvent(sessionID, decision, reason string, enforced bool) types.Event {
	return types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "tor_control",
		SessionID: sessionID,
		Fields: map[string]any{
			"vector":   VectorGateway,
			"decision": decision,
			"reason":   reason,
			"enforced": enforced,
			"rule":     "tor",
		},
	}
}
