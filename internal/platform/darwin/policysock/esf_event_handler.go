//go:build darwin

package policysock

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

// esfEventStore is the subset of store.EventStore needed by ESFEventHandler.
type esfEventStore interface {
	AppendEvent(ctx context.Context, ev types.Event) error
}

// ESFEventHandler processes ESF events from the sysext and stores them.
type ESFEventHandler struct {
	store       esfEventStore
	cmdResolver *CommandResolver
	tracker     *SessionTracker
}

// NewESFEventHandler creates a handler that processes ESF events.
func NewESFEventHandler(store esfEventStore, cmdResolver *CommandResolver, tracker *SessionTracker) *ESFEventHandler {
	return &ESFEventHandler{
		store:       store,
		cmdResolver: cmdResolver,
		tracker:     tracker,
	}
}

// esfEvent is the JSON structure sent by the Swift sysext.
type esfEvent struct {
	Type      string `json:"type"`
	EventType string `json:"event_type"`
	Path      string `json:"path"`
	Path2     string `json:"path2,omitempty"`
	Operation string `json:"operation"`
	PID       int32  `json:"pid"`
	ChildPID  int32  `json:"child_pid,omitempty"`
	SessionID string `json:"session_id"`
	Decision  string `json:"decision"`
	Rule      string `json:"rule"`
	Action    string `json:"action,omitempty"`
	Timestamp string `json:"timestamp"`
}

// HandleESFEvent implements the EventHandler interface.
func (h *ESFEventHandler) HandleESFEvent(ctx context.Context, payload []byte) error {
	var ev esfEvent
	if err := json.Unmarshal(payload, &ev); err != nil {
		return fmt.Errorf("unmarshal esf event: %w", err)
	}

	switch ev.EventType {
	case "process_fork":
		h.cmdResolver.RegisterFork(ev.PID, ev.ChildPID)
		return nil
	case "process_exit":
		h.cmdResolver.UnregisterPID(ev.PID)
		return nil
	}

	// Resolve command ID from PID
	commandID := h.cmdResolver.CommandForPID(ev.PID)

	// Resolve session ID -- prefer payload, fall back to tracker
	sessionID := ev.SessionID
	if sessionID == "" {
		sessionID = h.tracker.SessionForPID(ev.PID)
	}

	// Parse timestamp
	ts, err := time.Parse(time.RFC3339, ev.Timestamp)
	if err != nil {
		ts = time.Now()
	}

	// Build types.Event
	event := types.Event{
		ID:        uuid.NewString(),
		Timestamp: ts,
		Type:      ev.EventType,
		SessionID: sessionID,
		CommandID: commandID,
		Source:    "esf",
		PID:       int(ev.PID),
		Path:      ev.Path,
		Operation: ev.Operation,
		Fields:    make(map[string]any),
	}

	// Policy info
	if ev.Decision != "" {
		event.Policy = &types.PolicyInfo{
			Decision: types.Decision(ev.Decision),
			Rule:     ev.Rule,
		}
	}

	// Extra fields
	if ev.Path2 != "" {
		event.Fields["path2"] = ev.Path2
	}
	if ev.Action != "" {
		event.Fields["action"] = ev.Action
	}

	if err := h.store.AppendEvent(ctx, event); err != nil {
		slog.Warn("failed to store ESF event", "type", ev.EventType, "error", err)
		return err
	}

	return nil
}
