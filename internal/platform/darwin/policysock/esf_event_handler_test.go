//go:build darwin

package policysock

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

// fakeEventStore captures events for testing.
type fakeEventStore struct {
	events []types.Event
}

func (f *fakeEventStore) AppendEvent(_ context.Context, ev types.Event) error {
	f.events = append(f.events, ev)
	return nil
}

func TestESFEventHandler_FileOpen(t *testing.T) {
	store := &fakeEventStore{}
	cr := NewCommandResolver()
	cr.RegisterCommand(1234, "cmd-test-123")
	tracker := NewSessionTracker()

	h := NewESFEventHandler(store, cr, tracker)

	payload, _ := json.Marshal(map[string]any{
		"type":       "file_event",
		"event_type": "file_open",
		"path":       "/workspace/secret.txt",
		"operation":  "read",
		"pid":        1234,
		"session_id": "session-abc",
		"decision":   "allow",
		"rule":       "allow-workspace-read",
		"timestamp":  "2026-04-02T16:34:08Z",
	})

	err := h.HandleESFEvent(context.Background(), payload)
	if err != nil {
		t.Fatalf("HandleESFEvent error: %v", err)
	}

	if len(store.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(store.events))
	}

	ev := store.events[0]
	if ev.Type != "file_open" {
		t.Errorf("Type = %q, want %q", ev.Type, "file_open")
	}
	if ev.Path != "/workspace/secret.txt" {
		t.Errorf("Path = %q, want %q", ev.Path, "/workspace/secret.txt")
	}
	if ev.SessionID != "session-abc" {
		t.Errorf("SessionID = %q, want %q", ev.SessionID, "session-abc")
	}
	if ev.CommandID != "cmd-test-123" {
		t.Errorf("CommandID = %q, want %q", ev.CommandID, "cmd-test-123")
	}
	if ev.Source != "esf" {
		t.Errorf("Source = %q, want %q", ev.Source, "esf")
	}
	if ev.Operation != "read" {
		t.Errorf("Operation = %q, want %q", ev.Operation, "read")
	}
}

func TestESFEventHandler_FileRename(t *testing.T) {
	store := &fakeEventStore{}
	cr := NewCommandResolver()
	tracker := NewSessionTracker()

	h := NewESFEventHandler(store, cr, tracker)

	payload, _ := json.Marshal(map[string]any{
		"type":       "file_event",
		"event_type": "file_rename",
		"path":       "/workspace/old.txt",
		"path2":      "/workspace/new.txt",
		"pid":        100,
		"session_id": "session-abc",
		"decision":   "allow",
		"rule":       "allow-workspace",
		"timestamp":  "2026-04-02T16:35:00Z",
	})

	err := h.HandleESFEvent(context.Background(), payload)
	if err != nil {
		t.Fatalf("HandleESFEvent error: %v", err)
	}

	ev := store.events[0]
	if ev.Type != "file_rename" {
		t.Errorf("Type = %q, want %q", ev.Type, "file_rename")
	}
	if ev.Fields["path2"] != "/workspace/new.txt" {
		t.Errorf("Fields[path2] = %v, want %q", ev.Fields["path2"], "/workspace/new.txt")
	}
}

func TestESFEventHandler_ProcessFork(t *testing.T) {
	store := &fakeEventStore{}
	cr := NewCommandResolver()
	cr.RegisterCommand(100, "cmd-parent")
	tracker := NewSessionTracker()

	h := NewESFEventHandler(store, cr, tracker)

	payload, _ := json.Marshal(map[string]any{
		"type":       "file_event",
		"event_type": "process_fork",
		"pid":        100,
		"child_pid":  101,
		"session_id": "session-abc",
		"timestamp":  "2026-04-02T16:36:00Z",
	})

	err := h.HandleESFEvent(context.Background(), payload)
	if err != nil {
		t.Fatalf("HandleESFEvent error: %v", err)
	}

	// Fork should register child PID, not store an event
	if len(store.events) != 0 {
		t.Errorf("expected 0 stored events for fork, got %d", len(store.events))
	}
	if cr.CommandForPID(101) != "cmd-parent" {
		t.Errorf("child PID command = %q, want %q", cr.CommandForPID(101), "cmd-parent")
	}
}

func TestESFEventHandler_ProcessExit(t *testing.T) {
	store := &fakeEventStore{}
	cr := NewCommandResolver()
	cr.RegisterCommand(100, "cmd-test")
	tracker := NewSessionTracker()

	h := NewESFEventHandler(store, cr, tracker)

	payload, _ := json.Marshal(map[string]any{
		"type":       "file_event",
		"event_type": "process_exit",
		"pid":        100,
		"session_id": "session-abc",
		"timestamp":  "2026-04-02T16:37:00Z",
	})

	err := h.HandleESFEvent(context.Background(), payload)
	if err != nil {
		t.Fatalf("HandleESFEvent error: %v", err)
	}

	if cr.CommandForPID(100) != "" {
		t.Errorf("PID should be unregistered after exit, got %q", cr.CommandForPID(100))
	}
}

func TestESFEventHandler_NotifyEvent(t *testing.T) {
	store := &fakeEventStore{}
	cr := NewCommandResolver()
	tracker := NewSessionTracker()

	h := NewESFEventHandler(store, cr, tracker)

	payload, _ := json.Marshal(map[string]any{
		"type":       "file_event",
		"event_type": "file_write",
		"path":       "/workspace/modified.txt",
		"operation":  "close_modified",
		"pid":        200,
		"session_id": "session-def",
		"decision":   "observed",
		"timestamp":  "2026-04-02T16:38:00Z",
	})

	err := h.HandleESFEvent(context.Background(), payload)
	if err != nil {
		t.Fatalf("HandleESFEvent error: %v", err)
	}

	ev := store.events[0]
	if ev.Type != "file_write" {
		t.Errorf("Type = %q, want %q", ev.Type, "file_write")
	}
	if ev.Policy == nil || ev.Policy.Decision != "observed" {
		t.Errorf("expected decision 'observed'")
	}
}

func TestESFEventHandler_ActionField(t *testing.T) {
	store := &fakeEventStore{}
	cr := NewCommandResolver()
	tracker := NewSessionTracker()

	h := NewESFEventHandler(store, cr, tracker)

	payload, _ := json.Marshal(map[string]any{
		"type":       "file_event",
		"event_type": "file_delete",
		"path":       "/workspace/important.txt",
		"operation":  "delete",
		"pid":        300,
		"session_id": "session-ghi",
		"decision":   "deny",
		"rule":       "soft-delete-rule",
		"action":     "soft_delete",
		"timestamp":  "2026-04-02T16:39:00Z",
	})

	err := h.HandleESFEvent(context.Background(), payload)
	if err != nil {
		t.Fatalf("HandleESFEvent error: %v", err)
	}

	ev := store.events[0]
	if ev.Fields["action"] != "soft_delete" {
		t.Errorf("Fields[action] = %v, want %q", ev.Fields["action"], "soft_delete")
	}
}
