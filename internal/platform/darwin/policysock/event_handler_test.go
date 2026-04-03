//go:build darwin

package policysock

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

type mockEventHandler struct {
	events []types.Event
}

func (m *mockEventHandler) HandleESFEvent(ctx context.Context, payload []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return err
	}
	ev := types.Event{
		Type:      raw["type"].(string),
		Source:    "esf",
		SessionID: raw["session_id"].(string),
	}
	m.events = append(m.events, ev)
	return nil
}

func TestDecodeESFEventPayload(t *testing.T) {
	payload := map[string]any{
		"type":       "file_write",
		"path":       "/tmp/test.txt",
		"operation":  "close_modified",
		"pid":        1234,
		"session_id": "session-abc",
		"timestamp":  "2026-03-31T10:00:00Z",
	}
	data, _ := json.Marshal(payload)

	handler := &mockEventHandler{}
	if err := handler.HandleESFEvent(context.Background(), data); err != nil {
		t.Fatal(err)
	}
	if len(handler.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(handler.events))
	}
	if handler.events[0].Type != "file_write" {
		t.Fatalf("expected file_write, got %s", handler.events[0].Type)
	}
	if handler.events[0].Source != "esf" {
		t.Fatalf("expected esf source, got %s", handler.events[0].Source)
	}
}
