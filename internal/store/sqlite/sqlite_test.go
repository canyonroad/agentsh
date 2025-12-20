package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestAppendAndQueryEvents(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "events.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	ev := types.Event{
		ID:        "evt1",
		SessionID: "sess",
		Type:      "demo",
		Timestamp: time.Now().UTC(),
		Policy: &types.PolicyInfo{
			Decision:          types.DecisionAllow,
			EffectiveDecision: types.DecisionAllow,
			Rule:              "r1",
		},
	}
	if err := s.AppendEvent(context.Background(), ev); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}

	got, err := s.QueryEvents(context.Background(), types.EventQuery{SessionID: "sess"})
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	if len(got) != 1 || got[0].ID != ev.ID || got[0].Policy == nil || got[0].Policy.Rule != "r1" {
		t.Fatalf("unexpected events: %+v", got)
	}
}

func TestSaveAndReadOutputChunk(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "events.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	stdout := []byte("hello world")
	if err := s.SaveOutput(context.Background(), "sess", "cmd", stdout, []byte(""), int64(len(stdout)), 0, false, false); err != nil {
		t.Fatalf("SaveOutput: %v", err)
	}

	chunk, total, truncated, err := s.ReadOutputChunk(context.Background(), "cmd", "stdout", 0, 5)
	if err != nil {
		t.Fatalf("ReadOutputChunk: %v", err)
	}
	if string(chunk) != "hello" || total != int64(len(stdout)) || truncated {
		t.Fatalf("unexpected chunk=%q total=%d truncated=%v", chunk, total, truncated)
	}

	_, _, _, err = s.ReadOutputChunk(context.Background(), "missing", "stdout", 0, 5)
	if err == nil {
		t.Fatal("expected error for missing output")
	}
}
