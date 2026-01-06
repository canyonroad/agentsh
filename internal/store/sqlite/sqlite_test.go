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

func TestMCPToolsTableExists(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	st, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer st.Close()

	// Verify table exists by querying it
	_, err = st.db.Exec("SELECT server_id, tool_name, tool_hash FROM mcp_tools LIMIT 1")
	if err != nil {
		t.Errorf("mcp_tools table should exist: %v", err)
	}
}

func TestUpsertMCPTool(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer st.Close()

	tool := MCPTool{
		ServerID:    "filesystem",
		ToolName:    "read_file",
		ToolHash:    "abc123",
		Description: "Reads a file",
	}

	// Insert
	err = st.UpsertMCPTool(context.Background(), tool)
	if err != nil {
		t.Fatalf("UpsertMCPTool failed: %v", err)
	}

	// Verify
	tools, err := st.ListMCPTools(context.Background(), MCPToolFilter{})
	if err != nil {
		t.Fatalf("ListMCPTools failed: %v", err)
	}
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}
	if tools[0].ToolName != "read_file" {
		t.Errorf("expected read_file, got %s", tools[0].ToolName)
	}
}

func TestListMCPTools_FilterByServer(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer st.Close()

	// Insert tools for different servers
	st.UpsertMCPTool(context.Background(), MCPTool{ServerID: "fs", ToolName: "read", ToolHash: "a"})
	st.UpsertMCPTool(context.Background(), MCPTool{ServerID: "fs", ToolName: "write", ToolHash: "b"})
	st.UpsertMCPTool(context.Background(), MCPTool{ServerID: "db", ToolName: "query", ToolHash: "c"})

	// Filter by server
	tools, err := st.ListMCPTools(context.Background(), MCPToolFilter{ServerID: "fs"})
	if err != nil {
		t.Fatalf("ListMCPTools failed: %v", err)
	}
	if len(tools) != 2 {
		t.Errorf("expected 2 tools for fs, got %d", len(tools))
	}
}
