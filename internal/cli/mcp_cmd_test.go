package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/sqlite"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestMCPToolsCmd_ListsTools(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Setup test data
	st, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	st.UpsertMCPTool(context.Background(), sqlite.MCPTool{
		ServerID: "filesystem",
		ToolName: "read_file",
		ToolHash: "abc123",
	})
	st.Close()

	// Run command
	cmd := NewRoot("test")
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"mcp", "tools", "--direct-db", "--db-path", dbPath})

	err = cmd.Execute()
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("read_file")) {
		t.Errorf("expected output to contain read_file, got: %s", output)
	}
}

func TestMCPServersCmd_ListsServers(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Setup test data
	st, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	st.UpsertMCPTool(context.Background(), sqlite.MCPTool{ServerID: "filesystem", ToolName: "read", ToolHash: "a"})
	st.UpsertMCPTool(context.Background(), sqlite.MCPTool{ServerID: "filesystem", ToolName: "write", ToolHash: "b"})
	st.UpsertMCPTool(context.Background(), sqlite.MCPTool{ServerID: "sqlite", ToolName: "query", ToolHash: "c"})
	st.Close()

	cmd := NewRoot("test")
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"mcp", "servers", "--direct-db", "--db-path", dbPath})

	err = cmd.Execute()
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("filesystem")) {
		t.Errorf("expected output to contain filesystem, got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("2")) { // tool count
		t.Errorf("expected output to contain tool count 2, got: %s", output)
	}
}

func TestMCPEventsCmd_QueriesMCPEvents(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Setup test data
	st, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// Insert MCP event
	ev := types.Event{
		ID:        "evt_001",
		Type:      "mcp_tool_seen",
		SessionID: "sess_123",
		Timestamp: time.Now(),
	}
	st.AppendEvent(context.Background(), ev)
	st.Close()

	cmd := NewRoot("test")
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"mcp", "events", "--direct-db", "--db-path", dbPath})

	err = cmd.Execute()
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("mcp_tool_seen")) {
		t.Errorf("expected output to contain mcp_tool_seen, got: %s", output)
	}
}

func TestMCPDetectionsCmd_ShowsDetections(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Setup test data
	st, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	st.UpsertMCPTool(context.Background(), sqlite.MCPTool{
		ServerID:       "malicious-server",
		ToolName:       "steal_data",
		ToolHash:       "bad123",
		DetectionCount: 3,
		MaxSeverity:    "critical",
	})
	st.UpsertMCPTool(context.Background(), sqlite.MCPTool{
		ServerID:       "good-server",
		ToolName:       "read_file",
		ToolHash:       "good456",
		DetectionCount: 0,
	})
	st.Close()

	cmd := NewRoot("test")
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"mcp", "detections", "--direct-db", "--db-path", dbPath})

	err = cmd.Execute()
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("steal_data")) {
		t.Errorf("expected output to contain steal_data, got: %s", output)
	}
	if bytes.Contains([]byte(output), []byte("read_file")) {
		t.Errorf("expected output to NOT contain read_file (no detections), got: %s", output)
	}
}

// helper: insert an mcp_tool_call_intercepted event.
func insertCallEvent(t *testing.T, st *sqlite.Store, id, toolName, serverID, action, reason string, decision types.Decision) {
	t.Helper()
	ev := types.Event{
		ID:        id,
		Type:      "mcp_tool_call_intercepted",
		SessionID: "sess_1",
		Timestamp: time.Now(),
		Path:      toolName,
		Domain:    serverID,
		Policy:    &types.PolicyInfo{Decision: decision},
		Fields: map[string]any{
			"tool_name": toolName,
			"server_id": serverID,
			"action":    action,
			"reason":    reason,
		},
	}
	if err := st.AppendEvent(context.Background(), ev); err != nil {
		t.Fatalf("AppendEvent(%s): %v", id, err)
	}
}

func TestMCPCallsCmd_ListsCalls(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	st, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	insertCallEvent(t, st, "evt_1", "read_file", "filesystem", "allow", "", types.DecisionAllow)
	insertCallEvent(t, st, "evt_2", "exec_cmd", "malicious-srv", "block", "tool denied by policy", types.DecisionDeny)
	st.Close()

	cmd := NewRoot("test")
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"mcp", "calls", "--direct-db", "--db-path", dbPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "read_file") {
		t.Errorf("expected output to contain read_file, got: %s", output)
	}
	if !strings.Contains(output, "exec_cmd") {
		t.Errorf("expected output to contain exec_cmd, got: %s", output)
	}
	if !strings.Contains(output, "tool denied by policy") {
		t.Errorf("expected output to contain reason, got: %s", output)
	}
}

func TestMCPCallsCmd_FilterByAction(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	st, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	insertCallEvent(t, st, "evt_1", "read_file", "filesystem", "allow", "", types.DecisionAllow)
	insertCallEvent(t, st, "evt_2", "exec_cmd", "malicious-srv", "block", "denied", types.DecisionDeny)
	st.Close()

	cmd := NewRoot("test")
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"mcp", "calls", "--direct-db", "--db-path", dbPath, "--action", "block"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "exec_cmd") {
		t.Errorf("expected blocked call in output, got: %s", output)
	}
	if strings.Contains(output, "read_file") {
		t.Errorf("expected allowed call to be filtered out, got: %s", output)
	}
}

func TestMCPCallsCmd_FilterByTool(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	st, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	insertCallEvent(t, st, "evt_1", "read_file", "filesystem", "allow", "", types.DecisionAllow)
	insertCallEvent(t, st, "evt_2", "exec_cmd", "malicious-srv", "block", "denied", types.DecisionDeny)
	st.Close()

	cmd := NewRoot("test")
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"mcp", "calls", "--direct-db", "--db-path", dbPath, "--tool", "read_file"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "read_file") {
		t.Errorf("expected read_file in output, got: %s", output)
	}
	if strings.Contains(output, "exec_cmd") {
		t.Errorf("expected exec_cmd to be filtered out, got: %s", output)
	}
}

func TestMCPCallsCmd_JSONOutput(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	st, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	insertCallEvent(t, st, "evt_1", "read_file", "filesystem", "allow", "", types.DecisionAllow)
	st.Close()

	cmd := NewRoot("test")
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"mcp", "calls", "--direct-db", "--db-path", dbPath, "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	var result []types.Event
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON output: %v\nraw: %s", err, buf.String())
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 event, got %d", len(result))
	}
	if result[0].Type != "mcp_tool_call_intercepted" {
		t.Errorf("expected type mcp_tool_call_intercepted, got %s", result[0].Type)
	}
}

func TestMCPCallsCmd_EmptyResult(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	st, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	st.Close()

	cmd := NewRoot("test")
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"mcp", "calls", "--direct-db", "--db-path", dbPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No MCP tool calls found") {
		t.Errorf("expected empty result message, got: %s", output)
	}
}
