package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/store/sqlite"
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
