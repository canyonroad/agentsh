# MCP Tool Inspection Phase 4: CLI Commands

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add CLI commands for viewing MCP tool registry and querying MCP-related events.

**Architecture:** Extend SQLite store with mcp_tools table, add MCPToolStore interface in mcpinspect package, create `agentsh mcp` command group with subcommands for tools, servers, events, and detections.

**Tech Stack:** Go, Cobra CLI, SQLite (modernc.org/sqlite), existing store patterns.

---

## Task 1: Add mcp_tools Table to SQLite Store

**Files:**
- Modify: `internal/store/sqlite/sqlite.go`
- Test: `internal/store/sqlite/sqlite_test.go`

**Step 1: Write the failing test**

```go
// Add to sqlite_test.go

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
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/store/sqlite/... -v -run TestMCPToolsTableExists`
Expected: FAIL - no such table: mcp_tools

**Step 3: Add migration for mcp_tools table**

Add to the `stmts` slice in `migrate()` function in `sqlite.go`:

```go
		`CREATE TABLE IF NOT EXISTS mcp_tools (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			server_id TEXT NOT NULL,
			tool_name TEXT NOT NULL,
			tool_hash TEXT NOT NULL,
			description TEXT,
			first_seen_ns INTEGER NOT NULL,
			last_seen_ns INTEGER NOT NULL,
			pinned INTEGER DEFAULT 1,
			detection_count INTEGER DEFAULT 0,
			max_severity TEXT,
			UNIQUE(server_id, tool_name)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_mcp_tools_server ON mcp_tools(server_id);`,
		`CREATE INDEX IF NOT EXISTS idx_mcp_tools_severity ON mcp_tools(max_severity);`,
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/store/sqlite/... -v -run TestMCPToolsTableExists`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/store/sqlite/sqlite.go internal/store/sqlite/sqlite_test.go
git commit -m "feat(sqlite): add mcp_tools table for MCP tool registry"
```

---

## Task 2: Add MCP Tool Store Methods to SQLite

**Files:**
- Modify: `internal/store/sqlite/sqlite.go`
- Modify: `internal/store/sqlite/sqlite_test.go`

**Step 1: Write the failing test**

```go
// Add to sqlite_test.go

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
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/store/sqlite/... -v -run "TestUpsertMCPTool|TestListMCPTools"`
Expected: FAIL - UpsertMCPTool undefined

**Step 3: Implement MCP tool store methods**

Add to `sqlite.go`:

```go
// MCPTool represents a registered MCP tool.
type MCPTool struct {
	ServerID       string
	ToolName       string
	ToolHash       string
	Description    string
	FirstSeen      time.Time
	LastSeen       time.Time
	Pinned         bool
	DetectionCount int
	MaxSeverity    string
}

// MCPToolFilter for querying tools.
type MCPToolFilter struct {
	ServerID      string
	HasDetections bool
}

// UpsertMCPTool inserts or updates an MCP tool.
func (s *Store) UpsertMCPTool(ctx context.Context, tool MCPTool) error {
	now := time.Now().UTC().UnixNano()
	if tool.FirstSeen.IsZero() {
		tool.FirstSeen = time.Now().UTC()
	}
	if tool.LastSeen.IsZero() {
		tool.LastSeen = time.Now().UTC()
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO mcp_tools (server_id, tool_name, tool_hash, description, first_seen_ns, last_seen_ns, pinned, detection_count, max_severity)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(server_id, tool_name) DO UPDATE SET
			tool_hash = excluded.tool_hash,
			description = excluded.description,
			last_seen_ns = excluded.last_seen_ns,
			detection_count = excluded.detection_count,
			max_severity = excluded.max_severity
	`,
		tool.ServerID,
		tool.ToolName,
		tool.ToolHash,
		nullable(tool.Description),
		tool.FirstSeen.UnixNano(),
		tool.LastSeen.UnixNano(),
		boolToInt(tool.Pinned),
		tool.DetectionCount,
		nullable(tool.MaxSeverity),
	)
	if err != nil {
		return fmt.Errorf("upsert mcp tool: %w", err)
	}
	return nil
}

// ListMCPTools returns tools matching the filter.
func (s *Store) ListMCPTools(ctx context.Context, filter MCPToolFilter) ([]MCPTool, error) {
	where := []string{"1=1"}
	var args []any

	if filter.ServerID != "" {
		where = append(where, "server_id = ?")
		args = append(args, filter.ServerID)
	}
	if filter.HasDetections {
		where = append(where, "detection_count > 0")
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT server_id, tool_name, tool_hash, description, first_seen_ns, last_seen_ns, pinned, detection_count, max_severity
		 FROM mcp_tools WHERE `+strings.Join(where, " AND ")+` ORDER BY server_id, tool_name`,
		args...,
	)
	if err != nil {
		return nil, fmt.Errorf("query mcp tools: %w", err)
	}
	defer rows.Close()

	var tools []MCPTool
	for rows.Next() {
		var t MCPTool
		var desc sql.NullString
		var severity sql.NullString
		var firstNs, lastNs int64
		var pinned int

		if err := rows.Scan(&t.ServerID, &t.ToolName, &t.ToolHash, &desc, &firstNs, &lastNs, &pinned, &t.DetectionCount, &severity); err != nil {
			return nil, fmt.Errorf("scan mcp tool: %w", err)
		}
		t.Description = desc.String
		t.MaxSeverity = severity.String
		t.FirstSeen = time.Unix(0, firstNs)
		t.LastSeen = time.Unix(0, lastNs)
		t.Pinned = pinned != 0
		tools = append(tools, t)
	}
	return tools, rows.Err()
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/store/sqlite/... -v -run "TestUpsertMCPTool|TestListMCPTools"`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/store/sqlite/sqlite.go internal/store/sqlite/sqlite_test.go
git commit -m "feat(sqlite): add UpsertMCPTool and ListMCPTools methods"
```

---

## Task 3: Add ListMCPServers Method

**Files:**
- Modify: `internal/store/sqlite/sqlite.go`
- Modify: `internal/store/sqlite/sqlite_test.go`

**Step 1: Write the failing test**

```go
// Add to sqlite_test.go

func TestListMCPServers(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer st.Close()

	// Insert tools
	st.UpsertMCPTool(context.Background(), MCPTool{ServerID: "fs", ToolName: "read", ToolHash: "a"})
	st.UpsertMCPTool(context.Background(), MCPTool{ServerID: "fs", ToolName: "write", ToolHash: "b"})
	st.UpsertMCPTool(context.Background(), MCPTool{ServerID: "db", ToolName: "query", ToolHash: "c", DetectionCount: 2, MaxSeverity: "high"})

	servers, err := st.ListMCPServers(context.Background())
	if err != nil {
		t.Fatalf("ListMCPServers failed: %v", err)
	}
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}

	// Find fs server
	var fs *MCPServerSummary
	for i := range servers {
		if servers[i].ServerID == "fs" {
			fs = &servers[i]
			break
		}
	}
	if fs == nil {
		t.Fatal("fs server not found")
	}
	if fs.ToolCount != 2 {
		t.Errorf("fs tool count = %d, want 2", fs.ToolCount)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/store/sqlite/... -v -run TestListMCPServers`
Expected: FAIL - ListMCPServers undefined

**Step 3: Implement ListMCPServers**

Add to `sqlite.go`:

```go
// MCPServerSummary aggregates tool info per server.
type MCPServerSummary struct {
	ServerID       string
	ToolCount      int
	LastSeen       time.Time
	DetectionCount int
}

// ListMCPServers returns summary of all MCP servers.
func (s *Store) ListMCPServers(ctx context.Context) ([]MCPServerSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT server_id, COUNT(*) as tool_count, MAX(last_seen_ns) as last_seen, SUM(detection_count) as detections
		FROM mcp_tools
		GROUP BY server_id
		ORDER BY server_id
	`)
	if err != nil {
		return nil, fmt.Errorf("query mcp servers: %w", err)
	}
	defer rows.Close()

	var servers []MCPServerSummary
	for rows.Next() {
		var s MCPServerSummary
		var lastNs int64
		if err := rows.Scan(&s.ServerID, &s.ToolCount, &lastNs, &s.DetectionCount); err != nil {
			return nil, fmt.Errorf("scan mcp server: %w", err)
		}
		s.LastSeen = time.Unix(0, lastNs)
		servers = append(servers, s)
	}
	return servers, rows.Err()
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/store/sqlite/... -v -run TestListMCPServers`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/store/sqlite/sqlite.go internal/store/sqlite/sqlite_test.go
git commit -m "feat(sqlite): add ListMCPServers aggregation method"
```

---

## Task 4: Create MCP Parent Command

**Files:**
- Create: `internal/cli/mcp_cmd.go`
- Modify: `internal/cli/root.go`

**Step 1: Create the MCP command file**

```go
// internal/cli/mcp_cmd.go
package cli

import (
	"github.com/spf13/cobra"
)

func newMCPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "MCP tool inspection commands",
	}

	cmd.AddCommand(newMCPToolsCmd())
	cmd.AddCommand(newMCPServersCmd())
	cmd.AddCommand(newMCPEventsCmd())
	cmd.AddCommand(newMCPDetectionsCmd())

	return cmd
}

func newMCPToolsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tools",
		Short: "List registered MCP tools",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println("MCP tools command - not yet implemented")
			return nil
		},
	}
}

func newMCPServersCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "servers",
		Short: "List known MCP servers",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println("MCP servers command - not yet implemented")
			return nil
		},
	}
}

func newMCPEventsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "events",
		Short: "Query MCP-related events",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println("MCP events command - not yet implemented")
			return nil
		},
	}
}

func newMCPDetectionsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "detections",
		Short: "Show tools with security detections",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println("MCP detections command - not yet implemented")
			return nil
		},
	}
}
```

**Step 2: Add to root.go**

Add after line 39 in `root.go`:

```go
	cmd.AddCommand(newMCPCmd())
```

**Step 3: Verify build**

Run: `go build ./internal/cli/...`
Expected: Success

**Step 4: Test command exists**

Run: `go run ./cmd/agentsh mcp --help`
Expected: Shows MCP subcommands (tools, servers, events, detections)

**Step 5: Commit**

```bash
git add internal/cli/mcp_cmd.go internal/cli/root.go
git commit -m "feat(cli): add mcp command group with subcommand stubs"
```

---

## Task 5: Implement mcp tools Command

**Files:**
- Modify: `internal/cli/mcp_cmd.go`
- Create: `internal/cli/mcp_cmd_test.go`

**Step 1: Write the failing test**

```go
// internal/cli/mcp_cmd_test.go
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
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/... -v -run TestMCPToolsCmd`
Expected: FAIL - output doesn't contain read_file

**Step 3: Implement mcp tools command**

Replace `newMCPToolsCmd` in `mcp_cmd.go`:

```go
func newMCPToolsCmd() *cobra.Command {
	var (
		serverID string
		jsonOut  bool
		directDB bool
		dbPath   string
	)

	cmd := &cobra.Command{
		Use:   "tools",
		Short: "List registered MCP tools",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !directDB {
				return fmt.Errorf("API mode not yet implemented, use --direct-db")
			}

			if dbPath == "" {
				dbPath = getenvDefault("AGENTSH_DB_PATH", "./data/events.db")
			}
			st, err := sqlite.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open database: %w", err)
			}
			defer st.Close()

			filter := sqlite.MCPToolFilter{ServerID: serverID}
			tools, err := st.ListMCPTools(cmd.Context(), filter)
			if err != nil {
				return err
			}

			if len(tools) == 0 {
				cmd.Println("No MCP tools found")
				return nil
			}

			if jsonOut {
				return printJSON(cmd, tools)
			}

			// Table output
			cmd.Println("SERVER              TOOL                HASH        LAST SEEN            DETECTIONS")
			for _, t := range tools {
				detections := fmt.Sprintf("%d", t.DetectionCount)
				if t.MaxSeverity != "" {
					detections = fmt.Sprintf("%d (%s)", t.DetectionCount, t.MaxSeverity)
				}
				cmd.Printf("%-19s %-19s %-11s %-20s %s\n",
					truncate(t.ServerID, 19),
					truncate(t.ToolName, 19),
					truncate(t.ToolHash, 11),
					t.LastSeen.Format("2006-01-02 15:04:05"),
					detections,
				)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&serverID, "server", "", "Filter by server ID")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")
	cmd.Flags().BoolVar(&directDB, "direct-db", false, "Query local SQLite directly")
	cmd.Flags().StringVar(&dbPath, "db-path", "", "SQLite DB path (used with --direct-db)")

	return cmd
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
```

Add imports at top of `mcp_cmd.go`:

```go
import (
	"fmt"

	"github.com/agentsh/agentsh/internal/store/sqlite"
	"github.com/spf13/cobra"
)
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/cli/... -v -run TestMCPToolsCmd`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/cli/mcp_cmd.go internal/cli/mcp_cmd_test.go
git commit -m "feat(cli): implement mcp tools command with table output"
```

---

## Task 6: Implement mcp servers Command

**Files:**
- Modify: `internal/cli/mcp_cmd.go`
- Modify: `internal/cli/mcp_cmd_test.go`

**Step 1: Write the failing test**

```go
// Add to mcp_cmd_test.go

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
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/... -v -run TestMCPServersCmd`
Expected: FAIL

**Step 3: Implement mcp servers command**

Replace `newMCPServersCmd` in `mcp_cmd.go`:

```go
func newMCPServersCmd() *cobra.Command {
	var (
		jsonOut  bool
		directDB bool
		dbPath   string
	)

	cmd := &cobra.Command{
		Use:   "servers",
		Short: "List known MCP servers",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !directDB {
				return fmt.Errorf("API mode not yet implemented, use --direct-db")
			}

			if dbPath == "" {
				dbPath = getenvDefault("AGENTSH_DB_PATH", "./data/events.db")
			}
			st, err := sqlite.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open database: %w", err)
			}
			defer st.Close()

			servers, err := st.ListMCPServers(cmd.Context())
			if err != nil {
				return err
			}

			if len(servers) == 0 {
				cmd.Println("No MCP servers found")
				return nil
			}

			if jsonOut {
				return printJSON(cmd, servers)
			}

			cmd.Println("SERVER              TOOLS  LAST SEEN            DETECTIONS")
			for _, s := range servers {
				cmd.Printf("%-19s %-6d %-20s %d\n",
					truncate(s.ServerID, 19),
					s.ToolCount,
					s.LastSeen.Format("2006-01-02 15:04:05"),
					s.DetectionCount,
				)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")
	cmd.Flags().BoolVar(&directDB, "direct-db", false, "Query local SQLite directly")
	cmd.Flags().StringVar(&dbPath, "db-path", "", "SQLite DB path (used with --direct-db)")

	return cmd
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/cli/... -v -run TestMCPServersCmd`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/cli/mcp_cmd.go internal/cli/mcp_cmd_test.go
git commit -m "feat(cli): implement mcp servers command"
```

---

## Task 7: Implement mcp events Command

**Files:**
- Modify: `internal/cli/mcp_cmd.go`
- Modify: `internal/cli/mcp_cmd_test.go`

**Step 1: Write the failing test**

```go
// Add to mcp_cmd_test.go

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
```

Add import for `time` and `types` in test file:

```go
import (
	"time"
	"github.com/agentsh/agentsh/pkg/types"
)
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/... -v -run TestMCPEventsCmd`
Expected: FAIL

**Step 3: Implement mcp events command**

Replace `newMCPEventsCmd` in `mcp_cmd.go`:

```go
func newMCPEventsCmd() *cobra.Command {
	var (
		sessionID string
		serverID  string
		eventType string
		since     string
		limit     int
		jsonOut   bool
		directDB  bool
		dbPath    string
	)

	cmd := &cobra.Command{
		Use:   "events",
		Short: "Query MCP-related events",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !directDB {
				return fmt.Errorf("API mode not yet implemented, use --direct-db")
			}

			if dbPath == "" {
				dbPath = getenvDefault("AGENTSH_DB_PATH", "./data/events.db")
			}
			st, err := sqlite.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open database: %w", err)
			}
			defer st.Close()

			// Build query with MCP event types
			mcpTypes := []string{"mcp_tool_seen", "mcp_tool_changed", "mcp_detection"}
			if eventType != "" {
				mcpTypes = []string{eventType}
			}

			q := types.EventQuery{
				SessionID: sessionID,
				Types:     mcpTypes,
				Limit:     limit,
			}

			if since != "" {
				t, err := parseTimeOrAgo(since)
				if err != nil {
					return fmt.Errorf("invalid --since: %w", err)
				}
				q.Since = &t
			}

			events, err := st.QueryEvents(cmd.Context(), q)
			if err != nil {
				return err
			}

			// Filter by server if specified (in payload)
			if serverID != "" {
				var filtered []types.Event
				for _, e := range events {
					// Check if payload contains server_id
					if bytes.Contains([]byte(fmt.Sprintf("%v", e)), []byte(serverID)) {
						filtered = append(filtered, e)
					}
				}
				events = filtered
			}

			if len(events) == 0 {
				cmd.Println("No MCP events found")
				return nil
			}

			if jsonOut {
				return printJSON(cmd, events)
			}

			// Table output
			cmd.Println("TIMESTAMP            TYPE                SESSION")
			for _, e := range events {
				cmd.Printf("%-20s %-19s %s\n",
					e.Timestamp.Format("2006-01-02 15:04:05"),
					truncate(e.Type, 19),
					truncate(e.SessionID, 20),
				)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&sessionID, "session", "", "Filter by session ID")
	cmd.Flags().StringVar(&serverID, "server", "", "Filter by server ID")
	cmd.Flags().StringVar(&eventType, "type", "", "Event type: tool_seen|tool_changed|detection")
	cmd.Flags().StringVar(&since, "since", "", "Start time (RFC3339) or duration (e.g. 1h)")
	cmd.Flags().IntVar(&limit, "limit", 100, "Result limit")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")
	cmd.Flags().BoolVar(&directDB, "direct-db", false, "Query local SQLite directly")
	cmd.Flags().StringVar(&dbPath, "db-path", "", "SQLite DB path (used with --direct-db)")

	return cmd
}
```

Add `bytes` to imports in `mcp_cmd.go`:

```go
import (
	"bytes"
	"fmt"

	"github.com/agentsh/agentsh/internal/store/sqlite"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/spf13/cobra"
)
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/cli/... -v -run TestMCPEventsCmd`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/cli/mcp_cmd.go internal/cli/mcp_cmd_test.go
git commit -m "feat(cli): implement mcp events command with event querying"
```

---

## Task 8: Implement mcp detections Command

**Files:**
- Modify: `internal/cli/mcp_cmd.go`
- Modify: `internal/cli/mcp_cmd_test.go`

**Step 1: Write the failing test**

```go
// Add to mcp_cmd_test.go

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
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/... -v -run TestMCPDetectionsCmd`
Expected: FAIL

**Step 3: Implement mcp detections command**

Replace `newMCPDetectionsCmd` in `mcp_cmd.go`:

```go
func newMCPDetectionsCmd() *cobra.Command {
	var (
		severity string
		serverID string
		jsonOut  bool
		directDB bool
		dbPath   string
	)

	cmd := &cobra.Command{
		Use:   "detections",
		Short: "Show tools with security detections",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !directDB {
				return fmt.Errorf("API mode not yet implemented, use --direct-db")
			}

			if dbPath == "" {
				dbPath = getenvDefault("AGENTSH_DB_PATH", "./data/events.db")
			}
			st, err := sqlite.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open database: %w", err)
			}
			defer st.Close()

			filter := sqlite.MCPToolFilter{
				ServerID:      serverID,
				HasDetections: true,
			}
			tools, err := st.ListMCPTools(cmd.Context(), filter)
			if err != nil {
				return err
			}

			// Filter by severity if specified
			if severity != "" {
				var filtered []sqlite.MCPTool
				for _, t := range tools {
					if matchesSeverity(t.MaxSeverity, severity) {
						filtered = append(filtered, t)
					}
				}
				tools = filtered
			}

			if len(tools) == 0 {
				cmd.Println("No tools with detections found")
				return nil
			}

			if jsonOut {
				return printJSON(cmd, tools)
			}

			cmd.Println("SERVER              TOOL                SEVERITY   DETECTIONS")
			for _, t := range tools {
				cmd.Printf("%-19s %-19s %-10s %d\n",
					truncate(t.ServerID, 19),
					truncate(t.ToolName, 19),
					t.MaxSeverity,
					t.DetectionCount,
				)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&severity, "severity", "", "Minimum severity: low|medium|high|critical")
	cmd.Flags().StringVar(&serverID, "server", "", "Filter by server ID")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")
	cmd.Flags().BoolVar(&directDB, "direct-db", false, "Query local SQLite directly")
	cmd.Flags().StringVar(&dbPath, "db-path", "", "SQLite DB path (used with --direct-db)")

	return cmd
}

// matchesSeverity returns true if toolSeverity >= minSeverity
func matchesSeverity(toolSeverity, minSeverity string) bool {
	levels := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	toolLevel := levels[toolSeverity]
	minLevel := levels[minSeverity]
	return toolLevel >= minLevel
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/cli/... -v -run TestMCPDetectionsCmd`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/cli/mcp_cmd.go internal/cli/mcp_cmd_test.go
git commit -m "feat(cli): implement mcp detections command"
```

---

## Task 9: Final Verification

**Step 1: Run full test suite for sqlite package**

Run: `go test ./internal/store/sqlite/... -v`
Expected: All tests pass

**Step 2: Run full test suite for cli package**

Run: `go test ./internal/cli/... -v -run MCP`
Expected: All MCP tests pass

**Step 3: Run go vet**

Run: `go vet ./internal/store/sqlite/... ./internal/cli/...`
Expected: No issues

**Step 4: Build entire project**

Run: `go build ./...`
Expected: Success

**Step 5: Manual test of commands**

Run:
```bash
go run ./cmd/agentsh mcp --help
go run ./cmd/agentsh mcp tools --help
go run ./cmd/agentsh mcp servers --help
go run ./cmd/agentsh mcp events --help
go run ./cmd/agentsh mcp detections --help
```
Expected: All show help text

---

## Summary

Phase 4 adds CLI commands for MCP tool inspection:

| Component | File | Purpose |
|-----------|------|---------|
| mcp_tools table | `sqlite.go` | Persistent storage for MCP tools |
| UpsertMCPTool | `sqlite.go` | Insert/update tools |
| ListMCPTools | `sqlite.go` | Query tools with filters |
| ListMCPServers | `sqlite.go` | Aggregate server stats |
| mcp command | `mcp_cmd.go` | Parent command group |
| mcp tools | `mcp_cmd.go` | List registered tools |
| mcp servers | `mcp_cmd.go` | List server summaries |
| mcp events | `mcp_cmd.go` | Query MCP events |
| mcp detections | `mcp_cmd.go` | Show tools with detections |

**Next steps (future work):**
- Wire MCP event emission to also upsert to mcp_tools table
- Add server API endpoints for non-direct-db mode
- Add MCP summary to session reports
