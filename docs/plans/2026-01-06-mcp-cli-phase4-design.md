# MCP Tool Inspection Phase 4: CLI Commands Design

**Status:** Implemented

## Overview

Add CLI commands for viewing MCP tool registry and querying MCP-related events.

## Command Structure

Parent command: `agentsh mcp`

| Command | Purpose |
|---------|---------|
| `agentsh mcp tools` | List registered MCP tools from persistent registry |
| `agentsh mcp servers` | List known MCP servers with tool counts |
| `agentsh mcp events` | Query MCP-related events (tool_seen, tool_changed, detection) |
| `agentsh mcp detections` | Show tools with security detections |

### Common Flags

- `--session <id>` - Filter by session
- `--server <id>` - Filter by MCP server ID
- `--json` - Output as JSON (default is table)
- `--direct-db` - Query local SQLite directly

### Examples

```bash
# List all known MCP tools
agentsh mcp tools

# List tools for a specific server
agentsh mcp tools --server=filesystem

# Show MCP events for current session
agentsh mcp events --session=sess_abc123

# Show only tools with detections
agentsh mcp detections --severity=high
```

## Storage Design

### New SQLite Table: `mcp_tools`

```sql
CREATE TABLE mcp_tools (
    id INTEGER PRIMARY KEY,
    server_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    tool_hash TEXT NOT NULL,
    description TEXT,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    pinned BOOLEAN DEFAULT TRUE,
    detection_count INTEGER DEFAULT 0,
    max_severity TEXT,

    UNIQUE(server_id, tool_name)
);

CREATE INDEX idx_mcp_tools_server ON mcp_tools(server_id);
CREATE INDEX idx_mcp_tools_severity ON mcp_tools(max_severity);
```

### Key Behaviors

- Insert on first see (mcp_tool_seen with status="new")
- Update on change (mcp_tool_seen with status="changed")
- Track detection count and max severity
- Upsert pattern for concurrent safety

## Data Flow

### Write Path

```
Shell Shim detects MCP server
    ↓
MCPBridge inspects stdio
    ↓
Inspector emits MCPToolSeenEvent
    ↓
Event written to SQLite events table (existing)
    ↓
Also upsert to mcp_tools table (new)
```

### Read Path

```
agentsh mcp tools --server=filesystem
    ↓
MCPToolStore.ListTools(filter)
    ↓
SQLite query on mcp_tools table
    ↓
Format and display
```

## Interface Design

```go
// MCPToolStore persists MCP tool registry to storage
type MCPToolStore interface {
    UpsertTool(ctx context.Context, tool RegisteredTool, detections []DetectionResult) error
    ListTools(ctx context.Context, filter ToolFilter) ([]*RegisteredTool, error)
    ListServers(ctx context.Context) ([]ServerSummary, error)
    GetToolsWithDetections(ctx context.Context, minSeverity Severity) ([]*RegisteredTool, error)
}

type ToolFilter struct {
    ServerID      string
    SessionID     string
    HasDetections *bool
}

type ServerSummary struct {
    ServerID       string
    ToolCount      int
    LastSeen       time.Time
    DetectionCount int
}
```

## File Structure

```
internal/cli/mcp_cmd.go          # Parent command + subcommands
internal/cli/mcp_cmd_test.go     # CLI tests
internal/mcpinspect/store.go     # MCPToolStore interface
internal/mcpinspect/store_test.go
internal/store/sqlite/mcp.go     # SQLite implementation
internal/store/sqlite/mcp_test.go
internal/cli/root.go             # Add newMCPCmd()
```

## Output Format

### Table Mode (default)

```
$ agentsh mcp tools
SERVER              TOOL            HASH        LAST SEEN            DETECTIONS
filesystem          read_file       a1b2c3d4    2026-01-06 10:30:00  0
filesystem          write_file      e5f6g7h8    2026-01-06 10:30:00  0
sqlite              query           i9j0k1l2    2026-01-06 10:31:00  2 (high)
```

### JSON Mode

```json
[
  {"server_id": "filesystem", "tool_name": "read_file", "hash": "a1b2c3d4", ...}
]
```

## Error Handling

| Scenario | Behavior |
|----------|----------|
| No MCP tools registered | Show "No MCP tools found" message, exit 0 |
| Database not found | Error with hint to check path |
| Server unreachable | Error with connection details |
| Invalid filter values | Validation error with usage hint |

## Testing Strategy

1. **Unit tests** - Command flag parsing, output formatting, mock store
2. **Store tests** - Upsert, List, filter, aggregation queries
3. **Integration test** - End-to-end with real SQLite
