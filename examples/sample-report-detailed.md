# Session Report: sess-abc123

**Generated:** 2025-01-15T10:31:00Z
**Report Level:** Detailed

## Session Overview

| Property | Value |
|----------|-------|
| Session ID | sess-abc123 |
| Start Time | 2025-01-15T10:30:00Z |
| End Time | 2025-01-15T10:30:25Z |
| Duration | 25s |
| Workspace | /home/user/project |
| Policy | default |

## Activity Summary

| Metric | Count |
|--------|-------|
| Commands Executed | 6 |
| Files Accessed | 1 |
| Network Connections | 2 |
| Policy Denials | 2 |

## Security Findings

### Critical
- **Dangerous command blocked**: `rm -rf /` - rm -rf blocked for safety
- **MCP cross-server pattern detected**: read_then_send pattern between `notes` and `web-search` servers

### Warning
- **Network access denied**: Connection to `internal.corp.local:80` blocked - internal networks blocked
- **MCP tool blocked by proxy**: `web-search/fetch_url` blocked — version_pin (tool definition changed)

## MCP Tools

| Metric | Value |
|--------|-------|
| Tools Seen | 5 |
| Servers | 2 |
| Security Detections | 1 |
| Changed Tools (Rug Pull) | 1 |
| Tool Calls Observed | 8 |
| Intercepted (Proxy) | 8 |
| Blocked by Proxy | 2 |
| Cross-Server Blocked | 1 |
| Network Connections | 3 |

### High Risk Tools

| Server | Tool | Risk |
|--------|------|------|
| web-search | fetch_url | Tool definition changed (rug pull) |

### Detections by Severity

| Severity | Count |
|----------|-------|
| critical | 1 |

## Policy Decisions

| Decision | Count |
|----------|-------|
| Allow | 5 |
| Deny | 2 |
| Redirect | 0 |

## Command History

| Time | Command | Decision | Exit Code | Duration |
|------|---------|----------|-----------|----------|
| 10:30:01 | `ls -la` | allow | 0 | 126ms |
| 10:30:05 | `git status` | allow | 0 | 149ms |
| 10:30:10 | `cat src/main.go` | allow | 0 | 49ms |
| 10:30:15 | `rm -rf /` | **deny** | - | - |
| 10:30:20 | `curl https://api.github.com/repos/agentsh/agentsh` | allow | 0 | 499ms |
| 10:30:25 | `curl http://internal.corp.local/secrets` | allow | 7 | 10ms |

## File Access

| Time | Path | Operation | Decision |
|------|------|-----------|----------|
| 10:30:10 | /home/user/project/src/main.go | read | allow |

## Network Connections

| Time | Domain | Port | Decision | Rule |
|------|--------|------|----------|------|
| 10:30:20 | api.github.com | 443 | allow | github.com allowed |
| 10:30:25 | internal.corp.local | 80 | **deny** | internal networks blocked |

## Resource Usage

| Command | CPU User | CPU System | Peak Memory |
|---------|----------|------------|-------------|
| ls -la | 5ms | 3ms | 1 MB |
| git status | 12ms | 8ms | 2 MB |
| cat src/main.go | 2ms | 1ms | 512 KB |
| curl api.github.com | 25ms | 15ms | 4 MB |
| curl internal.corp.local | 1ms | 1ms | 512 KB |

## Event Timeline

```
10:30:00.000 [session_created] Session started in /home/user/project
10:30:01.123 [command_policy] ls -la → allow (allowed by default)
10:30:01.124 [command_started] ls -la
10:30:01.250 [command_finished] ls -la exit=0
10:30:05.000 [command_policy] git status → allow (git commands allowed)
10:30:05.001 [command_started] git status
10:30:05.150 [command_finished] git status exit=0
10:30:10.000 [command_policy] cat src/main.go → allow (cat allowed for reading)
10:30:10.001 [command_started] cat src/main.go
10:30:10.002 [file_read] /home/user/project/src/main.go → allow
10:30:10.050 [command_finished] cat src/main.go exit=0
10:30:15.000 [command_policy] rm -rf / → DENY (rm -rf blocked for safety)
10:30:17.000 [mcp_tool_seen] notes/read_note (sha256:a1b2c3) on server "notes" (stdio)
10:30:17.100 [mcp_tool_seen] notes/write_note (sha256:d4e5f6) on server "notes" (stdio)
10:30:17.200 [mcp_tool_seen] web-search/search (sha256:111222) on server "web-search" (stdio)
10:30:17.300 [mcp_tool_seen] web-search/fetch_url (sha256:333444) on server "web-search" (stdio)
10:30:17.400 [mcp_tool_seen] web-search/summarize (sha256:555666) on server "web-search" (stdio)
10:30:18.000 [mcp_tool_called] notes/read_note on server "notes"
10:30:18.001 [mcp_tool_call_intercepted] notes/read_note → allow
10:30:18.500 [mcp_tool_called] web-search/search on server "web-search"
10:30:18.501 [mcp_tool_call_intercepted] web-search/search → allow
10:30:19.000 [mcp_tool_changed] web-search/fetch_url hash changed (sha256:333444 → sha256:999000)
10:30:19.100 [mcp_tool_called] web-search/fetch_url on server "web-search"
10:30:19.101 [mcp_tool_call_intercepted] web-search/fetch_url → BLOCK (version_pin)
10:30:19.500 [mcp_cross_server_blocked] read_then_send: notes → web-search (critical)
10:30:20.000 [command_policy] curl api.github.com → allow (curl allowed)
10:30:20.001 [command_started] curl api.github.com
10:30:20.010 [net_connect] api.github.com:443 → allow
10:30:20.500 [command_finished] curl api.github.com exit=0
10:30:25.000 [command_policy] curl internal.corp.local → allow (curl allowed)
10:30:25.001 [command_started] curl internal.corp.local
10:30:25.010 [net_connect] internal.corp.local:80 → DENY (internal networks blocked)
10:30:25.011 [command_finished] curl internal.corp.local exit=7
```

---
*Report generated by agentsh v0.2.0*
