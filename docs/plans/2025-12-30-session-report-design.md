# Session Report Command Design

**Date:** 2025-12-30
**Status:** Approved

## Overview

Add a CLI command to generate markdown reports summarizing agentsh sessions. Reports are designed for human operators reviewing agent activity after CI/CD runs or for security audits.

## CLI Interface

```
agentsh report <session-id|latest> --level=<summary|detailed> [--output=<path>]
```

**Arguments:**
- `session-id` - UUID of the session, or the literal `latest`
- `--level` - required, either `summary` or `detailed`
- `--output` - optional, if set writes to file (no stdout), otherwise stdout only

**Examples:**
```bash
# Quick check on latest session
agentsh report latest --level=summary

# Full investigation, save to file
agentsh report abc123 --level=detailed --output=./session-report.md

# Pipe summary to another tool
agentsh report latest --level=summary | less
```

**Errors:**
- Session not found → clear error with suggestion to run `agentsh session list`
- No sessions exist → "No sessions found"
- Invalid level → show valid options

## Summary Report Structure (~1 page)

```markdown
# Session Report: abc123-def4-5678-...
**Generated:** 2025-12-30 14:32:00 UTC

## Overview
| Metric | Value |
|--------|-------|
| Duration | 12m 34s |
| Commands Executed | 47 |
| Commands Failed | 2 |
| Policy | production-agent-v2 |
| Status | completed |

## Decision Summary
| Decision | Count |
|----------|-------|
| ✅ Allowed | 1,234 |
| 🚫 Blocked | 3 |
| ↪️ Redirected | 12 |
| 🗑️ Soft-deleted | 2 |
| ✋ Approval Required | 5 |
| ✋ Approved | 4 |
| ✋ Denied | 1 |

## Findings
⚠️ **3 operations blocked** - file writes outside workspace
⚠️ **1 approval denied** - attempted `curl` to external API
ℹ️ **12 redirects** - commands substituted per policy
ℹ️ **2 files soft-deleted** - recoverable via `agentsh trash`

## Top Activity
**Files (156 ops):** `/workspace/src/` (89), `/workspace/tests/` (42), `/tmp/` (25)
**Network (8 conns):** `api.github.com` (5), `registry.npmjs.org` (3)
**Commands (47):** `npm` (12), `node` (18), `git` (9), `grep` (8)
```

## Detailed Report Structure (Full Investigation)

```markdown
# Session Report: abc123-def4-5678-... (Detailed)
**Generated:** 2025-12-30 14:32:00 UTC

## Overview
[Same as summary]

## Decision Summary
[Same as summary]

## Findings
[Same as summary, but with expanded details:]

### Blocked Operations
| Time | Type | Path/Target | Rule | Message |
|------|------|-------------|------|---------|
| 14:21:03 | file_write | /etc/hosts | no-system-files | Write to system file denied |
| 14:21:45 | file_write | /usr/bin/foo | no-system-files | Write to system file denied |
| 14:28:12 | net_connect | evil.com:443 | allowed-domains | Domain not in allowlist |

### Denied Approvals
| Time | Type | Target | Requested By | Reason |
|------|------|--------|--------------|--------|
| 14:25:00 | command | curl https://external.io | agent | Operator denied - unexpected API |

### Redirects
| Time | Original | Redirected To | Rule |
|------|----------|---------------|------|
| 14:20:01 | curl https://api.com | audited-fetch --audit https://api.com | audit-curl |
| ... | ... | ... | ... |

## Event Timeline
| Time | Type | Decision | Summary |
|------|------|----------|---------|
| 14:20:00 | command_intercept | allow | npm install |
| 14:20:01 | net_connect | allow | registry.npmjs.org:443 |
| 14:20:01 | file_write | allow | /workspace/node_modules/... |
| ... | ... | ... | ... |

## Activity by Category

### File Operations (156)
| Operation | Count | Top Paths |
|-----------|-------|-----------|
| read | 89 | /workspace/src/index.ts, /workspace/package.json, ... |
| write | 52 | /workspace/node_modules/..., /workspace/dist/... |
| delete | 8 | /workspace/dist/old/... |
| stat | 7 | ... |

**All file paths:**
- /workspace/src/index.ts (read x12, write x3)
- /workspace/src/utils.ts (read x8, write x2)
- [full list...]

### Network Operations (8)
| Host | Port | Count | Decision |
|------|------|-------|----------|
| registry.npmjs.org | 443 | 3 | allow |
| api.github.com | 443 | 5 | allow |

### Commands Executed (47)
| Command | Count | Failures | Avg Duration |
|---------|-------|----------|--------------|
| npm | 12 | 1 | 2.3s |
| node | 18 | 0 | 0.8s |
| git | 9 | 1 | 0.2s |

**Full command history:**
1. [14:20:00] npm install (exit 0, 12.4s)
2. [14:20:15] node build.js (exit 0, 0.9s)
3. [full list...]

## Resource Usage
| Metric | Value |
|--------|-------|
| Peak Memory | 256 MB |
| CPU Time | 34.2s |
| Bytes Read | 12.4 MB |
| Bytes Written | 8.1 MB |
| Network TX | 1.2 MB |
| Network RX | 4.5 MB |

## Raw Event Samples
<details>
<summary>Sample blocked event (JSON)</summary>

{
  "event_id": "...",
  "type": "file_write",
  "decision": "deny",
  ...full event...
}

</details>
```

## Findings Detection Logic

Built-in heuristics that flag items as findings:

### Policy Violations (always flagged)
- Any operation with `decision=deny`
- Any approval that was denied
- Any approval still pending at session end

### Notable Operations (always flagged)
- Redirects (command or path substitutions)
- Soft-deletes (files sent to trash)
- Approvals granted (human intervention occurred)
- Commands with non-zero exit codes

### Anomaly Detection (heuristic-based)

| Anomaly | Trigger |
|---------|---------|
| High file write volume | >100 writes in single command |
| Sensitive path access | `/etc/*`, `/usr/*`, `~/.ssh/*`, `~/.aws/*`, credentials files |
| Unexpected network | Connections to IPs (not domains), non-443/80 ports, >10 unique hosts |
| Long-running command | Single command >5 minutes |
| High resource usage | Memory >1GB or CPU >90% quota |
| Unusual process tree | Tree depth >5, or >50 child processes |

### Severity Levels

- `🔴` Critical - blocked ops, denied approvals
- `⚠️` Warning - anomalies, soft-deletes
- `ℹ️` Info - redirects, granted approvals, notable but expected

## Implementation Approach

### New Files
- `internal/cli/report.go` - CLI command definition
- `internal/report/generator.go` - report generation logic
- `internal/report/findings.go` - anomaly detection heuristics
- `internal/report/templates.go` - markdown output formatting

### Integration Points
- Query events from SQLite via existing `internal/events/store.go`
- Resolve "latest" session via `internal/session/manager.go`
- Reuse `SessionStats` already tracked in session

### Data Flow
```
CLI args → resolve session ID → load session + stats → query events from store
        → run findings detection → format as markdown → output (stdout or file)
```

### Performance Considerations
- Detailed report on large sessions could be many events - stream/paginate internally
- Consider `--limit` flag for timeline in detailed view (default: all, can cap to e.g., 1000)

## Out of Scope (for now)
- HTML output format
- Configurable thresholds for anomalies
- Multi-session aggregate reports
- Real-time/streaming reports
