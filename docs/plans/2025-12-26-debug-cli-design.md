# CLI Debug Commands Design

**Status:** Implemented

## Overview

Add one-shot debug commands for operational visibility into agentsh sessions.
These wrap existing infrastructure and add a `debug` command namespace.

## Commands

```
agentsh debug
  ├── stats SESSION_ID [--json]
  │     Show session statistics: event counts by type/decision,
  │     latency percentiles, resource usage, duration
  │
  ├── pending [SESSION_ID] [--all] [--json]
  │     List pending approval requests. Without SESSION_ID, shows all.
  │     With --all, includes recently resolved approvals.
  │
  └── policy test [--session SESSION_ID] --op TYPE --path PATH [--json]
        Test what the policy engine would decide for an operation.
        Uses session's policy if --session provided, else default policy.
```

## Data Structures

### Stats Response

```go
type SessionStats struct {
    SessionID   string        `json:"session_id"`
    State       string        `json:"state"`
    Duration    time.Duration `json:"duration"`

    // Event counts
    EventCounts map[string]int `json:"event_counts"` // by type
    Decisions   struct {
        Allow  int `json:"allow"`
        Deny   int `json:"deny"`
        Prompt int `json:"prompt"`
    } `json:"decisions"`

    // Latency (policy evaluation)
    LatencyP50 time.Duration `json:"latency_p50"`
    LatencyP99 time.Duration `json:"latency_p99"`

    // Resource usage
    ProcessCount int   `json:"process_count"`
    OpenFiles    int   `json:"open_files,omitempty"`
    MemoryBytes  int64 `json:"memory_bytes,omitempty"`
}
```

### Pending Approvals Response

```go
type PendingApproval struct {
    ID          string    `json:"id"`
    SessionID   string    `json:"session_id"`
    Operation   string    `json:"operation"`
    Path        string    `json:"path"`
    RequestedAt time.Time `json:"requested_at"`
    ExpiresAt   time.Time `json:"expires_at"`
    Reason      string    `json:"reason"`
}
```

### Policy Test Request/Response

```go
type PolicyTestRequest struct {
    SessionID string `json:"session_id,omitempty"`
    Operation string `json:"operation"`
    Path      string `json:"path"`
}

type PolicyTestResponse struct {
    Decision   string `json:"decision"`
    Rule       string `json:"rule"`
    Reason     string `json:"reason"`
    PolicyFile string `json:"policy_file"`
}
```

## Human-Readable Output

### debug stats

```
Session: sess_abc123
State:   running
Uptime:  2h 15m 30s

Events:
  file_read      1,247
  file_write       183
  net_connect       42
  exec              17
  ─────────────────────
  Total          1,489

Decisions:
  allow          1,401 (94.1%)
  deny              71 (4.8%)
  prompt            17 (1.1%)

Latency:
  p50    0.2ms
  p99    1.8ms

Resources:
  Processes    3
  Open files  24
```

### debug pending

```
ID        SESSION       OPERATION    PATH                    AGE      EXPIRES
ap_001    sess_abc123   file_write   /etc/hosts              2m ago   in 8m
ap_002    sess_abc123   net_connect  internal.corp:443       45s ago  in 9m

2 pending approvals
```

### debug policy test

```
Operation: file_read
Path:      /home/user/.ssh/id_rsa

Decision:  DENY
Rule:      sensitive-files
Reason:    Path matches "**/.ssh/**" in blocklist
Source:    policies/default.yaml:47
```

## Implementation

### New Files

- `internal/cli/debug.go` - CLI commands
- `internal/cli/debug_test.go` - tests

### API Endpoints

Check if these exist, add if not:

- `GET /sessions/{id}/stats` - aggregate stats
- `GET /approvals` - list approvals with filters
- `POST /policy/test` - dry-run policy evaluation

### Server-Side Changes (if needed)

- `internal/api/debug.go` - handlers
- Wire stats aggregation from event store
- Wire policy test through policy engine

### Implementation Order

1. Add CLI commands with client calls
2. Check which APIs exist, implement missing ones
3. Add tests

## Testing

- Unit tests for output formatting
- Integration test with test server

## Decisions

- Hybrid approach: new `debug` namespace wraps existing client code
- One-shot commands first (scriptable), REPL later if needed
- Human-readable default, `--json` for scripting
