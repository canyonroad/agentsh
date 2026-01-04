# LLM Storage Retention Policy Design

**Date:** 2026-01-04
**Status:** Draft

## 1. Problem Statement

The embedded LLM proxy stores request/response logs in `~/.agentsh/sessions/<session-id>/llm-requests.jsonl`. Without cleanup, these logs accumulate indefinitely, consuming disk space. The existing config defines retention settings (`max_age_days`, `max_size_mb`, `eviction`) but no code enforces them.

## 2. Goals

- Automatically clean up old LLM logs based on configured retention policy
- Delete entire session directories (not individual files) for simplicity
- Run cleanup on session start with minimal performance impact
- Log eviction events for auditability

## 3. Non-Goals

- Per-file granular cleanup (too complex, minimal benefit)
- Real-time size monitoring (polling adds overhead)
- Cleanup of active sessions (only inactive sessions)

## 4. Design

### 4.1 Retention Logic

The retention policy enforces two constraints:

1. **Age-based:** Delete sessions older than `max_age_days`
2. **Size-based:** If total size exceeds `max_size_mb`, delete sessions using `eviction` strategy

```
RunRetention(sessionsDir, config)
    │
    ├── 1. List all session directories
    │
    ├── 2. For each session:
    │       ├── Get directory mtime (last modification)
    │       ├── Calculate directory size
    │       └── Build session info list
    │
    ├── 3. Age-based cleanup:
    │       └── Delete sessions where mtime < now - max_age_days
    │
    ├── 4. Size-based cleanup (if total > max_size_mb):
    │       ├── Sort by eviction strategy (oldest_first | largest_first)
    │       └── Delete until under quota
    │
    └── 5. Return list of deleted sessions for logging
```

### 4.2 Session Age Detection

Use the session directory's modification time (`mtime`) as the "last activity" timestamp. This is updated whenever files are written to the session.

Alternative considered: Parse `llm-requests.jsonl` for latest timestamp. Rejected because:
- Requires reading potentially large files
- mtime is simpler and accurate enough

### 4.3 Eviction Strategies

| Strategy | Description | Use Case |
|----------|-------------|----------|
| `oldest_first` | Delete oldest sessions first | Default, fair cleanup |
| `largest_first` | Delete largest sessions first | Recover space quickly |

### 4.4 Integration Point

Run retention at proxy startup, before creating new storage:

```go
// In session.StartLLMProxy or llmproxy.New
func New(cfg Config, storagePath string, logger *slog.Logger) (*Proxy, error) {
    // Run retention cleanup (lightweight, runs in background after first call)
    if cfg.Storage.Retention.MaxAgeDays > 0 || cfg.Storage.Retention.MaxSizeMB > 0 {
        go RunRetention(filepath.Dir(storagePath), cfg.Storage.Retention, logger)
    }
    // ... rest of initialization
}
```

Using a goroutine ensures proxy startup isn't blocked by cleanup.

### 4.5 Skip Active Sessions

The retention logic must skip sessions that are currently active. Detection:
- Check if session exists in the session manager (requires passing session list)
- OR check for lock file in session directory
- OR simply skip current session by ID

Simplest approach: Pass current session ID to retention, skip it.

## 5. API

### 5.1 New Types

```go
// RetentionConfig matches config.LLMStorageRetentionConfig
type RetentionConfig struct {
    MaxAgeDays int
    MaxSizeMB  int
    Eviction   string // "oldest_first" | "largest_first"
}

// RetentionResult reports cleanup results
type RetentionResult struct {
    SessionsRemoved int
    BytesReclaimed  int64
    Sessions        []string // IDs of removed sessions
}
```

### 5.2 New Functions

```go
// RunRetention cleans up old sessions based on retention policy.
// currentSessionID is excluded from cleanup.
// Returns result and any error encountered.
func RunRetention(
    sessionsDir string,
    config RetentionConfig,
    currentSessionID string,
    logger *slog.Logger,
) (*RetentionResult, error)
```

## 6. File Structure

```
internal/llmproxy/
├── retention.go      # New: retention logic
├── retention_test.go # New: tests
├── storage.go        # Existing: calls RunRetention
└── ...
```

## 7. Configuration

Existing config (no changes needed):

```yaml
storage:
  retention:
    max_age_days: 30      # Delete sessions older than 30 days
    max_size_mb: 500      # Max total storage size
    eviction: oldest_first # oldest_first | largest_first
```

## 8. Logging

Eviction events logged at INFO level:

```
INFO retention cleanup started sessions_dir=/home/user/.agentsh/sessions
INFO session evicted session_id=session-abc123 reason=age age_days=45
INFO session evicted session_id=session-def456 reason=size size_mb=120
INFO retention cleanup complete removed=2 reclaimed_mb=180
```

## 9. Testing Strategy

1. **Unit tests:** Mock filesystem, verify age/size logic
2. **Integration test:** Create temp sessions, run retention, verify cleanup
3. **Edge cases:**
   - Empty sessions directory
   - No sessions exceed limits
   - All sessions exceed limits
   - Current session not deleted
   - Invalid session directories (skip gracefully)

## 10. Implementation Tasks

1. Create `retention.go` with `RunRetention` function
2. Create `retention_test.go` with unit tests
3. Integrate retention call in `llmproxy.New()`
4. Add integration test
5. Verify with manual testing

## 11. Future Considerations

- **Notification hooks:** Alert when cleanup runs
- **Dry-run mode:** Preview what would be deleted
- **Per-session limits:** Different retention per policy
- **Compression:** Compress old logs before deletion
