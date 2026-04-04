# Add Flag to Disable SQLite Audit Storage

**Issue:** #181
**Date:** 2026-03-30

## Problem

AgentSH unconditionally opens a SQLite database for audit event storage. There is no config flag to disable it — if `sqlite_path` is empty, it defaults to `events.db`. Deployments using only JSONL or webhook output waste memory and I/O on an unnecessary database.

## Design

### 1. Config change

Add `Enabled *bool` to `AuditStorageConfig` with a default of `true` (via `boolPtr`), following the existing `*bool` pattern used by `SandboxSeccompConfig`, `FileMonitorConfig`, etc.

```go
type AuditStorageConfig struct {
    Enabled       *bool         `yaml:"enabled"`        // defaults to true
    SQLitePath    string        `yaml:"sqlite_path"`
    BatchSize     int           `yaml:"batch_size"`
    FlushInterval time.Duration `yaml:"flush_interval"`
    ChannelSize   int           `yaml:"channel_size"`
}
```

In `applyDefaultsWithSource`, add:
```go
if cfg.Audit.Storage.Enabled == nil {
    cfg.Audit.Storage.Enabled = boolPtr(true)
}
```

Config usage:
```yaml
audit:
  storage:
    enabled: false  # skip SQLite entirely
```

### 2. Server wiring (`server.go`)

Wrap the SQLite block in a conditional. When disabled:
- Skip `sqlite.Open`
- Skip `metrics.WrapEventStore`
- Pass `nil` for both `primary` and `output` to `composite.New`
- Log a warning at startup so operators know SQLite-dependent features are unavailable

Since `applyDefaultsWithSource` guarantees `Enabled` is never nil by the time `New()` runs, use a direct dereference (consistent with all other `*bool` config fields):

```go
var db *sqlite.Store
if *cfg.Audit.Storage.Enabled {
    sqlitePath := cfg.Audit.Storage.SQLitePath
    if sqlitePath == "" {
        sqlitePath = filepath.Join(filepath.Dir(cfg.Sessions.BaseDir), "events.db")
    }
    db, err = sqlite.Open(sqlitePath, sqlite.BatchConfig{...})
    if err != nil {
        return nil, err
    }
} else {
    slog.Warn("SQLite audit storage disabled; event queries, output storage, and MCP tool tracking are unavailable")
}

// ...later...
var primary storepkg.EventStore
var output storepkg.OutputStore
if db != nil {
    primary = metrics.WrapEventStore(db, metricsCollector)
    output = db
}
store := composite.New(primary, output, eventStores...)
```

### 3. Composite store nil-safety

`composite.Store` needs nil guards for `primary`:

- **`AppendEvent`**: Skip `s.primary.AppendEvent` if `s.primary == nil`. Still write to `others` (JSONL, webhook, OTEL):
  ```go
  if s.primary != nil {
      if err := s.primary.AppendEvent(ctx, ev); err != nil && firstErr == nil {
          firstErr = err
      }
  }
  ```
- **`QueryEvents`**: Return `nil, nil` (empty results, no error) if `s.primary == nil`.
- **`Close`**: Skip `s.primary.Close()` if `s.primary == nil`.

The `output` path (`SaveOutput`/`ReadOutputChunk`) already returns errors when `s.output == nil`. The MCP methods (`UpsertMCPToolFromEvent`, `ListMCPTools`, `ListMCPServers`) already type-assert and silently skip or return errors when primary isn't `*sqlite.Store`.

### 4. Error-path cleanup in `server.go`

There are 7 `db.Close()` call sites in `New()` on error paths. All need nil guards:
```go
if db != nil {
    _ = db.Close()
}
```

These are at the error returns after: JSONL store creation, integrity chain init, webhook flush_interval parse, webhook timeout parse, webhook.New, OTEL timeout parse, and OTEL batch timeout parse.

## Known limitations

- **Event metrics not counted when SQLite is disabled.** `metrics.WrapEventStore` wraps the primary store only. When primary is nil, events written to JSONL/webhook/OTEL are not counted in metrics. This is an observability gap, not a correctness bug.
- **MCP tool queries return errors.** `ListMCPTools` and `ListMCPServers` return `"MCP queries not supported by primary store"` when SQLite is disabled. API handlers will return 500s for these endpoints. Operators disabling SQLite presumably don't use these features.
- **Output storage returns errors.** `SaveOutput`/`ReadOutputChunk` return `"output store not configured"` when SQLite is disabled.

## Testing strategy

### Unit tests

1. **`internal/config/config_test.go` — `TestAuditStorageEnabledDefault`**
   - Parse empty config, verify `Audit.Storage.Enabled` defaults to `true`

2. **`internal/config/config_test.go` — `TestAuditStorageDisabled`**
   - Parse config with `audit.storage.enabled: false`, verify it's `false`

3. **`internal/store/composite/composite_test.go` — `TestComposite_NilPrimary_AppendEvent`**
   - Create composite with `nil` primary and a mock `others` store
   - Verify `AppendEvent` succeeds and writes to `others`

4. **`internal/store/composite/composite_test.go` — `TestComposite_NilPrimary_QueryEvents`**
   - Verify `QueryEvents` returns empty results (not panic/error)

5. **`internal/store/composite/composite_test.go` — `TestComposite_NilPrimary_Close`**
   - Verify `Close` succeeds with nil primary
