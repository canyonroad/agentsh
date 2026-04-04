# Disable SQLite Audit Storage Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `audit.storage.enabled` config flag so deployments using only JSONL/webhook output can skip SQLite entirely.

**Architecture:** Add `Enabled *bool` to `AuditStorageConfig` (default `true`), make composite store nil-safe for nil primary, conditionally skip `sqlite.Open` in `server.New()`.

**Tech Stack:** Go, YAML config

**Spec:** `docs/superpowers/specs/2026-03-30-disable-sqlite-audit-design.md`

---

### Task 1: Add `Enabled` field to `AuditStorageConfig` and set default

**Files:**
- Modify: `internal/config/config.go` — `AuditStorageConfig` struct and `applyDefaultsWithSource`
- Test: `internal/config/config_test.go`

- [ ] **Step 1: Write failing tests**

Add to `internal/config/config_test.go`:

```go
func TestAuditStorageEnabledDefault(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Audit.Storage.Enabled == nil {
		t.Fatal("Audit.Storage.Enabled should not be nil after defaults")
	}
	if !*cfg.Audit.Storage.Enabled {
		t.Error("Audit.Storage.Enabled should default to true")
	}
}

func TestAuditStorageDisabled(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(`
audit:
  storage:
    enabled: false
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Audit.Storage.Enabled == nil {
		t.Fatal("Audit.Storage.Enabled should not be nil")
	}
	if *cfg.Audit.Storage.Enabled {
		t.Error("Audit.Storage.Enabled should be false when explicitly set")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/ -run 'TestAuditStorage' -v`
Expected: FAIL — `Enabled` field does not exist on `AuditStorageConfig`.

- [ ] **Step 3: Add `Enabled` field to config struct**

In `internal/config/config.go`, modify `AuditStorageConfig` (line 158) to add the `Enabled` field:

```go
type AuditStorageConfig struct {
	Enabled       *bool         `yaml:"enabled"`         // defaults to true; set false to skip SQLite
	SQLitePath    string        `yaml:"sqlite_path"`
	BatchSize     int           `yaml:"batch_size"`      // events per batch (default 64)
	FlushInterval time.Duration `yaml:"flush_interval"`  // max time before flush (default 50ms)
	ChannelSize   int           `yaml:"channel_size"`    // async buffer capacity (default 4096)
}
```

- [ ] **Step 4: Add default in `applyDefaultsWithSource`**

In `internal/config/config.go`, in the `applyDefaultsWithSource` function, add before the `cfg.Audit.Storage.SQLitePath` default block:

```go
	if cfg.Audit.Storage.Enabled == nil {
		cfg.Audit.Storage.Enabled = boolPtr(true)
	}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/config/ -run 'TestAuditStorage' -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat: add audit.storage.enabled config flag (#181)"
```

---

### Task 2: Make composite store nil-safe for nil primary

**Files:**
- Modify: `internal/store/composite/composite.go`
- Test: `internal/store/composite/composite_test.go`

- [ ] **Step 1: Write failing tests**

Add to `internal/store/composite/composite_test.go`:

```go
func TestComposite_NilPrimary_AppendEvent(t *testing.T) {
	other := &fakeEventStore{}
	s := New(nil, nil, other)

	if err := s.AppendEvent(context.Background(), types.Event{ID: "1"}); err != nil {
		t.Fatalf("AppendEvent with nil primary: %v", err)
	}
	if other.appended != 1 {
		t.Fatalf("expected other store to receive event, got %d appends", other.appended)
	}
}

func TestComposite_NilPrimary_QueryEvents(t *testing.T) {
	s := New(nil, nil)

	events, err := s.QueryEvents(context.Background(), types.EventQuery{})
	if err != nil {
		t.Fatalf("QueryEvents with nil primary: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected empty results, got %d", len(events))
	}
}

func TestComposite_NilPrimary_Close(t *testing.T) {
	other := &fakeEventStore{}
	s := New(nil, nil, other)

	if err := s.Close(); err != nil {
		t.Fatalf("Close with nil primary: %v", err)
	}
	if !other.closed {
		t.Fatal("expected other store to be closed")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/store/composite/ -run 'TestComposite_NilPrimary' -v`
Expected: FAIL — panic on nil pointer dereference in `AppendEvent`, `QueryEvents`, or `Close`.

- [ ] **Step 3: Add nil guards to composite store**

In `internal/store/composite/composite.go`, modify three methods:

**`AppendEvent`** (line 23-34) — change to:
```go
func (s *Store) AppendEvent(ctx context.Context, ev types.Event) error {
	var firstErr error
	if s.primary != nil {
		if err := s.primary.AppendEvent(ctx, ev); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, o := range s.others {
		if err := o.AppendEvent(ctx, ev); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
```

**`QueryEvents`** (line 36-38) — change to:
```go
func (s *Store) QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error) {
	if s.primary == nil {
		return nil, nil
	}
	return s.primary.QueryEvents(ctx, q)
}
```

**`Close`** (line 54-65) — change to:
```go
func (s *Store) Close() error {
	var firstErr error
	if s.primary != nil {
		if err := s.primary.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, o := range s.others {
		if err := o.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/store/composite/ -v`
Expected: PASS — all existing and new tests.

- [ ] **Step 5: Commit**

```bash
git add internal/store/composite/composite.go internal/store/composite/composite_test.go
git commit -m "fix: make composite store nil-safe for nil primary (#181)"
```

---

### Task 3: Wire the flag into `server.go`

**Files:**
- Modify: `internal/server/server.go` — SQLite conditional, `db.Close()` nil guards, composite wiring

- [ ] **Step 1: Wrap SQLite creation in conditional**

In `internal/server/server.go`, replace lines 149-160 (the SQLite block) with:

```go
	var db *sqlite.Store
	if *cfg.Audit.Storage.Enabled {
		sqlitePath := cfg.Audit.Storage.SQLitePath
		if sqlitePath == "" {
			sqlitePath = filepath.Join(filepath.Dir(cfg.Sessions.BaseDir), "events.db")
		}
		db, err = sqlite.Open(sqlitePath, sqlite.BatchConfig{
			BatchSize:     cfg.Audit.Storage.BatchSize,
			FlushInterval: cfg.Audit.Storage.FlushInterval,
			ChannelSize:   cfg.Audit.Storage.ChannelSize,
		})
		if err != nil {
			return nil, err
		}
	} else {
		slog.Warn("SQLite audit storage disabled; event queries, output storage, and MCP tool tracking are unavailable")
	}
```

- [ ] **Step 2: Replace composite store wiring**

Replace lines 273-275 (the `primary`/`store` creation) with:

```go
	var primary storepkg.EventStore
	var output storepkg.OutputStore
	if db != nil {
		primary = metrics.WrapEventStore(db, metricsCollector)
		output = db
	}
	store := composite.New(primary, output, eventStores...)
```

- [ ] **Step 3: Add nil guards to all `db.Close()` error paths**

Find all `_ = db.Close()` calls in the `New()` function and wrap each with:

```go
	if db != nil {
		_ = db.Close()
	}
```

There are 7 call sites in `New()`:
1. After JSONL store creation failure (line 166)
2. After integrity chain init failure (line 182)
3. After webhook flush_interval parse failure (line 199)
4. After webhook timeout parse failure (line 204)
5. After webhook.New failure (line 209)
6. After OTEL timeout parse failure (line 221)
7. After OTEL batch timeout parse failure (line 226)

- [ ] **Step 4: Verify build**

Run: `go build ./...`
Expected: Clean build.

Run: `GOOS=windows go build ./...`
Expected: Clean build.

- [ ] **Step 5: Run all tests**

Run: `go test ./internal/server/ ./internal/store/composite/ ./internal/config/ -v`
Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/server/server.go
git commit -m "feat: skip SQLite when audit.storage.enabled is false (#181)"
```

---

### Task 4: Full test suite and cross-compile verification

**Files:** None (verification only)

- [ ] **Step 1: Run all tests**

Run: `go test ./...`
Expected: All PASS.

- [ ] **Step 2: Verify cross-compilation**

Run: `GOOS=windows go build ./...`
Expected: Clean build.

- [ ] **Step 3: Final commit (if any fixups needed)**

Only if prior steps required fixes.
