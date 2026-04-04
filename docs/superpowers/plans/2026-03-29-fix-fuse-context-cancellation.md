# Fix FUSE Context Cancellation Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix silent event drops caused by HTTP request context cancellation in FUSE event processing.

**Architecture:** Replace the captured HTTP request context in `processIOEvents` and `NotifySoftDelete` with per-event `context.WithTimeout(context.Background(), 5s)`, matching the existing MCP event callback pattern. Log errors instead of discarding them.

**Tech Stack:** Go, context package, slog structured logging

---

### Task 1: Add regression test proving bug exists, then fix processIOEvents

**Files:**
- Create: `internal/api/core_fuse_ctx_test.go`
- Modify: `internal/api/core.go:1303-1317` (processIOEvents method)
- Modify: `internal/api/core.go:1203` (call site in mountFUSEForSession)

- [ ] **Step 1: Write the regression test**

This test uses a context-aware fake store that respects context cancellation (like the real SQLite store does). It proves events are dropped when a canceled context is used, then proves the fixed code persists them.

Create `internal/api/core_fuse_ctx_test.go`:

```go
package api

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/platform"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)

// ctxAwareEventStore respects context cancellation, like the real SQLite store.
type ctxAwareEventStore struct {
	mu     sync.Mutex
	events []types.Event
}

func (f *ctxAwareEventStore) AppendEvent(ctx context.Context, ev types.Event) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
	return nil
}

func (f *ctxAwareEventStore) QueryEvents(_ context.Context, _ types.EventQuery) ([]types.Event, error) {
	return nil, nil
}

func (f *ctxAwareEventStore) Close() error { return nil }

func (f *ctxAwareEventStore) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.events)
}

// TestProcessIOEvents_PersistsAfterContextCancellation verifies that
// processIOEvents uses its own background context, not a caller-provided
// context that may already be canceled. This is a regression test for a bug
// where the HTTP request context was captured and used for event persistence,
// causing silent drops after the first exec response was sent.
func TestProcessIOEvents_PersistsAfterContextCancellation(t *testing.T) {
	fake := &ctxAwareEventStore{}
	cStore := composite.New(fake, nil)
	broker := events.NewBroker()
	app := &App{
		store:    cStore,
		broker:   broker,
		sessions: session.NewManager(0),
	}

	ch := make(chan platform.IOEvent, 10)

	// Send 3 events
	for i := 0; i < 3; i++ {
		ch <- platform.IOEvent{
			Timestamp: time.Now(),
			SessionID: "test-session",
			Type:      platform.EventFileWrite,
			Path:      "/tmp/test",
		}
	}
	close(ch)

	// processIOEvents no longer takes a context — it creates its own
	// background context per event. All 3 events should be persisted.
	app.processIOEvents(ch)

	if got := fake.count(); got != 3 {
		t.Fatalf("expected 3 events persisted, got %d", got)
	}
}
```

- [ ] **Step 2: Run test — expect compile error (processIOEvents still takes ctx)**

Run: `go test ./internal/api/ -run TestProcessIOEvents -v`
Expected: compile error — `processIOEvents` has wrong signature

- [ ] **Step 3: Fix processIOEvents — remove ctx parameter, use background context**

Change the signature and loop body at `core.go:1303-1317`:

```go
// processIOEvents reads events from the platform event channel and forwards
// them to the event store and broker. It runs until the channel is closed.
func (a *App) processIOEvents(eventChan <-chan platform.IOEvent) {
	for ioEvent := range eventChan {
		// Convert platform.IOEvent to types.Event
		ev := ioEvent.ToEvent()
		ev.ID = uuid.NewString()

		// Inject trace context from session for distributed tracing correlation
		if s, ok := a.sessions.Get(ioEvent.SessionID); ok {
			s.InjectTraceContext(ev.Fields)
		}

		// Store and publish the event
		persistCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := a.store.AppendEvent(persistCtx, ev)
		cancel()
		if err != nil {
			slog.Error("persist fuse io event", "error", err, "event_type", ev.Type, "event_id", ev.ID)
		}
		a.broker.Publish(ev)
	}
}
```

- [ ] **Step 4: Update call site**

Change `core.go:1203` from:
```go
go a.processIOEvents(ctx, eventChan)
```
to:
```go
go a.processIOEvents(eventChan)
```

- [ ] **Step 5: Run test — expect PASS**

Run: `go test ./internal/api/ -run TestProcessIOEvents -v`
Expected: PASS — all 3 events persisted

- [ ] **Step 6: Commit**

```bash
git add internal/api/core.go internal/api/core_fuse_ctx_test.go
git commit -m "fix: use background context in processIOEvents to prevent silent event drops"
```

---

### Task 2: Fix NotifySoftDelete closure to use background context

**Files:**
- Modify: `internal/api/core.go:1228-1243` (NotifySoftDelete closure in mountFUSEForSession)

- [ ] **Step 1: Replace captured ctx with per-call background context**

Change the closure at `core.go:1228-1243` from:
```go
fsCfg.NotifySoftDelete = func(path, token string) {
    ev := types.Event{
        ID:        uuid.NewString(),
        Timestamp: time.Now().UTC(),
        Type:      "file_soft_deleted",
        SessionID: s.ID,
        CommandID: s.CurrentCommandID(),
        Path:      path,
        Fields: map[string]any{
            "trash_token":  token,
            "restore_hint": fmt.Sprintf("agentsh trash restore %s", token),
        },
    }
    _ = a.store.AppendEvent(ctx, ev)
    a.broker.Publish(ev)
}
```

to:
```go
fsCfg.NotifySoftDelete = func(path, token string) {
    ev := types.Event{
        ID:        uuid.NewString(),
        Timestamp: time.Now().UTC(),
        Type:      "file_soft_deleted",
        SessionID: s.ID,
        CommandID: s.CurrentCommandID(),
        Path:      path,
        Fields: map[string]any{
            "trash_token":  token,
            "restore_hint": fmt.Sprintf("agentsh trash restore %s", token),
        },
    }
    persistCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    err := a.store.AppendEvent(persistCtx, ev)
    cancel()
    if err != nil {
        slog.Error("persist fuse soft-delete event", "error", err, "event_type", ev.Type, "path", path)
    }
    a.broker.Publish(ev)
}
```

- [ ] **Step 2: Verify build and run full test suite**

Run: `go build ./internal/api/... && go test ./internal/api/ -count=1`
Expected: clean build, all tests pass

- [ ] **Step 3: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: clean

- [ ] **Step 4: Commit**

```bash
git add internal/api/core.go
git commit -m "fix: use background context in NotifySoftDelete to prevent silent event drops"
```
