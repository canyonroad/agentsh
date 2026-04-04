# Fix Context Cancellation in FUSE Event Processing

## Problem

`processIOEvents` (core.go:1303) and the `NotifySoftDelete` closure (core.go:1228) in `mountFUSEForSession` capture the HTTP request context passed from `execInSession`. After the HTTP response is sent, the context cancels. All subsequent FUSE event appends fail silently because:

1. `AppendEvent` in the SQLite store does a two-phase channel send with `ctx.Done()` in both `select` branches. When the context is already canceled, `ctx.Done()` wins immediately and the event is guaranteed to be dropped.
2. Both callers discard the error with `_ =`.

This means file events (IO events, soft-delete notifications) from FUSE operations after the first exec are silently dropped.

**Note**: `mountFUSEForSession` also calls `AppendEvent(ctx, ...)` at lines 1263 (`fuse_mount_failed`) and 1296 (`fuse_mounted`). These are out of scope — they execute synchronously during mount setup, before the HTTP response is sent, so the context is still valid.

## Approach

Use `context.WithTimeout(context.Background(), 5*time.Second)` for each event append, matching the existing MCP event callback pattern (app.go). Log errors instead of discarding them.

### Changes

**`internal/api/core.go`**

1. **`processIOEvents`**: Remove the `ctx` parameter. Inside the loop, create a per-event timeout context. Call `cancel()` eagerly after `AppendEvent` returns — do NOT use `defer cancel()` in the loop body, as defers stack until the function returns, leaking timer resources for every event.

   ```go
   persistCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
   err := a.store.AppendEvent(persistCtx, ev)
   cancel()
   if err != nil {
       slog.Error("persist fuse io event", "error", err, "event_type", ev.Type, "event_id", ev.ID)
   }
   ```

2. **`NotifySoftDelete` closure**: Same pattern — per-call timeout context with eager cancel. Log errors:

   ```go
   persistCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
   err := a.store.AppendEvent(persistCtx, ev)
   cancel()
   if err != nil {
       slog.Error("persist fuse soft-delete event", "error", err, "event_type", ev.Type, "path", path)
   }
   ```

3. **Call site** (line 1203): Remove `ctx` argument from `go a.processIOEvents(...)`.

### Test

**`internal/api/core_fuse_ctx_test.go`**

Test that `processIOEvents` persists events regardless of the caller's context state. Use an in-memory SQLite store (`:memory:`) since that's the real store implementation and avoids needing a mock interface:

- Open an in-memory store
- Create a cancelable context, cancel it immediately
- Construct an `App` with the store
- Send events through a channel to `processIOEvents`
- Close the channel, wait for the goroutine to finish
- Query the store and assert events were persisted

Also test the `NotifySoftDelete` closure path — invoke it after context cancellation and assert the event was stored.

## Existing Pattern

MCP event callbacks in app.go already use this pattern:

```go
persistCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
if err := store.AppendEvent(persistCtx, typesEv); err != nil {
    slog.Error("persist mcp intercept event", "error", err, ...)
}
```

## Verification

- `go test ./internal/api/ -run TestProcessIOEvents` — new test passes
- `go build ./...` — clean build
- `GOOS=windows go build ./...` — cross-compile check
