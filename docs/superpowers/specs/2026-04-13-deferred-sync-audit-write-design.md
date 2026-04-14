# Deferred Sync Audit Write Design

**Date:** 2026-04-13
**Status:** Draft
**Related:**
- `docs/superpowers/specs/2026-03-30-wire-hmac-integrity-chain-design.md` (original chain wiring)
- `docs/superpowers/specs/2026-04-11-hmac-chain-tamper-evidence-design.md` (sidecar, startup recovery)

## Problem

`IntegrityStore.AppendEvent` performs 3 synchronous fsync calls on the seccomp notify response hot path, blocking the traced process until all disk I/O completes:

| # | Call | Location |
|---|------|----------|
| 1 | `file.Sync()` on JSONL data file | `jsonl.go:150` |
| 2 | `tmpFile.Sync()` on sidecar temp file | `sidecar.go:133` |
| 3 | `file.Sync()` on directory (rename durability) | `fsync_dir_unix.go:7-13` via `sidecar.go:145` |

The call chain is:

```
NotifReceive
  -> h.Handle()                           # policy decision
    -> emitEvent()                        # inside Handle, before returning
      -> IntegrityStore.AppendEvent()     # integrity_wrapper.go:436
        -> chain.Wrap()                   # HMAC computation (~us)
        -> rw.WriteRaw()                  # jsonl.go:120 -> file.Sync() <- BLOCKS
        -> audit.WriteSidecar()           # sidecar.go:106 -> 2 more fsyncs <- BLOCKS
  -> NotifRespondContinue/Deny           # process only unblocks HERE
```

**Measured impact on arm64 Ubuntu Server VM (ext4 CoW disk):**

| Config | ms/exec | Delta from baseline |
|--------|---------|---------------------|
| audit disabled | 35ms | -- |
| audit on tmpfs | 31ms | -4ms (noise; tmpfs Sync is a no-op) |
| audit on ext4 CoW | 292ms | +257ms |

The entire 257ms overhead is the 3 fsyncs. For a workload like `npm install` with 500 execs, this adds ~130 seconds of pure fsync overhead.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| **Durability model** | No-gap audit: every event fsync'd, but AFTER process unblocks | Threat model includes attacker who can kill agentsh to suppress records. Accepts a narrow ~100ms window where events are written but not yet fsync'd. |
| **Approach** | Deferred sync: emit after response + periodic background fsync | Best balance of performance and complexity. Page cache serves as natural write buffer. |
| **Flush interval** | 100ms default | Bounds durability window. At ~28 notifs/sec, ~3 events per batch. 10 fsyncs/sec is negligible on any disk. |
| **Non-integrity path** | Keep inline Sync when IntegrityStore is not wrapping | Performance issue is driven by sidecar overhead (3 fsyncs). Bare JSONL with 1 fsync is acceptable. |

## Architecture

Four layers of change:

1. **Notify loop restructuring** -- Handle() returns the decision and event separately. Response is sent first, then the event is appended (page-cache only, no fsync).
2. **JSONL store split** -- `WriteRaw()` loses its `file.Sync()` call. A new `Sync()` method is added for the background timer.
3. **IntegrityStore split** -- `AppendEvent()` does Wrap + Write (fast). A new `FlushSync()` method does fsync + sidecar update (slow, background).
4. **Background sync timer** -- A goroutine ticks every ~100ms, calls `FlushSync()`. Amortizes 3N fsyncs per N events down to 3 per batch.

```
 Before (292ms/exec):
 +--------------------------------------------------------------+
 | NotifReceive -> Handle -> Wrap -> Write -> Sync -> Sidecar -> Respond |
 +--------------------------------------------------------------+
                                      ^^^ 260ms ^^^

 After (~35ms/exec):
 +---------------------------+                +------------------------------+
 | NotifReceive -> Handle -> Respond |  then  | Wrap -> Write(page cache)    |
 +---------------------------+                +------------------------------+
        ~35ms (kernel + policy)                       ~us (all in-memory)
                                     +-------------------------------------+
                                     | Background timer (100ms): Sync + Sidecar |
                                     +-------------------------------------+
```

Handle() becomes a pure event-builder (returns the decision + event struct, no I/O). The response is sent immediately. Then `AppendEvent()` does Wrap + page-cache Write — both ~microseconds. The HMAC chain ordering guarantee is preserved: Wrap() is called under the IntegrityStore mutex, which serializes all chain mutations regardless of which notify loop goroutine (session) calls it. Wrap() happening after the response is fine — chain integrity depends on serialization, not on timing relative to the response.

## Detailed Design

### 1. Notify Loop Restructuring

Split Handle() so the decision and event emission are decoupled.

**Current flow (execve path):**

```go
// execve_handler.go -- Handle() calls emitEvent internally
result := h.Handle(goCtx, ectx)  // emitEvent + AppendEvent + fsync inside
// handler.go -- response sent after Handle returns
NotifRespondContinue(fd, req.ID)
```

**New flow:**

```go
// Handle returns both the decision AND the pre-built event
result, ev := h.Handle(goCtx, ectx)

// Response FIRST -- process unblocks
NotifRespondContinue(fd, req.ID)

// Emit AFTER -- page-cache write only, ~us
if ev != nil {
    _ = h.emitter.AppendEvent(context.Background(), ev)
    h.emitter.Publish(ev)
}
```

**Handler changes:**

- `ExecveHandler.Handle()` returns `(ExecveResult, *types.Event)`. The `emitEvent()` helper builds and returns the event instead of calling `AppendEvent`.
- `FileHandler.Handle()` returns `(FileResult, *types.Event)`.
- `handleExecveNotification()`, `handleFileNotification()`, and `handleFileNotificationEmulated()` in `handler.go` adopt the respond-then-emit pattern.
- The unix socket path (`emitEvent` in `handler.go`) gets the same treatment.
- The `emitEvent` helpers become pure event-builders with no side effects. The caller controls when emission happens.

### 2. JSONL Store Changes

**`WriteRaw()` -- drop the fsync:**

The existing `file.Sync()` call at `jsonl.go:150` is removed. Everything else in `WriteRaw` (locking, rotation check, stat, write, truncate-on-failure) stays unchanged.

**New `Sync()` method on `jsonl.Store`:**

```go
func (s *Store) Sync() error {
    s.mu.Lock()
    defer s.mu.Unlock()
    if s.file == nil {
        return nil
    }
    return s.file.Sync()
}
```

Takes the write mutex to serialize with `WriteRaw` and `rotateIfNeededLocked`.

**New `Syncer` interface in `internal/store/store.go`:**

```go
// Syncer can flush buffered writes to durable storage.
type Syncer interface {
    Sync() error
}
```

The IntegrityStore type-asserts for this, same pattern as `RawWriter`.

**`syncOnWrite` flag:** Add a `syncOnWrite bool` field to `jsonl.Store`, defaulting to `true`. When the IntegrityStore wraps the JSONL store, it disables inline sync via a `SetSyncOnWrite(false)` call (the JSONL store exposes this method). When `syncOnWrite` is `true`, `WriteRaw` retains the inline `file.Sync()` call. This ensures the non-integrity path keeps its existing durability behavior.

**`DurabilityError`** moves from `WriteRaw` to the `Sync()` method. The error type itself is unchanged.

### 3. IntegrityStore Changes

**`AppendEvent()` -- write only, no sync, no sidecar:**

Same logic as today for Wrap + WriteRaw, but removes the `WriteSidecar` call. A `pendingFlush bool` field tracks whether there are unflushed events.

**New `FlushSync()` method:**

```go
func (s *IntegrityStore) FlushSync() error {
    // Snapshot chain state under the chain mutex
    s.mu.Lock()
    if !s.pendingFlush || s.fatal {
        s.mu.Unlock()
        return nil
    }
    state := s.chain.State()
    s.pendingFlush = false
    s.mu.Unlock()

    // Sync the underlying store (slow -- NOT under chain mutex)
    if syncer, ok := s.inner.(Syncer); ok {
        if err := syncer.Sync(); err != nil {
            s.mu.Lock()
            s.fatal = true
            s.mu.Unlock()
            return &FatalIntegrityError{Op: "sync audit log", Err: err}
        }
    }

    // Update sidecar (slow -- NOT under chain mutex)
    if err := audit.WriteSidecar(s.sidecarPath, audit.SidecarState{
        Sequence:       state.Sequence,
        PrevHash:       state.PrevHash,
        KeyFingerprint: s.keyFingerprint,
        UpdatedAt:      s.now().UTC(),
    }); err != nil {
        s.mu.Lock()
        s.fatal = true
        s.mu.Unlock()
        return &FatalIntegrityError{Op: "write audit integrity sidecar", Err: err}
    }
    return nil
}
```

Critical detail: `s.mu` is released before the slow I/O. The notify loop is never blocked waiting on fsync -- it only contends for the mutex during the ~microsecond Wrap+Write window.

**New fields on IntegrityStore:**

```go
type IntegrityStore struct {
    // ... existing fields ...
    pendingFlush bool           // events written since last flush
    flushTick    *time.Ticker   // periodic sync timer
    stopFlush    chan struct{}   // signals timer goroutine to exit
    flushDone    chan struct{}   // closed when timer goroutine exits
}
```

### 4. Background Sync Timer

**Started in the constructor:**

```go
func NewIntegrityStore(...) *IntegrityStore {
    s := &IntegrityStore{
        // ... existing init ...
        stopFlush: make(chan struct{}),
        flushDone: make(chan struct{}),
    }
    interval := 100 * time.Millisecond
    s.flushTick = time.NewTicker(interval)
    go s.runFlushLoop()
    return s
}
```

**The flush loop:**

```go
func (s *IntegrityStore) runFlushLoop() {
    defer close(s.flushDone)
    for {
        select {
        case <-s.flushTick.C:
            if err := s.FlushSync(); err != nil {
                slog.Error("audit flush failed", "error", err)
            }
        case <-s.stopFlush:
            s.flushTick.Stop()
            return
        }
    }
}
```

**Shutdown ordering in `Close()`:**

```go
func (s *IntegrityStore) Close() error {
    // 1. Signal timer to stop
    close(s.stopFlush)
    // 2. Wait for timer goroutine to exit
    <-s.flushDone
    // 3. Final flush -- ensures last batch is durable
    if err := s.FlushSync(); err != nil {
        slog.Error("final audit flush failed", "error", err)
    }
    // 4. Close inner store
    return s.inner.Close()
}
```

### 5. Crash Recovery: Extending Sidecar Startup to seq+N

The deferred sync means the sidecar can be behind by N events on crash. The existing tamper-evidence startup logic (2026-04-11 spec) handles seq+1. We generalize.

**Crash scenario:**

```
Events written (page cache):  seq 100, 101, 102, 103, 104
Last FlushSync completed:     seq 102 (sidecar says seq=102, prev_hash=hash_of_102)
Crash happens.
On-disk after recovery:       seq 100..104 may be fully or partially present
```

**Generalized recovery rule:**

Replace the existing `sidecar.seq + 1 == last_line.seq` check with:

```
sidecar.seq <= last_line.seq
AND last_line verifies under current key
AND chain is continuous from sidecar.seq to last_line.seq
    (walk forward from sidecar.seq+1, verify each link)
```

A valid chain suffix proves the events are genuine (can't be forged without the HMAC key) and the sidecar just wasn't updated before the crash.

**Recovery action:** Advance the sidecar to `last_line.seq` / `last_line.entry_hash`, log a warning:

```go
slog.Warn("audit integrity: sidecar behind by N events, advancing after crash recovery",
    "sidecar_seq", sidecarState.Sequence,
    "log_seq", lastLine.Sequence,
    "events_recovered", lastLine.Sequence - sidecarState.Sequence)
```

**Truncated last line:** If the crash happened mid-Write(), the last line may be truncated (incomplete JSON). Startup detects this (JSON parse failure on the last line) and truncates the file back to the last complete line before chain verification.

**Bound on N:** With 100ms flush interval and ~28 notifs/sec, N is at most ~3 events per batch. No special handling needed for large N.

### 6. Error Handling

**Write failures (detected inline):** `file.Write()` fails in `WriteRaw()` -> truncate-and-rollback or `PartialWriteError` -> `AppendEvent` returns error immediately. The notify response was already sent, so the process isn't affected. Same behavior as today.

**Sync failures (detected in background timer):** `file.Sync()` fails in `FlushSync()` -> sets `s.fatal = true` under mutex -> next `AppendEvent` call sees `s.fatal` and returns `ErrIntegrityFatal`. The process that triggered the next `AppendEvent` is unaffected (response already sent), but no further events can be written.

**Sidecar write failures (detected in background timer):** `WriteSidecar()` fails in `FlushSync()` -> same fatal path.

**Fatal flag visibility:** `s.fatal` is read/written under `s.mu`. Both background timer and notify loop hold the mutex. No atomic operations needed.

**Logging:** `FlushSync()` returns the error to `runFlushLoop()`, which logs via `slog.Error`. This is strictly better than the current behavior where `emitEvent` discards errors with `_ =`.

## Testing Strategy

### JSONL Store Tests (`internal/store/jsonl/`)

1. **`TestWriteRaw_NoSync`** -- Write an event via `WriteRaw` with `syncOnWrite=false`. Verify file contents are correct. Use a spy file wrapper that counts Sync calls to confirm no Sync occurred.

2. **`TestSync_FlushesToDisk`** -- Write multiple events via `WriteRaw`, call `Sync()`, read the file back, verify all events present and complete.

3. **`TestSync_NilFile`** -- Call `Sync()` on a closed/nil-file store. Verify it returns nil without panic.

4. **`TestWriteRaw_And_Sync_Concurrent`** -- Launch N goroutines calling `WriteRaw` concurrently with a goroutine calling `Sync()` every 10ms. Verify no data corruption: all written events are present and complete lines in the file.

### IntegrityStore Tests (`internal/store/`)

5. **`TestAppendEvent_NoSidecarWrite`** -- Append an event, verify the JSONL file has the wrapped entry but no sidecar update occurred (check mtime or use a spy).

6. **`TestFlushSync_WritesSidecar`** -- Append events, call `FlushSync()`, verify sidecar reflects latest chain state.

7. **`TestFlushSync_Noop_WhenNoPending`** -- Call `FlushSync()` without preceding `AppendEvent`. Verify it returns nil and doesn't touch the sidecar.

8. **`TestFlushSync_SetsFatal_OnSyncError`** -- Inject a sync error via mock Syncer. Call `FlushSync()`, verify `s.fatal` is set. Call `AppendEvent`, verify `ErrIntegrityFatal`.

9. **`TestFlushSync_SetsFatal_OnSidecarError`** -- Point `sidecarPath` to unwritable directory. Call `FlushSync()`, verify fatal behavior.

10. **`TestAppendEvent_Then_FlushSync_ChainContinuity`** -- Append 10 events, `FlushSync()`, append 10 more, `FlushSync()`. Read JSONL file, verify entire 20-event HMAC chain is valid.

11. **`TestConcurrent_AppendEvent_And_FlushSync`** -- N goroutines appending events + goroutine calling `FlushSync()` every 10ms. Verify chain integrity across all written events.

### Background Timer Tests (`internal/store/`)

12. **`TestFlushLoop_PeriodicSync`** -- Create IntegrityStore with short flush interval (10ms). Append events, sleep 50ms, verify sidecar updated.

13. **`TestFlushLoop_StopsOnClose`** -- Create store, verify timer is running, call `Close()`, verify `flushDone` channel is closed.

14. **`TestClose_FinalFlush`** -- Append events, immediately `Close()` (don't wait for timer). Verify sidecar reflects latest state.

### Crash Recovery Tests (`internal/store/` or `internal/audit/`)

15. **`TestStartup_SidecarBehindByN`** -- JSONL file with seq 0..10, sidecar at seq 7. Construct IntegrityStore. Verify it recovers: walks seq 8..10, validates chain, advances sidecar to seq 10, resumes normally.

16. **`TestStartup_SidecarBehindByN_InvalidChain`** -- Same as above, corrupt one event between seq 8..10 (bad HMAC). Verify store refuses to start.

17. **`TestStartup_TruncatedLastLine`** -- Events seq 0..5 plus truncated line. Verify startup truncates bad line and recovers from seq 5.

### Notify Loop Integration Tests (`internal/netmonitor/unix/`)

18. **`TestHandleExecve_RespondsBeforeEmit`** -- Mock seccomp fd and emitter. Verify `NotifRespondContinue` called BEFORE `emitter.AppendEvent` (recording mock captures call order).

19. **`TestHandleFile_RespondsBeforeEmit`** -- Same for file handler path.

20. **`TestHandleUnixSocket_RespondsBeforeEmit`** -- Same for unix socket path.

### Benchmark Tests

21. **`BenchmarkAppendEvent_DeferredSync`** -- Benchmark `AppendEvent` on ext4 with deferred sync. Verify per-event cost is in the microsecond range.

22. **`BenchmarkFlushSync`** -- Benchmark `FlushSync` standalone to characterize per-flush cost.

## Out of Scope

- Configurable flush interval (hardcoded at 100ms; can be added later via `IntegrityOption`)
- Parallelizing the notify loop (multiple goroutines handling notifications concurrently)
- Async write path for the non-integrity JSONL store (inline fsync is acceptable there)
- Changing the verify CLI (it already walks the chain; seq+N recovery is startup-only)
