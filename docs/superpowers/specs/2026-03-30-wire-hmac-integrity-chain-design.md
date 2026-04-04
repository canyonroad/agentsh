# Wire HMAC Integrity Chain into JSONL Audit Output

**Issue:** #182
**Date:** 2026-03-30

## Problem

The HMAC integrity chain infrastructure is fully built but not wired into the server startup path. Events written to the JSONL audit log are unsigned, so `agentsh audit verify` cannot verify the live audit log even when `audit.integrity.enabled: true` is configured.

**Existing infrastructure:**
- `internal/audit/integrity.go` — `IntegrityChain` with `Wrap()`, `NewIntegrityChainFromConfig()`
- `internal/store/integrity_wrapper.go` — `IntegrityStore` wrapper (pass-through, does not wrap)
- `internal/cli/audit.go` — `agentsh audit verify` command
- Config: `audit.integrity.enabled`, `algorithm`, `key_source`, `key_file`, etc.

**What's missing:**
1. `IntegrityStore.AppendEvent` is a pass-through — never calls `chain.Wrap()`
2. `server.go` never instantiates the integrity chain or wraps the JSONL store

## Design

### 1. `RawWriter` interface and `jsonl.Store.WriteRaw`

Define a `RawWriter` interface in `internal/store/store.go`:

```go
// RawWriter can write pre-serialized bytes as a single JSONL line.
type RawWriter interface {
    WriteRaw(ctx context.Context, data []byte) error
}
```

Add `WriteRaw` to `jsonl.Store` — same lock, rotation, and newline-append logic as `AppendEvent`, but accepts pre-serialized bytes instead of a `types.Event`:

```go
func (s *Store) WriteRaw(_ context.Context, data []byte) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    if err := s.rotateIfNeededLocked(); err != nil {
        return err
    }
    if _, err := s.file.Write(append(data, '\n')); err != nil {
        return fmt.Errorf("write jsonl raw: %w", err)
    }
    return nil
}
```

### 2. `IntegrityStore.AppendEvent` — wrap and write

Replace the pass-through with actual wrapping:

```go
func (s *IntegrityStore) AppendEvent(ctx context.Context, ev types.Event) error {
    // Marshal the event to canonical JSON
    payload, err := json.Marshal(ev)
    if err != nil {
        return fmt.Errorf("integrity marshal: %w", err)
    }

    // Add integrity metadata (HMAC chain)
    wrapped, err := s.chain.Wrap(payload)
    if err != nil {
        return fmt.Errorf("integrity wrap: %w", err)
    }

    // Write signed bytes directly if the inner store supports it
    if rw, ok := s.inner.(RawWriter); ok {
        return rw.WriteRaw(ctx, wrapped)
    }

    // Fallback: delegate unsigned (inner store will re-marshal)
    return s.inner.AppendEvent(ctx, ev)
}
```

**Key points:**
- The JSONL store implements `RawWriter`, so the signed payload goes straight to disk with no re-serialization.
- Non-JSONL stores (SQLite, webhook, OTEL) still receive the original event via `AppendEvent` — integrity is a JSONL-only concern per issue #182's use case.
- The `RawWriter` type assertion keeps `IntegrityStore` decoupled from `jsonl.Store` directly.
- `IntegrityStore` is in `package store`, same as `RawWriter`, so no package qualifier needed.
- `encoding/json` must be added to `integrity_wrapper.go` imports.
- The double-marshal (once in `AppendEvent`, once inside `Wrap` for canonicalization) is intentional — `Wrap` re-canonicalizes through `map[string]any` to ensure deterministic key ordering for HMAC verification.

### 3. Server wiring in `server.go`

After JSONL store creation (~line 162) and before the composite store assembly (~line 232).

New imports needed in `server.go`:
- `"github.com/agentsh/agentsh/internal/audit"`
- `"io"` (for `io.Closer` type on kmsProvider field)

```go
var kmsProvider kms.Provider
if jsonlStore != nil && cfg.Audit.Integrity.Enabled {
    chain, provider, err := audit.NewIntegrityChainFromConfig(
        context.Background(), cfg.Audit.Integrity)
    if err != nil {
        _ = db.Close()
        return nil, fmt.Errorf("audit integrity chain: %w", err)
    }
    kmsProvider = provider
    jsonlStore = storepkg.NewIntegrityStore(jsonlStore, chain)
}
```

**Note:** `NewIntegrityStore` returns `*IntegrityStore`, not `*jsonl.Store`. The `eventStores` slice is `[]storepkg.EventStore`, and `IntegrityStore` implements `EventStore`, so `jsonlStore` needs to be reassigned as a `storepkg.EventStore`. A local variable type change handles this — see implementation plan for details.

### 4. Provider lifecycle

Add `kmsProvider` field to `Server` struct using `io.Closer`. Close it in `Server.Close()`:

```go
type Server struct {
    // ...existing fields...
    kmsProvider io.Closer // audit/kms.Provider, only Close needed at server level
}
```

In `Close()` (before `s.store.Close()`):
```go
if s.kmsProvider != nil {
    _ = s.kmsProvider.Close()
}
```

**Error-path cleanup:** The `kmsProvider` must also be cleaned up if `New()` fails after chain creation. Assign it to `srv.kmsProvider` early, so it's closed via the existing error-path cleanup (or add an explicit `defer` that closes it on failure).

## Variable type handling

Currently `jsonlStore` is typed `*jsonl.Store`. After wrapping, it becomes `*storepkg.IntegrityStore`. Both implement `storepkg.EventStore`. The simplest approach: change the variable used in the `eventStores` append to an `storepkg.EventStore` interface variable:

```go
var jsonlEventStore storepkg.EventStore
if jsonlStore != nil {
    jsonlEventStore = jsonlStore
}
if jsonlStore != nil && cfg.Audit.Integrity.Enabled {
    // ...wrap...
    jsonlEventStore = storepkg.NewIntegrityStore(jsonlStore, chain)
}
// Later:
if jsonlEventStore != nil {
    eventStores = append(eventStores, jsonlEventStore)
}
```

## Testing strategy

### Unit tests

1. **`internal/store/jsonl/jsonl_test.go` — `TestWriteRaw`**
   - Write raw bytes, read back the file, verify exact bytes + newline
   - Verify rotation still triggers on raw writes

2. **`internal/store/integrity_wrapper_test.go` — `TestIntegrityStore_AppendEvent_WrapsPayload`**
   - Use a mock `RawWriter` inner store
   - Append an event, verify `WriteRaw` was called with JSON containing `integrity` field
   - Verify sequence/prev_hash/entry_hash are present and correct

3. **`internal/store/integrity_wrapper_test.go` — `TestIntegrityStore_AppendEvent_FallbackWithoutRawWriter`**
   - Use a plain `EventStore` mock (no `RawWriter`)
   - Verify it falls back to `inner.AppendEvent` (event passed through unsigned)

4. **`internal/store/integrity_wrapper_test.go` — `TestIntegrityStore_ChainContinuity`**
   - Append 3 events, collect raw writes, verify chain links correctly (prev_hash matches previous entry_hash)

### Integration test

5. **`internal/store/integrity_wrapper_test.go` — `TestIntegrityStore_EndToEnd_VerifyWithAuditVerify`**
   - Create a temp JSONL file + key file
   - Create `jsonl.Store` → wrap with `IntegrityStore`
   - Append several events
   - Close the store
   - Run the verify logic (`verifyIntegrityChain` from cli/audit.go — or replicate the core verification) against the JSONL file
   - Verify chain intact

### Server wiring test

6. **`internal/server/server_test.go` — `TestNew_IntegrityEnabled`**
   - Construct a minimal config with `audit.integrity.enabled: true`, `key_source: file`, `key_file: <tmpfile>`
   - Call `server.New(cfg)`
   - Verify the server starts without error (or as close as possible given other required config)
   - This may need to be a build-level test rather than a full integration test, depending on required dependencies

## Out of scope

- Integrity wrapping for non-JSONL stores (webhook, OTEL, SQLite)
- Key rotation support

### Known limitation: chain breaks on restart

Chain state persistence across server restarts is out of scope. When the server restarts, the chain resets to sequence 0 with an empty `prev_hash`. If the JSONL file already contains signed entries from a previous run, `audit verify` will report a chain break at the restart boundary — even without tampering. Operators should be aware that chain breaks at restart points are expected. A future enhancement could persist chain state or scan the existing JSONL tail on startup to continue the chain.
