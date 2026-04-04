# Wire HMAC Integrity Chain Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the existing HMAC integrity chain infrastructure into the JSONL audit output so events are signed and `agentsh audit verify` works against the live audit log.

**Architecture:** Add a `RawWriter` interface + `WriteRaw` to the JSONL store, make `IntegrityStore.AppendEvent` actually call `chain.Wrap()` and write signed bytes via `RawWriter`, then wire the chain creation into `server.New()` with proper lifecycle management.

**Tech Stack:** Go, HMAC-SHA256/512, JSONL

**Spec:** `docs/superpowers/specs/2026-03-30-wire-hmac-integrity-chain-design.md`

---

### Task 1: Add `RawWriter` interface and `jsonl.Store.WriteRaw`

**Files:**
- Modify: `internal/store/store.go:1-18`
- Modify: `internal/store/jsonl/jsonl.go:51-67`
- Test: `internal/store/jsonl/jsonl_test.go`

- [ ] **Step 1: Write the failing test for `WriteRaw`**

Add to `internal/store/jsonl/jsonl_test.go`:

```go
func TestWriteRaw(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.log")

	store, err := New(path, 1, 2)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	raw := []byte(`{"id":"1","type":"test","integrity":{"sequence":1,"prev_hash":"","entry_hash":"abc123"}}`)
	if err := store.WriteRaw(context.Background(), raw); err != nil {
		t.Fatalf("WriteRaw: %v", err)
	}

	// Read back the file and verify exact bytes + newline
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	expected := string(raw) + "\n"
	if string(data) != expected {
		t.Errorf("file content = %q, want %q", string(data), expected)
	}
}

func TestWriteRaw_TriggersRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.log")

	store, err := New(path, 1, 2) // 1 MB limit
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	// Write >1MB via WriteRaw to trigger rotation
	big := []byte(strings.Repeat("x", 2<<20))
	if err := store.WriteRaw(context.Background(), big); err != nil {
		t.Fatalf("WriteRaw large: %v", err)
	}
	// Next write should trigger rotation
	if err := store.WriteRaw(context.Background(), []byte(`{"after":"rotate"}`)); err != nil {
		t.Fatalf("WriteRaw post-rotate: %v", err)
	}

	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("expected rotated backup .1, got err: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/jsonl/ -run 'TestWriteRaw' -v`
Expected: FAIL — `store.WriteRaw` method does not exist.

- [ ] **Step 3: Add `RawWriter` interface to `store.go`**

Add to `internal/store/store.go` after the `EventStore` interface (after line 13):

```go
// RawWriter can write pre-serialized bytes as a single JSONL line.
type RawWriter interface {
	WriteRaw(ctx context.Context, data []byte) error
}
```

- [ ] **Step 4: Implement `WriteRaw` on `jsonl.Store`**

Add to `internal/store/jsonl/jsonl.go` after the `AppendEvent` method (after line 67):

```go
// WriteRaw writes pre-serialized bytes as a single JSONL line.
// It uses the same locking and rotation logic as AppendEvent.
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

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/store/jsonl/ -run 'TestWriteRaw' -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/store/store.go internal/store/jsonl/jsonl.go internal/store/jsonl/jsonl_test.go
git commit -m "feat: add RawWriter interface and jsonl.Store.WriteRaw (#182)"
```

---

### Task 2: Make `IntegrityStore.AppendEvent` wrap events

**Files:**
- Modify: `internal/store/integrity_wrapper.go:1-42`
- Test: `internal/store/integrity_wrapper_test.go`

- [ ] **Step 1: Write failing tests**

Replace the contents of `internal/store/integrity_wrapper_test.go` with:

```go
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/pkg/types"
)

var testKey = []byte("test-key-32-bytes-for-hmac-sha!!")

// mockRawWriter implements both EventStore and RawWriter.
type mockRawWriter struct {
	mu       sync.Mutex
	rawCalls [][]byte
	events   []types.Event
}

func (m *mockRawWriter) WriteRaw(_ context.Context, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	m.rawCalls = append(m.rawCalls, cp)
	return nil
}

func (m *mockRawWriter) AppendEvent(_ context.Context, ev types.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
	return nil
}

func (m *mockRawWriter) QueryEvents(_ context.Context, _ types.EventQuery) ([]types.Event, error) {
	return nil, nil
}

func (m *mockRawWriter) Close() error { return nil }

// mockPlainStore implements EventStore only (no RawWriter).
type mockPlainStore struct {
	mu     sync.Mutex
	events []types.Event
}

func (m *mockPlainStore) AppendEvent(_ context.Context, ev types.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
	return nil
}

func (m *mockPlainStore) QueryEvents(_ context.Context, _ types.EventQuery) ([]types.Event, error) {
	return nil, nil
}

func (m *mockPlainStore) Close() error { return nil }

func TestIntegrityChain_StateAdvances(t *testing.T) {
	chain, err := audit.NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}

	state1 := chain.State()
	if state1.Sequence != 0 {
		t.Errorf("initial sequence should be 0, got %d", state1.Sequence)
	}

	_, err = chain.Wrap([]byte(`{"test": true}`))
	if err != nil {
		t.Fatalf("failed to wrap: %v", err)
	}

	state2 := chain.State()
	if state2.Sequence != 1 {
		t.Errorf("sequence should be 1, got %d", state2.Sequence)
	}
	if state1.PrevHash == state2.PrevHash {
		t.Error("hash should have changed")
	}
}

func TestNewIntegrityStore(t *testing.T) {
	chain, err := audit.NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}

	wrapper := NewIntegrityStore(nil, chain)
	if wrapper == nil {
		t.Fatal("expected non-nil wrapper")
	}
	if wrapper.Chain() != chain {
		t.Error("Chain() should return the same chain")
	}
}

func TestIntegrityStore_AppendEvent_WrapsPayload(t *testing.T) {
	chain, err := audit.NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("create chain: %v", err)
	}

	mock := &mockRawWriter{}
	s := NewIntegrityStore(mock, chain)

	ev := types.Event{
		ID:        "ev-1",
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Type:      "test_event",
		SessionID: "sess-1",
	}

	if err := s.AppendEvent(context.Background(), ev); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}

	// Should have called WriteRaw, not AppendEvent
	if len(mock.rawCalls) != 1 {
		t.Fatalf("expected 1 WriteRaw call, got %d", len(mock.rawCalls))
	}
	if len(mock.events) != 0 {
		t.Fatalf("expected 0 AppendEvent calls, got %d", len(mock.events))
	}

	// Parse the raw bytes and verify integrity field
	var result map[string]any
	if err := json.Unmarshal(mock.rawCalls[0], &result); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}

	integrity, ok := result["integrity"].(map[string]any)
	if !ok {
		t.Fatal("integrity field missing")
	}

	seq, _ := integrity["sequence"].(float64)
	if seq != 1 {
		t.Errorf("sequence = %v, want 1", seq)
	}

	prevHash, _ := integrity["prev_hash"].(string)
	if prevHash != "" {
		t.Errorf("prev_hash = %q, want empty (first entry)", prevHash)
	}

	entryHash, _ := integrity["entry_hash"].(string)
	if entryHash == "" {
		t.Error("entry_hash should not be empty")
	}

	// Verify original event fields are preserved
	if result["id"] != "ev-1" {
		t.Errorf("id = %v, want ev-1", result["id"])
	}
	if result["type"] != "test_event" {
		t.Errorf("type = %v, want test_event", result["type"])
	}
}

func TestIntegrityStore_AppendEvent_FallbackWithoutRawWriter(t *testing.T) {
	chain, err := audit.NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("create chain: %v", err)
	}

	mock := &mockPlainStore{}
	s := NewIntegrityStore(mock, chain)

	ev := types.Event{
		ID:   "ev-1",
		Type: "test_event",
	}

	if err := s.AppendEvent(context.Background(), ev); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}

	// Should have called AppendEvent on the inner store (unsigned fallback)
	if len(mock.events) != 1 {
		t.Fatalf("expected 1 AppendEvent call, got %d", len(mock.events))
	}
	if mock.events[0].ID != "ev-1" {
		t.Errorf("event ID = %q, want ev-1", mock.events[0].ID)
	}
}

func TestIntegrityStore_ChainContinuity(t *testing.T) {
	chain, err := audit.NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("create chain: %v", err)
	}

	mock := &mockRawWriter{}
	s := NewIntegrityStore(mock, chain)

	// Append 3 events
	for i := 0; i < 3; i++ {
		ev := types.Event{
			ID:   fmt.Sprintf("ev-%d", i),
			Type: "test",
		}
		if err := s.AppendEvent(context.Background(), ev); err != nil {
			t.Fatalf("AppendEvent %d: %v", i, err)
		}
	}

	if len(mock.rawCalls) != 3 {
		t.Fatalf("expected 3 WriteRaw calls, got %d", len(mock.rawCalls))
	}

	// Verify chain links
	var prevEntryHash string
	for i, raw := range mock.rawCalls {
		var result map[string]any
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatalf("unmarshal %d: %v", i, err)
		}
		integrity := result["integrity"].(map[string]any)
		prevHash := integrity["prev_hash"].(string)
		entryHash := integrity["entry_hash"].(string)
		seq := int64(integrity["sequence"].(float64))

		if seq != int64(i+1) {
			t.Errorf("entry %d: sequence = %d, want %d", i, seq, i+1)
		}
		if prevHash != prevEntryHash {
			t.Errorf("entry %d: prev_hash = %q, want %q", i, prevHash, prevEntryHash)
		}
		prevEntryHash = entryHash
	}
}
```

Note: The `fmt` import is already included in the import block above.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/store/ -run 'TestIntegrityStore_AppendEvent|TestIntegrityStore_ChainContinuity' -v`
Expected: FAIL — `AppendEvent` still passes through without wrapping.

- [ ] **Step 3: Implement `IntegrityStore.AppendEvent` wrapping**

Replace the contents of `internal/store/integrity_wrapper.go` with:

```go
package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/pkg/types"
)

var _ EventStore = (*IntegrityStore)(nil)

// IntegrityStore wraps an EventStore and adds integrity metadata to events.
type IntegrityStore struct {
	inner EventStore
	chain *audit.IntegrityChain
}

// NewIntegrityStore wraps an existing store with integrity chain.
func NewIntegrityStore(inner EventStore, chain *audit.IntegrityChain) *IntegrityStore {
	return &IntegrityStore{inner: inner, chain: chain}
}

// AppendEvent marshals the event, wraps it with HMAC integrity metadata,
// and writes the signed bytes via RawWriter if the inner store supports it.
// Falls back to unsigned inner.AppendEvent otherwise.
func (s *IntegrityStore) AppendEvent(ctx context.Context, ev types.Event) error {
	payload, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("integrity marshal: %w", err)
	}

	wrapped, err := s.chain.Wrap(payload)
	if err != nil {
		return fmt.Errorf("integrity wrap: %w", err)
	}

	if rw, ok := s.inner.(RawWriter); ok {
		return rw.WriteRaw(ctx, wrapped)
	}

	// Fallback: delegate unsigned
	return s.inner.AppendEvent(ctx, ev)
}

// QueryEvents delegates to the inner store.
func (s *IntegrityStore) QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error) {
	return s.inner.QueryEvents(ctx, q)
}

// Close closes the inner store.
func (s *IntegrityStore) Close() error {
	return s.inner.Close()
}

// Chain returns the integrity chain for state management.
func (s *IntegrityStore) Chain() *audit.IntegrityChain {
	return s.chain
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/store/ -v`
Expected: PASS — all tests including new ones.

- [ ] **Step 5: Commit**

```bash
git add internal/store/integrity_wrapper.go internal/store/integrity_wrapper_test.go
git commit -m "feat: IntegrityStore.AppendEvent wraps events with HMAC chain (#182)"
```

---

### Task 3: End-to-end integration test (write → verify)

**Files:**
- Test: `internal/store/integrity_wrapper_test.go` (append to existing)

- [ ] **Step 1: Write the end-to-end test**

First, update the import block at the top of `internal/store/integrity_wrapper_test.go` to the complete final form:

```go
import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store/jsonl"
	"github.com/agentsh/agentsh/pkg/types"
)
```

Then append these test functions to the end of the file:

```go
func TestIntegrityStore_EndToEnd_VerifyWithAuditVerify(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	// Create JSONL store → wrap with IntegrityStore
	jsonlStore, err := jsonl.New(logPath, 100, 3)
	if err != nil {
		t.Fatalf("jsonl.New: %v", err)
	}

	chain, err := audit.NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain: %v", err)
	}
	wrapped := NewIntegrityStore(jsonlStore, chain)

	// Append events
	events := []types.Event{
		{ID: "1", Type: "session_start", SessionID: "s1", Timestamp: time.Now()},
		{ID: "2", Type: "command_executed", SessionID: "s1", Timestamp: time.Now(), Fields: map[string]any{"command": "ls"}},
		{ID: "3", Type: "file_read", SessionID: "s1", Timestamp: time.Now(), Fields: map[string]any{"path": "/etc/hosts"}},
	}
	for _, ev := range events {
		if err := wrapped.AppendEvent(context.Background(), ev); err != nil {
			t.Fatalf("AppendEvent: %v", err)
		}
	}
	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Verify by reading back and checking the integrity chain manually.
	// This mirrors the logic in internal/cli/audit.go verifyIntegrityChain.
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}

	var prevEntryHash string
	for i, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("line %d unmarshal: %v", i, err)
		}

		integrity, ok := entry["integrity"].(map[string]any)
		if !ok {
			t.Fatalf("line %d: missing integrity field", i)
		}

		prevHash := integrity["prev_hash"].(string)
		entryHash := integrity["entry_hash"].(string)

		if prevHash != prevEntryHash {
			t.Errorf("line %d: prev_hash = %q, want %q", i, prevHash, prevEntryHash)
		}

		// Verify HMAC by recomputing
		delete(entry, "integrity")
		canonical, _ := json.Marshal(entry)
		seq := int64(integrity["sequence"].(float64))
		computed := computeHMAC(testKey, seq, prevHash, canonical)
		if computed != entryHash {
			t.Errorf("line %d: entry_hash mismatch: computed %q, got %q", i, computed, entryHash)
		}

		prevEntryHash = entryHash
	}
}

// computeHMAC replicates the HMAC computation from audit.IntegrityChain.computeHash
// for verification in tests.
func computeHMAC(key []byte, sequence int64, prevHash string, payload []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(strconv.FormatInt(sequence, 10)))
	h.Write([]byte("|"))
	h.Write([]byte(prevHash))
	h.Write([]byte("|"))
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `go test ./internal/store/ -run 'TestIntegrityStore_EndToEnd' -v`
Expected: PASS — events written via IntegrityStore, read back, HMAC chain verified.

- [ ] **Step 3: Commit**

```bash
git add internal/store/integrity_wrapper_test.go
git commit -m "test: add end-to-end integrity chain verification test (#182)"
```

---

### Task 4: Wire integrity chain into `server.go`

**Files:**
- Modify: `internal/server/server.go` — Server struct, New() function (store setup), Close() method

- [ ] **Step 1: Add `kmsProvider` field to `Server` struct**

In `internal/server/server.go`, add `"io"` to imports (line 3-43) and add the field to the struct.

Add to imports after `"fmt"` (line 7):
```go
"io"
```

Add to the `Server` struct (after line 71, the `app` field):
```go
kmsProvider io.Closer // audit/kms.Provider for HMAC key lifecycle
```

- [ ] **Step 2: Add `audit` import**

Add to imports (between the `"github.com/agentsh/agentsh/internal/approvals"` and `"github.com/agentsh/agentsh/internal/auth"` lines):
```go
"github.com/agentsh/agentsh/internal/audit"
```

- [ ] **Step 3: Declare local `kmsProvider` variable and wire integrity chain**

In `internal/server/server.go`, in the `New()` function, add local variable declarations right after the function signature (before the first `if cfg == nil` check):

```go
	var kmsProvider io.Closer
	var kmsCloser func() error
```

Then, after the JSONL store creation block (after the `if cfg.Audit.Output != ""` block that creates `jsonlStore`, and before the webhook store block), insert:

```go
	var jsonlEventStore storepkg.EventStore
	if jsonlStore != nil {
		jsonlEventStore = jsonlStore
	}
	if jsonlStore != nil && cfg.Audit.Integrity.Enabled {
		chain, provider, err := audit.NewIntegrityChainFromConfig(
			context.Background(), cfg.Audit.Integrity)
		if err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("audit integrity chain: %w", err)
		}
		kmsProvider = provider
		jsonlEventStore = storepkg.NewIntegrityStore(jsonlStore, chain)
	}
```

- [ ] **Step 4: Replace jsonlStore reference in eventStores assembly**

Find the `var eventStores []storepkg.EventStore` block and change the jsonlStore append from:
```go
	var eventStores []storepkg.EventStore
	if jsonlStore != nil {
		eventStores = append(eventStores, jsonlStore)
	}
```

To:
```go
	var eventStores []storepkg.EventStore
	if jsonlEventStore != nil {
		eventStores = append(eventStores, jsonlEventStore)
	}
```

- [ ] **Step 5: Assign kmsProvider to Server struct**

In the `srv := &Server{...}` block (find `app: app,`), add after `app`:
```go
kmsProvider: kmsProvider,
```

This ensures it gets cleaned up on error paths where `srv.Close()` is called.

- [ ] **Step 6: Add kmsProvider cleanup to `Close()`**

In `Server.Close()`, add *after* the `s.store.Close()` block (the HMAC key must remain available while the store flushes):
```go
	if s.kmsProvider != nil {
		_ = s.kmsProvider.Close()
	}
```

- [ ] **Step 7: Add deferred kmsProvider cleanup for error paths**

Follow the same pattern as `appCloser` in the existing code. The `kmsCloser` variable was already declared in Step 3.

Inside the integrity `if` block (after `kmsProvider = provider`), add:
```go
		kmsCloser = provider.Close
		defer func() {
			if kmsCloser != nil {
				kmsCloser()
			}
		}()
```

At the success path (find `appCloser = nil`), add right after it:
```go
	kmsCloser = nil
```

This ensures the KMS provider is closed on any error path after chain creation, but not on success (where `srv.kmsProvider` takes ownership).

- [ ] **Step 8: Verify build**

Run: `go build ./...`
Expected: Clean build, no errors.

Run: `GOOS=windows go build ./...`
Expected: Clean build (cross-compile check per CLAUDE.md).

- [ ] **Step 9: Run all tests**

Run: `go test ./internal/server/ ./internal/store/ ./internal/store/jsonl/ ./internal/audit/ ./internal/cli/ -v`
Expected: All PASS.

- [ ] **Step 10: Commit**

```bash
git add internal/server/server.go
git commit -m "feat: wire HMAC integrity chain into server startup (#182)"
```

---

### Task 5: Run full test suite and verify

**Files:** None (verification only)

**Note on spec test #6 (`TestNew_IntegrityEnabled`):** The spec suggested a server wiring test, but `server.New()` requires many heavy dependencies (SQLite, policy, session manager, etc.) and no existing server tests call it directly. The wiring correctness is verified by: (a) successful build with the new code paths, (b) the end-to-end integration test in Task 3 proving `IntegrityStore` + `jsonl.Store` work together, and (c) existing tests continuing to pass. A full server integration test would be mostly fixture setup with little additional value.

- [ ] **Step 1: Run all tests**

Run: `go test ./...`
Expected: All PASS.

- [ ] **Step 2: Verify cross-compilation**

Run: `GOOS=windows go build ./...`
Expected: Clean build.

- [ ] **Step 3: Final commit (if any fixups needed)**

Only if prior steps required fixes.
