# Deferred Sync Audit Write Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move synchronous fsync off the seccomp notify hot path so audit I/O no longer blocks traced processes (292ms/exec -> ~35ms/exec on ext4).

**Architecture:** Handle() becomes a pure decision+event-builder. The notify response is sent before any I/O. AppendEvent writes to the page cache (~us). A background timer fsyncs and updates the sidecar every ~100ms. Crash recovery is extended from seq+1 to seq+N.

**Tech Stack:** Go, seccomp-notify, HMAC-SHA256 integrity chain, JSONL audit log

**Spec:** `docs/superpowers/specs/2026-04-13-deferred-sync-audit-write-design.md`

---

## File Structure

**Modified files:**
- `internal/store/store.go` — add `Syncer` interface
- `internal/store/jsonl/jsonl.go` — add `syncOnWrite` flag, `SetSyncOnWrite()`, `Sync()` method; conditional fsync in `WriteRaw`
- `internal/store/integrity_wrapper.go` — add `pendingFlush`, timer fields, `FlushSync()`, `runFlushLoop()`; remove `WriteSidecar` from `AppendEvent`; update `Close()` shutdown; extend `resumeFromSidecar` for seq+N; add `recoverFromSidecarGap` and `truncateAfterLastCompleteLine`
- `internal/netmonitor/unix/execve_handler.go` — `Handle()` returns `(ExecveResult, *types.Event)`; rename `emitEvent` to `buildEvent`
- `internal/netmonitor/unix/file_handler.go` — `Handle()` returns `(FileResult, *types.Event)`; rename `emitFileEvent` to `buildFileEvent`
- `internal/netmonitor/unix/handler.go` — all `handle*Notification` functions: respond before emit; rename `emitEvent` to `buildUnixSocketEvent`

**Modified test files:**
- `internal/store/jsonl/jsonl_test.go`
- `internal/store/integrity_wrapper_test.go`

**New test files:**
- `internal/netmonitor/unix/emit_order_test.go`

---

### Task 1: Add `Syncer` interface and `syncOnWrite` flag to JSONL store

**Files:**
- Modify: `internal/store/store.go:15-18`
- Modify: `internal/store/jsonl/jsonl.go:41-49` (Store struct), `120-154` (WriteRaw)
- Test: `internal/store/jsonl/jsonl_test.go`

- [ ] **Step 1: Write failing test for `Sync()` method**

In `internal/store/jsonl/jsonl_test.go`, add:

```go
func TestSync_FlushesToDisk(t *testing.T) {
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "audit.jsonl"), 10*1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	data := []byte(`{"type":"test","id":"1"}`)
	if err := s.WriteRaw(context.Background(), data); err != nil {
		t.Fatal(err)
	}

	if err := s.Sync(); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	// Verify data is readable after sync
	content, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(content, data) {
		t.Fatalf("file does not contain written data")
	}
}

func TestSync_NilFile(t *testing.T) {
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "audit.jsonl"), 10*1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	// Sync after close should not panic
	if err := s.Sync(); err != nil {
		t.Fatalf("Sync() on closed store should return nil, got %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/jsonl/ -run 'TestSync_FlushesToDisk|TestSync_NilFile' -v`
Expected: FAIL — `s.Sync undefined`

- [ ] **Step 3: Add `Syncer` interface to `store.go`**

In `internal/store/store.go`, after the `RawWriter` interface (line 18), add:

```go
// Syncer can flush buffered writes to durable storage.
type Syncer interface {
	Sync() error
}
```

- [ ] **Step 4: Add `syncOnWrite` field and `Sync()` method to JSONL store**

In `internal/store/jsonl/jsonl.go`, add `syncOnWrite` to the Store struct (line 41):

```go
type Store struct {
	path       string
	maxBytes   int64
	maxBackups int

	mu          sync.Mutex
	file        *os.File
	lockFile    *os.File
	syncOnWrite bool
}
```

In the `New()` constructor, set the default in the struct literal:

```go
	syncOnWrite: true,
```

Add the `SetSyncOnWrite` method after the Store struct:

```go
// SetSyncOnWrite controls whether WriteRaw calls file.Sync() after each write.
// When false, callers are responsible for calling Sync() periodically.
func (s *Store) SetSyncOnWrite(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncOnWrite = v
}
```

Add the `Sync()` method after `WriteRaw`:

```go
// Sync flushes buffered writes to durable storage.
func (s *Store) Sync() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	return s.file.Sync()
}
```

Make the existing `file.Sync()` in `WriteRaw` (line 150) conditional. Replace lines 150-152:
```go
	if err := s.file.Sync(); err != nil {
		return &DurabilityError{Err: fmt.Errorf("sync jsonl raw: %w", err)}
	}
```

With:
```go
	if s.syncOnWrite {
		if err := s.file.Sync(); err != nil {
			return &DurabilityError{Err: fmt.Errorf("sync jsonl raw: %w", err)}
		}
	}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/store/jsonl/ -run 'TestSync_FlushesToDisk|TestSync_NilFile' -v`
Expected: PASS

- [ ] **Step 6: Write test for `WriteRaw` with `syncOnWrite=false`**

In `internal/store/jsonl/jsonl_test.go`, add:

```go
func TestWriteRaw_NoSyncWhenDisabled(t *testing.T) {
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "audit.jsonl"), 10*1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.SetSyncOnWrite(false)

	data := []byte(`{"type":"test","id":"nosync"}`)
	if err := s.WriteRaw(context.Background(), data); err != nil {
		t.Fatal(err)
	}

	// Data should be in the file (page cache write still happens)
	content, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(content, data) {
		t.Fatalf("file does not contain written data")
	}
}
```

- [ ] **Step 7: Run test to verify it passes**

Run: `go test ./internal/store/jsonl/ -run TestWriteRaw_NoSyncWhenDisabled -v`
Expected: PASS

- [ ] **Step 8: Write concurrent WriteRaw + Sync test**

In `internal/store/jsonl/jsonl_test.go`, add:

```go
func TestWriteRaw_And_Sync_Concurrent(t *testing.T) {
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "audit.jsonl"), 10*1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.SetSyncOnWrite(false)

	const numWriters = 4
	const eventsPerWriter = 50

	var wg sync.WaitGroup

	// Spawn writers
	for w := 0; w < numWriters; w++ {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()
			for i := 0; i < eventsPerWriter; i++ {
				data := []byte(fmt.Sprintf(`{"writer":%d,"seq":%d}`, writerID, i))
				if err := s.WriteRaw(context.Background(), data); err != nil {
					t.Errorf("WriteRaw error: %v", err)
				}
			}
		}(w)
	}

	// Spawn syncer
	stopSync := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopSync:
				return
			default:
				_ = s.Sync()
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()

	wg.Wait()
	close(stopSync)

	// Final sync
	if err := s.Sync(); err != nil {
		t.Fatal(err)
	}

	// Verify all events are present as complete lines
	content, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))
	if len(lines) != numWriters*eventsPerWriter {
		t.Fatalf("got %d lines, want %d", len(lines), numWriters*eventsPerWriter)
	}
	for i, line := range lines {
		var obj map[string]any
		if err := json.Unmarshal(line, &obj); err != nil {
			t.Fatalf("line %d: invalid JSON: %v", i, err)
		}
	}
}
```

- [ ] **Step 9: Run concurrent test**

Run: `go test ./internal/store/jsonl/ -run TestWriteRaw_And_Sync_Concurrent -v -count=5`
Expected: PASS (all 5 runs)

- [ ] **Step 10: Run all existing JSONL tests to check for regressions**

Run: `go test ./internal/store/jsonl/ -v`
Expected: All PASS

- [ ] **Step 11: Commit**

```bash
git add internal/store/store.go internal/store/jsonl/jsonl.go internal/store/jsonl/jsonl_test.go
git commit -m "feat(store): add Syncer interface and syncOnWrite flag to JSONL store

WriteRaw no longer calls file.Sync() when syncOnWrite is false.
Callers use the new Sync() method for periodic flush instead."
```

---

### Task 2: Add `FlushSync()` and background timer to IntegrityStore

**Files:**
- Modify: `internal/store/integrity_wrapper.go:44-54` (struct), `74-98` (constructor), `436-482` (AppendEvent), `490-492` (Close)
- Test: `internal/store/integrity_wrapper_test.go`

- [ ] **Step 1: Write failing test for `FlushSync()` — basic behavior**

In `internal/store/integrity_wrapper_test.go`, add:

```go
func TestFlushSync_WritesSidecar(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	expectedState := writeResumableIntegrityState(t, logPath)
	chain := mustNewIntegrityChain(t)

	inner := &mockRawWriter{}
	store, err := NewIntegrityStore(inner, chain, testIntegrityOptions(logPath))
	if err != nil {
		t.Fatal(err)
	}

	ev := types.Event{ID: "ev-flush-1", Timestamp: time.Now().UTC(), Type: "test", SessionID: "s1"}
	if err := store.AppendEvent(context.Background(), ev); err != nil {
		t.Fatal(err)
	}

	// Before FlushSync, sidecar should still have the bootstrap state
	sidecar, err := audit.ReadSidecar(audit.SidecarPath(logPath))
	if err != nil {
		t.Fatal(err)
	}
	if sidecar.Sequence != expectedState.Sequence {
		t.Fatalf("pre-flush sidecar.Sequence = %d, want %d", sidecar.Sequence, expectedState.Sequence)
	}

	// FlushSync should update sidecar
	if err := store.FlushSync(); err != nil {
		t.Fatal(err)
	}

	sidecar, err = audit.ReadSidecar(audit.SidecarPath(logPath))
	if err != nil {
		t.Fatal(err)
	}
	if sidecar.Sequence != expectedState.Sequence+1 {
		t.Fatalf("post-flush sidecar.Sequence = %d, want %d", sidecar.Sequence, expectedState.Sequence+1)
	}
}

func TestFlushSync_Noop_WhenNoPending(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	writeResumableIntegrityState(t, logPath)
	chain := mustNewIntegrityChain(t)

	inner := &mockRawWriter{}
	store, err := NewIntegrityStore(inner, chain, testIntegrityOptions(logPath))
	if err != nil {
		t.Fatal(err)
	}

	sidecarBefore, err := audit.ReadSidecar(audit.SidecarPath(logPath))
	if err != nil {
		t.Fatal(err)
	}

	if err := store.FlushSync(); err != nil {
		t.Fatal(err)
	}

	sidecarAfter, err := audit.ReadSidecar(audit.SidecarPath(logPath))
	if err != nil {
		t.Fatal(err)
	}
	if sidecarAfter.Sequence != sidecarBefore.Sequence {
		t.Fatalf("sidecar changed without pending events: %d -> %d", sidecarBefore.Sequence, sidecarAfter.Sequence)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/ -run 'TestFlushSync_WritesSidecar|TestFlushSync_Noop' -v`
Expected: FAIL — `store.FlushSync undefined`

- [ ] **Step 3: Add `pendingFlush` field, `FlushSync()` method, and modify `AppendEvent()`**

In `internal/store/integrity_wrapper.go`, update the `IntegrityStore` struct (line 44) to add `pendingFlush`:

```go
type IntegrityStore struct {
	mu             sync.Mutex
	inner          EventStore
	chain          *audit.IntegrityChain
	logPath        string
	sidecarPath    string
	algorithm      string
	keyFingerprint string
	now            func() time.Time
	fatal          bool // sticky; set on first FatalIntegrityError
	pendingFlush   bool // events written since last FlushSync
}
```

Modify `AppendEvent()` — replace the `WriteSidecar` block (lines 471-480) with just:

```go
	s.pendingFlush = true
	return nil
```

So the tail of AppendEvent after the `WriteRaw` error handling becomes:

```go
	if err := rw.WriteRaw(ctx, wrapped); err != nil {
		type partialWriter interface{ IsPartialWrite() bool }
		if pw, ok := err.(partialWriter); ok && pw.IsPartialWrite() {
			s.fatal = true
			return &FatalIntegrityError{Op: "write audit log", Err: err}
		}
		s.chain.Restore(prevState.Sequence, prevState.PrevHash)
		return err
	}

	s.pendingFlush = true
	return nil
}
```

Add the `FlushSync()` method after `AppendEvent`:

```go
// FlushSync flushes buffered writes to durable storage and updates the sidecar.
// Safe to call concurrently with AppendEvent — the chain mutex is held only
// briefly to snapshot state, then released before slow I/O.
func (s *IntegrityStore) FlushSync() error {
	s.mu.Lock()
	if !s.pendingFlush || s.fatal {
		s.mu.Unlock()
		return nil
	}
	state := s.chain.State()
	s.pendingFlush = false
	s.mu.Unlock()

	if syncer, ok := s.inner.(Syncer); ok {
		if err := syncer.Sync(); err != nil {
			s.mu.Lock()
			s.fatal = true
			s.mu.Unlock()
			return &FatalIntegrityError{Op: "sync audit log", Err: err}
		}
	}

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

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/store/ -run 'TestFlushSync_WritesSidecar|TestFlushSync_Noop' -v`
Expected: PASS

- [ ] **Step 5: Write test for AppendEvent no longer updating sidecar**

In `internal/store/integrity_wrapper_test.go`, add:

```go
func TestAppendEvent_NoSidecarWrite(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	initialState := writeResumableIntegrityState(t, logPath)
	chain := mustNewIntegrityChain(t)

	inner := &mockRawWriter{}
	store, err := NewIntegrityStore(inner, chain, testIntegrityOptions(logPath))
	if err != nil {
		t.Fatal(err)
	}

	sidecarPath := audit.SidecarPath(logPath)
	infoBefore, err := os.Stat(sidecarPath)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(50 * time.Millisecond)

	ev := types.Event{ID: "ev-no-sidecar", Timestamp: time.Now().UTC(), Type: "test", SessionID: "s1"}
	if err := store.AppendEvent(context.Background(), ev); err != nil {
		t.Fatal(err)
	}

	infoAfter, err := os.Stat(sidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	if !infoBefore.ModTime().Equal(infoAfter.ModTime()) {
		t.Fatalf("sidecar was modified by AppendEvent (mtime changed)")
	}

	sidecar, _ := audit.ReadSidecar(sidecarPath)
	if sidecar.Sequence != initialState.Sequence {
		t.Fatalf("sidecar.Sequence = %d, want %d", sidecar.Sequence, initialState.Sequence)
	}
}
```

- [ ] **Step 6: Run test**

Run: `go test ./internal/store/ -run TestAppendEvent_NoSidecarWrite -v`
Expected: PASS

- [ ] **Step 7: Write tests for FlushSync fatal on sync and sidecar errors**

In `internal/store/integrity_wrapper_test.go`, add:

```go
type mockSyncerWriter struct {
	mockRawWriter
	syncErr error
}

func (m *mockSyncerWriter) Sync() error {
	return m.syncErr
}

func TestFlushSync_SetsFatal_OnSyncError(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	writeResumableIntegrityState(t, logPath)
	chain := mustNewIntegrityChain(t)

	inner := &mockSyncerWriter{syncErr: errors.New("disk failure")}
	store, err := NewIntegrityStore(inner, chain, testIntegrityOptions(logPath))
	if err != nil {
		t.Fatal(err)
	}

	ev := types.Event{ID: "ev-fatal", Timestamp: time.Now().UTC(), Type: "test", SessionID: "s1"}
	if err := store.AppendEvent(context.Background(), ev); err != nil {
		t.Fatal(err)
	}

	err = store.FlushSync()
	if err == nil {
		t.Fatal("FlushSync() should have returned error")
	}
	var fatal *FatalIntegrityError
	if !errors.As(err, &fatal) {
		t.Fatalf("expected FatalIntegrityError, got %T: %v", err, err)
	}

	ev2 := types.Event{ID: "ev-after-fatal", Timestamp: time.Now().UTC(), Type: "test", SessionID: "s1"}
	if err := store.AppendEvent(context.Background(), ev2); !errors.Is(err, ErrIntegrityFatal) {
		t.Fatalf("AppendEvent after fatal = %v, want ErrIntegrityFatal", err)
	}
}

func TestFlushSync_SetsFatal_OnSidecarError(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	writeResumableIntegrityState(t, logPath)
	chain := mustNewIntegrityChain(t)

	inner := &mockRawWriter{}
	store, err := NewIntegrityStore(inner, chain, testIntegrityOptions(logPath))
	if err != nil {
		t.Fatal(err)
	}

	// Point sidecar to an unwritable path
	store.sidecarPath = "/proc/nonexistent/sidecar.json"

	ev := types.Event{ID: "ev-sidecar-fail", Timestamp: time.Now().UTC(), Type: "test", SessionID: "s1"}
	if err := store.AppendEvent(context.Background(), ev); err != nil {
		t.Fatal(err)
	}

	err = store.FlushSync()
	if err == nil {
		t.Fatal("FlushSync() should have returned error for unwritable sidecar")
	}
	var fatal *FatalIntegrityError
	if !errors.As(err, &fatal) {
		t.Fatalf("expected FatalIntegrityError, got %T: %v", err, err)
	}

	ev2 := types.Event{ID: "ev-after-sidecar-fatal", Timestamp: time.Now().UTC(), Type: "test", SessionID: "s1"}
	if err := store.AppendEvent(context.Background(), ev2); !errors.Is(err, ErrIntegrityFatal) {
		t.Fatalf("AppendEvent after sidecar fatal = %v, want ErrIntegrityFatal", err)
	}
}
```

- [ ] **Step 8: Run fatal tests**

Run: `go test ./internal/store/ -run 'TestFlushSync_SetsFatal' -v`
Expected: PASS

- [ ] **Step 9: Write chain continuity test across multiple FlushSync calls**

In `internal/store/integrity_wrapper_test.go`, add:

```go
func TestAppendEvent_Then_FlushSync_ChainContinuity(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	writeResumableIntegrityState(t, logPath)

	chain := mustNewIntegrityChain(t)
	jstore, err := jsonl.New(logPath, 10*1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	jstore.SetSyncOnWrite(false)
	defer jstore.Close()

	store, err := NewIntegrityStore(jstore, chain, testIntegrityOptions(logPath))
	if err != nil {
		t.Fatal(err)
	}

	for batch := 0; batch < 2; batch++ {
		for i := 0; i < 10; i++ {
			ev := types.Event{
				ID:        fmt.Sprintf("ev-%d-%d", batch, i),
				Timestamp: time.Now().UTC(),
				Type:      "test",
				SessionID: "s1",
			}
			if err := store.AppendEvent(context.Background(), ev); err != nil {
				t.Fatalf("batch %d event %d: %v", batch, i, err)
			}
		}
		if err := store.FlushSync(); err != nil {
			t.Fatalf("FlushSync batch %d: %v", batch, err)
		}
	}

	// Verify chain integrity
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))

	var prevHash string
	for i, line := range lines {
		entry, err := audit.ParseIntegrityEntry(line)
		if err != nil {
			t.Fatalf("line %d: parse error: %v", i, err)
		}
		if entry.Integrity == nil {
			t.Fatalf("line %d: no integrity metadata", i)
		}
		if entry.Type == "integrity_chain_rotated" {
			prevHash = entry.Integrity.EntryHash
			continue
		}
		if entry.Integrity.PrevHash != prevHash {
			t.Fatalf("line %d: chain broken: prev_hash=%q, want %q", i, entry.Integrity.PrevHash, prevHash)
		}
		ok, err := chain.VerifyHash(
			entry.Integrity.FormatVersion, entry.Integrity.Sequence,
			entry.Integrity.PrevHash, entry.CanonicalPayload, entry.Integrity.EntryHash,
		)
		if err != nil {
			t.Fatalf("line %d: verify error: %v", i, err)
		}
		if !ok {
			t.Fatalf("line %d: HMAC verification failed", i)
		}
		prevHash = entry.Integrity.EntryHash
	}
}
```

- [ ] **Step 10: Run chain continuity test**

Run: `go test ./internal/store/ -run TestAppendEvent_Then_FlushSync_ChainContinuity -v`
Expected: PASS

- [ ] **Step 11: Write concurrent AppendEvent + FlushSync test**

In `internal/store/integrity_wrapper_test.go`, add:

```go
func TestConcurrent_AppendEvent_And_FlushSync(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	writeResumableIntegrityState(t, logPath)

	chain := mustNewIntegrityChain(t)
	jstore, err := jsonl.New(logPath, 10*1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	jstore.SetSyncOnWrite(false)
	defer jstore.Close()

	store, err := NewIntegrityStore(jstore, chain, testIntegrityOptions(logPath))
	if err != nil {
		t.Fatal(err)
	}

	const numEvents = 100
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numEvents; i++ {
			ev := types.Event{
				ID:        "ev-concurrent-" + strconv.Itoa(i),
				Timestamp: time.Now().UTC(),
				Type:      "test",
				SessionID: "s1",
			}
			if err := store.AppendEvent(context.Background(), ev); err != nil {
				t.Errorf("AppendEvent %d: %v", i, err)
				return
			}
		}
	}()

	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = store.FlushSync()
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()

	wg.Wait()
	close(stop)

	if err := store.FlushSync(); err != nil {
		t.Fatal(err)
	}

	// Verify chain integrity
	verifyChain := mustNewIntegrityChain(t)
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))

	var prevHash string
	for i, line := range lines {
		entry, err := audit.ParseIntegrityEntry(line)
		if err != nil {
			t.Fatalf("line %d: parse: %v", i, err)
		}
		if entry.Integrity == nil {
			t.Fatalf("line %d: no integrity", i)
		}
		if entry.Type == "integrity_chain_rotated" {
			prevHash = entry.Integrity.EntryHash
			continue
		}
		if entry.Integrity.PrevHash != prevHash {
			t.Fatalf("line %d: chain broken", i)
		}
		ok, err := verifyChain.VerifyHash(
			entry.Integrity.FormatVersion, entry.Integrity.Sequence,
			entry.Integrity.PrevHash, entry.CanonicalPayload, entry.Integrity.EntryHash,
		)
		if err != nil || !ok {
			t.Fatalf("line %d: HMAC verify failed", i)
		}
		prevHash = entry.Integrity.EntryHash
	}
}
```

- [ ] **Step 12: Run concurrent test**

Run: `go test ./internal/store/ -run TestConcurrent_AppendEvent_And_FlushSync -v -count=5`
Expected: PASS (all 5 runs)

- [ ] **Step 13: Add background flush timer to IntegrityStore**

In `internal/store/integrity_wrapper.go`, add timer fields to the struct:

```go
type IntegrityStore struct {
	mu             sync.Mutex
	inner          EventStore
	chain          *audit.IntegrityChain
	logPath        string
	sidecarPath    string
	algorithm      string
	keyFingerprint string
	now            func() time.Time
	fatal          bool
	pendingFlush   bool
	flushTick      *time.Ticker
	stopFlush      chan struct{}
	flushDone      chan struct{}
}
```

Add `"log/slog"` to imports if not already present.

Add the `runFlushLoop` method:

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

In `NewIntegrityStore`, after `store.bootstrap()` succeeds (line 94-96), add timer startup and disable inner sync:

```go
	if err := store.bootstrap(); err != nil {
		return nil, err
	}

	// Disable per-write sync on inner store — FlushSync handles it.
	type syncController interface{ SetSyncOnWrite(bool) }
	if sc, ok := inner.(syncController); ok {
		sc.SetSyncOnWrite(false)
	}

	store.stopFlush = make(chan struct{})
	store.flushDone = make(chan struct{})
	store.flushTick = time.NewTicker(100 * time.Millisecond)
	go store.runFlushLoop()

	return store, nil
```

Update `Close()` (line 490-492) to shut down the timer and do a final flush:

```go
func (s *IntegrityStore) Close() error {
	if s.stopFlush != nil {
		close(s.stopFlush)
		<-s.flushDone
	}
	if err := s.FlushSync(); err != nil {
		slog.Error("final audit flush failed", "error", err)
	}
	return s.inner.Close()
}
```

- [ ] **Step 14: Write tests for background timer and Close**

In `internal/store/integrity_wrapper_test.go`, add:

```go
func TestFlushLoop_PeriodicSync(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	writeResumableIntegrityState(t, logPath)

	chain := mustNewIntegrityChain(t)
	jstore, err := jsonl.New(logPath, 10*1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer jstore.Close()

	store, err := NewIntegrityStore(jstore, chain, testIntegrityOptions(logPath))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ev := types.Event{ID: "ev-timer", Timestamp: time.Now().UTC(), Type: "test", SessionID: "s1"}
	if err := store.AppendEvent(context.Background(), ev); err != nil {
		t.Fatal(err)
	}

	// Wait for background timer (100ms interval, wait 250ms)
	time.Sleep(250 * time.Millisecond)

	sidecar, err := audit.ReadSidecar(audit.SidecarPath(logPath))
	if err != nil {
		t.Fatal(err)
	}
	chainState := chain.State()
	if sidecar.Sequence != chainState.Sequence {
		t.Fatalf("sidecar.Sequence = %d, want %d (timer should have flushed)", sidecar.Sequence, chainState.Sequence)
	}
}

func TestClose_FinalFlush(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	initialState := writeResumableIntegrityState(t, logPath)

	chain := mustNewIntegrityChain(t)
	jstore, err := jsonl.New(logPath, 10*1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewIntegrityStore(jstore, chain, testIntegrityOptions(logPath))
	if err != nil {
		t.Fatal(err)
	}

	ev := types.Event{ID: "ev-close", Timestamp: time.Now().UTC(), Type: "test", SessionID: "s1"}
	if err := store.AppendEvent(context.Background(), ev); err != nil {
		t.Fatal(err)
	}

	// Close immediately — no timer tick should have fired
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	sidecar, err := audit.ReadSidecar(audit.SidecarPath(logPath))
	if err != nil {
		t.Fatal(err)
	}
	if sidecar.Sequence != initialState.Sequence+1 {
		t.Fatalf("sidecar.Sequence = %d, want %d (Close should have flushed)", sidecar.Sequence, initialState.Sequence+1)
	}
}

func TestFlushLoop_StopsOnClose(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	writeResumableIntegrityState(t, logPath)

	chain := mustNewIntegrityChain(t)
	jstore, err := jsonl.New(logPath, 10*1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewIntegrityStore(jstore, chain, testIntegrityOptions(logPath))
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case <-store.flushDone:
		// OK — goroutine exited
	default:
		t.Fatal("flushDone channel not closed after Close()")
	}
}
```

- [ ] **Step 15: Run all integrity store tests**

Run: `go test ./internal/store/ -v`
Expected: All PASS

- [ ] **Step 16: Commit**

```bash
git add internal/store/integrity_wrapper.go internal/store/integrity_wrapper_test.go
git commit -m "feat(store): add FlushSync and background timer to IntegrityStore

AppendEvent no longer calls WriteSidecar or file.Sync().
FlushSync() flushes buffered writes and updates the sidecar.
Background timer calls FlushSync every 100ms.
Close() stops the timer and performs a final flush."
```

---

### Task 3: Extend crash recovery for seq+N sidecar gap

**Files:**
- Modify: `internal/store/integrity_wrapper.go:269-321` (resumeFromSidecar)
- Test: `internal/store/integrity_wrapper_test.go`

- [ ] **Step 1: Write failing test for seq+N recovery**

In `internal/store/integrity_wrapper_test.go`, add helpers and tests:

```go
// writeIntegrityStateWithGap writes a JSONL file with events seq 0..totalEvents-1
// (plus an initial rotation boundary at seq 0) and a sidecar pointing to sidecarSeq.
// This simulates a crash where the sidecar is behind by N unflushed events.
func writeIntegrityStateWithGap(t testing.TB, logPath string, totalEvents, sidecarSeq int) {
	t.Helper()

	chain, err := audit.NewIntegrityChain(testKey, "hmac-sha256")
	if err != nil {
		t.Fatal(err)
	}

	f, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}

	var sidecarState audit.ChainState
	for i := 0; i < totalEvents; i++ {
		ev := types.Event{
			ID:        "gap-ev-" + strconv.Itoa(i),
			Timestamp: time.Now().UTC(),
			Type:      "test",
			SessionID: "s1",
		}
		payload, _ := json.Marshal(ev)
		wrapped, _ := chain.Wrap(payload)
		f.Write(append(wrapped, '\n'))

		if int(chain.State().Sequence) == sidecarSeq {
			sidecarState = chain.State()
		}
	}
	f.Close()

	if err := audit.WriteSidecar(audit.SidecarPath(logPath), audit.SidecarState{
		Sequence:       sidecarState.Sequence,
		PrevHash:       sidecarState.PrevHash,
		KeyFingerprint: chain.KeyFingerprint(),
		UpdatedAt:      time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestStartup_SidecarBehindByN(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	// 11 events (seq 0..10), sidecar at seq 7 — behind by 3
	writeIntegrityStateWithGap(t, logPath, 11, 7)

	chain := mustNewIntegrityChain(t)
	jstore, err := jsonl.New(logPath, 10*1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer jstore.Close()

	store, err := NewIntegrityStore(jstore, chain, testIntegrityOptions(logPath))
	if err != nil {
		t.Fatalf("NewIntegrityStore should recover from seq+N gap, got: %v", err)
	}
	defer store.Close()

	// Sidecar should have been advanced to seq 10
	sidecar, err := audit.ReadSidecar(audit.SidecarPath(logPath))
	if err != nil {
		t.Fatal(err)
	}
	if sidecar.Sequence != 10 {
		t.Fatalf("sidecar.Sequence = %d, want 10 (should have recovered)", sidecar.Sequence)
	}

	// Chain should resume from seq 10
	state := chain.State()
	if state.Sequence != 10 {
		t.Fatalf("chain.State().Sequence = %d, want 10", state.Sequence)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/ -run TestStartup_SidecarBehindByN -v`
Expected: FAIL — `audit integrity chain mismatch: sidecar does not match`

- [ ] **Step 3: Extend `resumeFromSidecar` and add `recoverFromSidecarGap`**

In `internal/store/integrity_wrapper.go`, replace the `resumeFromSidecar` method (lines 269-321) with:

```go
func (s *IntegrityStore) resumeFromSidecar(sidecar audit.SidecarState, lastFile audit.LogFile, lastLine []byte, lastErr error) error {
	if lastErr != nil {
		return fmt.Errorf("audit integrity chain mismatch: %w", lastErr)
	}

	entry, err := audit.ParseIntegrityEntry(lastLine)
	if err != nil || entry.Integrity == nil {
		return fmt.Errorf("audit integrity chain mismatch: malformed last entry in %s", lastFile.Path)
	}

	// Case 1: sidecar exactly matches last entry — normal resume.
	if sidecar.Sequence == entry.Integrity.Sequence && sidecar.PrevHash == entry.Integrity.EntryHash {
		ok, err := s.chain.VerifyHash(
			entry.Integrity.FormatVersion,
			entry.Integrity.Sequence,
			entry.Integrity.PrevHash,
			entry.CanonicalPayload,
			entry.Integrity.EntryHash,
		)
		if err != nil {
			return fmt.Errorf("audit integrity chain mismatch: verify last entry: %w", err)
		}
		if !ok {
			return fmt.Errorf("audit integrity chain mismatch: invalid last entry in %s", lastFile.Path)
		}
		s.chain.Restore(sidecar.Sequence, sidecar.PrevHash)
		return nil
	}

	// Case 2: sidecar is behind — crash recovery (seq+N from deferred sync).
	if sidecar.Sequence < entry.Integrity.Sequence {
		advanced, err := s.recoverFromSidecarGap(sidecar, lastFile)
		if err != nil {
			return err
		}
		if advanced {
			return nil
		}
	}

	return fmt.Errorf("audit integrity chain mismatch: sidecar does not match %s", lastFile.Path)
}

// recoverFromSidecarGap walks the audit log from the sidecar position forward,
// verifying each entry forms a valid chain continuation. On success, advances
// the sidecar to the last verified entry. Also handles truncated last lines
// from crash-during-Write by truncating the file back to the last complete line.
func (s *IntegrityStore) recoverFromSidecarGap(sidecar audit.SidecarState, lastFile audit.LogFile) (bool, error) {
	f, err := os.Open(lastFile.Path)
	if err != nil {
		return false, fmt.Errorf("open %s for recovery: %w", lastFile.Path, err)
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	var lastVerified *audit.IntegrityEntry
	var lastGoodOffset int64
	var currentOffset int64
	expectedSeq := sidecar.Sequence + 1
	expectedPrev := sidecar.PrevHash

	for {
		rawLine, readErr := reader.ReadBytes('\n')
		lineLen := int64(len(rawLine))

		if errors.Is(readErr, io.EOF) && len(rawLine) == 0 {
			break
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return false, fmt.Errorf("read %s for recovery: %w", lastFile.Path, readErr)
		}

		line := bytes.TrimSpace(rawLine)
		if len(line) == 0 {
			currentOffset += lineLen
			if errors.Is(readErr, io.EOF) {
				break
			}
			continue
		}

		entry, parseErr := audit.ParseIntegrityEntry(line)
		if parseErr != nil || entry.Integrity == nil {
			// Truncated last line — truncate file to last good position
			if err := truncateFile(lastFile.Path, lastGoodOffset+lineLen); err != nil {
				slog.Warn("failed to truncate partial line during recovery",
					"path", lastFile.Path, "error", err)
			}
			break
		}

		currentOffset += lineLen

		// Skip entries at or before the sidecar position
		if entry.Integrity.Sequence <= sidecar.Sequence {
			lastGoodOffset = currentOffset
			continue
		}

		// Verify chain link
		if entry.Integrity.Sequence != expectedSeq || entry.Integrity.PrevHash != expectedPrev {
			return false, fmt.Errorf("audit integrity chain mismatch: chain broken during recovery at seq %d", entry.Integrity.Sequence)
		}

		ok, err := s.chain.VerifyHash(
			entry.Integrity.FormatVersion,
			entry.Integrity.Sequence,
			entry.Integrity.PrevHash,
			entry.CanonicalPayload,
			entry.Integrity.EntryHash,
		)
		if err != nil {
			return false, fmt.Errorf("audit integrity chain mismatch: verify entry seq %d: %w", entry.Integrity.Sequence, err)
		}
		if !ok {
			return false, fmt.Errorf("audit integrity chain mismatch: invalid HMAC at seq %d", entry.Integrity.Sequence)
		}

		expectedSeq = entry.Integrity.Sequence + 1
		expectedPrev = entry.Integrity.EntryHash
		lastVerified = entry
		lastGoodOffset = currentOffset

		if errors.Is(readErr, io.EOF) {
			break
		}
	}

	if lastVerified == nil {
		return false, nil
	}

	s.chain.Restore(lastVerified.Integrity.Sequence, lastVerified.Integrity.EntryHash)
	slog.Warn("audit integrity: sidecar behind, advancing after crash recovery",
		"sidecar_seq", sidecar.Sequence,
		"log_seq", lastVerified.Integrity.Sequence,
		"events_recovered", lastVerified.Integrity.Sequence-sidecar.Sequence,
	)
	return true, audit.WriteSidecar(s.sidecarPath, audit.SidecarState{
		Sequence:       lastVerified.Integrity.Sequence,
		PrevHash:       lastVerified.Integrity.EntryHash,
		KeyFingerprint: s.keyFingerprint,
		UpdatedAt:      s.now().UTC(),
	})
}

// truncateFile truncates a file to the given size (removing a partial trailing line).
func truncateFile(path string, size int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Truncate(size)
}
```

Ensure `"bufio"`, `"bytes"`, `"io"`, `"log/slog"` are in the imports (they should already be from earlier tasks or the existing code).

- [ ] **Step 4: Run test**

Run: `go test ./internal/store/ -run TestStartup_SidecarBehindByN -v`
Expected: PASS

- [ ] **Step 5: Write tests for corrupted chain and truncated last line**

In `internal/store/integrity_wrapper_test.go`, add:

```go
func TestStartup_SidecarBehindByN_InvalidChain(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	writeIntegrityStateWithGap(t, logPath, 11, 7)

	// Corrupt an event after the sidecar position by modifying the file
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))
	// Corrupt line 9 (an event after sidecar seq 7)
	if len(lines) > 9 {
		lines[9] = bytes.Replace(lines[9], []byte(`"test"`), []byte(`"tampered"`), 1)
	}
	os.WriteFile(logPath, append(bytes.Join(lines, []byte("\n")), '\n'), 0o644)

	chain := mustNewIntegrityChain(t)
	jstore, err := jsonl.New(logPath, 10*1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer jstore.Close()

	_, err = NewIntegrityStore(jstore, chain, testIntegrityOptions(logPath))
	if err == nil {
		t.Fatal("expected error for tampered chain, got nil")
	}
	if !strings.Contains(err.Error(), "chain mismatch") && !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStartup_TruncatedLastLine(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	// Write 6 events, sidecar at seq 3 (behind by 2)
	writeIntegrityStateWithGap(t, logPath, 6, 3)

	// Append a truncated line (incomplete JSON)
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"integrity":{"sequence":6,"prev_hash":"abc","entry_hash":`)
	f.Close()

	chain := mustNewIntegrityChain(t)
	jstore, err := jsonl.New(logPath, 10*1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer jstore.Close()

	store, err := NewIntegrityStore(jstore, chain, testIntegrityOptions(logPath))
	if err != nil {
		t.Fatalf("should recover from truncated last line, got: %v", err)
	}
	defer store.Close()

	// Sidecar should have been advanced to seq 5 (last valid event)
	sidecar, err := audit.ReadSidecar(audit.SidecarPath(logPath))
	if err != nil {
		t.Fatal(err)
	}
	if sidecar.Sequence != 5 {
		t.Fatalf("sidecar.Sequence = %d, want 5 (should recover up to last valid)", sidecar.Sequence)
	}
}
```

- [ ] **Step 6: Run recovery tests**

Run: `go test ./internal/store/ -run 'TestStartup_SidecarBehind|TestStartup_Truncated' -v`
Expected: All PASS

- [ ] **Step 7: Run all existing tests for regressions**

Run: `go test ./internal/store/ -v`
Expected: All PASS

- [ ] **Step 8: Commit**

```bash
git add internal/store/integrity_wrapper.go internal/store/integrity_wrapper_test.go
git commit -m "feat(store): extend crash recovery for seq+N sidecar gap

resumeFromSidecar now walks forward from the sidecar position,
verifying each entry's HMAC chain link. Handles truncated last
lines by truncating the file before chain verification."
```

---

### Task 4: Restructure execve handler — separate decision from emission

**Files:**
- Modify: `internal/netmonitor/unix/execve_handler.go:48-56` (ExecveResult), `143-484` (Handle, emitEvent)
- Modify: `internal/netmonitor/unix/handler.go:274-394` (handleExecveNotification)

- [ ] **Step 1: Rename `emitEvent` to `buildEvent` and change it to return `*types.Event`**

In `internal/netmonitor/unix/execve_handler.go`, rename the method at line 433 and change the signature:

```go
// buildEvent builds an execve audit event without emitting it.
func (h *ExecveHandler) buildEvent(ctx ExecveContext, result ExecveResult, rule string) *types.Event {
	if h.emitter == nil {
		return nil
	}

	action := "allowed"
	if !result.Allow {
		action = "blocked"
	}

	decision := types.Decision(result.Decision)
	if decision == "" {
		if result.Allow {
			decision = types.DecisionAllow
		} else {
			decision = types.DecisionDeny
		}
	}

	effectiveDecision := types.DecisionAllow
	if !result.Allow {
		effectiveDecision = types.DecisionDeny
	}

	return &types.Event{
		ID:        fmt.Sprintf("execve-%d-%d", ctx.PID, time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Type:      "execve",
		SessionID: ctx.SessionID,
		PID:       ctx.PID,
		ParentPID: ctx.ParentPID,
		Depth:     ctx.Depth,
		Filename:    ctx.Filename,
		RawFilename: ctx.RawFilename,
		Argv:        ctx.Argv,
		Truncated:      ctx.Truncated,
		UnwrappedFrom:  ctx.UnwrappedFrom,
		PayloadCommand: ctx.PayloadCommand,
		Policy: &types.PolicyInfo{
			Decision:          decision,
			EffectiveDecision: effectiveDecision,
			Rule:              rule,
			Message:           result.Reason,
		},
		EffectiveAction: action,
	}
}
```

- [ ] **Step 2: Change `Handle()` to return `(ExecveResult, *types.Event)`**

Change the signature at line 143:

```go
func (h *ExecveHandler) Handle(goCtx context.Context, ctx ExecveContext) (ExecveResult, *types.Event) {
```

Replace every `h.emitEvent(ctx, result, ...)` / `return result` pair with a single `return result, h.buildEvent(ctx, result, ...)`.

The call sites to change (all in Handle()):

1. Internal bypass (line ~188): `h.emitEvent(ctx, result, "internal_bypass")` + `return result` -> `return result, h.buildEvent(ctx, result, "internal_bypass")`
2. Truncated deny (~line 205): same pattern
3. Truncated no_approver (~line 216): same pattern
4. Truncated approval error (~line 246): same pattern
5. Truncated approval denied (~line 257): same pattern
6. Unwrap payload deny (~line 310): same pattern
7. Unwrap wrapper deny (~line 322): same pattern
8. Unwrap allow (~line 339): same pattern
9. Unwrap redirect (~line 346): same pattern
10. No policy (~line 355): same pattern
11. Policy allow (~line 377): same pattern
12. Policy deny (~line 389): same pattern
13. Policy approve (~line 401): same pattern
14. Policy redirect (~line 413): same pattern
15. Unknown decision (~line 425): same pattern

Each becomes: `return result, h.buildEvent(ctx, result, ruleString)`

Remove the old `emitEvent` method body (the two-line `AppendEvent` + `Publish` calls are gone).

- [ ] **Step 3: Update `handleExecveNotification` to respond before emit**

In `internal/netmonitor/unix/handler.go`, at line 356 change:

```go
	result := h.Handle(goCtx, ectx)
```

To:

```go
	result, ev := h.Handle(goCtx, ectx)

	defer func() {
		if ev != nil && h.emitter != nil {
			_ = h.emitter.AppendEvent(context.Background(), *ev)
			h.emitter.Publish(*ev)
		}
	}()
```

The rest of the switch statement (ActionRedirect, ActionDeny, default) stays unchanged — the `return` in each case triggers the deferred emit after the notify response.

- [ ] **Step 4: Verify compilation and tests**

Run: `go build ./internal/netmonitor/unix/...`
Expected: SUCCESS (fix any callers of `Handle` that need `_, ev :=` or just `result, _ :=`)

Run: `go test ./internal/netmonitor/unix/ -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add internal/netmonitor/unix/execve_handler.go internal/netmonitor/unix/handler.go
git commit -m "refactor(netmonitor): separate execve decision from event emission

Handle() returns (ExecveResult, *types.Event). The caller sends the
notify response first, then emits the event via deferred function."
```

---

### Task 5: Restructure file handler — separate decision from emission

**Files:**
- Modify: `internal/netmonitor/unix/file_handler.go:81-193` (Handle, emitFileEvent)
- Modify: `internal/netmonitor/unix/handler.go:399-484` (handleFileNotification), `492-678` (handleFileNotificationEmulated)

- [ ] **Step 1: Rename `emitFileEvent` to `buildFileEvent` and change to return `*types.Event`**

In `internal/netmonitor/unix/file_handler.go`, rename at line 152:

```go
func (h *FileHandler) buildFileEvent(req FileRequest, dec FilePolicyDecision, blocked, shadowDeny bool) *types.Event {
	if h.emitter == nil {
		return nil
	}

	action := "allowed"
	if blocked {
		action = "blocked"
	}

	fields := map[string]any{
		"syscall": fileSyscallName(req.Syscall),
	}
	if shadowDeny {
		fields["shadow_deny"] = true
	}
	if req.Path2 != "" {
		fields["path2"] = req.Path2
	}

	return &types.Event{
		ID:        fmt.Sprintf("file-%d-%d", req.PID, time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Type:      "file_" + req.Operation,
		SessionID: req.SessionID,
		Source:    "seccomp",
		PID:       req.PID,
		Path:      req.Path,
		Operation: req.Operation,
		Policy: &types.PolicyInfo{
			Decision:          types.Decision(dec.Decision),
			EffectiveDecision: types.Decision(dec.EffectiveDecision),
			Rule:              dec.Rule,
			Message:           dec.Message,
		},
		EffectiveAction: action,
		Fields:          fields,
	}
}
```

- [ ] **Step 2: Change `Handle()` to return `(FileResult, *types.Event)`**

Change signature at line 81:

```go
func (h *FileHandler) Handle(req FileRequest) (FileResult, *types.Event) {
```

Replace each `h.emitFileEvent(...); return FileResult{...}` pair:

1. Pseudo-path early return (line ~93): `return FileResult{Action: ActionContinue}, nil`
2. No policy (line ~97): `return FileResult{Action: ActionContinue}, h.buildFileEvent(req, dec, false, false)`
3. FUSE mount (line ~119): `return FileResult{Action: ActionContinue}, h.buildFileEvent(req, dec, false, shadowDeny)`
4. Audit-only deny (line ~138): `return FileResult{Action: ActionContinue}, h.buildFileEvent(req, dec, false, false)`
5. Enforced deny (line ~142): `return FileResult{Action: ActionDeny, Errno: int32(sysunix.EACCES)}, h.buildFileEvent(req, dec, true, false)`
6. Allowed (line ~147): `return FileResult{Action: ActionContinue}, h.buildFileEvent(req, dec, false, false)`

- [ ] **Step 3: Update `handleFileNotification` to respond before emit**

In `internal/netmonitor/unix/handler.go`, replace the block at line 473:

```go
	result, ev := h.Handle(frequest)

	if result.Action == ActionDeny {
		if err := NotifRespondDeny(int(fd), req.ID, result.Errno); err != nil {
			slog.Error("file handler: deny response failed", "pid", pid, "path", path, "error", err)
		}
	} else {
		if err := NotifRespondContinue(int(fd), req.ID); err != nil {
			slog.Debug("file handler: continue response failed", "pid", pid, "error", err)
		}
	}

	if ev != nil && h.emitter != nil {
		_ = h.emitter.AppendEvent(context.Background(), *ev)
		h.emitter.Publish(*ev)
	}
```

- [ ] **Step 4: Update `handleFileNotificationEmulated` similarly**

In `handleFileNotificationEmulated`, find `result := h.Handle(frequest)` and change to:

```go
	result, ev := h.Handle(frequest)

	defer func() {
		if ev != nil && h.emitter != nil {
			_ = h.emitter.AppendEvent(context.Background(), *ev)
			h.emitter.Publish(*ev)
		}
	}()
```

The rest of the emulated handler's response logic stays unchanged — the deferred emit runs after whatever response path executes.

- [ ] **Step 5: Verify compilation and tests**

Run: `go build ./internal/netmonitor/unix/...`
Expected: SUCCESS

Run: `go test ./internal/netmonitor/unix/ -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add internal/netmonitor/unix/file_handler.go internal/netmonitor/unix/handler.go
git commit -m "refactor(netmonitor): separate file handler decision from event emission

Handle() returns (FileResult, *types.Event). Notify response is sent
before the audit event is emitted."
```

---

### Task 6: Restructure unix socket emit path

**Files:**
- Modify: `internal/netmonitor/unix/handler.go:30-95` (ServeNotify), `140-158` (emitEvent), `235-268` (unix socket block in ServeNotifyWithExecve)

- [ ] **Step 1: Rename `emitEvent` to `buildUnixSocketEvent` and return event**

In `internal/netmonitor/unix/handler.go`, replace the `emitEvent` function (line 140) with:

```go
func buildUnixSocketEvent(emit Emitter, session string, dec policy.Decision, path string, abstract bool, op string) *types.Event {
	if emit == nil {
		return nil
	}
	return &types.Event{
		ID:        fmt.Sprintf("evt-%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Type:      "unix_socket_op",
		SessionID: session,
		Policy: &types.PolicyInfo{
			Decision:          dec.PolicyDecision,
			EffectiveDecision: dec.EffectiveDecision,
			Rule:              dec.Rule,
			Message:           dec.Message,
		},
		Path:      path,
		Abstract:  abstract,
		Operation: op,
	}
}
```

Note: This remains a package-level function (matching the existing `emitEvent` pattern, which was also package-level, not a method).

- [ ] **Step 2: Update the unix socket block in `ServeNotifyWithExecve`**

Replace lines 243-268:

```go
		allow := true
		errno := int32(unix.EACCES)
		path := ""
		abstract := false
		var ev *types.Event
		if raw, err := ReadSockaddr(ctxReq.PID, ctxReq.AddrPtr, ctxReq.AddrLen); err == nil {
			if p, abs, perr := ParseSockaddr(raw); perr == nil {
				path, abstract = p, abs
				op := syscallName(ctxReq.Syscall)
				dec := pol.CheckUnixSocket(path, op)
				allow = dec.EffectiveDecision == types.DecisionAllow
				if !allow {
					errno = int32(unix.EACCES)
					ev = buildUnixSocketEvent(emit, sessID, dec, path, abstract, op)
				}
			}
		}
		if allow {
			if err := NotifRespondContinue(int(scmpFD), req.ID); err != nil {
				slog.Debug("unix socket: continue response failed", "error", err)
			}
		} else {
			if err := NotifRespondDeny(int(scmpFD), req.ID, errno); err != nil {
				slog.Error("unix socket: deny response failed", "path", path, "error", err)
			}
		}
		if ev != nil {
			_ = emit.AppendEvent(context.Background(), *ev)
			emit.Publish(*ev)
		}
```

- [ ] **Step 3: Apply the same change to the `ServeNotify` function**

The identical unix socket block in `ServeNotify` (lines 69-93) gets the same treatment: build event first, respond, then emit.

- [ ] **Step 4: Verify compilation and tests**

Run: `go build ./internal/netmonitor/unix/...`
Expected: SUCCESS

Run: `go test ./internal/netmonitor/unix/ -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add internal/netmonitor/unix/handler.go
git commit -m "refactor(netmonitor): separate unix socket decision from event emission

Notify response is sent before the audit event is emitted for unix
socket syscalls."
```

---

### Task 7: Notify loop ordering integration tests

**Files:**
- Create: `internal/netmonitor/unix/emit_order_test.go`

- [ ] **Step 1: Write ordering tests**

Create `internal/netmonitor/unix/emit_order_test.go`:

```go
package unix

import (
	"context"
	"sync"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

// recordingEmitter records calls in order to verify emit-after-respond.
type recordingEmitter struct {
	mu    sync.Mutex
	calls []string
}

func (r *recordingEmitter) AppendEvent(_ context.Context, ev types.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "AppendEvent:"+ev.Type)
	return nil
}

func (r *recordingEmitter) Publish(ev types.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "Publish:"+ev.Type)
}

func TestBuildEvent_ExecveHandler_NoSideEffects(t *testing.T) {
	rec := &recordingEmitter{}
	h := &ExecveHandler{emitter: rec}

	ctx := ExecveContext{
		PID: 1234, Filename: "/bin/ls", Argv: []string{"ls"},
		SessionID: "test-sess",
	}
	result := ExecveResult{Allow: true, Action: ActionContinue, Rule: "test", Decision: "allow"}

	ev := h.buildEvent(ctx, result, "test")
	if ev == nil {
		t.Fatal("buildEvent returned nil")
	}
	if ev.Type != "execve" {
		t.Fatalf("ev.Type = %q, want %q", ev.Type, "execve")
	}
	if len(rec.calls) != 0 {
		t.Fatalf("emitter was called during buildEvent: %v", rec.calls)
	}
}

func TestBuildEvent_FileHandler_NoSideEffects(t *testing.T) {
	rec := &recordingEmitter{}
	h := &FileHandler{emitter: rec}

	req := FileRequest{PID: 1234, Path: "/tmp/test", Operation: "write", SessionID: "test-sess"}
	dec := FilePolicyDecision{Decision: "allow", EffectiveDecision: "allow", Rule: "test"}

	ev := h.buildFileEvent(req, dec, false, false)
	if ev == nil {
		t.Fatal("buildFileEvent returned nil")
	}
	if ev.Type != "file_write" {
		t.Fatalf("ev.Type = %q, want %q", ev.Type, "file_write")
	}
	if len(rec.calls) != 0 {
		t.Fatalf("emitter was called during buildFileEvent: %v", rec.calls)
	}
}

func TestBuildEvent_UnixSocket_NoSideEffects(t *testing.T) {
	rec := &recordingEmitter{}

	dec := policy.Decision{
		PolicyDecision:    types.DecisionDeny,
		EffectiveDecision: types.DecisionDeny,
		Rule:              "test_rule",
	}
	ev := buildUnixSocketEvent(rec, "test-sess", dec, "/tmp/sock", false, "connect")
	if ev == nil {
		t.Fatal("buildUnixSocketEvent returned nil")
	}
	if ev.Type != "unix_socket_op" {
		t.Fatalf("ev.Type = %q, want %q", ev.Type, "unix_socket_op")
	}
	if len(rec.calls) != 0 {
		t.Fatalf("emitter was called during buildUnixSocketEvent: %v", rec.calls)
	}
}
```

Add the policy import at the top:

```go
import (
	"context"
	"sync"
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/netmonitor/unix/ -run 'TestBuildEvent' -v`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/netmonitor/unix/emit_order_test.go
git commit -m "test(netmonitor): verify event builders have no side effects

Confirms that buildEvent, buildFileEvent, and buildUnixSocketEvent
return events without calling the emitter."
```

---

### Task 8: Full build verification, benchmarks, and cross-compilation

**Files:**
- Modify: `internal/store/integrity_wrapper_test.go` (benchmarks)

- [ ] **Step 1: Run full test suite**

Run: `go test ./...`
Expected: All PASS

- [ ] **Step 2: Verify cross-compilation**

Run: `GOOS=windows go build ./...`
Expected: SUCCESS

Run: `GOOS=darwin go build ./...`
Expected: SUCCESS

- [ ] **Step 3: Add benchmarks**

In `internal/store/integrity_wrapper_test.go`, add a `testing.TB`-compatible setup helper and benchmarks:

```go
// benchmarkIntegritySetup creates a bootstrapped IntegrityStore with deferred sync
// suitable for both tests and benchmarks.
func benchmarkIntegritySetup(tb testing.TB) (*IntegrityStore, func()) {
	tb.Helper()
	dir := tb.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	// Write initial state manually (writeResumableIntegrityState needs *testing.T)
	chain, err := audit.NewIntegrityChain(testKey, "hmac-sha256")
	if err != nil {
		tb.Fatal(err)
	}
	f, err := os.Create(logPath)
	if err != nil {
		tb.Fatal(err)
	}
	// Write a rotation boundary as initial event
	rotEv := types.Event{ID: "init", Timestamp: time.Now().UTC(), Type: "integrity_chain_rotated", SessionID: "bench"}
	payload, _ := json.Marshal(rotEv)
	wrapped, _ := chain.Wrap(payload)
	f.Write(append(wrapped, '\n'))
	f.Close()

	state := chain.State()
	audit.WriteSidecar(audit.SidecarPath(logPath), audit.SidecarState{
		Sequence:       state.Sequence,
		PrevHash:       state.PrevHash,
		KeyFingerprint: chain.KeyFingerprint(),
		UpdatedAt:      time.Now().UTC(),
	})

	chain2, _ := audit.NewIntegrityChain(testKey, "hmac-sha256")
	jstore, err := jsonl.New(logPath, 100*1024*1024, 3)
	if err != nil {
		tb.Fatal(err)
	}

	store, err := NewIntegrityStore(jstore, chain2, IntegrityOptions{
		LogPath: logPath, Now: time.Now,
	})
	if err != nil {
		jstore.Close()
		tb.Fatal(err)
	}

	cleanup := func() {
		store.Close()
	}
	return store, cleanup
}

func BenchmarkAppendEvent_DeferredSync(b *testing.B) {
	store, cleanup := benchmarkIntegritySetup(b)
	defer cleanup()

	ev := types.Event{
		ID: "bench-ev", Timestamp: time.Now().UTC(), Type: "execve",
		SessionID: "bench", Filename: "/usr/bin/ls",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev.ID = "bench-" + strconv.Itoa(i)
		_ = store.AppendEvent(context.Background(), ev)
	}
}

func BenchmarkFlushSync(b *testing.B) {
	store, cleanup := benchmarkIntegritySetup(b)
	defer cleanup()

	ev := types.Event{
		ID: "bench-ev", Timestamp: time.Now().UTC(), Type: "execve",
		SessionID: "bench",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev.ID = "bench-" + strconv.Itoa(i)
		_ = store.AppendEvent(context.Background(), ev)
		_ = store.FlushSync()
	}
}
```

- [ ] **Step 4: Run benchmarks**

Run: `go test ./internal/store/ -run=^$ -bench 'BenchmarkAppendEvent_DeferredSync|BenchmarkFlushSync' -benchtime=3s`
Expected: `BenchmarkAppendEvent_DeferredSync` should show microsecond-range per-op (page-cache writes only).

- [ ] **Step 5: Commit**

```bash
git add internal/store/integrity_wrapper_test.go
git commit -m "test(store): add benchmarks for deferred sync AppendEvent and FlushSync"
```
