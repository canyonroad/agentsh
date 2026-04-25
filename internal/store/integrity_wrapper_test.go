package store

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store/jsonl"
	"github.com/agentsh/agentsh/pkg/types"
)

var testKey = []byte("test-key-32-bytes-for-hmac-sha!!")

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

type mockFailingRawWriter struct{}

func (m *mockFailingRawWriter) WriteRaw(_ context.Context, _ []byte) error {
	return errors.New("disk full")
}

func (m *mockFailingRawWriter) AppendEvent(_ context.Context, _ types.Event) error {
	return nil
}

func (m *mockFailingRawWriter) QueryEvents(_ context.Context, _ types.EventQuery) ([]types.Event, error) {
	return nil, nil
}

func (m *mockFailingRawWriter) Close() error { return nil }

type mockPartialFailRawWriter struct{}

type testPartialWriteError struct{ msg string }

func (e *testPartialWriteError) Error() string        { return e.msg }
func (e *testPartialWriteError) IsPartialWrite() bool { return true }

func (m *mockPartialFailRawWriter) WriteRaw(_ context.Context, _ []byte) error {
	return &testPartialWriteError{msg: "partial write: disk full (truncate failed: read-only fs)"}
}

func (m *mockPartialFailRawWriter) AppendEvent(_ context.Context, _ types.Event) error {
	return nil
}

func (m *mockPartialFailRawWriter) QueryEvents(_ context.Context, _ types.EventQuery) ([]types.Event, error) {
	return nil, nil
}

func (m *mockPartialFailRawWriter) Close() error { return nil }

func newBootstrappedRawIntegrityStore(t *testing.T, inner EventStore) (*IntegrityStore, *audit.IntegrityChain, string, audit.ChainState) {
	t.Helper()

	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	expectedState := writeResumableIntegrityState(t, logPath)
	chain := mustNewIntegrityChain(t)
	store, err := NewIntegrityStore(inner, chain, testIntegrityOptions(logPath))
	if err != nil {
		t.Fatalf("NewIntegrityStore() error = %v", err)
	}
	if state := chain.State(); state != expectedState {
		t.Fatalf("chain.State() = %+v, want %+v", state, expectedState)
	}
	return store, chain, logPath, expectedState
}

func TestIntegrityStore_AppendEvent_WrapsPayload(t *testing.T) {
	mock := &mockRawWriter{}
	store, _, _, initialState := newBootstrappedRawIntegrityStore(t, mock)
	t.Cleanup(func() { _ = store.Close() })

	ev := types.Event{
		ID:        "ev-1",
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Type:      "test_event",
		SessionID: "sess-1",
	}

	if err := store.AppendEvent(context.Background(), ev); err != nil {
		t.Fatalf("AppendEvent() error = %v", err)
	}

	if len(mock.rawCalls) != 1 {
		t.Fatalf("len(mock.rawCalls) = %d, want 1", len(mock.rawCalls))
	}
	if len(mock.events) != 0 {
		t.Fatalf("len(mock.events) = %d, want 0", len(mock.events))
	}

	var result map[string]any
	if err := json.Unmarshal(mock.rawCalls[0], &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	integrity := result["integrity"].(map[string]any)
	if got := int64(integrity["sequence"].(float64)); got != initialState.Sequence+1 {
		t.Fatalf("sequence = %d, want %d", got, initialState.Sequence+1)
	}
	if got := integrity["prev_hash"].(string); got != initialState.PrevHash {
		t.Fatalf("prev_hash = %q, want %q", got, initialState.PrevHash)
	}
	if got := integrity["entry_hash"].(string); got == "" {
		t.Fatal("entry_hash is empty")
	}
	if result["id"] != "ev-1" {
		t.Fatalf("id = %v, want ev-1", result["id"])
	}
	if result["type"] != "test_event" {
		t.Fatalf("type = %v, want test_event", result["type"])
	}
}

func TestIntegrityStore_AppendEvent_FallbackWithoutRawWriter(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	expectedState := writeResumableIntegrityState(t, logPath)

	chain := mustNewIntegrityChain(t)
	mock := &mockPlainStore{}
	store, err := NewIntegrityStore(mock, chain, testIntegrityOptions(logPath))
	if err != nil {
		t.Fatalf("NewIntegrityStore() error = %v", err)
	}

	if state := chain.State(); state != expectedState {
		t.Fatalf("chain.State() = %+v, want %+v", state, expectedState)
	}

	ev := types.Event{ID: "ev-1", Type: "test_event"}
	if err := store.AppendEvent(context.Background(), ev); err != nil {
		t.Fatalf("AppendEvent() error = %v", err)
	}

	if len(mock.events) != 1 {
		t.Fatalf("len(mock.events) = %d, want 1", len(mock.events))
	}
	if state := chain.State(); state != expectedState {
		t.Fatalf("chain.State() after fallback append = %+v, want %+v", state, expectedState)
	}
}

func TestIntegrityStore_ChainContinuity(t *testing.T) {
	mock := &mockRawWriter{}
	store, _, _, prevState := newBootstrappedRawIntegrityStore(t, mock)
	t.Cleanup(func() { _ = store.Close() })

	for i := 0; i < 3; i++ {
		if err := store.AppendEvent(context.Background(), types.Event{
			ID:   strconv.Itoa(i),
			Type: "test",
		}); err != nil {
			t.Fatalf("AppendEvent(%d) error = %v", i, err)
		}
	}

	if len(mock.rawCalls) != 3 {
		t.Fatalf("len(mock.rawCalls) = %d, want 3", len(mock.rawCalls))
	}

	expectedPrevHash := prevState.PrevHash
	for i, raw := range mock.rawCalls {
		var result map[string]any
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatalf("json.Unmarshal(%d) error = %v", i, err)
		}

		integrity := result["integrity"].(map[string]any)
		if got := int64(integrity["sequence"].(float64)); got != int64(i+1) {
			t.Fatalf("entry %d sequence = %d, want %d", i, got, i+1)
		}
		if got := integrity["prev_hash"].(string); got != expectedPrevHash {
			t.Fatalf("entry %d prev_hash = %q, want %q", i, got, expectedPrevHash)
		}
		expectedPrevHash = integrity["entry_hash"].(string)
	}
}

func TestIntegrityStore_AppendEvent_WriteFailureRollsBackChain(t *testing.T) {
	store, chain, _, initialState := newBootstrappedRawIntegrityStore(t, &mockFailingRawWriter{})
	t.Cleanup(func() { _ = store.Close() })

	err := store.AppendEvent(context.Background(), types.Event{ID: "ev-1", Type: "test"})
	if err == nil {
		t.Fatal("AppendEvent() error = nil, want write failure")
	}

	if state := chain.State(); state != initialState {
		t.Fatalf("chain.State() = %+v, want %+v", state, initialState)
	}
}

func TestIntegrityStore_FatalSidecarFailureRecoversOnRestart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permission failure is not reliable on Windows")
	}

	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	jsonlStore, err := jsonl.New(logPath, 100, 3)
	if err != nil {
		t.Fatalf("jsonl.New() error = %v", err)
	}

	chain := mustNewIntegrityChain(t)
	store, err := NewIntegrityStore(jsonlStore, chain, testIntegrityOptions(logPath))
	if err != nil {
		t.Fatalf("NewIntegrityStore() error = %v", err)
	}

	if err := store.AppendEvent(context.Background(), types.Event{ID: "1", Type: "ok"}); err != nil {
		t.Fatalf("AppendEvent(first) error = %v", err)
	}
	if err := store.FlushSync(); err != nil {
		t.Fatalf("FlushSync(first) error = %v", err)
	}

	sidecarPath := audit.SidecarPath(logPath)
	beforeFailure, err := audit.ReadSidecar(sidecarPath)
	if err != nil {
		t.Fatalf("audit.ReadSidecar() before failure error = %v", err)
	}

	if err := store.AppendEvent(context.Background(), types.Event{ID: "2", Type: "fatal_sidecar"}); err != nil {
		t.Fatalf("AppendEvent(second) error = %v", err)
	}

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("os.Chmod(%q, 0500) error = %v", dir, err)
	}
	fatalErr := store.FlushSync()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("os.Chmod(%q, 0700) error = %v", dir, err)
	}
	if fatalErr == nil {
		_ = store.Close()
		t.Skip("directory permissions did not block sidecar rewrite in this environment")
	}

	var fatal *FatalIntegrityError
	if !errors.As(fatalErr, &fatal) {
		t.Fatalf("FlushSync(second) error = %v, want FatalIntegrityError", fatalErr)
	}

	afterFailure, err := audit.ReadSidecar(sidecarPath)
	if err != nil {
		t.Fatalf("audit.ReadSidecar() after failure error = %v", err)
	}
	if afterFailure.Sequence != beforeFailure.Sequence || afterFailure.PrevHash != beforeFailure.PrevHash {
		t.Fatalf("sidecar advanced after fatal failure: before=%+v after=%+v", beforeFailure, afterFailure)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("store.Close() error = %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) error = %v", logPath, err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("line count = %d, want 3 after durable fatal write", len(lines))
	}

	reopen, err := jsonl.New(logPath, 100, 3)
	if err != nil {
		t.Fatalf("jsonl.New(reopen) error = %v", err)
	}
	t.Cleanup(func() { _ = reopen.Close() })

	resumeChain := mustNewIntegrityChain(t)
	resumed, err := NewIntegrityStore(reopen, resumeChain, testIntegrityOptions(logPath))
	if err != nil {
		t.Fatalf("NewIntegrityStore(reopen) error = %v", err)
	}
	t.Cleanup(func() { _ = resumed.Close() })

	if got := resumeChain.State().Sequence; got != beforeFailure.Sequence+1 {
		t.Fatalf("recovered sequence = %d, want %d", got, beforeFailure.Sequence+1)
	}
}

func TestIntegrityStore_PartialWriteReturnsFatalErrorAndDoesNotRollBack(t *testing.T) {
	store, chain, _, initialState := newBootstrappedRawIntegrityStore(t, &mockPartialFailRawWriter{})
	t.Cleanup(func() { _ = store.Close() })

	err := store.AppendEvent(context.Background(), types.Event{ID: "ev-1", Type: "test"})
	if err == nil {
		t.Fatal("AppendEvent() error = nil, want partial write failure")
	}
	var fatal *FatalIntegrityError
	if !errors.As(err, &fatal) {
		t.Fatalf("AppendEvent() error = %v, want FatalIntegrityError", err)
	}

	state := chain.State()
	if state.Sequence != initialState.Sequence+1 {
		t.Fatalf("chain sequence = %d, want %d", state.Sequence, initialState.Sequence+1)
	}
	if state.PrevHash == initialState.PrevHash {
		t.Fatal("prev_hash did not advance after partial write")
	}
}

func TestIntegrityStore_StickyFatalRejectsSubsequentAppends(t *testing.T) {
	store, _, _, _ := newBootstrappedRawIntegrityStore(t, &mockPartialFailRawWriter{})
	t.Cleanup(func() { _ = store.Close() })

	// First append triggers a partial write → FatalIntegrityError.
	err := store.AppendEvent(context.Background(), types.Event{ID: "ev-1", Type: "test"})
	var fatal *FatalIntegrityError
	if !errors.As(err, &fatal) {
		t.Fatalf("first AppendEvent() error = %v, want FatalIntegrityError", err)
	}

	// Second append must be rejected immediately without touching the chain or log.
	err = store.AppendEvent(context.Background(), types.Event{ID: "ev-2", Type: "test"})
	if !errors.Is(err, ErrIntegrityFatal) {
		t.Fatalf("second AppendEvent() error = %v, want ErrIntegrityFatal", err)
	}
}

func TestIntegrityStore_EndToEnd_VerifyWithAuditHelpers(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")

	jsonlStore, err := jsonl.New(logPath, 100, 3)
	if err != nil {
		t.Fatalf("jsonl.New() error = %v", err)
	}

	chain := mustNewIntegrityChain(t)
	store, err := NewIntegrityStore(jsonlStore, chain, testIntegrityOptions(logPath))
	if err != nil {
		t.Fatalf("NewIntegrityStore() error = %v", err)
	}

	events := []types.Event{
		{ID: "1", Type: "session_start", SessionID: "s1", Timestamp: time.Now().UTC()},
		{ID: "2", Type: "command_executed", SessionID: "s1", Timestamp: time.Now().UTC(), Fields: map[string]any{"command": "ls"}},
		{ID: "3", Type: "file_read", SessionID: "s1", Timestamp: time.Now().UTC(), Fields: map[string]any{"path": "/etc/hosts"}},
	}
	for _, ev := range events {
		if err := store.AppendEvent(context.Background(), ev); err != nil {
			t.Fatalf("AppendEvent() error = %v", err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != len(events)+1 {
		t.Fatalf("line count = %d, want %d", len(lines), len(events)+1)
	}

	var prevEntryHash string
	for i, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("json.Unmarshal(line %d) error = %v", i, err)
		}

		integrity := entry["integrity"].(map[string]any)
		formatVersion := int(integrity["format_version"].(float64))
		sequence := int64(integrity["sequence"].(float64))
		prevHash := integrity["prev_hash"].(string)
		entryHash := integrity["entry_hash"].(string)

		if prevHash != prevEntryHash {
			t.Fatalf("line %d prev_hash = %q, want %q", i, prevHash, prevEntryHash)
		}

		delete(entry, "integrity")
		canonicalPayload, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("json.Marshal(line %d payload) error = %v", i, err)
		}
		if got := computeHMAC(testKey, formatVersion, sequence, prevHash, canonicalPayload); got != entryHash {
			t.Fatalf("line %d entry_hash = %q, want %q", i, entryHash, got)
		}

		prevEntryHash = entryHash
	}
}

func computeHMAC(key []byte, formatVersion int, sequence int64, prevHash string, payload []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(strconv.Itoa(formatVersion)))
	h.Write([]byte("|"))
	h.Write([]byte(strconv.FormatInt(sequence, 10)))
	h.Write([]byte("|"))
	h.Write([]byte(prevHash))
	h.Write([]byte("|"))
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

func TestFlushSync_WritesSidecar(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	expectedState := writeResumableIntegrityState(t, logPath)
	chain := mustNewIntegrityChain(t)

	inner := &mockRawWriter{}
	store, err := NewIntegrityStore(inner, chain, testIntegrityOptions(logPath))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ev := types.Event{ID: "ev-flush-1", Timestamp: time.Now().UTC(), Type: "test", SessionID: "s1"}
	if err := store.AppendEvent(context.Background(), ev); err != nil {
		t.Fatal(err)
	}

	sidecar, err := audit.ReadSidecar(audit.SidecarPath(logPath))
	if err != nil {
		t.Fatal(err)
	}
	if sidecar.Sequence != expectedState.Sequence {
		t.Fatalf("pre-flush sidecar.Sequence = %d, want %d", sidecar.Sequence, expectedState.Sequence)
	}

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
	t.Cleanup(func() { _ = store.Close() })

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

func TestAppendEvent_NoSidecarWrite(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	initialState := writeResumableIntegrityState(t, logPath)
	chain := mustNewIntegrityChain(t)

	inner := &mockRawWriter{}
	store, err := NewIntegrityStore(inner, chain, testIntegrityOptions(logPath))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	// Stop the background timer so only AppendEvent's behavior is tested.
	close(store.stopFlush)
	<-store.flushDone
	store.stopFlush = nil // prevent double-close in Close()

	sidecarPath := audit.SidecarPath(logPath)

	ev := types.Event{ID: "ev-no-sidecar", Timestamp: time.Now().UTC(), Type: "test", SessionID: "s1"}
	if err := store.AppendEvent(context.Background(), ev); err != nil {
		t.Fatal(err)
	}

	sidecar, _ := audit.ReadSidecar(sidecarPath)
	if sidecar.Sequence != initialState.Sequence {
		t.Fatalf("sidecar.Sequence = %d, want %d (AppendEvent should not write sidecar)", sidecar.Sequence, initialState.Sequence)
	}
}

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
	t.Cleanup(func() { _ = store.Close() })

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
	t.Cleanup(func() { _ = store.Close() })

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

func TestConcurrent_AppendEvent_And_FlushSync(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows CI flakes on the t.TempDir cleanup: after the
		// concurrent writer goroutines return, the JSONL + sidecar
		// file handles are briefly held by the audit integrity
		// pipeline during its async flush, and Windows' RemoveAll
		// returns ERROR_DIR_NOT_EMPTY when any handle is still live
		// on a child. The test body itself passes — the failure is
		// purely in the framework's post-run cleanup. Proper fix is
		// a coordinated close on the audit pipeline before the
		// Cleanup's TempDir removal runs; scope as follow-up.
		t.Skip("Windows: t.TempDir cleanup races the audit pipeline's async flush close")
	}
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
	var flushWg sync.WaitGroup
	flushWg.Add(1)
	go func() {
		defer flushWg.Done()
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
	flushWg.Wait()

	if err := store.FlushSync(); err != nil {
		t.Fatal(err)
	}

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

	chainState := chain.State()

	sidecar, err := waitForSidecarSequence(audit.SidecarPath(logPath), chainState.Sequence, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if sidecar.Sequence != chainState.Sequence {
		t.Fatalf("sidecar.Sequence = %d, want %d (timer should have flushed)", sidecar.Sequence, chainState.Sequence)
	}
}

func TestWaitForSidecarSequence_Timeout(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	writeSidecarForState(t, logPath, audit.ChainState{
		Sequence: 0,
		PrevHash: "prev-hash",
	})

	if _, err := waitForSidecarSequence(audit.SidecarPath(logPath), 1, 50*time.Millisecond); err == nil {
		t.Fatal("waitForSidecarSequence() error = nil, want timeout")
	}
}

func TestWaitForSidecarSequence_RetriesTransientReadErrors(t *testing.T) {
	t.Parallel()

	var calls int
	got, err := waitForSidecarSequenceWithReader("audit.jsonl.chain", 3, 100*time.Millisecond, func(string) (audit.SidecarState, error) {
		calls++
		if calls == 1 {
			return audit.SidecarState{}, &os.PathError{
				Op:   "open",
				Path: "audit.jsonl.chain",
				Err:  errors.New("The process cannot access the file because it is being used by another process."),
			}
		}
		return audit.SidecarState{Sequence: 3}, nil
	})
	if err != nil {
		t.Fatalf("waitForSidecarSequenceWithReader() error = %v", err)
	}
	if got.Sequence != 3 {
		t.Fatalf("Sequence = %d, want 3", got.Sequence)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
}

func TestWaitForSidecarSequence_FailsFastOnNonRetryableReadError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("boom")
	_, err := waitForSidecarSequenceWithReader("audit.jsonl.chain", 1, 100*time.Millisecond, func(string) (audit.SidecarState, error) {
		return audit.SidecarState{}, wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("waitForSidecarSequenceWithReader() error = %v, want %v", err, wantErr)
	}
}

func waitForSidecarSequence(sidecarPath string, want int64, timeout time.Duration) (audit.SidecarState, error) {
	return waitForSidecarSequenceWithReader(sidecarPath, want, timeout, audit.ReadSidecar)
}

func waitForSidecarSequenceWithReader(sidecarPath string, want int64, timeout time.Duration, readSidecar func(string) (audit.SidecarState, error)) (audit.SidecarState, error) {
	deadline := time.Now().Add(timeout)
	var lastSidecar audit.SidecarState
	var lastErr error
	for {
		sidecar, err := readSidecar(sidecarPath)
		if err != nil {
			if !shouldRetrySidecarRead(err) {
				return audit.SidecarState{}, err
			}
			lastErr = err
		} else {
			lastSidecar = sidecar
			lastErr = nil
			if sidecar.Sequence == want {
				return sidecar, nil
			}
		}
		if time.Now().After(deadline) {
			if lastErr != nil {
				return audit.SidecarState{}, fmt.Errorf("timed out waiting for sidecar sequence %d after read error: %w", want, lastErr)
			}
			return lastSidecar, fmt.Errorf("timed out waiting for sidecar sequence %d; got %d", want, lastSidecar.Sequence)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func shouldRetrySidecarRead(err error) bool {
	if errors.Is(err, audit.ErrSidecarNotFound) || errors.Is(err, os.ErrNotExist) {
		return true
	}

	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		return false
	}

	msg := strings.ToLower(pathErr.Err.Error())
	return strings.Contains(msg, "sharing violation") ||
		strings.Contains(msg, "used by another process") ||
		strings.Contains(msg, "cannot access the file")
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
	default:
		t.Fatal("flushDone channel not closed after Close()")
	}
}

// writeIntegrityStateWithGap writes a JSONL file with totalEvents events
// (seq 0..totalEvents-1) and a sidecar pointing to sidecarSeq.
// Simulates a crash where the sidecar is behind by N unflushed events.
func writeIntegrityStateWithGap(t testing.TB, logPath string, totalEvents, sidecarSeq int) {
	t.Helper()

	chain, err := audit.NewIntegrityChain(testKey)
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

		if chain.State().Sequence == int64(sidecarSeq) {
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

	sidecar, err := audit.ReadSidecar(audit.SidecarPath(logPath))
	if err != nil {
		t.Fatal(err)
	}
	if sidecar.Sequence != 10 {
		t.Fatalf("sidecar.Sequence = %d, want 10 (should have recovered)", sidecar.Sequence)
	}

	state := chain.State()
	if state.Sequence != 10 {
		t.Fatalf("chain.State().Sequence = %d, want 10", state.Sequence)
	}
}

func TestStartup_SidecarBehindByN_InvalidChain(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	writeIntegrityStateWithGap(t, logPath, 11, 7)

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

	sidecar, err := audit.ReadSidecar(audit.SidecarPath(logPath))
	if err != nil {
		t.Fatal(err)
	}
	if sidecar.Sequence != 5 {
		t.Fatalf("sidecar.Sequence = %d, want 5 (should recover up to last valid)", sidecar.Sequence)
	}
}

// benchmarkIntegritySetup creates a bootstrapped IntegrityStore with deferred sync
// suitable for both tests and benchmarks.
func benchmarkIntegritySetup(tb testing.TB) (*IntegrityStore, func()) {
	tb.Helper()
	dir := tb.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	chain, err := audit.NewIntegrityChain(testKey)
	if err != nil {
		tb.Fatal(err)
	}
	f, err := os.Create(logPath)
	if err != nil {
		tb.Fatal(err)
	}
	rotEv := types.Event{ID: "init", Timestamp: time.Now().UTC(), Type: "integrity_chain_rotated", SessionID: "bench"}
	payload, _ := json.Marshal(rotEv)
	wrapped, _ := chain.Wrap(payload)
	f.Write(append(wrapped, '\n'))
	f.Close()

	state := chain.State()
	if err := audit.WriteSidecar(audit.SidecarPath(logPath), audit.SidecarState{
		Sequence:       state.Sequence,
		PrevHash:       state.PrevHash,
		KeyFingerprint: chain.KeyFingerprint(),
		UpdatedAt:      time.Now().UTC(),
	}); err != nil {
		tb.Fatal(err)
	}

	chain2, err := audit.NewIntegrityChain(testKey)
	if err != nil {
		tb.Fatal(err)
	}
	jstore, err := jsonl.New(logPath, 100, 3)
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
