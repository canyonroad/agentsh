package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

	sidecarPath := audit.SidecarPath(logPath)
	beforeFailure, err := audit.ReadSidecar(sidecarPath)
	if err != nil {
		t.Fatalf("audit.ReadSidecar() before failure error = %v", err)
	}

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("os.Chmod(%q, 0500) error = %v", dir, err)
	}
	fatalErr := store.AppendEvent(context.Background(), types.Event{ID: "2", Type: "fatal_sidecar"})
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("os.Chmod(%q, 0700) error = %v", dir, err)
	}
	if fatalErr == nil {
		_ = store.Close()
		t.Skip("directory permissions did not block sidecar rewrite in this environment")
	}

	var fatal *FatalIntegrityError
	if !errors.As(fatalErr, &fatal) {
		t.Fatalf("AppendEvent(second) error = %v, want FatalIntegrityError", fatalErr)
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

func TestIntegrityStore_PartialWriteDoesNotRollBack(t *testing.T) {
	store, chain, _, initialState := newBootstrappedRawIntegrityStore(t, &mockPartialFailRawWriter{})

	err := store.AppendEvent(context.Background(), types.Event{ID: "ev-1", Type: "test"})
	if err == nil {
		t.Fatal("AppendEvent() error = nil, want partial write failure")
	}

	state := chain.State()
	if state.Sequence != initialState.Sequence+1 {
		t.Fatalf("chain sequence = %d, want %d", state.Sequence, initialState.Sequence+1)
	}
	if state.PrevHash == initialState.PrevHash {
		t.Fatal("prev_hash did not advance after partial write")
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
