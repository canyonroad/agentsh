package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

// mockFailingRawWriter implements RawWriter but always fails on WriteRaw.
type mockFailingRawWriter struct {
	mu       sync.Mutex
	rawCalls int
	events   []types.Event
}

func (m *mockFailingRawWriter) WriteRaw(_ context.Context, _ []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rawCalls++
	return errors.New("disk full")
}

func (m *mockFailingRawWriter) AppendEvent(_ context.Context, ev types.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
	return nil
}

func (m *mockFailingRawWriter) QueryEvents(_ context.Context, _ types.EventQuery) ([]types.Event, error) {
	return nil, nil
}

func (m *mockFailingRawWriter) Close() error { return nil }

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

func TestIntegrityStore_AppendEvent_WriteFailureRollsBackChain(t *testing.T) {
	chain, err := audit.NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("create chain: %v", err)
	}

	mock := &mockFailingRawWriter{}
	s := NewIntegrityStore(mock, chain)

	ev := types.Event{ID: "ev-1", Type: "test"}

	// First call should fail
	err = s.AppendEvent(context.Background(), ev)
	if err == nil {
		t.Fatal("expected error from failing WriteRaw")
	}

	// Chain state should be rolled back to initial (sequence=0)
	state := chain.State()
	if state.Sequence != 0 {
		t.Errorf("chain sequence = %d after failed write, want 0 (rolled back)", state.Sequence)
	}
	if state.PrevHash != "" {
		t.Errorf("chain prev_hash = %q after failed write, want empty", state.PrevHash)
	}

	// Now retry with a working mock — chain should start fresh at sequence 1
	goodMock := &mockRawWriter{}
	s2 := NewIntegrityStore(goodMock, chain)
	if err := s2.AppendEvent(context.Background(), ev); err != nil {
		t.Fatalf("retry AppendEvent: %v", err)
	}

	if len(goodMock.rawCalls) != 1 {
		t.Fatalf("expected 1 WriteRaw call, got %d", len(goodMock.rawCalls))
	}

	var result map[string]any
	if err := json.Unmarshal(goodMock.rawCalls[0], &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	integrity := result["integrity"].(map[string]any)
	seq := int64(integrity["sequence"].(float64))
	if seq != 1 {
		t.Errorf("sequence after retry = %d, want 1", seq)
	}
}

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
