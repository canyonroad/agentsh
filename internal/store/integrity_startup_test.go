package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/store/jsonl"
	"github.com/agentsh/agentsh/pkg/types"
)

func testIntegrityOptions(logPath string) IntegrityOptions {
	return IntegrityOptions{
		LogPath:        logPath,
		Algorithm:      "hmac-sha256",
		KeyFingerprint: audit.KeyFingerprint(testKey),
		Now: func() time.Time {
			return time.Date(2026, 4, 11, 12, 0, 0, 0, time.UTC)
		},
	}
}

func mustNewIntegrityChain(t *testing.T) *audit.IntegrityChain {
	t.Helper()

	chain, err := audit.NewIntegrityChain(testKey)
	if err != nil {
		t.Fatalf("audit.NewIntegrityChain() error = %v", err)
	}
	return chain
}

func TestNewIntegrityStore_FreshInstallWritesInitialRotationEvent(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	inner, err := jsonl.New(logPath, 100, 3)
	if err != nil {
		t.Fatalf("jsonl.New() error = %v", err)
	}
	t.Cleanup(func() { _ = inner.Close() })

	chain := mustNewIntegrityChain(t)

	store, err := NewIntegrityStore(inner, chain, testIntegrityOptions(logPath))
	if err != nil {
		t.Fatalf("NewIntegrityStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if state := chain.State(); state.Sequence != 0 {
		t.Fatalf("chain sequence after initial rotation = %d, want 0", state.Sequence)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) error = %v", logPath, err)
	}
	if len(data) == 0 {
		t.Fatal("audit log is empty after bootstrap, want initial rotation event")
	}

	sidecar, err := audit.ReadSidecar(audit.SidecarPath(logPath))
	if err != nil {
		t.Fatalf("audit.ReadSidecar() error = %v", err)
	}
	if sidecar.Sequence != 0 {
		t.Fatalf("sidecar sequence = %d, want 0", sidecar.Sequence)
	}
}

func TestNewIntegrityStore_RejectsLegacyLogWithoutSidecar(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(logPath, []byte(`{"type":"legacy","integrity":{"sequence":1,"prev_hash":"","entry_hash":"deadbeef"}}`+"\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	inner, err := jsonl.New(logPath, 100, 3)
	if err != nil {
		t.Fatalf("jsonl.New() error = %v", err)
	}
	t.Cleanup(func() { _ = inner.Close() })

	chain := mustNewIntegrityChain(t)

	if _, err := NewIntegrityStore(inner, chain, testIntegrityOptions(logPath)); err == nil {
		t.Fatal("NewIntegrityStore() error = nil, want legacy log rejection")
	}
}

func TestNewIntegrityStore_ResumesFromMatchingSidecar(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	expectedState := writeResumableIntegrityState(t, logPath)

	inner, err := jsonl.New(logPath, 100, 3)
	if err != nil {
		t.Fatalf("jsonl.New() error = %v", err)
	}
	t.Cleanup(func() { _ = inner.Close() })

	chain := mustNewIntegrityChain(t)
	store, err := NewIntegrityStore(inner, chain, testIntegrityOptions(logPath))
	if err != nil {
		t.Fatalf("NewIntegrityStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if state := chain.State(); state != expectedState {
		t.Fatalf("chain.State() = %+v, want %+v", state, expectedState)
	}
}

func TestNewIntegrityStore_RejectsTamperedLastEntryEvenWhenSidecarMatches(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")

	chain := mustNewIntegrityChain(t)
	line, err := chain.Wrap([]byte(`{"type":"existing","timestamp":"2026-04-11T12:00:00Z","fields":{"value":"ok"}}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}

	var entry map[string]any
	if err := json.Unmarshal(line, &entry); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	entry["fields"] = map[string]any{"value": "tampered"}
	tampered, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if err := os.WriteFile(logPath, append(tampered, '\n'), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath, err)
	}

	state := chain.State()
	if err := audit.WriteSidecar(audit.SidecarPath(logPath), audit.SidecarState{
		Sequence:       state.Sequence,
		PrevHash:       state.PrevHash,
		KeyFingerprint: audit.KeyFingerprint(testKey),
		UpdatedAt:      time.Date(2026, 4, 11, 12, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("audit.WriteSidecar() error = %v", err)
	}

	inner, err := jsonl.New(logPath, 100, 3)
	if err != nil {
		t.Fatalf("jsonl.New() error = %v", err)
	}
	t.Cleanup(func() { _ = inner.Close() })

	if _, err := NewIntegrityStore(inner, mustNewIntegrityChain(t), testIntegrityOptions(logPath)); err == nil {
		t.Fatal("NewIntegrityStore() error = nil, want tampered exact-match resume rejection")
	}
}

func writeResumableIntegrityState(t *testing.T, logPath string) audit.ChainState {
	t.Helper()

	chain := mustNewIntegrityChain(t)
	line, err := chain.Wrap([]byte(`{"type":"integrity_chain_rotated","timestamp":"2026-04-11T12:00:00Z"}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}
	if err := os.WriteFile(logPath, append(line, '\n'), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath, err)
	}

	state := chain.State()
	if err := audit.WriteSidecar(audit.SidecarPath(logPath), audit.SidecarState{
		Sequence:       state.Sequence,
		PrevHash:       state.PrevHash,
		KeyFingerprint: audit.KeyFingerprint(testKey),
		UpdatedAt:      time.Date(2026, 4, 11, 12, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("audit.WriteSidecar() error = %v", err)
	}

	return state
}

func TestNewIntegrityStore_SidecarMissingStartsFreshRotation(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")

	previousChain := mustNewIntegrityChain(t)
	line, err := previousChain.Wrap([]byte(`{"type":"existing","timestamp":"2026-04-11T12:00:00Z"}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}
	if err := os.WriteFile(logPath, append(line, '\n'), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath, err)
	}

	inner, err := jsonl.New(logPath, 100, 3)
	if err != nil {
		t.Fatalf("jsonl.New() error = %v", err)
	}
	t.Cleanup(func() { _ = inner.Close() })

	chain := mustNewIntegrityChain(t)
	store, err := NewIntegrityStore(inner, chain, testIntegrityOptions(logPath))
	if err != nil {
		t.Fatalf("NewIntegrityStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if state := chain.State(); state.Sequence != 0 {
		t.Fatalf("chain sequence = %d, want 0 after sidecar-missing rotation", state.Sequence)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) error = %v", logPath, err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("line count = %d, want 2", len(lines))
	}

	var last map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &last); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got := last["type"]; got != "integrity_chain_rotated" {
		t.Fatalf("last type = %v, want integrity_chain_rotated", got)
	}
	fields := last["fields"].(map[string]any)
	if got := fields["reason_code"]; got != "sidecar_missing" {
		t.Fatalf("reason_code = %v, want sidecar_missing", got)
	}
}

func TestNewIntegrityStore_SidecarMissingRejectsTamperedV2Log(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")

	previousChain := mustNewIntegrityChain(t)
	line, err := previousChain.Wrap([]byte(`{"type":"existing","timestamp":"2026-04-11T12:00:00Z","fields":{"value":"ok"}}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}

	var entry map[string]any
	if err := json.Unmarshal(line, &entry); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	entry["fields"] = map[string]any{"value": "tampered"}
	tampered, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if err := os.WriteFile(logPath, append(tampered, '\n'), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath, err)
	}

	inner, err := jsonl.New(logPath, 100, 3)
	if err != nil {
		t.Fatalf("jsonl.New() error = %v", err)
	}
	t.Cleanup(func() { _ = inner.Close() })

	chain := mustNewIntegrityChain(t)
	if _, err := NewIntegrityStore(inner, chain, testIntegrityOptions(logPath)); err == nil {
		t.Fatal("NewIntegrityStore() error = nil, want tampered v2 log rejection")
	}
}

func TestIntegrityStore_AppendEvent_WritesSidecarAfterRawWrite(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	inner, err := jsonl.New(logPath, 100, 3)
	if err != nil {
		t.Fatalf("jsonl.New() error = %v", err)
	}
	t.Cleanup(func() { _ = inner.Close() })

	chain := mustNewIntegrityChain(t)
	store, err := NewIntegrityStore(inner, chain, testIntegrityOptions(logPath))
	if err != nil {
		t.Fatalf("NewIntegrityStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if err := store.AppendEvent(context.Background(), types.Event{
		ID:        "1",
		Type:      "event",
		Timestamp: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("AppendEvent() error = %v", err)
	}

	sidecar, err := audit.ReadSidecar(audit.SidecarPath(logPath))
	if err != nil {
		t.Fatalf("audit.ReadSidecar() error = %v", err)
	}
	if sidecar.Sequence != chain.State().Sequence {
		t.Fatalf("sidecar sequence = %d, want %d", sidecar.Sequence, chain.State().Sequence)
	}
}
