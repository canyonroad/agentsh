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

func TestNewIntegrityStore_RejectsVisibleMidChainWithMatchingSidecar(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")

	chain := mustNewIntegrityChain(t)
	first, err := chain.Wrap([]byte(`{"type":"first"}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}
	second, err := chain.Wrap([]byte(`{"type":"second"}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}
	third, err := chain.Wrap([]byte(`{"type":"third"}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}

	_ = first
	data := append([]byte{}, second...)
	data = append(data, '\n')
	data = append(data, third...)
	data = append(data, '\n')
	if err := os.WriteFile(logPath, data, 0o600); err != nil {
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
		t.Fatal("NewIntegrityStore() error = nil, want visible mid-chain rejection")
	}
}

func TestNewIntegrityStore_AcceptsRetainedBackupStartingMidChain(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")

	chain := mustNewIntegrityChain(t)
	first, err := chain.Wrap([]byte(`{"type":"first"}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}
	second, err := chain.Wrap([]byte(`{"type":"second"}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}
	third, err := chain.Wrap([]byte(`{"type":"third"}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}
	fourth, err := chain.Wrap([]byte(`{"type":"fourth"}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}

	_ = first
	if err := os.WriteFile(logPath+".1", joinLines(second, third), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath+".1", err)
	}
	if err := os.WriteFile(logPath, joinLines(fourth), 0o600); err != nil {
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

	resumeChain := mustNewIntegrityChain(t)
	store, err := NewIntegrityStore(inner, resumeChain, testIntegrityOptions(logPath))
	if err != nil {
		t.Fatalf("NewIntegrityStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if got := resumeChain.State(); got != state {
		t.Fatalf("chain.State() = %+v, want %+v", got, state)
	}
}

func TestNewIntegrityStore_RejectsTamperedOldestVisibleBackupWithMatchingSidecar(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")

	chain := mustNewIntegrityChain(t)
	first, err := chain.Wrap([]byte(`{"type":"first","fields":{"value":"ok"}}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}
	second, err := chain.Wrap([]byte(`{"type":"second"}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}
	third, err := chain.Wrap([]byte(`{"type":"third"}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}

	var entry map[string]any
	if err := json.Unmarshal(first, &entry); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	entry["fields"] = map[string]any{"value": "tampered"}
	tamperedFirst, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	if err := os.WriteFile(logPath+".1", joinLines(tamperedFirst, second), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath+".1", err)
	}
	if err := os.WriteFile(logPath, joinLines(third), 0o600); err != nil {
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
		t.Fatal("NewIntegrityStore() error = nil, want tampered oldest visible backup rejection")
	}
}

func joinLines(lines ...[]byte) []byte {
	var out []byte
	for _, line := range lines {
		out = append(out, line...)
		out = append(out, '\n')
	}
	return out
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

func TestNewIntegrityStore_RejectsCorruptSidecar(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")

	previousChain := mustNewIntegrityChain(t)
	line, err := previousChain.Wrap([]byte(`{"type":"existing","timestamp":"2026-04-11T12:00:00Z"}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}
	if err := os.WriteFile(logPath, append(line, '\n'), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath, err)
	}
	if err := os.WriteFile(audit.SidecarPath(logPath), []byte(`{"format_version":2,"sequence":0,"prev_hash":`), 0o600); err != nil {
		t.Fatalf("os.WriteFile(sidecar) error = %v", err)
	}

	inner, err := jsonl.New(logPath, 100, 3)
	if err != nil {
		t.Fatalf("jsonl.New() error = %v", err)
	}
	t.Cleanup(func() { _ = inner.Close() })

	if _, err := NewIntegrityStore(inner, mustNewIntegrityChain(t), testIntegrityOptions(logPath)); err == nil {
		t.Fatal("NewIntegrityStore() error = nil, want corrupt sidecar rejection")
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
