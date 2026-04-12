package cli

import (
	"bytes"
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

func TestAuditChainStatusCmd_ReadsSidecar(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	writeAuditVerifyConfig(t, cfgPath, logPath)

	if err := audit.WriteSidecar(audit.SidecarPath(logPath), audit.SidecarState{
		Sequence:       9,
		PrevHash:       "feedbeef",
		KeyFingerprint: "sha256:00112233445566778899aabbccddeeff",
		UpdatedAt:      time.Date(2026, 4, 11, 12, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("audit.WriteSidecar() error = %v", err)
	}

	cmd := newAuditChainStatusCmd()
	cmd.SetArgs([]string{"--config", cfgPath})

	var out bytes.Buffer
	cmd.SetOut(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := out.String(); !strings.Contains(got, `"sequence": 9`) {
		t.Fatalf("output = %q, want sequence 9", got)
	}
}

func TestAuditChainResetCmd_RequiresReason(t *testing.T) {
	cmd := newAuditChainResetCmd()
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want reason-required error")
	}
}

func TestAuditChainResetCmd_LegacyArchiveRenamesLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	writeAuditVerifyConfig(t, cfgPath, logPath)
	t.Setenv("AGENTSH_AUDIT_TEST_KEY", string(testAuditKey))

	if err := os.WriteFile(logPath, []byte(`{"type":"legacy"}`+"\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath, err)
	}

	cmd := newAuditChainResetCmd()
	cmd.SetArgs([]string{"--config", cfgPath, "--reason", "upgrade", "--legacy-archive", "--force"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	matches, err := filepath.Glob(logPath + ".legacy.*")
	if err != nil {
		t.Fatalf("filepath.Glob() error = %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("legacy archive count = %d, want 1", len(matches))
	}
}

func TestAuditChainResetCmd_AppendsPriorChainSummary(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	writeAuditVerifyConfig(t, cfgPath, logPath)
	t.Setenv("AGENTSH_AUDIT_TEST_KEY", string(testAuditKey))

	chain, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("audit.NewIntegrityChain() error = %v", err)
	}
	first, err := chain.Wrap([]byte(`{"type":"before_reset"}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}
	if err := os.WriteFile(logPath, append(first, '\n'), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath, err)
	}

	cmd := newAuditChainResetCmd()
	cmd.SetArgs([]string{"--config", cfgPath, "--reason", "rotate key", "--force"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) error = %v", logPath, err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("line count = %d, want 2", len(lines))
	}

	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &entry); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	fields := entry["fields"].(map[string]any)
	prior, ok := fields["prior_chain_summary"].(map[string]any)
	if !ok {
		t.Fatalf("prior_chain_summary missing from reset event: %v", fields)
	}
	if got := int64(prior["last_sequence_seen_in_log"].(float64)); got != 0 {
		t.Fatalf("last_sequence = %d, want 0", got)
	}
	if got := prior["last_entry_hash_seen_in_log"].(string); got == "" {
		t.Fatal("last_entry_hash = empty, want previous entry hash")
	}
}

func TestAuditChainResetCmd_FailsWhenAuditWriterLockHeld(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	writeAuditVerifyConfig(t, cfgPath, logPath)
	t.Setenv("AGENTSH_AUDIT_TEST_KEY", string(testAuditKey))

	store, err := jsonl.New(logPath, 100, 3)
	if err != nil {
		t.Fatalf("jsonl.New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.AppendEvent(context.Background(), types.Event{ID: "1", Type: "live"}); err != nil {
		t.Fatalf("store.AppendEvent() error = %v", err)
	}

	cmd := newAuditChainResetCmd()
	cmd.SetArgs([]string{"--config", cfgPath, "--reason", "manual", "--force"})
	err = cmd.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want running-server lock failure")
	}
	if !strings.Contains(err.Error(), "stop it before resetting the chain") {
		t.Fatalf("Execute() error = %v, want stop-server message", err)
	}
}

func TestAuditChainResetCmd_SucceedsAfterAuditWriterCloses(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	writeAuditVerifyConfig(t, cfgPath, logPath)
	t.Setenv("AGENTSH_AUDIT_TEST_KEY", string(testAuditKey))

	store, err := jsonl.New(logPath, 100, 3)
	if err != nil {
		t.Fatalf("jsonl.New() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("store.Close() error = %v", err)
	}

	cmd := newAuditChainResetCmd()
	cmd.SetArgs([]string{"--config", cfgPath, "--reason", "manual", "--force"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
}
