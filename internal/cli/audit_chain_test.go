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
	auditstore "github.com/agentsh/agentsh/internal/store"
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

func TestAuditChainResetCmd_RejectsUnknownReasonCode(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	writeAuditVerifyConfig(t, cfgPath, logPath)
	t.Setenv("AGENTSH_AUDIT_TEST_KEY", string(testAuditKey))

	cmd := newAuditChainResetCmd()
	cmd.SetArgs([]string{"--config", cfgPath, "--reason", "manual", "--reason-code", "bogus", "--force"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want invalid reason-code rejection")
	}
	if !strings.Contains(err.Error(), "invalid --reason-code") {
		t.Fatalf("Execute() error = %v, want invalid reason-code message", err)
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

func TestAuditChainResetCmd_LegacyArchiveMovesEntireRotationSet(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	writeAuditVerifyConfig(t, cfgPath, logPath)
	t.Setenv("AGENTSH_AUDIT_TEST_KEY", string(testAuditKey))

	if err := os.WriteFile(logPath, []byte(`{"type":"current"}`+"\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath, err)
	}
	if err := os.WriteFile(logPath+".1", []byte(`{"type":"backup"}`+"\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath+".1", err)
	}

	cmd := newAuditChainResetCmd()
	cmd.SetArgs([]string{"--config", cfgPath, "--reason", "upgrade", "--legacy-archive", "--force"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if _, err := os.Stat(logPath + ".1"); !os.IsNotExist(err) {
		t.Fatalf("os.Stat(%q) err = %v, want not-exist after archive", logPath+".1", err)
	}
	matches, err := filepath.Glob(logPath + ".legacy.*")
	if err != nil {
		t.Fatalf("filepath.Glob() error = %v", err)
	}
	if len(matches) < 2 {
		t.Fatalf("legacy archive matches = %v, want archived base and backups", matches)
	}
}

func TestAuditChainResetCmd_LegacyArchiveResultVerifiesAndReopens(t *testing.T) {
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
	state := chain.State()
	if err := audit.WriteSidecar(audit.SidecarPath(logPath), audit.SidecarState{
		Sequence:       state.Sequence,
		PrevHash:       state.PrevHash,
		KeyFingerprint: audit.KeyFingerprint(testAuditKey),
		UpdatedAt:      time.Date(2026, 4, 11, 12, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("audit.WriteSidecar() error = %v", err)
	}

	resetCmd := newAuditChainResetCmd()
	resetCmd.SetArgs([]string{"--config", cfgPath, "--reason", "archive", "--legacy-archive", "--force"})
	if err := resetCmd.Execute(); err != nil {
		t.Fatalf("reset Execute() error = %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) error = %v", logPath, err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("line count = %d, want 1", len(lines))
	}

	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	fields := entry["fields"].(map[string]any)
	if got := fields["reason_code"]; got != "legacy_archived" {
		t.Fatalf("reason_code = %v, want legacy_archived", got)
	}
	archivedTo, ok := fields["prior_log_archived_to"].(string)
	if !ok || archivedTo == "" {
		t.Fatalf("prior_log_archived_to = %v, want archived path", fields["prior_log_archived_to"])
	}
	if !strings.Contains(archivedTo, logPath+".legacy.") {
		t.Fatalf("prior_log_archived_to = %q, want legacy archive path", archivedTo)
	}
	if _, err := os.Stat(archivedTo); err != nil {
		t.Fatalf("os.Stat(%q) error = %v", archivedTo, err)
	}

	verifyCmd := newAuditVerifyCmd()
	verifyCmd.SetArgs([]string{"--config", cfgPath, logPath})
	if err := verifyCmd.Execute(); err != nil {
		t.Fatalf("verify Execute() error = %v", err)
	}

	inner, err := jsonl.New(logPath, 100, 3)
	if err != nil {
		t.Fatalf("jsonl.New() error = %v", err)
	}
	t.Cleanup(func() { _ = inner.Close() })

	resumeChain, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("audit.NewIntegrityChain() error = %v", err)
	}
	store, err := auditstore.NewIntegrityStore(inner, resumeChain, auditstore.IntegrityOptions{
		LogPath:        logPath,
		Algorithm:      "hmac-sha256",
		KeyFingerprint: audit.KeyFingerprint(testAuditKey),
		Now: func() time.Time {
			return time.Date(2026, 4, 11, 12, 0, 0, 0, time.UTC)
		},
	})
	if err != nil {
		t.Fatalf("auditstore.NewIntegrityStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
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
	if got := fields["reason_code"]; got != "manual_reset" {
		t.Fatalf("reason_code = %v, want manual_reset", got)
	}
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

func TestAuditChainResetCmd_UsesConfiguredKeyProvider(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	writeAuditVerifyKMSConfig(t, cfgPath, logPath)

	cmd := newAuditChainResetCmd()
	cmd.SetArgs([]string{"--config", cfgPath, "--reason", "manual", "--force"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want KMS provider configuration failure")
	}
	if !strings.Contains(err.Error(), "create KMS provider") {
		t.Fatalf("Execute() error = %v, want KMS provider error", err)
	}
}

func TestAuditChainResetCmd_RequiresLegacyArchiveWhenPriorSummaryUnavailable(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	writeAuditVerifyConfig(t, cfgPath, logPath)
	t.Setenv("AGENTSH_AUDIT_TEST_KEY", string(testAuditKey))

	if err := os.WriteFile(logPath, []byte(`{"type":"current"}`+"\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath, err)
	}
	if err := os.WriteFile(logPath+".2", []byte(`{"type":"orphan-backup"}`+"\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath+".2", err)
	}

	cmd := newAuditChainResetCmd()
	cmd.SetArgs([]string{"--config", cfgPath, "--reason", "manual", "--force"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want legacy-archive requirement")
	}
	if !strings.Contains(err.Error(), "--legacy-archive") {
		t.Fatalf("Execute() error = %v, want legacy-archive guidance", err)
	}
}

func TestAuditChainResetCmd_RejectsIncompleteRotationSetEvenWhenCurrentSummaryReadable(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	writeAuditVerifyConfig(t, cfgPath, logPath)
	t.Setenv("AGENTSH_AUDIT_TEST_KEY", string(testAuditKey))

	chain, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("audit.NewIntegrityChain() error = %v", err)
	}
	current, err := chain.Wrap([]byte(`{"type":"current"}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}
	if err := os.WriteFile(logPath, append(current, '\n'), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath, err)
	}
	if err := os.WriteFile(logPath+".2", []byte(`{"type":"orphan-backup"}`+"\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath+".2", err)
	}

	cmd := newAuditChainResetCmd()
	cmd.SetArgs([]string{"--config", cfgPath, "--reason", "manual", "--force"})
	err = cmd.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want incomplete-rotation-set rejection")
	}
	if !strings.Contains(err.Error(), "--legacy-archive") {
		t.Fatalf("Execute() error = %v, want legacy-archive guidance", err)
	}
}

func TestAuditChainResetCmd_LegacyArchiveAllowsResetWhenPriorSummaryUnavailable(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	writeAuditVerifyConfig(t, cfgPath, logPath)
	t.Setenv("AGENTSH_AUDIT_TEST_KEY", string(testAuditKey))

	if err := os.WriteFile(logPath, []byte(`{"type":"current"}`+"\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath, err)
	}
	if err := os.WriteFile(logPath+".2", []byte(`{"type":"orphan-backup"}`+"\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath+".2", err)
	}

	cmd := newAuditChainResetCmd()
	cmd.SetArgs([]string{"--config", cfgPath, "--reason", "manual", "--legacy-archive", "--force"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestReadLastNonEmptyLineBestEffort_AllowsVeryLargeEntry(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "audit.jsonl")
	backup := base + ".1"

	if err := os.WriteFile(backup, []byte("older\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", backup, err)
	}
	line := bytes.Repeat([]byte("x"), 9*1024*1024)
	if err := os.WriteFile(base, append(line, '\n'), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", base, err)
	}

	files := []audit.LogFile{
		{Path: backup, Index: 1, IsBackup: true},
		{Path: base, Index: 0, IsBackup: false},
	}

	gotFile, gotLine, err := readLastNonEmptyLineBestEffort(files)
	if err != nil {
		t.Fatalf("readLastNonEmptyLineBestEffort() error = %v", err)
	}
	if gotFile.Path != base {
		t.Fatalf("readLastNonEmptyLineBestEffort() file = %+v, want base file", gotFile)
	}
	if len(gotLine) != len(line) {
		t.Fatalf("len(readLastNonEmptyLineBestEffort()) = %d, want %d", len(gotLine), len(line))
	}
}
