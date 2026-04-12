package cli

import (
	"bytes"
	"context"
	"fmt"
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

func writeAuditVerifyConfig(t *testing.T, path, logPath string) {
	t.Helper()

	content := fmt.Sprintf(`
audit:
  output: %s
  integrity:
    enabled: true
    key_source: env
    key_env: AGENTSH_AUDIT_TEST_KEY
`, logPath)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", path, err)
	}
}

func writeAuditVerifyConfigWithEnabled(t *testing.T, path, logPath string, enabled bool) {
	t.Helper()

	content := fmt.Sprintf(`
audit:
  output: %s
  integrity:
    enabled: %t
    key_source: env
    key_env: AGENTSH_AUDIT_TEST_KEY
`, logPath, enabled)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", path, err)
	}
}

func writeAuditVerifyConfigDisabledWithoutKey(t *testing.T, path, logPath string) {
	t.Helper()

	content := fmt.Sprintf(`
audit:
  output: %s
  integrity:
    enabled: false
`, logPath)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", path, err)
	}
}

func writeAuditVerifyKMSConfig(t *testing.T, path, logPath string) {
	t.Helper()

	content := fmt.Sprintf(`
audit:
  output: %s
  integrity:
    enabled: true
    key_source: aws_kms
`, logPath)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", path, err)
	}
}

func TestAuditVerifyCmd_StrictRejectsUnsignedLines(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")

	if err := os.WriteFile(logPath, []byte(`{"type":"unsigned"}`+"\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath, err)
	}
	writeAuditVerifyConfig(t, cfgPath, logPath)
	t.Setenv("AGENTSH_AUDIT_TEST_KEY", string(testAuditKey))

	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{"--config", cfgPath, logPath})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want strict unsigned-line failure")
	}
}

func TestAuditVerifyCmd_WalksRotationSetOldestFirst(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	t.Setenv("AGENTSH_AUDIT_TEST_KEY", string(testAuditKey))

	chain, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("audit.NewIntegrityChain() error = %v", err)
	}

	lines := make([][]byte, 0, 3)
	for _, payload := range []string{`{"type":"a"}`, `{"type":"b"}`, `{"type":"c"}`} {
		line, err := chain.Wrap([]byte(payload))
		if err != nil {
			t.Fatalf("chain.Wrap() error = %v", err)
		}
		lines = append(lines, line)
	}

	if err := os.WriteFile(base+".1", append(lines[0], '\n'), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", base+".1", err)
	}
	current := append([]byte{}, lines[1]...)
	current = append(current, '\n')
	current = append(current, lines[2]...)
	current = append(current, '\n')
	if err := os.WriteFile(base, current, 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", base, err)
	}
	writeAuditVerifyConfig(t, cfgPath, base)

	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{"--config", cfgPath, base})

	var out bytes.Buffer
	cmd.SetOut(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := out.String(); !strings.Contains(got, "verified 3 entries across 2 files") {
		t.Fatalf("output = %q, want rotation-set summary", got)
	}
}

func TestAuditVerifyCmd_DoesNotSkipExplicitLogWhenConfigDisabled(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	t.Setenv("AGENTSH_AUDIT_TEST_KEY", string(testAuditKey))

	chain, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("audit.NewIntegrityChain() error = %v", err)
	}
	line, err := chain.Wrap([]byte(`{"type":"signed"}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}
	if err := os.WriteFile(logPath, append(line, '\n'), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath, err)
	}
	writeAuditVerifyConfigWithEnabled(t, cfgPath, logPath, false)

	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{"--config", cfgPath, logPath})

	var out bytes.Buffer
	cmd.SetOut(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := out.String(); !strings.Contains(got, "verified 1 entries across 1 files") {
		t.Fatalf("output = %q, want signed verification summary", got)
	}
}

func TestAuditVerifyCmd_DoesNotRequireKeyForUnsignedLogWhenConfigDisabled(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")

	if err := os.WriteFile(logPath, []byte(`{"type":"unsigned"}`+"\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath, err)
	}
	writeAuditVerifyConfigDisabledWithoutKey(t, cfgPath, logPath)

	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{"--config", cfgPath, logPath})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := out.String(); !strings.Contains(got, "integrity not enabled in this log; nothing to verify") {
		t.Fatalf("output = %q, want unsigned disabled-config no-op message", got)
	}
}

func TestAuditVerifyCmd_DoesNotRequireKeyForUnsignedTruncatedLogWhenConfigDisabled(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")

	if err := os.WriteFile(logPath, []byte(`{"type":"unsigned"`), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath, err)
	}
	writeAuditVerifyConfigDisabledWithoutKey(t, cfgPath, logPath)

	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{"--config", cfgPath, "--tolerate-truncation", logPath})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := out.String(); !strings.Contains(got, "integrity not enabled in this log; nothing to verify") {
		t.Fatalf("output = %q, want unsigned disabled-config no-op message", got)
	}
}

func TestAuditVerifyCmd_UsesConfiguredKeyProvider(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")

	chain, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("audit.NewIntegrityChain() error = %v", err)
	}
	line, err := chain.Wrap([]byte(`{"type":"signed"}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}
	if err := os.WriteFile(logPath, append(line, '\n'), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath, err)
	}
	writeAuditVerifyKMSConfig(t, cfgPath, logPath)

	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{"--config", cfgPath, logPath})

	err = cmd.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want KMS provider configuration failure")
	}
	if !strings.Contains(err.Error(), "create KMS provider") {
		t.Fatalf("Execute() error = %v, want KMS provider error", err)
	}
}

func TestAuditVerifyCmd_VerifiesRealRotatedIntegrityStore(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	t.Setenv("AGENTSH_AUDIT_TEST_KEY", string(testAuditKey))

	inner, err := jsonl.New(logPath, 1, 3)
	if err != nil {
		t.Fatalf("jsonl.New() error = %v", err)
	}

	chain, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("audit.NewIntegrityChain() error = %v", err)
	}
	store, err := auditstore.NewIntegrityStore(inner, chain, auditstore.IntegrityOptions{
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

	if err := store.AppendEvent(context.Background(), types.Event{
		ID:     "big",
		Type:   "big_event",
		Fields: map[string]any{"blob": strings.Repeat("x", 2<<20)},
	}); err != nil {
		t.Fatalf("AppendEvent(big) error = %v", err)
	}
	if err := store.AppendEvent(context.Background(), types.Event{
		ID:   "after",
		Type: "after_rotate",
	}); err != nil {
		t.Fatalf("AppendEvent(after) error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("store.Close() error = %v", err)
	}

	if _, err := os.Stat(logPath + ".1"); err != nil {
		t.Fatalf("os.Stat(%q) error = %v", logPath+".1", err)
	}
	writeAuditVerifyConfig(t, cfgPath, logPath)

	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{"--config", cfgPath, logPath})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := out.String(); !strings.Contains(got, "verified 3 entries across 2 files") {
		t.Fatalf("output = %q, want rotated verification summary", got)
	}
}

func TestAuditVerifyCmd_AllowsBackupOnlyRetainedWindow(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	t.Setenv("AGENTSH_AUDIT_TEST_KEY", string(testAuditKey))

	chain, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("audit.NewIntegrityChain() error = %v", err)
	}

	lines := make([][]byte, 0, 4)
	for _, payload := range []string{`{"type":"a"}`, `{"type":"b"}`, `{"type":"c"}`, `{"type":"d"}`} {
		line, err := chain.Wrap([]byte(payload))
		if err != nil {
			t.Fatalf("chain.Wrap() error = %v", err)
		}
		lines = append(lines, line)
	}

	if err := os.WriteFile(base+".2", joinAuditVerifyLines(lines[0], lines[1]), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", base+".2", err)
	}
	if err := os.WriteFile(base+".1", joinAuditVerifyLines(lines[2], lines[3]), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", base+".1", err)
	}
	writeAuditVerifyConfig(t, cfgPath, base)

	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{"--config", cfgPath, base})

	var out bytes.Buffer
	cmd.SetOut(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := out.String(); !strings.Contains(got, "verified 4 entries across 2 files") {
		t.Fatalf("output = %q, want backup-only rotation-set summary", got)
	}
}

func TestAuditVerifyCmd_AllowsBackupOnlyHighSuffixWindow(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	t.Setenv("AGENTSH_AUDIT_TEST_KEY", string(testAuditKey))

	chain, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("audit.NewIntegrityChain() error = %v", err)
	}

	lines := make([][]byte, 0, 4)
	for _, payload := range []string{`{"type":"a"}`, `{"type":"b"}`, `{"type":"c"}`, `{"type":"d"}`} {
		line, err := chain.Wrap([]byte(payload))
		if err != nil {
			t.Fatalf("chain.Wrap() error = %v", err)
		}
		lines = append(lines, line)
	}

	if err := os.WriteFile(base+".8", joinAuditVerifyLines(lines[0], lines[1]), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", base+".8", err)
	}
	if err := os.WriteFile(base+".7", joinAuditVerifyLines(lines[2], lines[3]), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", base+".7", err)
	}
	writeAuditVerifyConfig(t, cfgPath, base)

	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{"--config", cfgPath, base})

	var out bytes.Buffer
	cmd.SetOut(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := out.String(); !strings.Contains(got, "verified 4 entries across 2 files") {
		t.Fatalf("output = %q, want high-suffix backup-only rotation-set summary", got)
	}
}

func TestDiscoverRotationSetForVerify_IgnoresNonPositiveSuffixes(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "audit.jsonl")

	if err := os.WriteFile(base, []byte("base\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", base, err)
	}
	if err := os.WriteFile(base+".0", []byte("zero\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", base+".0", err)
	}
	if err := os.WriteFile(base+".-1", []byte("negative\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", base+".-1", err)
	}

	files, err := discoverRotationSetForVerify(base)
	if err != nil {
		t.Fatalf("discoverRotationSetForVerify() error = %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("discoverRotationSetForVerify() returned %d files, want 1", len(files))
	}
	if files[0].Path != base {
		t.Fatalf("discoverRotationSetForVerify() returned base path %q, want %q", files[0].Path, base)
	}
	if files[0].IsBackup {
		t.Fatal("discoverRotationSetForVerify() marked base log as backup")
	}
}

func TestAuditVerifyCmd_RejectsLegacyFormatEntry(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	t.Setenv("AGENTSH_AUDIT_TEST_KEY", string(testAuditKey))

	legacy := `{"type":"legacy","integrity":{"format_version":1,"sequence":0,"prev_hash":"","entry_hash":"deadbeef"}}`
	if err := os.WriteFile(logPath, []byte(legacy+"\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath, err)
	}
	writeAuditVerifyConfig(t, cfgPath, logPath)

	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{"--config", cfgPath, logPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want legacy-format failure")
	}
}

func TestAuditVerifyCmd_RejectsMidHistoryRotationWithoutMatchingPriorSummary(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	t.Setenv("AGENTSH_AUDIT_TEST_KEY", string(testAuditKey))
	writeAuditVerifyConfig(t, cfgPath, logPath)

	chainA, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("audit.NewIntegrityChain() error = %v", err)
	}
	first, err := chainA.Wrap([]byte(`{"type":"before_reset"}`))
	if err != nil {
		t.Fatalf("chainA.Wrap() error = %v", err)
	}

	chainB, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("audit.NewIntegrityChain() error = %v", err)
	}
	reset, err := chainB.Wrap([]byte(`{"type":"integrity_chain_rotated","fields":{"reason":"manual reset","reason_code":"manual_reset","new_chain":{"format_version":2,"sequence":0}}}`))
	if err != nil {
		t.Fatalf("chainB.Wrap() error = %v", err)
	}
	after, err := chainB.Wrap([]byte(`{"type":"after_reset"}`))
	if err != nil {
		t.Fatalf("chainB.Wrap() error = %v", err)
	}

	data := append([]byte{}, first...)
	data = append(data, '\n')
	data = append(data, reset...)
	data = append(data, '\n')
	data = append(data, after...)
	data = append(data, '\n')
	if err := os.WriteFile(logPath, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath, err)
	}

	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{"--config", cfgPath, logPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want mid-history reset rejection")
	}
}

func TestAuditVerifyCmd_AcceptsMidHistoryRotationWithMatchingPriorSummary(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	t.Setenv("AGENTSH_AUDIT_TEST_KEY", string(testAuditKey))
	writeAuditVerifyConfig(t, cfgPath, logPath)

	chainA, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("audit.NewIntegrityChain() error = %v", err)
	}
	first, err := chainA.Wrap([]byte(`{"type":"before_reset"}`))
	if err != nil {
		t.Fatalf("chainA.Wrap() error = %v", err)
	}

	previousState := chainA.State()
	resetPayload := fmt.Sprintf(`{"type":"integrity_chain_rotated","fields":{"reason":"manual reset","reason_code":"manual_reset","prior_chain_summary":{"last_sequence_seen_in_log":%d,"last_entry_hash_seen_in_log":"%s"},"new_chain":{"format_version":2,"sequence":0}}}`, previousState.Sequence, previousState.PrevHash)
	chainB, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("audit.NewIntegrityChain() error = %v", err)
	}
	reset, err := chainB.Wrap([]byte(resetPayload))
	if err != nil {
		t.Fatalf("chainB.Wrap() error = %v", err)
	}
	after, err := chainB.Wrap([]byte(`{"type":"after_reset"}`))
	if err != nil {
		t.Fatalf("chainB.Wrap() error = %v", err)
	}

	data := append([]byte{}, first...)
	data = append(data, '\n')
	data = append(data, reset...)
	data = append(data, '\n')
	data = append(data, after...)
	data = append(data, '\n')
	if err := os.WriteFile(logPath, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath, err)
	}

	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{"--config", cfgPath, logPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestAuditVerifyCmd_AcceptsRotationAsFirstVisibleEntry(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	t.Setenv("AGENTSH_AUDIT_TEST_KEY", string(testAuditKey))
	writeAuditVerifyConfig(t, cfgPath, logPath)

	chain, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("audit.NewIntegrityChain() error = %v", err)
	}
	reset, err := chain.Wrap([]byte(`{"type":"integrity_chain_rotated","fields":{"reason":"fresh start","reason_code":"manual_reset","new_chain":{"format_version":2,"sequence":0}}}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}
	after, err := chain.Wrap([]byte(`{"type":"after_reset"}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}

	data := append([]byte{}, reset...)
	data = append(data, '\n')
	data = append(data, after...)
	data = append(data, '\n')
	if err := os.WriteFile(logPath, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath, err)
	}

	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{"--config", cfgPath, logPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestAuditVerifyCmd_RejectsBaseVisibleRotationBoundaryWithPriorHistory(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	t.Setenv("AGENTSH_AUDIT_TEST_KEY", string(testAuditKey))
	writeAuditVerifyConfig(t, cfgPath, logPath)

	previousChain, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("audit.NewIntegrityChain() error = %v", err)
	}
	first, err := previousChain.Wrap([]byte(`{"type":"before_reset"}`))
	if err != nil {
		t.Fatalf("previousChain.Wrap() error = %v", err)
	}

	previousState := previousChain.State()
	resetPayload := fmt.Sprintf(`{"type":"integrity_chain_rotated","fields":{"reason":"manual reset","reason_code":"manual_reset","prior_chain_summary":{"last_sequence_seen_in_log":%d,"last_entry_hash_seen_in_log":"%s"},"new_chain":{"format_version":2,"sequence":0}}}`, previousState.Sequence, previousState.PrevHash)
	currentChain, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("audit.NewIntegrityChain() error = %v", err)
	}
	reset, err := currentChain.Wrap([]byte(resetPayload))
	if err != nil {
		t.Fatalf("currentChain.Wrap() reset error = %v", err)
	}
	after, err := currentChain.Wrap([]byte(`{"type":"after_reset"}`))
	if err != nil {
		t.Fatalf("currentChain.Wrap() after error = %v", err)
	}

	_ = first
	if err := os.WriteFile(logPath, joinAuditVerifyLines(reset, after), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath, err)
	}

	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{"--config", cfgPath, logPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want missing prior history rejection")
	}
}

func TestAuditVerifyCmd_TolerateTruncationDoesNotHideMalformedEarlierLine(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	t.Setenv("AGENTSH_AUDIT_TEST_KEY", string(testAuditKey))
	writeAuditVerifyConfig(t, cfgPath, logPath)

	chain, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("audit.NewIntegrityChain() error = %v", err)
	}
	first, err := chain.Wrap([]byte(`{"type":"before_bad_line"}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}
	second, err := chain.Wrap([]byte(`{"type":"after_bad_line"}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}

	data := append([]byte{}, first...)
	data = append(data, '\n')
	data = append(data, []byte(`{"type":"broken"`)...)
	data = append(data, '\n')
	data = append(data, second...)
	data = append(data, '\n')
	if err := os.WriteFile(logPath, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath, err)
	}

	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{"--config", cfgPath, "--tolerate-truncation", logPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want malformed non-final line failure")
	}
}

func TestAuditVerifyCmd_TolerateTruncationAcceptsIncompleteFinalLine(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	t.Setenv("AGENTSH_AUDIT_TEST_KEY", string(testAuditKey))
	writeAuditVerifyConfig(t, cfgPath, logPath)

	chain, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("audit.NewIntegrityChain() error = %v", err)
	}
	first, err := chain.Wrap([]byte(`{"type":"before_truncated_tail"}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}

	data := append([]byte{}, first...)
	data = append(data, '\n')
	data = append(data, []byte(`{"type":"truncated_tail"`)...)
	if err := os.WriteFile(logPath, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath, err)
	}

	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{"--config", cfgPath, "--tolerate-truncation", logPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestAuditVerifyCmd_TolerateTruncationRejectsMalformedFinalLineWithoutNewline(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	t.Setenv("AGENTSH_AUDIT_TEST_KEY", string(testAuditKey))
	writeAuditVerifyConfig(t, cfgPath, logPath)

	chain, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("audit.NewIntegrityChain() error = %v", err)
	}
	first, err := chain.Wrap([]byte(`{"type":"before_bad_tail"}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}

	data := append([]byte{}, first...)
	data = append(data, '\n')
	data = append(data, []byte(`{"type":"bad",}`)...)
	if err := os.WriteFile(logPath, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath, err)
	}

	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{"--config", cfgPath, "--tolerate-truncation", logPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want malformed EOF tail failure")
	}
}

func TestAuditVerifyCmd_TolerateTruncationRejectsMalformedFinalLineWithTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "config.yaml")
	t.Setenv("AGENTSH_AUDIT_TEST_KEY", string(testAuditKey))
	writeAuditVerifyConfig(t, cfgPath, logPath)

	chain, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("audit.NewIntegrityChain() error = %v", err)
	}
	first, err := chain.Wrap([]byte(`{"type":"before_bad_tail"}`))
	if err != nil {
		t.Fatalf("chain.Wrap() error = %v", err)
	}

	data := append([]byte{}, first...)
	data = append(data, '\n')
	data = append(data, []byte(`{"type":"bad_tail"`)...)
	data = append(data, '\n')
	if err := os.WriteFile(logPath, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", logPath, err)
	}

	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{"--config", cfgPath, "--tolerate-truncation", logPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want malformed newline-terminated tail failure")
	}
}

func joinAuditVerifyLines(lines ...[]byte) []byte {
	var out []byte
	for _, line := range lines {
		out = append(out, line...)
		out = append(out, '\n')
	}
	return out
}
