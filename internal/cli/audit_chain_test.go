package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
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
