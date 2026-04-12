package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/audit"
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
