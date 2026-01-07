package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/audit"
)

// testKey is a valid 32-byte key for tests.
var testAuditKey = []byte("test-secret-key-32-bytes-long!!!")

func TestAuditCmd_HasSubcommands(t *testing.T) {
	cmd := newAuditCmd()

	if cmd.Use != "audit" {
		t.Errorf("Use = %q, want %q", cmd.Use, "audit")
	}

	// Should have the verify subcommand
	verifyCmd, _, err := cmd.Find([]string{"verify"})
	if err != nil {
		t.Errorf("Find(verify) error = %v", err)
	}
	if verifyCmd == nil || verifyCmd.Use != "verify <log-file>" {
		t.Errorf("verify subcommand not found or has wrong Use")
	}
}

func TestAuditVerifyCmd_Help(t *testing.T) {
	cmd := newAuditVerifyCmd()

	// Test help runs without error
	cmd.SetArgs([]string{"--help"})
	var out bytes.Buffer
	cmd.SetOut(&out)

	err := cmd.Execute()
	if err != nil {
		t.Errorf("help command should not error: %v", err)
	}

	output := out.String()
	if !bytes.Contains([]byte(output), []byte("--key-file")) {
		t.Error("help should mention --key-file flag")
	}
	if !bytes.Contains([]byte(output), []byte("--key-env")) {
		t.Error("help should mention --key-env flag")
	}
	if !bytes.Contains([]byte(output), []byte("--algorithm")) {
		t.Error("help should mention --algorithm flag")
	}
}

func TestAuditVerifyCmd_RequiresKeyFlag(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.jsonl")
	if err := os.WriteFile(logFile, []byte("{}"), 0600); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{logFile})
	var errOut bytes.Buffer
	cmd.SetErr(&errOut)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when neither --key-file nor --key-env is provided")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("--key-file or --key-env is required")) {
		t.Errorf("error = %q, want to contain key requirement message", err.Error())
	}
}

func TestAuditVerifyCmd_RequiresLogFile(t *testing.T) {
	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when log file argument is missing")
	}
}

func TestAuditVerifyCmd_ValidChain(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.jsonl")
	keyFile := filepath.Join(tmpDir, "hmac.key")

	// Write the key file
	if err := os.WriteFile(keyFile, testAuditKey, 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	// Create a valid integrity chain using the audit package
	chain, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain: %v", err)
	}

	// Create entries
	entries := []string{
		`{"event":"session_start","session_id":"test-123"}`,
		`{"event":"command_executed","command":"ls -la"}`,
		`{"event":"file_read","path":"/etc/passwd"}`,
	}

	var logContent bytes.Buffer
	for _, entry := range entries {
		wrapped, err := chain.Wrap([]byte(entry))
		if err != nil {
			t.Fatalf("Wrap: %v", err)
		}
		logContent.Write(wrapped)
		logContent.WriteByte('\n')
	}

	if err := os.WriteFile(logFile, logContent.Bytes(), 0600); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	// Verify the chain
	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{logFile, "--key-file", keyFile})
	var out bytes.Buffer
	cmd.SetOut(&out)

	err = cmd.Execute()
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	output := out.String()
	if !bytes.Contains([]byte(output), []byte("Verified 3 entries")) {
		t.Errorf("output = %q, want to contain 'Verified 3 entries'", output)
	}
	if !bytes.Contains([]byte(output), []byte("Chain intact: OK")) {
		t.Errorf("output = %q, want to contain 'Chain intact: OK'", output)
	}
}

func TestAuditVerifyCmd_KeyFromEnv(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.jsonl")

	envVar := "AGENTSH_TEST_AUDIT_VERIFY_KEY"
	t.Setenv(envVar, string(testAuditKey))

	// Create a valid integrity chain
	chain, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain: %v", err)
	}

	wrapped, err := chain.Wrap([]byte(`{"event":"test"}`))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	if err := os.WriteFile(logFile, append(wrapped, '\n'), 0600); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	// Verify using env var
	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{logFile, "--key-env", envVar})
	var out bytes.Buffer
	cmd.SetOut(&out)

	err = cmd.Execute()
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	output := out.String()
	if !bytes.Contains([]byte(output), []byte("Chain intact: OK")) {
		t.Errorf("output = %q, want to contain 'Chain intact: OK'", output)
	}
}

func TestAuditVerifyCmd_TamperedEntry(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.jsonl")
	keyFile := filepath.Join(tmpDir, "hmac.key")

	// Write the key file
	if err := os.WriteFile(keyFile, testAuditKey, 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	// Create a valid integrity chain
	chain, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain: %v", err)
	}

	// Create first entry
	wrapped1, err := chain.Wrap([]byte(`{"event":"first"}`))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// Create second entry
	wrapped2, err := chain.Wrap([]byte(`{"event":"second"}`))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// Tamper with the second entry by changing the event field
	var entry2 map[string]any
	if err := json.Unmarshal(wrapped2, &entry2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	entry2["event"] = "tampered"
	tampered2, err := json.Marshal(entry2)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Write log with tampered entry
	var logContent bytes.Buffer
	logContent.Write(wrapped1)
	logContent.WriteByte('\n')
	logContent.Write(tampered2)
	logContent.WriteByte('\n')

	if err := os.WriteFile(logFile, logContent.Bytes(), 0600); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	// Verify should fail
	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{logFile, "--key-file", keyFile})
	var out bytes.Buffer
	cmd.SetOut(&out)

	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected error for tampered entry")
	}

	output := out.String()
	if !bytes.Contains([]byte(output), []byte("Chain BROKEN")) {
		t.Errorf("output = %q, want to contain 'Chain BROKEN'", output)
	}
	if !bytes.Contains([]byte(output), []byte("entry_hash mismatch")) {
		t.Errorf("output = %q, want to contain 'entry_hash mismatch'", output)
	}
}

func TestAuditVerifyCmd_BrokenChain(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.jsonl")
	keyFile := filepath.Join(tmpDir, "hmac.key")

	// Write the key file
	if err := os.WriteFile(keyFile, testAuditKey, 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	// Create two separate chains (breaks the chain link)
	chain1, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain: %v", err)
	}
	chain2, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain: %v", err)
	}

	// Create entries from different chains
	wrapped1, err := chain1.Wrap([]byte(`{"event":"first"}`))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	wrapped2, err := chain2.Wrap([]byte(`{"event":"from_different_chain"}`))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// Write log with broken chain
	var logContent bytes.Buffer
	logContent.Write(wrapped1)
	logContent.WriteByte('\n')
	logContent.Write(wrapped2)
	logContent.WriteByte('\n')

	if err := os.WriteFile(logFile, logContent.Bytes(), 0600); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	// Verify should fail
	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{logFile, "--key-file", keyFile})
	var out bytes.Buffer
	cmd.SetOut(&out)

	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected error for broken chain")
	}

	output := out.String()
	if !bytes.Contains([]byte(output), []byte("Chain BROKEN")) {
		t.Errorf("output = %q, want to contain 'Chain BROKEN'", output)
	}
	if !bytes.Contains([]byte(output), []byte("prev_hash mismatch")) {
		t.Errorf("output = %q, want to contain 'prev_hash mismatch'", output)
	}
}

func TestAuditVerifyCmd_SkipsEntriesWithoutIntegrity(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.jsonl")
	keyFile := filepath.Join(tmpDir, "hmac.key")

	// Write the key file
	if err := os.WriteFile(keyFile, testAuditKey, 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	// Create a valid integrity chain
	chain, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain: %v", err)
	}

	// Create entries - mix of with and without integrity
	wrapped1, err := chain.Wrap([]byte(`{"event":"first"}`))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	wrapped2, err := chain.Wrap([]byte(`{"event":"second"}`))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// Write log with some entries without integrity
	var logContent bytes.Buffer
	logContent.Write(wrapped1)
	logContent.WriteByte('\n')
	logContent.WriteString(`{"event":"no_integrity","data":"plain"}` + "\n")
	logContent.Write(wrapped2)
	logContent.WriteByte('\n')
	logContent.WriteString(`{"another":"plain_entry"}` + "\n")

	if err := os.WriteFile(logFile, logContent.Bytes(), 0600); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	// Verify should succeed and report skipped entries
	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{logFile, "--key-file", keyFile})
	var out bytes.Buffer
	cmd.SetOut(&out)

	err = cmd.Execute()
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	output := out.String()
	if !bytes.Contains([]byte(output), []byte("Verified 2 entries")) {
		t.Errorf("output = %q, want to contain 'Verified 2 entries'", output)
	}
	if !bytes.Contains([]byte(output), []byte("2 skipped without integrity")) {
		t.Errorf("output = %q, want to contain '2 skipped without integrity'", output)
	}
	if !bytes.Contains([]byte(output), []byte("Chain intact: OK")) {
		t.Errorf("output = %q, want to contain 'Chain intact: OK'", output)
	}
}

func TestAuditVerifyCmd_NonexistentLogFile(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "hmac.key")

	// Write the key file
	if err := os.WriteFile(keyFile, testAuditKey, 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{"/nonexistent/path/audit.jsonl", "--key-file", keyFile})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for nonexistent log file")
	}
}

func TestAuditVerifyCmd_InvalidKeyFile(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.jsonl")

	if err := os.WriteFile(logFile, []byte("{}"), 0600); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{logFile, "--key-file", "/nonexistent/key.file"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for nonexistent key file")
	}
}

func TestAuditVerifyCmd_EmptyLogFile(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.jsonl")
	keyFile := filepath.Join(tmpDir, "hmac.key")

	// Write the key file
	if err := os.WriteFile(keyFile, testAuditKey, 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	// Create empty log file
	if err := os.WriteFile(logFile, []byte(""), 0600); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{logFile, "--key-file", keyFile})
	var out bytes.Buffer
	cmd.SetOut(&out)

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	output := out.String()
	if !bytes.Contains([]byte(output), []byte("Verified 0 entries")) {
		t.Errorf("output = %q, want to contain 'Verified 0 entries'", output)
	}
	if !bytes.Contains([]byte(output), []byte("Chain intact: OK")) {
		t.Errorf("output = %q, want to contain 'Chain intact: OK'", output)
	}
}

func TestAuditVerifyCmd_WrongKey(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.jsonl")
	keyFile := filepath.Join(tmpDir, "hmac.key")
	wrongKeyFile := filepath.Join(tmpDir, "wrong.key")

	// Create entries with one key
	chain, err := audit.NewIntegrityChain(testAuditKey)
	if err != nil {
		t.Fatalf("NewIntegrityChain: %v", err)
	}

	wrapped, err := chain.Wrap([]byte(`{"event":"test"}`))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	if err := os.WriteFile(logFile, append(wrapped, '\n'), 0600); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	// Write a different key for verification
	wrongKey := []byte("wrong-secret-key-32-bytes-long!!")
	if err := os.WriteFile(wrongKeyFile, wrongKey, 0600); err != nil {
		t.Fatalf("write wrong key file: %v", err)
	}

	// Verification should fail due to wrong key
	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{logFile, "--key-file", wrongKeyFile})
	var out bytes.Buffer
	cmd.SetOut(&out)

	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected error when using wrong key")
	}

	output := out.String()
	if !bytes.Contains([]byte(output), []byte("Chain BROKEN")) {
		t.Errorf("output = %q, want to contain 'Chain BROKEN'", output)
	}

	// Write correct key
	if err := os.WriteFile(keyFile, testAuditKey, 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
}
