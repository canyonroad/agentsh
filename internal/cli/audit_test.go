package cli

import (
	"bytes"
	"testing"
)

// testAuditKey is a valid 32-byte key for tests.
var testAuditKey = []byte("test-secret-key-32-bytes-long!!!")

func TestAuditCmd_HasSubcommands(t *testing.T) {
	cmd := newAuditCmd()

	if cmd.Use != "audit" {
		t.Fatalf("Use = %q, want %q", cmd.Use, "audit")
	}

	verifyCmd, _, err := cmd.Find([]string{"verify"})
	if err != nil {
		t.Fatalf("Find(verify) error = %v", err)
	}
	if verifyCmd == nil || verifyCmd.Use != "verify <log-file>" {
		t.Fatalf("verify subcommand not found or wrong Use")
	}

	chainCmd, _, err := cmd.Find([]string{"chain"})
	if err != nil {
		t.Fatalf("Find(chain) error = %v", err)
	}
	if chainCmd == nil || chainCmd.Use != "chain" {
		t.Fatalf("chain subcommand not found or wrong Use")
	}
}

func TestAuditVerifyCmd_Help(t *testing.T) {
	cmd := newAuditVerifyCmd()
	cmd.SetArgs([]string{"--help"})

	var out bytes.Buffer
	cmd.SetOut(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	output := out.String()
	for _, needle := range []string{"--config", "--tolerate-unsigned", "--tolerate-truncation", "--from-sequence"} {
		if !bytes.Contains([]byte(output), []byte(needle)) {
			t.Fatalf("help output missing %q", needle)
		}
	}
}
