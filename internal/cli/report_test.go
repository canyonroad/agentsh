package cli

import (
	"testing"
)

func TestReportCmdFlags(t *testing.T) {
	cmd := newReportCmd()

	// Check required flags exist
	levelFlag := cmd.Flag("level")
	if levelFlag == nil {
		t.Error("missing --level flag")
	}

	outputFlag := cmd.Flag("output")
	if outputFlag == nil {
		t.Error("missing --output flag")
	}
}

func TestReportCmdArgs(t *testing.T) {
	cmd := newReportCmd()

	// Test requires exactly 1 arg
	err := cmd.Args(cmd, []string{})
	if err == nil {
		t.Error("should require session ID argument")
	}

	err = cmd.Args(cmd, []string{"session-123"})
	if err != nil {
		t.Errorf("should accept 1 arg: %v", err)
	}
}
