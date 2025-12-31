// internal/cli/policy_generate_test.go
package cli

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestPolicyGenerateCmd_RequiresSessionArg(t *testing.T) {
	cmd := newPolicyCmd()
	cmd.SetArgs([]string{"generate"})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for missing session arg")
	}
}

func TestPolicyGenerateCmd_HasFlags(t *testing.T) {
	cmd := newPolicyCmd()

	// Find generate subcommand
	var generateCmd *cobra.Command
	for _, c := range cmd.Commands() {
		if c.Name() == "generate" {
			generateCmd = c
			break
		}
	}

	if generateCmd == nil {
		t.Fatal("generate subcommand not found")
	}

	// Check flags exist
	if generateCmd.Flag("output") == nil {
		t.Error("missing --output flag")
	}
	if generateCmd.Flag("name") == nil {
		t.Error("missing --name flag")
	}
	if generateCmd.Flag("threshold") == nil {
		t.Error("missing --threshold flag")
	}
}
