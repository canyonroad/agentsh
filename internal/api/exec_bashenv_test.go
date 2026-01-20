package api

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestBashStartupScript_DisablesBuiltins tests that when BASH_ENV points to
// the bash_startup.sh script, the kill builtin is disabled.
// This is an E2E test for the startup script itself.
func TestBashStartupScript_DisablesBuiltins(t *testing.T) {
	// Find bash_startup.sh relative to this test file
	// Test runs from internal/api/, script is at ../../packaging/bash_startup.sh
	scriptPath := filepath.Join("..", "..", "packaging", "bash_startup.sh")

	// Verify script exists
	absScript, err := filepath.Abs(scriptPath)
	if err != nil {
		t.Fatalf("failed to get absolute path: %v", err)
	}
	if _, err := os.Stat(absScript); os.IsNotExist(err) {
		t.Fatalf("bash_startup.sh not found at %s", absScript)
	}

	// Test: run "type kill" with BASH_ENV set to our startup script
	// When builtins are disabled, "type kill" should show it's not a builtin
	cmd := exec.Command("bash", "-c", "type kill")
	cmd.Env = append(os.Environ(), "BASH_ENV="+absScript)
	output, _ := cmd.CombinedOutput()

	// When kill builtin is disabled, "type kill" should either:
	// - Return "kill is /usr/bin/kill" (or similar path)
	// - Return "kill not found" (if /usr/bin/kill doesn't exist)
	// - Exit with error (builtin not found)
	// It should NOT say "kill is a shell builtin"
	if strings.Contains(string(output), "shell builtin") {
		t.Errorf("expected kill builtin to be disabled, but got: %s", output)
	}
}

// TestBashStartupScript_SyntaxValid verifies the bash_startup.sh script has valid bash syntax.
func TestBashStartupScript_SyntaxValid(t *testing.T) {
	// Find bash_startup.sh relative to this test file
	scriptPath := filepath.Join("..", "..", "packaging", "bash_startup.sh")

	absScript, err := filepath.Abs(scriptPath)
	if err != nil {
		t.Fatalf("failed to get absolute path: %v", err)
	}
	if _, err := os.Stat(absScript); os.IsNotExist(err) {
		t.Fatalf("bash_startup.sh not found at %s", absScript)
	}

	// Use bash -n to check syntax without executing
	cmd := exec.Command("bash", "-n", absScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash_startup.sh has syntax errors: %v\nOutput: %s", err, output)
	}
}
