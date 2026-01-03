package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestProxyStatusCmd(t *testing.T) {
	// This is a basic smoke test - full integration testing
	// requires a running server with a session
	cmd := newProxyCmd()
	if cmd.Use != "proxy" {
		t.Errorf("expected 'proxy' command, got %q", cmd.Use)
	}

	// Check subcommands exist
	statusCmd, _, err := cmd.Find([]string{"status"})
	if err != nil {
		t.Errorf("expected 'status' subcommand: %v", err)
	}
	if statusCmd == nil {
		t.Error("status subcommand not found")
	}
}

func TestProxyStatusCmd_Output(t *testing.T) {
	root := NewRoot("test")
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"proxy", "status"})

	err := root.ExecuteContext(context.Background())
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	output := buf.String()
	// Verify expected output format
	expectedPhrases := []string{
		"Session: latest",
		"Proxy:",
		"Mode: embedded",
		"DLP:",
		"patterns active",
		"Requests:",
		"Tokens:",
	}
	for _, phrase := range expectedPhrases {
		if !strings.Contains(output, phrase) {
			t.Errorf("expected output to contain %q, got:\n%s", phrase, output)
		}
	}
}

func TestProxyStatusCmd_WithSessionID(t *testing.T) {
	root := NewRoot("test")
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"proxy", "status", "test-session-123"})

	err := root.ExecuteContext(context.Background())
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Session: test-session-123") {
		t.Errorf("expected output to contain session ID, got:\n%s", output)
	}
}

func TestProxyStatusCmd_JSONOutput(t *testing.T) {
	root := NewRoot("test")
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"proxy", "status", "--json"})

	err := root.ExecuteContext(context.Background())
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	output := buf.String()
	// Verify JSON output contains expected fields
	expectedFields := []string{
		`"state"`,
		`"address"`,
		`"mode"`,
		`"dlp_mode"`,
		`"active_patterns"`,
		`"total_requests"`,
		`"total_input_tokens"`,
		`"total_output_tokens"`,
	}
	for _, field := range expectedFields {
		if !strings.Contains(output, field) {
			t.Errorf("expected JSON output to contain %q, got:\n%s", field, output)
		}
	}
}

func TestProxyStatusCmd_TooManyArgs(t *testing.T) {
	root := NewRoot("test")
	root.SetArgs([]string{"proxy", "status", "session1", "session2"})

	err := root.ExecuteContext(context.Background())
	if err == nil {
		t.Error("expected error for too many arguments")
	}
}
