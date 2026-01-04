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

func TestProxyStatusCmd_NoServer(t *testing.T) {
	// When no server is running, we should get a connection error
	// When server is running but no sessions, we get "no sessions found"
	root := NewRoot("test")
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"proxy", "status"})

	err := root.ExecuteContext(context.Background())
	// We expect an error since no server is running or no sessions exist
	if err == nil {
		t.Skip("server appears to be running with sessions, skipping no-server test")
	}
	// Error should mention list sessions, connection issue, or no sessions found
	errStr := err.Error()
	if !strings.Contains(errStr, "list sessions") &&
		!strings.Contains(errStr, "connection refused") &&
		!strings.Contains(errStr, "no sessions found") {
		t.Errorf("expected connection-related or no-sessions error, got: %v", err)
	}
}

func TestProxyStatusCmd_NoSessions(t *testing.T) {
	// This test documents the expected error when no sessions exist
	// It will only run if a server is available
	root := NewRoot("test")
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"proxy", "status"})

	err := root.ExecuteContext(context.Background())
	if err == nil {
		// Server returned something, check that we have output
		output := buf.String()
		if !strings.Contains(output, "Session:") {
			t.Errorf("expected output to contain session info, got: %s", output)
		}
	} else {
		// Error is expected when no server or no sessions
		errStr := err.Error()
		if !strings.Contains(errStr, "no sessions found") &&
			!strings.Contains(errStr, "list sessions") &&
			!strings.Contains(errStr, "connection refused") {
			t.Errorf("unexpected error: %v", err)
		}
	}
}

func TestProxyStatusCmd_WithSessionID(t *testing.T) {
	// Test that a specific session ID is passed through correctly
	// This tests error handling when session doesn't exist
	root := NewRoot("test")
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"proxy", "status", "nonexistent-session"})

	err := root.ExecuteContext(context.Background())
	if err == nil {
		// If no error, we must have a server with this session
		output := buf.String()
		if !strings.Contains(output, "nonexistent-session") {
			t.Errorf("expected session ID in output, got: %s", output)
		}
	} else {
		// Expected to fail with session not found or connection error
		errStr := err.Error()
		if !strings.Contains(errStr, "proxy status") &&
			!strings.Contains(errStr, "connection refused") &&
			!strings.Contains(errStr, "session") {
			t.Errorf("unexpected error: %v", err)
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

func TestGetFloat(t *testing.T) {
	tests := []struct {
		name     string
		m        map[string]any
		key      string
		expected float64
	}{
		{"float64 value", map[string]any{"count": float64(42)}, "count", 42},
		{"int value", map[string]any{"count": int(42)}, "count", 42},
		{"missing key", map[string]any{}, "count", 0},
		{"wrong type", map[string]any{"count": "42"}, "count", 0},
		{"nil map", nil, "count", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getFloat(tt.m, tt.key)
			if got != tt.expected {
				t.Errorf("getFloat() = %v, want %v", got, tt.expected)
			}
		})
	}
}
