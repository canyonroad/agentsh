package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecCmd_InvalidatesStaleSessionFile(t *testing.T) {
	// Create a mock server that returns 404 "session not found"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Mock server received: %s %s", r.Method, r.URL.Path)
		// Return 404 for all requests - simulates session not found
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"session not found"}`))
	}))
	defer server.Close()

	// Create a temp directory for the session file
	tmpDir, err := os.MkdirTemp("", "exec-stale-session-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a fake session file
	sessionFile := filepath.Join(tmpDir, "stale-session.sid")
	if err := os.WriteFile(sessionFile, []byte("stale-session-id-123"), 0644); err != nil {
		t.Fatalf("failed to write session file: %v", err)
	}

	// Verify file exists before the test
	if _, err := os.Stat(sessionFile); os.IsNotExist(err) {
		t.Fatal("session file should exist before test")
	}

	// Disable auto-start (uses AGENTSH_NO_AUTO)
	t.Setenv("AGENTSH_NO_AUTO", "1")
	// Don't set AGENTSH_SESSION_ROOT so auto-create doesn't kick in
	t.Setenv("AGENTSH_SESSION_ROOT", "")

	// Build the root command to get the proper flag setup
	root := NewRoot("test")
	root.SetArgs([]string{
		"--server", server.URL,
		"exec",
		"--session-file", sessionFile,
		"stale-session-id-123",
		"--", "echo", "hello",
	})

	// Execute the command - it should fail but invalidate the session
	err = root.Execute()
	t.Logf("Command error: %v", err)

	// We expect an error (either the 404 or the "cache invalidated" message)
	if err == nil {
		t.Error("expected an error when session not found")
	}

	// The error message should mention cache invalidation
	if err != nil && strings.Contains(err.Error(), "cache invalidated") {
		// Expected - invalidation happened
		t.Logf("cache invalidation message: %v", err)
	}

	// Verify the session file was deleted
	if _, err := os.Stat(sessionFile); !os.IsNotExist(err) {
		t.Error("session file should have been deleted after 404")
	}
}

func TestExecCmd_HasSessionFileFlag(t *testing.T) {
	cmd := newExecCmd()
	if cmd.Flags().Lookup("session-file") == nil {
		t.Fatal("expected exec command to define --session-file flag")
	}
}

func TestExecCmd_DoesNotDeleteWithoutSessionFile(t *testing.T) {
	// Create a mock server that returns 404 "session not found"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"session not found"}`))
	}))
	defer server.Close()

	// Disable auto-start
	t.Setenv("AGENTSH_NO_AUTO", "1")
	t.Setenv("AGENTSH_SESSION_ROOT", "")

	// Build the root command WITHOUT --session-file
	root := NewRoot("test")
	root.SetArgs([]string{
		"--server", server.URL,
		"exec",
		"some-session-id",
		"--", "echo", "hello",
	})

	// Execute - should fail with generic error (not cache invalidation)
	err := root.Execute()
	if err == nil {
		t.Error("expected an error when session not found")
	}

	// Error should NOT mention cache invalidation (no session file provided)
	if err != nil && strings.Contains(err.Error(), "cache invalidated") {
		t.Error("should not mention cache invalidation when --session-file not provided")
	}
}
