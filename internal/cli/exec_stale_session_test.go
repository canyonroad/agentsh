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

func TestExecCmd_AutoCreatesSessionBeforeInvalidating(t *testing.T) {
	// Track requests to verify auto-create is attempted
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		t.Logf("Mock server received: %s %s", r.Method, r.URL.Path)

		// First exec returns 404, session create succeeds, second exec succeeds
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/exec") {
			if len(requests) == 1 {
				// First exec attempt - session not found
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":"session not found"}`))
				return
			}
			// Second exec attempt - success
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"session_id":"test-session","command_id":"cmd-1","result":{"exit_code":0,"stdout":"hello\n"}}`))
			return
		}
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/sessions") {
			// Session creation succeeds
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"test-session","state":"ready"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Create a temp directory for the session file
	tmpDir, err := os.MkdirTemp("", "exec-auto-create-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a session file
	sessionFile := filepath.Join(tmpDir, "test-session.sid")
	if err := os.WriteFile(sessionFile, []byte("test-session"), 0644); err != nil {
		t.Fatalf("failed to write session file: %v", err)
	}

	// Enable auto (don't set AGENTSH_NO_AUTO)
	t.Setenv("AGENTSH_NO_AUTO", "")

	root := NewRoot("test")
	root.SetArgs([]string{
		"--server", server.URL,
		"exec",
		"--session-file", sessionFile,
		"test-session",
		"--", "echo", "hello",
	})

	err = root.Execute()
	t.Logf("Requests: %v", requests)
	t.Logf("Error: %v", err)

	// Should succeed because auto-create worked
	if err != nil {
		t.Errorf("expected success after auto-create, got error: %v", err)
	}

	// Session file should NOT be deleted (auto-create succeeded)
	if _, err := os.Stat(sessionFile); os.IsNotExist(err) {
		t.Error("session file should NOT have been deleted when auto-create succeeds")
	}

	// Verify the request sequence: exec -> create -> exec
	if len(requests) < 3 {
		t.Errorf("expected at least 3 requests (exec, create, exec), got %d: %v", len(requests), requests)
	}
}
