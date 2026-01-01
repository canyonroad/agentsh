package xpc

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// mockPolicyEngine implements a simple allow-all policy for testing.
type mockPolicyEngine struct{}

func (m *mockPolicyEngine) CheckFile(path, op string) (bool, string) {
	return true, "test-allow"
}

func (m *mockPolicyEngine) CheckNetwork(ip string, port int, domain string) (bool, string) {
	return true, "test-allow"
}

func (m *mockPolicyEngine) CheckCommand(cmd string, args []string) (bool, string) {
	return true, "test-allow"
}

func (m *mockPolicyEngine) ResolveSession(pid int32) string {
	if pid == 1234 {
		return "session-test"
	}
	return ""
}

// waitForServer retries dialing the socket with exponential backoff.
func waitForServer(t *testing.T, sockPath string, timeout time.Duration) net.Conn {
	t.Helper()
	deadline := time.Now().Add(timeout)
	backoff := 5 * time.Millisecond
	for time.Now().Before(deadline) {
		conn, err := net.Dial("unix", sockPath)
		if err == nil {
			return conn
		}
		time.Sleep(backoff)
		backoff *= 2
		if backoff > 100*time.Millisecond {
			backoff = 100 * time.Millisecond
		}
	}
	t.Fatalf("server did not become ready within %v", timeout)
	return nil
}

func TestServer_HandleFileRequest(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "policy.sock")

	srv := NewServer(sockPath, &mockPolicyEngine{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Run(ctx)

	// Wait for server to start with retry dial (longer timeout for CI)
	conn := waitForServer(t, sockPath, 5*time.Second)
	defer conn.Close()

	req := PolicyRequest{
		Type:      RequestTypeFile,
		Path:      "/test/file.txt",
		Operation: "read",
		PID:       1234,
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("encode: %v", err)
	}

	var resp PolicyResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !resp.Allow {
		t.Error("expected allow=true")
	}
	if resp.Rule != "test-allow" {
		t.Errorf("rule: got %q, want %q", resp.Rule, "test-allow")
	}
}

func TestServer_HandleSessionRequest(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "policy.sock")

	srv := NewServer(sockPath, &mockPolicyEngine{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Run(ctx)

	// Wait for server to start with retry dial (longer timeout for CI)
	conn := waitForServer(t, sockPath, 5*time.Second)
	defer conn.Close()

	req := PolicyRequest{
		Type: RequestTypeSession,
		PID:  1234,
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("encode: %v", err)
	}

	var resp PolicyResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.SessionID != "session-test" {
		t.Errorf("session_id: got %q, want %q", resp.SessionID, "session-test")
	}
}
