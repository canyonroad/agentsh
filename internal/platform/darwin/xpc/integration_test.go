//go:build integration

package xpc

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/policy"
)

func TestIntegration_FullPolicyFlow(t *testing.T) {
	if os.Getenv("AGENTSH_INTEGRATION") != "1" {
		t.Skip("set AGENTSH_INTEGRATION=1 to run")
	}

	// Create real policy
	p := &policy.Policy{
		Version: 1,
		Name:    "test",
		FileRules: []policy.FileRule{
			{Name: "deny-etc", Paths: []string{"/etc/**"}, Operations: []string{"write"}, Decision: "deny"},
			{Name: "allow-all", Paths: []string{"/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
		CommandRules: []policy.CommandRule{
			{Name: "deny-rm", Commands: []string{"rm"}, Decision: "deny"},
			{Name: "allow-all", Commands: []string{"*"}, Decision: "allow"},
		},
	}
	engine, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	// Start server
	sockPath := "/tmp/agentsh-test-policy.sock"
	tracker := NewSessionTracker()
	tracker.RegisterProcess("session-test", 12345, 0)

	adapter := NewPolicyAdapter(engine, tracker)
	srv := NewServer(sockPath, adapter)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Run(ctx)
	time.Sleep(100 * time.Millisecond)
	defer os.Remove(sockPath)

	// Test file allow
	t.Run("file_allow", func(t *testing.T) {
		resp := sendTestRequest(t, sockPath, PolicyRequest{
			Type:      RequestTypeFile,
			Path:      "/home/user/test.txt",
			Operation: "read",
			PID:       12345,
		})
		if !resp.Allow {
			t.Error("expected allow")
		}
	})

	// Test file deny
	t.Run("file_deny", func(t *testing.T) {
		resp := sendTestRequest(t, sockPath, PolicyRequest{
			Type:      RequestTypeFile,
			Path:      "/etc/passwd",
			Operation: "write",
			PID:       12345,
		})
		if resp.Allow {
			t.Error("expected deny")
		}
		if resp.Rule != "deny-etc" {
			t.Errorf("rule: got %q, want %q", resp.Rule, "deny-etc")
		}
	})

	// Test command deny
	t.Run("command_deny", func(t *testing.T) {
		resp := sendTestRequest(t, sockPath, PolicyRequest{
			Type: RequestTypeCommand,
			Path: "/bin/rm",
			Args: []string{"-rf", "/"},
			PID:  12345,
		})
		if resp.Allow {
			t.Error("expected deny")
		}
	})

	// Test session lookup
	t.Run("session_lookup", func(t *testing.T) {
		resp := sendTestRequest(t, sockPath, PolicyRequest{
			Type: RequestTypeSession,
			PID:  12345,
		})
		if resp.SessionID != "session-test" {
			t.Errorf("session_id: got %q, want %q", resp.SessionID, "session-test")
		}
	})
}

func sendTestRequest(t *testing.T, sockPath string, req PolicyRequest) PolicyResponse {
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("encode: %v", err)
	}

	var resp PolicyResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	return resp
}
