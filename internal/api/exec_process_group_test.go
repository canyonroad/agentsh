package api

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

// Helper to create a bare session and workspace.
func newTestSession(t *testing.T) *session.Session {
	t.Helper()
	sessions := session.NewManager(10)
	ws := t.TempDir()
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := sessions.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRunCommandTimeoutKillsProcessGroup(t *testing.T) {
	s := newTestSession(t)
	cfg := &config.Config{}

	childFile := filepath.Join(s.Workspace, "child.txt")

	req := types.ExecRequest{
		Command: "sh",
		Args:    []string{"-c", "sleep 1; echo child > /workspace/child.txt & sleep 5"},
		Timeout: "100ms",
	}

	exitCode, _, _, _, _, _, _, _, err := runCommandWithResources(context.Background(), s, "cmd-timeout", req, cfg, 0, nil)
	if exitCode != 124 {
		t.Fatalf("expected exit code 124 on timeout, got %d (err=%v)", exitCode, err)
	}

	time.Sleep(1200 * time.Millisecond)
	if _, statErr := os.Stat(childFile); statErr == nil {
		t.Fatalf("child process survived timeout and wrote file")
	}
}

func TestRunCommandTimeoutKillsProcessGroup_Streaming(t *testing.T) {
	s := newTestSession(t)
	cfg := &config.Config{}

	childFile := filepath.Join(s.Workspace, "child_stream.txt")

	req := types.ExecRequest{
		Command: "sh",
		Args:    []string{"-c", "sleep 1; echo child > /workspace/child_stream.txt & sleep 5"},
		Timeout: "100ms",
	}

	exitCode, _, _, _, _, _, _, _, err := runCommandWithResourcesStreamingEmit(context.Background(), s, "cmd-timeout-stream", req, cfg, 0, nil, nil)
	if exitCode != 124 {
		t.Fatalf("expected exit code 124 on timeout, got %d (err=%v)", exitCode, err)
	}

	time.Sleep(1200 * time.Millisecond)
	if _, statErr := os.Stat(childFile); statErr == nil {
		t.Fatalf("child process survived timeout and wrote file (streaming)")
	}
}
