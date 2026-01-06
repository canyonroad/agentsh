// internal/shim/mcp_exec_test.go
package shim

import (
	"os/exec"
	"testing"
)

func TestMCPExecConfig(t *testing.T) {
	cfg := MCPExecConfig{
		SessionID:       "sess_123",
		ServerID:        "test-server",
		EnableDetection: true,
	}

	if cfg.SessionID != "sess_123" {
		t.Errorf("SessionID = %q, want sess_123", cfg.SessionID)
	}
}

func TestBuildMCPExecWrapper(t *testing.T) {
	cfg := MCPExecConfig{
		SessionID:       "sess_123",
		ServerID:        "test-server",
		EnableDetection: true,
		EventEmitter: func(event interface{}) {
			// Capture events
		},
	}

	wrapper := BuildMCPExecWrapper(cfg)
	if wrapper == nil {
		t.Fatal("BuildMCPExecWrapper returned nil")
	}
}

func TestMCPExecWrapper_WrapCommand(t *testing.T) {
	var capturedEvents []interface{}
	emitter := func(event interface{}) {
		capturedEvents = append(capturedEvents, event)
	}

	cfg := MCPExecConfig{
		SessionID:       "sess_123",
		ServerID:        "test-server",
		EnableDetection: false,
		EventEmitter:    emitter,
	}

	wrapper := BuildMCPExecWrapper(cfg)

	// Create a simple command
	cmd := exec.Command("cat")

	cleanup, err := wrapper.WrapCommand(cmd)
	if err != nil {
		t.Fatalf("WrapCommand failed: %v", err)
	}
	defer cleanup()

	// Verify cleanup function is not nil
	if cleanup == nil {
		t.Error("expected non-nil cleanup function")
	}
}
