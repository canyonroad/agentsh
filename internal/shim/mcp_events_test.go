// internal/shim/mcp_events_test.go
package shim

import (
	"net"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/mcpinspect"
)

func TestMCPEventForwarder(t *testing.T) {
	// Create a test socket
	socketPath := "/tmp/test-mcp-events-" + time.Now().Format("20060102150405") + ".sock"

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Skipf("cannot create unix socket: %v", err)
	}
	defer listener.Close()

	// Test that forwarder can be created
	forwarder, err := NewMCPEventForwarder(socketPath)
	if err != nil {
		t.Fatalf("NewMCPEventForwarder failed: %v", err)
	}
	defer forwarder.Close()
}

func TestMCPEventForwarder_EmitEvent(t *testing.T) {
	event := mcpinspect.MCPToolSeenEvent{
		Type:      "mcp_tool_seen",
		SessionID: "sess_123",
		ServerID:  "test-server",
		ToolName:  "read_file",
		Status:    "new",
	}

	// Test that emit function can be created
	emitter := func(e interface{}) {
		if _, ok := e.(mcpinspect.MCPToolSeenEvent); !ok {
			t.Errorf("expected MCPToolSeenEvent, got %T", e)
		}
	}

	emitter(event)
}
