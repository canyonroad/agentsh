// internal/shim/mcp_bridge.go
package shim

import (
	"github.com/agentsh/agentsh/internal/mcpinspect"
)

// MCPBridge connects the shim's stdio wrapper to the mcpinspect package.
type MCPBridge struct {
	inspector *mcpinspect.Inspector
}

// NewMCPBridge creates a bridge without pattern detection (backward compatible).
func NewMCPBridge(sessionID, serverID string, emitter func(interface{})) *MCPBridge {
	return &MCPBridge{
		inspector: mcpinspect.NewInspector(sessionID, serverID, emitter),
	}
}

// NewMCPBridgeWithDetection creates a bridge with pattern detection enabled.
func NewMCPBridgeWithDetection(sessionID, serverID string, emitter func(interface{})) *MCPBridge {
	return &MCPBridge{
		inspector: mcpinspect.NewInspectorWithDetection(sessionID, serverID, emitter),
	}
}

// Inspect processes an MCP message and emits relevant events.
func (b *MCPBridge) Inspect(data []byte, dir MCPDirection) {
	mcpDir := mcpinspect.DirectionRequest
	if dir == MCPDirectionResponse {
		mcpDir = mcpinspect.DirectionResponse
	}

	// Inspect returns error for invalid messages, but we don't block on errors
	_ = b.inspector.Inspect(data, mcpDir)
}

// InspectorFunc returns a function suitable for ForwardWithInspection.
func (b *MCPBridge) InspectorFunc() MCPInspector {
	return func(data []byte, dir MCPDirection) {
		b.Inspect(data, dir)
	}
}
