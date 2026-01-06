// Package mcpinspect provides MCP (Model Context Protocol) message inspection
// for security monitoring.
//
// The package intercepts MCP JSON-RPC messages to:
//   - Parse tool definitions from tools/list responses
//   - Track tool definitions with content hashing for rug pull detection
//   - Emit audit events for tool discovery and changes
//
// Example usage:
//
//	emitter := func(event interface{}) {
//	    // Log or store the event
//	}
//	inspector := mcpinspect.NewInspector("session-id", "server-id", emitter)
//	err := inspector.Inspect(messageBytes, mcpinspect.DirectionResponse)
package mcpinspect
