// Package mcpinspect provides MCP (Model Context Protocol) message inspection
// for security monitoring.
//
// The package intercepts MCP JSON-RPC messages to:
//   - Parse tool definitions from tools/list responses
//   - Track tool definitions with content hashing for rug pull detection
//   - Detect suspicious patterns (credential theft, exfiltration, hidden instructions)
//   - Emit audit events for tool discovery, changes, and security detections
//
// Pattern Detection:
//
// The detector scans tool descriptions and inputSchema for:
//   - credential_theft: References to SSH keys, .env files, API keys, etc.
//   - exfiltration: curl, wget, netcat patterns
//   - hidden_instructions: HIDDEN:, IGNORE PREVIOUS, SYSTEM OVERRIDE
//   - shell_injection: Command chaining, substitution patterns
//   - path_traversal: ../.. sequences, /etc/, /root/ access
//
// Example usage:
//
//	emitter := func(event interface{}) {
//	    // Log or store the event
//	}
//	inspector := mcpinspect.NewInspectorWithDetection("session-id", "server-id", emitter)
//	err := inspector.Inspect(messageBytes, mcpinspect.DirectionResponse)
package mcpinspect
