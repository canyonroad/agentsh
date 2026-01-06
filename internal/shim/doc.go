// Package shim provides the shell shim infrastructure for agentsh.
//
// The shell shim intercepts shell commands (/bin/sh, /bin/bash) and routes
// them through agentsh for policy enforcement and auditing.
//
// # MCP Server Detection
//
// The shim detects MCP (Model Context Protocol) server launches using
// glob patterns and wraps their stdio with inspection:
//
//   - @modelcontextprotocol/* - Official MCP servers
//   - mcp-server-* - Convention prefix
//   - *-mcp-server - Convention suffix
//   - mcp_server_* - Python convention
//
// When an MCP server is detected, the shim:
//  1. Derives a server ID from the command
//  2. Creates an inspection bridge to mcpinspect
//  3. Forwards stdin/stdout while inspecting for tool poisoning
//  4. Emits audit events for tool definitions and detections
//
// Example detection:
//
//	if shim.IsMCPServer(cmd, args, nil) {
//	    serverID := shim.DeriveServerID(cmd, args)
//	    bridge := shim.NewMCPBridgeWithDetection(sessionID, serverID, emitter)
//	    // Wrap stdio with inspection
//	}
package shim
