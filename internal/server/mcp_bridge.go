package server

import (
	"github.com/agentsh/agentsh/internal/mcpregistry"
	"github.com/agentsh/agentsh/pkg/types"
)

// bridgeEventToRegistry updates the enforcement registry when the shim reports
// new or changed MCP tools. Called synchronously from AppendEvent.
func bridgeEventToRegistry(ev types.Event, reg *mcpregistry.Registry) {
	if ev.Fields == nil {
		return
	}
	switch ev.Type {
	case "mcp_tool_seen":
		serverID, _ := ev.Fields["server_id"].(string)
		serverType, _ := ev.Fields["server_type"].(string)
		toolName, _ := ev.Fields["tool_name"].(string)
		toolHash, _ := ev.Fields["tool_hash"].(string)
		if serverID == "" || toolName == "" {
			return
		}
		if serverType == "" {
			serverType = "stdio"
		}
		reg.Register(serverID, serverType, "", []mcpregistry.ToolInfo{
			{Name: toolName, Hash: toolHash},
		})
	case "mcp_tool_changed":
		serverID, _ := ev.Fields["server_id"].(string)
		serverType, _ := ev.Fields["server_type"].(string)
		toolName, _ := ev.Fields["tool_name"].(string)
		newHash, _ := ev.Fields["new_hash"].(string)
		if serverID == "" || toolName == "" {
			return
		}
		if serverType == "" {
			serverType = "stdio"
		}
		reg.Register(serverID, serverType, "", []mcpregistry.ToolInfo{
			{Name: toolName, Hash: newHash},
		})
	}
}
