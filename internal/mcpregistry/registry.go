// Package mcpregistry provides an in-memory registry that maps MCP tool names
// to their server metadata. It is the central data structure shared by the LLM
// proxy, shim, and network monitor for tool call interception.
//
// The registry is safe for concurrent use. Lookups use a read lock for minimal
// contention on the hot path (every LLM response).
package mcpregistry

import (
	"sync"
	"time"
)

// ToolEntry describes a single MCP tool and the server that provides it.
type ToolEntry struct {
	ToolName     string
	ServerID     string
	ServerType   string // "stdio" | "http" | "sse"
	ServerAddr   string // "" for stdio, "host:port" for network
	ToolHash     string
	RegisteredAt time.Time
}

// ToolInfo carries the minimal information needed to register a tool.
// The server identity fields (serverID, serverType, serverAddr) are provided
// separately in the Register call.
type ToolInfo struct {
	Name string
	Hash string
}

// Registry maps tool names to their MCP server metadata.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]*ToolEntry // keyed by tool name
	addrs map[string]string     // server addr -> server ID (for network monitor)
}

// NewRegistry creates an empty, ready-to-use registry.
func NewRegistry() *Registry {
	return &Registry{
		tools: make(map[string]*ToolEntry),
		addrs: make(map[string]string),
	}
}

// Register bulk-registers tools from a server. If a tool name already exists
// in the registry (from a different server), the new entry overwrites it
// (last-write-wins). If tools is empty, this is a no-op.
//
// For network servers (non-empty serverAddr), the address is also recorded in
// the address map so the network monitor can look it up.
func (r *Registry) Register(serverID, serverType, serverAddr string, tools []ToolInfo) {
	if len(tools) == 0 {
		return
	}

	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, t := range tools {
		r.tools[t.Name] = &ToolEntry{
			ToolName:     t.Name,
			ServerID:     serverID,
			ServerType:   serverType,
			ServerAddr:   serverAddr,
			ToolHash:     t.Hash,
			RegisteredAt: now,
		}
	}

	// Record network server addresses for the network monitor.
	if serverAddr != "" {
		r.addrs[serverAddr] = serverID
	}
}

// Lookup returns the registry entry for a tool name, or nil if not found.
// This is the hot-path call used by the LLM proxy on every tool_use block.
func (r *Registry) Lookup(toolName string) *ToolEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.tools[toolName]
}

// LookupBatch returns entries for multiple tool names at once. Only found
// entries are included in the returned map; missing tools are omitted.
// Used when an LLM response contains parallel tool calls.
func (r *Registry) LookupBatch(toolNames []string) map[string]*ToolEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]*ToolEntry, len(toolNames))
	for _, name := range toolNames {
		if entry, ok := r.tools[name]; ok {
			result[name] = entry
		}
	}
	return result
}

// ServerAddrs returns a copy of all known network MCP server addresses.
// The returned map is addr -> serverID. Stdio servers (which have empty
// addresses) are never included. Used by the network monitor to build its
// watch list.
func (r *Registry) ServerAddrs() map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]string, len(r.addrs))
	for addr, id := range r.addrs {
		result[addr] = id
	}
	return result
}

// Remove deletes all tools that were registered by the given server and
// removes the server's address from the address map. Used for cleanup when
// a server disconnects or is removed from the session.
func (r *Registry) Remove(serverID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Remove tools belonging to this server.
	for name, entry := range r.tools {
		if entry.ServerID == serverID {
			delete(r.tools, name)
		}
	}

	// Remove address entries for this server.
	for addr, id := range r.addrs {
		if id == serverID {
			delete(r.addrs, addr)
		}
	}
}
