// internal/mcpinspect/registry.go
package mcpinspect

import (
	"sync"
	"time"
)

// RegistrationStatus indicates the result of registering a tool.
type RegistrationStatus int

const (
	StatusNew RegistrationStatus = iota
	StatusUnchanged
	StatusChanged // Rug pull alert!
)

// String returns the string representation of RegistrationStatus.
func (s RegistrationStatus) String() string {
	switch s {
	case StatusNew:
		return "new"
	case StatusUnchanged:
		return "unchanged"
	case StatusChanged:
		return "changed"
	default:
		return "unknown"
	}
}

// RegisteredTool tracks a tool definition in the registry.
type RegisteredTool struct {
	Name       string         `json:"name"`
	ServerID   string         `json:"server_id"`
	Hash       string         `json:"hash"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
	Pinned     bool           `json:"pinned"`
	Definition ToolDefinition `json:"-"` // Current definition for change detection
}

// RegistrationResult is returned when registering a tool.
type RegistrationResult struct {
	Status             RegistrationStatus
	Tool               *RegisteredTool
	Definition         ToolDefinition
	PreviousHash       string         // Only set when Status == StatusChanged
	NewHash            string         // Only set when Status == StatusChanged
	PreviousDefinition ToolDefinition // Only set when Status == StatusChanged
}

// Registry tracks tool definitions for change detection.
type Registry struct {
	mu            sync.RWMutex
	tools         map[string]*RegisteredTool // key: serverID:toolName
	pinOnFirstUse bool
}

// NewRegistry creates a new tool registry.
func NewRegistry(pinOnFirstUse bool) *Registry {
	return &Registry{
		tools:         make(map[string]*RegisteredTool),
		pinOnFirstUse: pinOnFirstUse,
	}
}

// Register adds or updates a tool in the registry and returns the result.
func (r *Registry) Register(serverID string, tool ToolDefinition) *RegistrationResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := serverID + ":" + tool.Name
	hash := ComputeHash(tool)
	now := time.Now()

	existing, exists := r.tools[key]
	if !exists {
		// First time seeing this tool
		registered := &RegisteredTool{
			Name:       tool.Name,
			ServerID:   serverID,
			Hash:       hash,
			FirstSeen:  now,
			LastSeen:   now,
			Pinned:     r.pinOnFirstUse,
			Definition: tool,
		}
		r.tools[key] = registered

		return &RegistrationResult{
			Status:     StatusNew,
			Tool:       registered,
			Definition: tool,
		}
	}

	// Update last seen
	existing.LastSeen = now

	// Check for changes
	if existing.Hash != hash {
		previousHash := existing.Hash
		previousDef := existing.Definition
		existing.Hash = hash // Update to new hash
		existing.Definition = tool

		return &RegistrationResult{
			Status:             StatusChanged,
			Tool:               existing,
			Definition:         tool,
			PreviousHash:       previousHash,
			NewHash:            hash,
			PreviousDefinition: previousDef,
		}
	}

	return &RegistrationResult{
		Status:     StatusUnchanged,
		Tool:       existing,
		Definition: tool,
	}
}

// Get retrieves a registered tool by server and name.
func (r *Registry) Get(serverID, toolName string) *RegisteredTool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.tools[serverID+":"+toolName]
}

// List returns all registered tools.
func (r *Registry) List() []*RegisteredTool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*RegisteredTool, 0, len(r.tools))
	for _, tool := range r.tools {
		result = append(result, tool)
	}
	return result
}
