// internal/mcpinspect/hash.go
package mcpinspect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// ComputeHash computes a deterministic SHA-256 hash of a tool definition.
// The hash covers name, description, and inputSchema for change detection.
func ComputeHash(tool ToolDefinition) string {
	// Normalize by marshaling to JSON with consistent field order
	normalized := struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		InputSchema json.RawMessage `json:"inputSchema"`
	}{
		Name:        tool.Name,
		Description: tool.Description,
		InputSchema: tool.InputSchema,
	}

	data, _ := json.Marshal(normalized)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
