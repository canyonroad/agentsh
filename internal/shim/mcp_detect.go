// internal/shim/mcp_detect.go
package shim

import (
	"path/filepath"
	"strings"
)

// MCPServerPatterns are the default patterns for detecting MCP server commands.
var MCPServerPatterns = []string{
	"@modelcontextprotocol/*",
	"mcp-server-*",
	"*-mcp-server",
	"mcp_server_*",
}

// IsMCPServer checks if a command matches MCP server patterns.
// It checks the command itself and all arguments against default patterns
// plus any custom patterns provided.
func IsMCPServer(cmd string, args []string, customPatterns []string) bool {
	allPatterns := append([]string{}, MCPServerPatterns...)
	allPatterns = append(allPatterns, customPatterns...)

	// Check command name
	cmdBase := filepath.Base(cmd)
	if matchesAnyPattern(cmdBase, allPatterns) {
		return true
	}

	// Check arguments (for npx/uvx/python -m patterns)
	for _, arg := range args {
		if matchesAnyPattern(arg, allPatterns) {
			return true
		}
	}

	return false
}

// matchesAnyPattern checks if s matches any of the glob patterns.
func matchesAnyPattern(s string, patterns []string) bool {
	for _, pattern := range patterns {
		if matchGlob(pattern, s) {
			return true
		}
	}
	return false
}

// matchGlob performs simple glob matching with * wildcards.
func matchGlob(pattern, s string) bool {
	// Handle empty pattern
	if pattern == "" {
		return s == ""
	}

	// Simple glob matching
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		// No wildcards
		return pattern == s
	}

	// Check prefix
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]

	// Check middle parts and suffix
	for i := 1; i < len(parts)-1; i++ {
		idx := strings.Index(s, parts[i])
		if idx < 0 {
			return false
		}
		s = s[idx+len(parts[i]):]
	}

	// Check suffix
	return strings.HasSuffix(s, parts[len(parts)-1])
}
