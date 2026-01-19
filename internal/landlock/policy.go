package landlock

import (
	"path/filepath"
	"strings"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
)

// DeriveExecutePathsFromPolicy extracts directory paths from policy command rules.
func DeriveExecutePathsFromPolicy(p *policy.Policy) []string {
	if p == nil {
		return nil
	}

	pathSet := make(map[string]struct{})

	for _, rule := range p.CommandRules {
		// Only process allow rules
		if strings.ToLower(rule.Decision) != "allow" {
			continue
		}

		for _, cmd := range rule.Commands {
			cmd = strings.TrimSpace(cmd)
			if cmd == "" {
				continue
			}

			// Only process commands with path separators
			if !strings.Contains(cmd, "/") {
				continue
			}

			// Extract base directory
			dir := extractBaseDir(cmd)
			if dir != "" && dir != "." && dir != "/" {
				pathSet[dir] = struct{}{}
			}
		}
	}

	// Convert to slice
	paths := make([]string, 0, len(pathSet))
	for p := range pathSet {
		paths = append(paths, p)
	}

	return paths
}

// DeriveReadPathsFromPolicy extracts directory paths from policy file rules.
func DeriveReadPathsFromPolicy(p *policy.Policy) []string {
	if p == nil {
		return nil
	}

	pathSet := make(map[string]struct{})

	for _, rule := range p.FileRules {
		// Only process allow rules
		if strings.ToLower(rule.Decision) != "allow" {
			continue
		}

		// Only include rules that allow read operations
		hasRead := false
		for _, op := range rule.Operations {
			if strings.ToLower(op) == "read" {
				hasRead = true
				break
			}
		}
		if !hasRead && len(rule.Operations) > 0 {
			continue
		}

		for _, path := range rule.Paths {
			path = strings.TrimSpace(path)
			if path == "" {
				continue
			}

			// Extract base directory
			dir := extractBaseDir(path)
			if dir != "" && dir != "." && dir != "/" {
				pathSet[dir] = struct{}{}
			}
		}
	}

	// Convert to slice
	paths := make([]string, 0, len(pathSet))
	for p := range pathSet {
		paths = append(paths, p)
	}

	return paths
}

// DeriveWritePathsFromPolicy extracts directory paths from policy file rules with write access.
func DeriveWritePathsFromPolicy(p *policy.Policy) []string {
	if p == nil {
		return nil
	}

	pathSet := make(map[string]struct{})

	for _, rule := range p.FileRules {
		// Only process allow rules
		if strings.ToLower(rule.Decision) != "allow" {
			continue
		}

		// Only include rules that allow write operations
		hasWrite := false
		for _, op := range rule.Operations {
			op = strings.ToLower(op)
			if op == "write" || op == "create" || op == "delete" || op == "rename" {
				hasWrite = true
				break
			}
		}
		if !hasWrite {
			continue
		}

		for _, path := range rule.Paths {
			path = strings.TrimSpace(path)
			if path == "" {
				continue
			}

			// Extract base directory
			dir := extractBaseDir(path)
			if dir != "" && dir != "." && dir != "/" {
				pathSet[dir] = struct{}{}
			}
		}
	}

	// Convert to slice
	paths := make([]string, 0, len(pathSet))
	for p := range pathSet {
		paths = append(paths, p)
	}

	return paths
}

// extractBaseDir extracts the non-glob prefix from a path pattern.
// e.g., "/usr/bin/*" -> "/usr/bin"
// e.g., "/opt/*/bin/*" -> "/opt"
// e.g., "/usr/bin/git" -> "/usr/bin"
func extractBaseDir(pathPattern string) string {
	// Find first glob character
	for i, c := range pathPattern {
		if c == '*' || c == '?' || c == '[' {
			// Return directory up to this point
			prefix := pathPattern[:i]
			// Handle cases like "/usr/bin/*" -> get "/usr/bin" not "/usr/bin/"
			prefix = strings.TrimSuffix(prefix, "/")
			if prefix == "" {
				return "/"
			}
			return prefix
		}
	}
	// No glob characters, return directory of the path
	return filepath.Dir(pathPattern)
}

// BuildFromConfig creates a RulesetBuilder from config and policy.
func BuildFromConfig(cfg *config.LandlockConfig, pol *policy.Policy, workspace string, abi int) (*RulesetBuilder, error) {
	b := NewRulesetBuilder(abi)

	// Set workspace (full access)
	if workspace != "" {
		b.SetWorkspace(workspace)
	}

	// Add paths derived from policy
	if pol != nil {
		for _, p := range DeriveExecutePathsFromPolicy(pol) {
			_ = b.AddExecutePath(p)
		}
		for _, p := range DeriveReadPathsFromPolicy(pol) {
			_ = b.AddReadPath(p)
		}
		for _, p := range DeriveWritePathsFromPolicy(pol) {
			_ = b.AddWritePath(p)
		}
	}

	// Add explicit config paths
	if cfg != nil {
		for _, p := range cfg.AllowExecute {
			_ = b.AddExecutePath(p)
		}
		for _, p := range cfg.AllowRead {
			_ = b.AddReadPath(p)
		}
		for _, p := range cfg.AllowWrite {
			_ = b.AddWritePath(p)
		}
		for _, p := range cfg.DenyPaths {
			b.AddDenyPath(p)
		}
		b.SetNetworkAccess(cfg.Network.AllowConnectTCP, cfg.Network.AllowBindTCP)
	}

	// Add default deny paths (container escape vectors)
	defaultDenyPaths := []string{
		"/var/run/docker.sock",
		"/run/docker.sock",
		"/run/containerd/containerd.sock",
		"/run/crio/crio.sock",
		"/var/run/crio/crio.sock",
		"/var/run/secrets/kubernetes.io",
		"/run/systemd/private",
	}
	for _, p := range defaultDenyPaths {
		b.AddDenyPath(p)
	}

	return b, nil
}
