//go:build darwin

package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// WrapperConfig is passed via AGENTSH_SANDBOX_CONFIG env var
// or AGENTSH_SANDBOX_CONFIG_FILE (for large payloads >64KB).
type WrapperConfig struct {
	WorkspacePath string             `json:"workspace_path"`
	AllowedPaths  []string           `json:"allowed_paths"`
	AllowNetwork  bool               `json:"allow_network"`
	MachServices  MachServicesConfig `json:"mach_services"`

	// New fields for dynamic seatbelt
	CompiledProfile string   `json:"compiled_profile,omitempty"`
	ExtensionTokens []string `json:"extension_tokens,omitempty"`
}

// MachServicesConfig controls mach-lookup restrictions.
type MachServicesConfig struct {
	DefaultAction string   `json:"default_action"`
	Allow         []string `json:"allow"`
	Block         []string `json:"block"`
	AllowPrefixes []string `json:"allow_prefixes"`
	BlockPrefixes []string `json:"block_prefixes"`
}

func loadConfig() (*WrapperConfig, error) {
	// Check AGENTSH_SANDBOX_CONFIG_FILE first (for large payloads)
	if filePath := os.Getenv("AGENTSH_SANDBOX_CONFIG_FILE"); filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read config file %s: %w", filePath, err)
		}
		os.Remove(filePath) // best-effort cleanup

		var cfg WrapperConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("parse config file: %w", err)
		}
		return &cfg, nil
	}

	// Existing env var loading
	val := os.Getenv("AGENTSH_SANDBOX_CONFIG")
	if val == "" {
		return &WrapperConfig{
			MachServices: MachServicesConfig{
				DefaultAction: "allow",
			},
		}, nil
	}

	var cfg WrapperConfig
	if err := json.Unmarshal([]byte(val), &cfg); err != nil {
		return nil, fmt.Errorf("parse AGENTSH_SANDBOX_CONFIG: %w", err)
	}
	return &cfg, nil
}
