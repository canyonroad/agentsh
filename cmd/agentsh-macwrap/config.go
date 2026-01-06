//go:build darwin

package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// WrapperConfig is passed via AGENTSH_SANDBOX_CONFIG env var.
type WrapperConfig struct {
	WorkspacePath string             `json:"workspace_path"`
	AllowedPaths  []string           `json:"allowed_paths"`
	AllowNetwork  bool               `json:"allow_network"`
	MachServices  MachServicesConfig `json:"mach_services"`
}

// MachServicesConfig controls mach-lookup restrictions.
type MachServicesConfig struct {
	DefaultAction string   `json:"default_action"`
	Allow         []string `json:"allow"`
	Block         []string `json:"block"`
	AllowPrefixes []string `json:"allow_prefixes"`
	BlockPrefixes []string `json:"block_prefixes"`
}

// loadConfig reads wrapper config from environment.
func loadConfig() (*WrapperConfig, error) {
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
