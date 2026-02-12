//go:build linux && cgo

package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// WrapperConfig is the configuration passed via AGENTSH_SECCOMP_CONFIG env var.
type WrapperConfig struct {
	UnixSocketEnabled   bool     `json:"unix_socket_enabled"`
	ExecveEnabled       bool     `json:"execve_enabled"`
	SignalFilterEnabled bool     `json:"signal_filter_enabled"`
	FileMonitorEnabled  bool     `json:"file_monitor_enabled"`
	BlockedSyscalls     []string `json:"blocked_syscalls"`

	// Landlock filesystem restrictions
	LandlockEnabled bool     `json:"landlock_enabled,omitempty"`
	LandlockABI     int      `json:"landlock_abi,omitempty"`
	Workspace       string   `json:"workspace,omitempty"`
	AllowExecute    []string `json:"allow_execute,omitempty"`
	AllowRead       []string `json:"allow_read,omitempty"`
	AllowWrite      []string `json:"allow_write,omitempty"`
	DenyPaths       []string `json:"deny_paths,omitempty"`
	AllowNetwork    bool     `json:"allow_network,omitempty"`
	AllowBind       bool     `json:"allow_bind,omitempty"`
}

// loadConfig reads the wrapper config from environment.
func loadConfig() (*WrapperConfig, error) {
	val := os.Getenv("AGENTSH_SECCOMP_CONFIG")
	if val == "" {
		// Default: unix socket monitoring only, no blocked syscalls, no execve
		return &WrapperConfig{
			UnixSocketEnabled: true,
			ExecveEnabled:     false,
			BlockedSyscalls:   nil,
		}, nil
	}
	return parseConfigJSON(val)
}

func parseConfigJSON(data string) (*WrapperConfig, error) {
	var cfg WrapperConfig
	if err := json.Unmarshal([]byte(data), &cfg); err != nil {
		return nil, fmt.Errorf("parse AGENTSH_SECCOMP_CONFIG: %w", err)
	}
	return &cfg, nil
}
