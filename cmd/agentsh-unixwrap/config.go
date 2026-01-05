//go:build linux && cgo

package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// WrapperConfig is the configuration passed via AGENTSH_SECCOMP_CONFIG env var.
type WrapperConfig struct {
	UnixSocketEnabled bool     `json:"unix_socket_enabled"`
	BlockedSyscalls   []string `json:"blocked_syscalls"`
}

// loadConfig reads the wrapper config from environment.
func loadConfig() (*WrapperConfig, error) {
	val := os.Getenv("AGENTSH_SECCOMP_CONFIG")
	if val == "" {
		// Default: unix socket monitoring only, no blocked syscalls
		return &WrapperConfig{
			UnixSocketEnabled: true,
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
