//go:build linux && cgo

package main

import (
	"encoding/json"
	"fmt"
	"os"

	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
)

// WrapperConfig is the configuration passed via AGENTSH_SECCOMP_CONFIG env var.
type WrapperConfig struct {
	UnixSocketEnabled   bool                      `json:"unix_socket_enabled"`
	ExecveEnabled       bool                      `json:"execve_enabled"`
	SignalFilterEnabled bool                      `json:"signal_filter_enabled"`
	FileMonitorEnabled  bool                      `json:"file_monitor_enabled"`
	BlockedSyscalls     []string                  `json:"blocked_syscalls"`
	BlockedFamilies     []seccompkg.BlockedFamily `json:"blocked_families,omitempty"`
	SocketRules         []seccompkg.SocketRule    `json:"socket_rules,omitempty"`
	OnBlock             string                    `json:"on_block,omitempty"`

	InterceptMetadata bool `json:"intercept_metadata,omitempty"`
	WriteOnlyOpens    bool `json:"write_only_opens,omitempty"`
	BlockIOUring      bool `json:"block_io_uring,omitempty"`

	// WaitKillable, when non-nil, forces SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
	// on or off, bypassing the wrapper's legacy kernel-version probe. The
	// server makes this decision (boot-time behavioral probe + optional
	// config override) and forwards the result; nil means "fall back to
	// ProbeWaitKillable()" for direct/test invocations. Issue #369.
	WaitKillable *bool `json:"wait_killable,omitempty"`

	// WaitKillableSource records why WaitKillable was chosen
	// ("config", "kernel_unsupported", "filter_composition_safe",
	// "behavioral_probe", "behavioral_probe_error"). Forwarded into the
	// per-exec "seccomp: filter loaded" log line so a single grep tells
	// an operator why this exec saw a given flag value. Issue #369.
	WaitKillableSource string `json:"wait_killable_source,omitempty"`

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

	// Server PID for PR_SET_PTRACER (Yama ptrace_scope=1 workaround)
	ServerPID int `json:"server_pid,omitempty"`
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
