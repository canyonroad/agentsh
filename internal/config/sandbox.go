package config

import "time"

// This file contains sandbox configuration types for execve interception.
// The ExecveConfig and related types are used by the seccomp-notif based
// execve interception system.

// ExecveConfig configures execve/execveat interception.
type ExecveConfig struct {
	Enabled               bool          `yaml:"enabled"`
	MaxArgc               int           `yaml:"max_argc"`
	MaxArgvBytes          int           `yaml:"max_argv_bytes"`
	OnTruncated           string        `yaml:"on_truncated"` // deny | allow | approval
	ApprovalTimeout       time.Duration `yaml:"approval_timeout"`
	ApprovalTimeoutAction string        `yaml:"approval_timeout_action"` // deny | allow
	InternalBypass        []string      `yaml:"internal_bypass"`
}

// DefaultExecveConfig returns secure defaults.
func DefaultExecveConfig() ExecveConfig {
	return ExecveConfig{
		Enabled:               false,
		MaxArgc:               1000,
		MaxArgvBytes:          65536,
		OnTruncated:           "deny",
		ApprovalTimeout:       10 * time.Second,
		ApprovalTimeoutAction: "deny",
		InternalBypass: []string{
			"/usr/local/bin/agentsh",
			"/usr/local/bin/agentsh-unixwrap",
			"*.real",
		},
	}
}

// SeccompConfig is a standalone configuration struct for seccomp-related settings.
// It wraps ExecveConfig for YAML parsing of execve interception configuration.
type SeccompConfig struct {
	Execve ExecveConfig `yaml:"execve"`
}
