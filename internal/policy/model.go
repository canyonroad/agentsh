package policy

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

type Policy struct {
	Version     int    `yaml:"version"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`

	FileRules     []FileRule       `yaml:"file_rules"`
	NetworkRules  []NetworkRule    `yaml:"network_rules"`
	CommandRules  []CommandRule    `yaml:"command_rules"`
	UnixRules     []UnixSocketRule `yaml:"unix_socket_rules"`
	RegistryRules []RegistryRule   `yaml:"registry_rules"`
	SignalRules   []SignalRule     `yaml:"signal_rules"`

	ResourceLimits ResourceLimits `yaml:"resource_limits"`
	EnvPolicy      EnvPolicy      `yaml:"env_policy"`
	Audit          AuditSettings  `yaml:"audit"`
}

type FileRule struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Paths       []string `yaml:"paths"`
	Operations  []string `yaml:"operations"`
	Decision    string   `yaml:"decision"`
	Message     string   `yaml:"message"`
	Timeout     duration `yaml:"timeout"`

	// Redirect configuration for file operations
	RedirectTo   string `yaml:"redirect_to,omitempty"`   // Target directory for redirected files
	PreserveTree bool   `yaml:"preserve_tree,omitempty"` // Preserve directory structure under target
}

type NetworkRule struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Domains     []string `yaml:"domains"`
	Ports       []int    `yaml:"ports"`
	CIDRs       []string `yaml:"cidrs"`
	Decision    string   `yaml:"decision"`
	Message     string   `yaml:"message"`
	Timeout     duration `yaml:"timeout"`
}

type CommandRule struct {
	Name         string           `yaml:"name"`
	Description  string           `yaml:"description"`
	Commands     []string         `yaml:"commands"`
	ArgsPatterns []string         `yaml:"args_patterns"`
	Decision     string           `yaml:"decision"`
	Message      string           `yaml:"message"`
	RedirectTo   *CommandRedirect `yaml:"redirect_to,omitempty"`

	EnvAllow          []string `yaml:"env_allow"`
	EnvDeny           []string `yaml:"env_deny"`
	EnvMaxBytes       int      `yaml:"env_max_bytes"`
	EnvMaxKeys        int      `yaml:"env_max_keys"`
	EnvBlockIteration *bool    `yaml:"env_block_iteration,omitempty"`
}

type CommandRedirect struct {
	Command     string            `yaml:"command"`
	Args        []string          `yaml:"args,omitempty"`        // Prepended args
	ArgsAppend  []string          `yaml:"args_append,omitempty"` // Appended args
	Environment map[string]string `yaml:"environment,omitempty"` // Environment overrides
}

// UnixSocketRule controls AF_UNIX socket operations such as connect/bind/listen.
// Paths refer to filesystem socket paths; abstract namespace sockets use "@name" (no leading slash).
type UnixSocketRule struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Paths       []string `yaml:"paths"`
	Operations  []string `yaml:"operations"` // connect|bind|listen|sendto; empty = all
	Decision    string   `yaml:"decision"`   // allow|deny|approve
	Message     string   `yaml:"message"`
	Timeout     duration `yaml:"timeout"`
}

// RegistryRule controls Windows registry access (Windows-only).
type RegistryRule struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Paths       []string `yaml:"paths"`      // e.g., "HKLM\\SOFTWARE\\..."
	Operations  []string `yaml:"operations"` // read, write, delete, create, rename
	Decision    string   `yaml:"decision"`   // allow, deny, approve
	Message     string   `yaml:"message"`
	Timeout     duration `yaml:"timeout"`
	Priority    int      `yaml:"priority"`  // Higher = evaluated first
	CacheTTL    duration `yaml:"cache_ttl"` // Per-rule cache TTL override
	Notify      bool     `yaml:"notify"`    // Always notify on this rule
}

// SignalRule controls signal sending between processes.
type SignalRule struct {
	Name        string           `yaml:"name"`
	Description string           `yaml:"description"`
	Signals     []string         `yaml:"signals"`     // Signal names, numbers, or groups (@fatal, @job)
	Target      SignalTargetSpec `yaml:"target"`      // Who can receive the signal
	Decision    string           `yaml:"decision"`    // allow, deny, audit, approve, redirect, absorb
	Fallback    string           `yaml:"fallback"`    // Fallback decision if platform can't enforce
	RedirectTo  string           `yaml:"redirect_to"` // For redirect: target signal
	Message     string           `yaml:"message"`
	Timeout     duration         `yaml:"timeout"`
}

// SignalTargetSpec defines the target of a signal rule.
type SignalTargetSpec struct {
	Type    string `yaml:"type"`              // self, children, external, system, etc.
	Pattern string `yaml:"pattern,omitempty"` // For process name matching
	Min     int    `yaml:"min,omitempty"`     // For pid_range
	Max     int    `yaml:"max,omitempty"`     // For pid_range
}

type ResourceLimits struct {
	MaxMemoryMB      int      `yaml:"max_memory_mb"`
	MemorySwapMaxMB  int      `yaml:"memory_swap_max_mb"`
	CPUQuotaPercent  int      `yaml:"cpu_quota_percent"`
	DiskReadBpsMax   int64    `yaml:"disk_read_bps_max"`
	DiskWriteBpsMax  int64    `yaml:"disk_write_bps_max"`
	NetBandwidthMbps int      `yaml:"net_bandwidth_mbps"`
	PidsMax          int      `yaml:"pids_max"`
	CommandTimeout   duration `yaml:"command_timeout"`
	SessionTimeout   duration `yaml:"session_timeout"`
	IdleTimeout      duration `yaml:"idle_timeout"`
}

type EnvPolicy struct {
	Allow          []string `yaml:"allow"`
	Deny           []string `yaml:"deny"`
	MaxBytes       int      `yaml:"max_bytes"`
	MaxKeys        int      `yaml:"max_keys"`
	BlockIteration bool     `yaml:"block_iteration"`
}

type AuditSettings struct {
	LogAllowed         bool `yaml:"log_allowed"`
	LogDenied          bool `yaml:"log_denied"`
	LogApproved        bool `yaml:"log_approved"`
	IncludeStdout      bool `yaml:"include_stdout"`
	IncludeStderr      bool `yaml:"include_stderr"`
	IncludeFileContent bool `yaml:"include_file_content"`
	RetentionDays      int  `yaml:"retention_days"`
}

type duration struct{ time.Duration }

func (d *duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("duration must be scalar")
	}
	dd, err := time.ParseDuration(value.Value)
	if err != nil {
		return err
	}
	d.Duration = dd
	return nil
}

// Validate performs minimal semantic validation of a policy.
func (p Policy) Validate() error {
	if p.Version <= 0 {
		return fmt.Errorf("version must be > 0")
	}
	if p.Name == "" {
		return fmt.Errorf("name is required")
	}
	return nil
}
