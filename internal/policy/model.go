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

	// Process context-based rules (parent-conditional policies)
	ProcessContexts   map[string]ProcessContext `yaml:"process_contexts,omitempty"`
	ProcessIdentities map[string]ProcessIdentityConfig `yaml:"process_identities,omitempty"`
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

// ProcessContext defines rules that apply to processes spawned from specific parents.
// This enables parent-conditional policies for AI tool sandboxing.
type ProcessContext struct {
	Description string   `yaml:"description,omitempty"`
	Identities  []string `yaml:"identities"` // Process identities that trigger this context

	// Chain rules for escape hatch detection (evaluated before context rules)
	ChainRules []ChainRuleConfig `yaml:"chain_rules,omitempty"`

	// Rules that apply within this context (override global rules)
	CommandRules  []CommandRule    `yaml:"command_rules,omitempty"`
	FileRules     []FileRule       `yaml:"file_rules,omitempty"`
	NetworkRules  []NetworkRule    `yaml:"network_rules,omitempty"`
	UnixRules     []UnixSocketRule `yaml:"unix_socket_rules,omitempty"`
	EnvPolicy     *EnvPolicy       `yaml:"env_policy,omitempty"`

	// Quick command lists (simpler alternative to full CommandRules)
	AllowedCommands []string `yaml:"allowed_commands,omitempty"` // Commands allowed without restriction
	DeniedCommands  []string `yaml:"denied_commands,omitempty"`  // Commands always denied
	RequireApproval []string `yaml:"require_approval,omitempty"` // Commands requiring approval

	// Per-command argument filtering
	CommandOverrides map[string]CommandOverrideConfig `yaml:"command_overrides,omitempty"`

	// Default decision when no rules match
	DefaultDecision string `yaml:"default_decision,omitempty"` // allow, deny, approve (default: deny)

	// Race condition handling
	RacePolicy *RacePolicyConfig `yaml:"race_policy,omitempty"`

	// Propagation settings
	MaxDepth    int      `yaml:"max_depth,omitempty"`    // Max ancestry depth (0 = unlimited)
	StopAt      []string `yaml:"stop_at,omitempty"`      // Stop propagation at these process classes
	PassThrough []string `yaml:"pass_through,omitempty"` // Classes that inherit but don't count toward depth
}

// ChainRuleConfig is the YAML-friendly version of ancestry.ChainRule.
type ChainRuleConfig struct {
	Name        string                `yaml:"name"`
	Description string                `yaml:"description,omitempty"`
	Priority    int                   `yaml:"priority"`  // Higher = evaluated first
	Condition   *ChainConditionConfig `yaml:"condition"` // When this rule applies
	Action      string                `yaml:"action"`    // allow_normal_policy, apply_context_policy, deny, approve, mark_as_agent, allow
	Message     string                `yaml:"message,omitempty"`
	Continue    bool                  `yaml:"continue"` // Keep evaluating after this rule
}

// ChainConditionConfig is the YAML-friendly version of ancestry.ChainCondition.
type ChainConditionConfig struct {
	// Via chain conditions
	ViaIndex       *int     `yaml:"via_index,omitempty"`        // Check specific via position (0-indexed)
	ViaIndexValue  string   `yaml:"via_index_value,omitempty"`  // Value to match at ViaIndex
	ViaContains    []string `yaml:"via_contains,omitempty"`     // Any of these patterns in via
	ViaNotContains []string `yaml:"via_not_contains,omitempty"` // None of these patterns in via
	ViaMatches     []string `yaml:"via_matches,omitempty"`      // Pattern match against via entries

	// Class-based conditions
	ClassContains    []string `yaml:"class_contains,omitempty"`     // Any of these classes in chain
	ClassNotContains []string `yaml:"class_not_contains,omitempty"` // None of these classes in chain

	// Consecutive pattern detection (shell laundering)
	ConsecutiveClass *ConsecutiveMatchConfig `yaml:"consecutive_class,omitempty"` // Consecutive class occurrences
	ConsecutiveComm  *ConsecutiveMatchConfig `yaml:"consecutive_comm,omitempty"`  // Consecutive comm occurrences

	// Depth conditions
	DepthEQ *int `yaml:"depth_eq,omitempty"` // Depth equals
	DepthGT *int `yaml:"depth_gt,omitempty"` // Depth greater than
	DepthLT *int `yaml:"depth_lt,omitempty"` // Depth less than
	DepthGE *int `yaml:"depth_ge,omitempty"` // Depth greater or equal
	DepthLE *int `yaml:"depth_le,omitempty"` // Depth less or equal

	// Taint flags
	IsTainted *bool `yaml:"is_tainted,omitempty"` // Is descended from AI tool
	IsAgent   *bool `yaml:"is_agent,omitempty"`   // Is detected as agent

	// Execution context conditions
	EnvContains  []string `yaml:"env_contains,omitempty"`  // Environment variable patterns
	ArgsContain  []string `yaml:"args_contain,omitempty"`  // Command argument patterns
	CommMatches  []string `yaml:"comm_matches,omitempty"`  // Command name patterns
	PathMatches  []string `yaml:"path_matches,omitempty"`  // Executable path patterns

	// Source conditions
	SourceName    []string `yaml:"source_name,omitempty"`    // Source process name patterns
	SourceContext []string `yaml:"source_context,omitempty"` // Source context name patterns

	// Logical composition
	Or  []*ChainConditionConfig `yaml:"or,omitempty"`  // OR sub-conditions (any must match)
	And []*ChainConditionConfig `yaml:"and,omitempty"` // AND sub-conditions (all must match)
	Not *ChainConditionConfig   `yaml:"not,omitempty"` // NOT sub-condition (must not match)
}

// ConsecutiveMatchConfig specifies a consecutive occurrence requirement.
type ConsecutiveMatchConfig struct {
	Value   string `yaml:"value"`              // Class name or comm pattern
	CountGE int    `yaml:"count_ge,omitempty"` // Count must be >= this
	CountLE int    `yaml:"count_le,omitempty"` // Count must be <= this (0 = no limit)
}

// CommandOverrideConfig provides per-command argument filtering.
type CommandOverrideConfig struct {
	ArgsAllow []string `yaml:"args_allow,omitempty"` // Allowed argument patterns
	ArgsDeny  []string `yaml:"args_deny,omitempty"`  // Denied argument patterns
	Default   string   `yaml:"default,omitempty"`    // Default decision if no patterns match
}

// RacePolicyConfig defines how to handle race conditions in taint validation.
type RacePolicyConfig struct {
	OnMissingParent   string `yaml:"on_missing_parent,omitempty"`   // deny, allow, approve (default: deny)
	OnPIDMismatch     string `yaml:"on_pid_mismatch,omitempty"`     // deny, allow, approve (default: deny)
	OnValidationError string `yaml:"on_validation_error,omitempty"` // deny, allow, approve (default: deny)
	LogRaceConditions bool   `yaml:"log_race_conditions,omitempty"` // Log race condition events
}

// ProcessIdentityConfig defines how to identify a process in policy configuration.
// This is the YAML-friendly version of identity.ProcessIdentity.
type ProcessIdentityConfig struct {
	Description  string               `yaml:"description,omitempty"`
	Linux        *PlatformMatchConfig `yaml:"linux,omitempty"`
	Darwin       *PlatformMatchConfig `yaml:"darwin,omitempty"`
	Windows      *PlatformMatchConfig `yaml:"windows,omitempty"`
	AllPlatforms *PlatformMatchConfig `yaml:"all_platforms,omitempty"`
}

// PlatformMatchConfig defines platform-specific process matching rules.
type PlatformMatchConfig struct {
	Comm     []string `yaml:"comm,omitempty"`      // Process name patterns
	ExePath  []string `yaml:"exe_path,omitempty"`  // Executable path patterns
	Cmdline  []string `yaml:"cmdline,omitempty"`   // Command line patterns
	BundleID []string `yaml:"bundle_id,omitempty"` // macOS bundle ID
	ExeName  []string `yaml:"exe_name,omitempty"`  // Windows exe name
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
