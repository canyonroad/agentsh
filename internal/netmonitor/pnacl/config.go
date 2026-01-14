package pnacl

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the top-level network ACL configuration.
type Config struct {
	// Default is the global default decision (deny, allow, approve, audit).
	Default string `yaml:"default,omitempty"`
	// Processes defines per-process network policies.
	Processes []ProcessConfig `yaml:"processes,omitempty"`
	// ApprovalUI configures the interactive approval dialog.
	ApprovalUI *ApprovalUIConfig `yaml:"approval_ui,omitempty"`
}

// ApprovalUIConfig configures the interactive approval dialog.
type ApprovalUIConfig struct {
	// Mode determines when to show dialogs: "auto" (default), "enabled", "disabled"
	// auto: detect display availability, disable in CI environments
	Mode string `yaml:"mode,omitempty"`

	// Timeout for user response (e.g., "30s"). Uses approval timeout if not set.
	Timeout string `yaml:"timeout,omitempty"`
}

// GetMode returns the mode, defaulting to "auto".
func (c *ApprovalUIConfig) GetMode() string {
	if c == nil || c.Mode == "" {
		return "auto"
	}
	return c.Mode
}

// GetTimeout parses and returns the timeout duration.
// Returns 0 (no timeout) if not set or invalid.
func (c *ApprovalUIConfig) GetTimeout() time.Duration {
	if c == nil || c.Timeout == "" {
		return 0
	}
	d, _ := time.ParseDuration(c.Timeout)
	return d
}

// ProcessConfig defines the network policy for a specific process.
type ProcessConfig struct {
	// Name is a human-readable name for this process policy.
	Name string `yaml:"name"`
	// Match defines criteria for matching this process.
	Match ProcessMatchCriteria `yaml:"match"`
	// Default is the default decision for this process.
	Default string `yaml:"default,omitempty"`
	// Rules are the network rules for this process.
	Rules []NetworkTarget `yaml:"rules,omitempty"`
	// Children defines policies for child processes.
	Children []ChildConfig `yaml:"children,omitempty"`
}

// ChildConfig defines the network policy for a child process.
type ChildConfig struct {
	// Name is a human-readable name for this child policy.
	Name string `yaml:"name"`
	// Match defines criteria for matching this child process.
	Match ProcessMatchCriteria `yaml:"match"`
	// Inherit specifies whether to inherit parent rules.
	// If nil (not specified), defaults to true.
	Inherit *bool `yaml:"inherit,omitempty"`
	// Rules are additional rules specific to this child.
	Rules []NetworkTarget `yaml:"rules,omitempty"`
}

// InheritRules returns whether this child should inherit parent rules.
// Defaults to true if not explicitly set.
func (cc *ChildConfig) InheritRules() bool {
	if cc.Inherit == nil {
		return true
	}
	return *cc.Inherit
}

// NetworkACLConfig wraps the network_acl section of a policy file.
type NetworkACLConfig struct {
	NetworkACL Config `yaml:"network_acl"`
}

// LoadConfig loads a PNACL configuration from a file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	return ParseConfig(data)
}

// ParseConfig parses a PNACL configuration from YAML data.
func ParseConfig(data []byte) (*Config, error) {
	// Try parsing as a wrapped config (network_acl: ...).
	var wrapped NetworkACLConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	if err := dec.Decode(&wrapped); err == nil && (wrapped.NetworkACL.Default != "" || len(wrapped.NetworkACL.Processes) > 0) {
		config := wrapped.NetworkACL
		if err := config.Validate(); err != nil {
			return nil, fmt.Errorf("validate config: %w", err)
		}
		return &config, nil
	}

	// Try parsing as a direct config.
	var config Config
	dec = yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	if err := dec.Decode(&config); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &config, nil
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	// Validate default decision if specified.
	if c.Default != "" {
		if !isValidDecision(c.Default) {
			return fmt.Errorf("invalid default decision %q", c.Default)
		}
	}

	// Validate each process configuration.
	for i, pc := range c.Processes {
		if err := pc.Validate(); err != nil {
			return fmt.Errorf("process %d (%q): %w", i, pc.Name, err)
		}
	}

	return nil
}

// Validate validates a process configuration.
func (pc *ProcessConfig) Validate() error {
	if pc.Name == "" {
		return fmt.Errorf("name is required")
	}

	// Validate match criteria.
	if !hasCriteria(pc.Match) {
		return fmt.Errorf("at least one match criterion is required")
	}

	// Validate default decision if specified.
	if pc.Default != "" {
		if !isValidDecision(pc.Default) {
			return fmt.Errorf("invalid default decision %q", pc.Default)
		}
	}

	// Validate rules.
	for i, rule := range pc.Rules {
		if err := validateNetworkTarget(rule); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
	}

	// Validate children.
	for i, child := range pc.Children {
		if err := child.Validate(); err != nil {
			return fmt.Errorf("child %d (%q): %w", i, child.Name, err)
		}
	}

	return nil
}

// Validate validates a child configuration.
func (cc *ChildConfig) Validate() error {
	if cc.Name == "" {
		return fmt.Errorf("name is required")
	}

	if !hasCriteria(cc.Match) {
		return fmt.Errorf("at least one match criterion is required")
	}

	for i, rule := range cc.Rules {
		if err := validateNetworkTarget(rule); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
	}

	return nil
}

// validateNetworkTarget validates a network target.
func validateNetworkTarget(t NetworkTarget) error {
	// At least one target specifier is required.
	if t.Host == "" && t.IP == "" && t.CIDR == "" {
		return fmt.Errorf("at least one of target, ip, or cidr is required")
	}

	// Validate decision.
	if t.Decision == "" {
		return fmt.Errorf("decision is required")
	}
	if !isValidDecision(string(t.Decision)) {
		return fmt.Errorf("invalid decision %q", t.Decision)
	}

	// Validate protocol if specified.
	if t.Protocol != "" && t.Protocol != "*" {
		proto := t.Protocol
		if proto != "tcp" && proto != "udp" {
			return fmt.Errorf("invalid protocol %q (must be tcp, udp, or *)", proto)
		}
	}

	return nil
}

// isValidDecision checks if a decision string is valid.
func isValidDecision(d string) bool {
	switch Decision(d) {
	case DecisionAllow, DecisionDeny, DecisionApprove, DecisionAllowOnceThenApprove, DecisionAudit:
		return true
	default:
		return false
	}
}

// MergeConfigs merges two configurations, with the override taking precedence.
// Rules for the same process are merged, with override rules prepended (higher priority).
func MergeConfigs(base, override *Config) *Config {
	if base == nil {
		return override
	}
	if override == nil {
		return base
	}

	merged := &Config{
		Default:   base.Default,
		Processes: make([]ProcessConfig, 0),
	}

	// Override default if specified.
	if override.Default != "" {
		merged.Default = override.Default
	}

	// Build a map of base processes by name.
	baseProcesses := make(map[string]ProcessConfig)
	for _, pc := range base.Processes {
		baseProcesses[pc.Name] = pc
	}

	// Track which base processes have been merged.
	mergedNames := make(map[string]bool)

	// Add override processes, merging with base if exists.
	for _, overridePC := range override.Processes {
		if basePC, exists := baseProcesses[overridePC.Name]; exists {
			merged.Processes = append(merged.Processes, mergeProcessConfigs(basePC, overridePC))
			mergedNames[overridePC.Name] = true
		} else {
			merged.Processes = append(merged.Processes, overridePC)
		}
	}

	// Add remaining base processes that weren't overridden.
	for _, pc := range base.Processes {
		if !mergedNames[pc.Name] {
			merged.Processes = append(merged.Processes, pc)
		}
	}

	return merged
}

// mergeProcessConfigs merges two process configurations.
func mergeProcessConfigs(base, override ProcessConfig) ProcessConfig {
	merged := ProcessConfig{
		Name:  base.Name,
		Match: base.Match,
	}

	// Override match criteria if specified.
	if hasCriteria(override.Match) {
		merged.Match = override.Match
	}

	// Override default if specified.
	if override.Default != "" {
		merged.Default = override.Default
	} else {
		merged.Default = base.Default
	}

	// Prepend override rules (higher priority).
	merged.Rules = make([]NetworkTarget, 0, len(override.Rules)+len(base.Rules))
	merged.Rules = append(merged.Rules, override.Rules...)
	merged.Rules = append(merged.Rules, base.Rules...)

	// Merge children.
	merged.Children = mergeChildConfigs(base.Children, override.Children)

	return merged
}

// mergeChildConfigs merges child configurations.
func mergeChildConfigs(base, override []ChildConfig) []ChildConfig {
	if len(override) == 0 {
		return base
	}
	if len(base) == 0 {
		return override
	}

	// Build map of base children.
	baseChildren := make(map[string]ChildConfig)
	for _, cc := range base {
		baseChildren[cc.Name] = cc
	}

	merged := make([]ChildConfig, 0)
	mergedNames := make(map[string]bool)

	// Add override children, merging with base if exists.
	for _, overrideCC := range override {
		if baseCC, exists := baseChildren[overrideCC.Name]; exists {
			mergedChild := ChildConfig{
				Name:    baseCC.Name,
				Match:   baseCC.Match,
				Inherit: baseCC.Inherit, // Start with base inherit setting
			}
			if hasCriteria(overrideCC.Match) {
				mergedChild.Match = overrideCC.Match
			}
			// Only override inherit if explicitly specified in override
			if overrideCC.Inherit != nil {
				mergedChild.Inherit = overrideCC.Inherit
			}
			// Prepend override rules.
			mergedChild.Rules = append(overrideCC.Rules, baseCC.Rules...)
			merged = append(merged, mergedChild)
			mergedNames[overrideCC.Name] = true
		} else {
			merged = append(merged, overrideCC)
		}
	}

	// Add remaining base children.
	for _, cc := range base {
		if !mergedNames[cc.Name] {
			merged = append(merged, cc)
		}
	}

	return merged
}

// Clone creates a deep copy of the configuration.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}

	clone := &Config{
		Default:   c.Default,
		Processes: make([]ProcessConfig, len(c.Processes)),
	}

	for i, pc := range c.Processes {
		clone.Processes[i] = pc.Clone()
	}

	return clone
}

// Clone creates a deep copy of the process configuration.
func (pc ProcessConfig) Clone() ProcessConfig {
	clone := ProcessConfig{
		Name:     pc.Name,
		Match:    pc.Match, // Struct copy is sufficient.
		Default:  pc.Default,
		Rules:    make([]NetworkTarget, len(pc.Rules)),
		Children: make([]ChildConfig, len(pc.Children)),
	}

	copy(clone.Rules, pc.Rules)

	for i, cc := range pc.Children {
		clone.Children[i] = cc.Clone()
	}

	return clone
}

// Clone creates a deep copy of the child configuration.
func (cc ChildConfig) Clone() ChildConfig {
	clone := ChildConfig{
		Name:    cc.Name,
		Match:   cc.Match,
		Inherit: cc.Inherit,
		Rules:   make([]NetworkTarget, len(cc.Rules)),
	}

	copy(clone.Rules, cc.Rules)

	return clone
}
