// Package pnacl provides Process Network ACL (PNACL) functionality for
// per-process network access control policies.
package pnacl

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the top-level network ACL configuration.
type Config struct {
	// Default is the global default decision (deny, allow, approve, audit).
	Default string `yaml:"default,omitempty"`
	// Processes defines per-process network policies.
	Processes []ProcessConfig `yaml:"processes,omitempty"`
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
	// Inherit specifies whether to inherit parent rules (default: true).
	Inherit bool `yaml:"inherit"`
	// Rules are additional rules specific to this child.
	Rules []NetworkTarget `yaml:"rules,omitempty"`
}

// NetworkACLConfig wraps the network_acl section of a policy file.
// This allows loading from both standalone network-acl.yaml files
// and from the network_acl block within an existing policy.yaml file.
type NetworkACLConfig struct {
	NetworkACL Config `yaml:"network_acl"`
}

// LoadConfig loads a PNACL configuration from a file.
// It supports loading from:
//   - Standalone network-acl.yaml file with direct Config structure
//   - Files with a network_acl wrapper block (e.g., within policy.yaml)
//
// The function automatically detects the format and parses accordingly.
// Returns an error if the file cannot be read or parsed.
func LoadConfig(path string) (*NetworkACLConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	return ParseConfig(data)
}

// ParseConfig parses a PNACL configuration from YAML data.
// It supports two formats:
//  1. Wrapped format with network_acl key:
//     network_acl:
//     default: deny
//     processes: [...]
//  2. Direct format without wrapper:
//     default: deny
//     processes: [...]
//
// The function automatically validates the parsed configuration.
// Returns an error if the YAML is malformed or validation fails.
func ParseConfig(data []byte) (*NetworkACLConfig, error) {
	// Try parsing as a wrapped config (network_acl: ...).
	var wrapped NetworkACLConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	if err := dec.Decode(&wrapped); err == nil && len(wrapped.NetworkACL.Processes) > 0 {
		if err := ValidateConfig(&wrapped); err != nil {
			return nil, fmt.Errorf("validate config: %w", err)
		}
		return &wrapped, nil
	}

	// Try parsing as a direct config (no network_acl wrapper).
	var config Config
	dec = yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	if err := dec.Decode(&config); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Wrap the direct config in NetworkACLConfig.
	result := &NetworkACLConfig{
		NetworkACL: config,
	}

	if err := ValidateConfig(result); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return result, nil
}

// ValidateConfig validates the entire network ACL configuration.
// It performs comprehensive validation including:
//   - Decision values are valid (allow/deny/approve/audit/allow_once_then_approve)
//   - Port ranges are valid (start <= end, within 1-65535)
//   - CIDR notation is parseable
//   - Protocol is tcp/udp/*
//   - Process match has at least one identifier (name, path, or bundleID)
//
// Returns nil if the configuration is valid, or an error describing
// the first validation failure encountered.
func ValidateConfig(config *NetworkACLConfig) error {
	if config == nil {
		return fmt.Errorf("config is nil")
	}

	c := &config.NetworkACL

	// Validate default decision if specified.
	if c.Default != "" {
		if !isValidDecision(c.Default) {
			return fmt.Errorf("invalid default decision %q: must be one of allow, deny, approve, audit, allow_once_then_approve", c.Default)
		}
	}

	// Validate each process configuration.
	for i, pc := range c.Processes {
		if err := validateProcessConfig(pc); err != nil {
			return fmt.Errorf("process %d (%q): %w", i, pc.Name, err)
		}
	}

	return nil
}

// MergeConfigs merges two NetworkACLConfig configurations, with the overlay
// taking precedence over the base configuration.
//
// Merge behavior:
//   - If overlay specifies a default decision, it overrides base's default
//   - Process configurations are merged by name:
//   - If both base and overlay have the same process name, overlay's rules
//     are prepended (higher priority) to base's rules
//   - Process-specific defaults in overlay override base
//   - Child configurations follow the same merge pattern
//   - Processes only in base are preserved
//   - Processes only in overlay are added
//
// Returns nil if both inputs are nil. Returns a clone of the non-nil input
// if the other is nil.
func MergeConfigs(base, overlay *NetworkACLConfig) *NetworkACLConfig {
	if base == nil && overlay == nil {
		return nil
	}
	if base == nil {
		return overlay.Clone()
	}
	if overlay == nil {
		return base.Clone()
	}

	merged := &NetworkACLConfig{
		NetworkACL: Config{
			Default:   base.NetworkACL.Default,
			Processes: make([]ProcessConfig, 0),
		},
	}

	// Override default if specified in overlay.
	if overlay.NetworkACL.Default != "" {
		merged.NetworkACL.Default = overlay.NetworkACL.Default
	}

	// Build a map of base processes by name.
	baseProcesses := make(map[string]ProcessConfig)
	for _, pc := range base.NetworkACL.Processes {
		baseProcesses[pc.Name] = pc
	}

	// Track which base processes have been merged.
	mergedNames := make(map[string]bool)

	// Add overlay processes, merging with base if exists.
	for _, overlayPC := range overlay.NetworkACL.Processes {
		if basePC, exists := baseProcesses[overlayPC.Name]; exists {
			merged.NetworkACL.Processes = append(merged.NetworkACL.Processes, mergeProcessConfigs(basePC, overlayPC))
			mergedNames[overlayPC.Name] = true
		} else {
			merged.NetworkACL.Processes = append(merged.NetworkACL.Processes, overlayPC)
		}
	}

	// Add remaining base processes that weren't overridden.
	for _, pc := range base.NetworkACL.Processes {
		if !mergedNames[pc.Name] {
			merged.NetworkACL.Processes = append(merged.NetworkACL.Processes, pc)
		}
	}

	return merged
}

// validateProcessConfig validates a process configuration.
func validateProcessConfig(pc ProcessConfig) error {
	if pc.Name == "" {
		return fmt.Errorf("name is required")
	}

	// Validate match criteria - must have at least one identifier.
	if !hasCriteria(pc.Match) {
		return fmt.Errorf("at least one match criterion is required (process_name, path, or bundle_id)")
	}

	// Validate default decision if specified.
	if pc.Default != "" {
		if !isValidDecision(pc.Default) {
			return fmt.Errorf("invalid default decision %q: must be one of allow, deny, approve, audit, allow_once_then_approve", pc.Default)
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
		if err := validateChildConfig(child); err != nil {
			return fmt.Errorf("child %d (%q): %w", i, child.Name, err)
		}
	}

	return nil
}

// validateChildConfig validates a child configuration.
func validateChildConfig(cc ChildConfig) error {
	if cc.Name == "" {
		return fmt.Errorf("name is required")
	}

	if !hasCriteria(cc.Match) {
		return fmt.Errorf("at least one match criterion is required (process_name, path, or bundle_id)")
	}

	for i, rule := range cc.Rules {
		if err := validateNetworkTarget(rule); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
	}

	return nil
}

// validateNetworkTarget validates a network target rule.
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
		return fmt.Errorf("invalid decision %q: must be one of allow, deny, approve, audit, allow_once_then_approve", t.Decision)
	}

	// Validate protocol if specified.
	if t.Protocol != "" && t.Protocol != "*" {
		proto := strings.ToLower(t.Protocol)
		if proto != "tcp" && proto != "udp" {
			return fmt.Errorf("invalid protocol %q: must be tcp, udp, or *", proto)
		}
	}

	// Validate IP address if specified.
	if t.IP != "" {
		if ip := net.ParseIP(t.IP); ip == nil {
			return fmt.Errorf("invalid IP address %q", t.IP)
		}
	}

	// Validate CIDR notation if specified.
	if t.CIDR != "" {
		if _, _, err := net.ParseCIDR(t.CIDR); err != nil {
			return fmt.Errorf("invalid CIDR notation %q: %w", t.CIDR, err)
		}
	}

	// Validate port specification if provided.
	if t.Port != "" && t.Port != "*" {
		if err := validatePortSpec(t.Port); err != nil {
			return fmt.Errorf("invalid port specification %q: %w", t.Port, err)
		}
	}

	return nil
}

// validatePortSpec validates a port specification string.
// Valid formats are: single port ("443"), range ("8000-9000"), or wildcard ("*").
func validatePortSpec(spec string) error {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "*" {
		return nil
	}

	// Check for range format.
	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid range format")
		}

		start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return fmt.Errorf("invalid range start: %w", err)
		}

		end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return fmt.Errorf("invalid range end: %w", err)
		}

		// Validate start <= end.
		if start > end {
			return fmt.Errorf("port range start (%d) must be less than or equal to end (%d)", start, end)
		}

		// Validate port bounds.
		if start < 1 || start > 65535 {
			return fmt.Errorf("port range start %d out of bounds (1-65535)", start)
		}
		if end < 1 || end > 65535 {
			return fmt.Errorf("port range end %d out of bounds (1-65535)", end)
		}

		return nil
	}

	// Single port.
	port, err := strconv.Atoi(spec)
	if err != nil {
		return fmt.Errorf("invalid port number: %w", err)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("port %d out of bounds (1-65535)", port)
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

// mergeProcessConfigs merges two process configurations.
func mergeProcessConfigs(base, overlay ProcessConfig) ProcessConfig {
	merged := ProcessConfig{
		Name:  base.Name,
		Match: base.Match,
	}

	// Override match criteria if specified in overlay.
	if hasCriteria(overlay.Match) {
		merged.Match = overlay.Match
	}

	// Override default if specified in overlay.
	if overlay.Default != "" {
		merged.Default = overlay.Default
	} else {
		merged.Default = base.Default
	}

	// Prepend overlay rules (higher priority).
	merged.Rules = make([]NetworkTarget, 0, len(overlay.Rules)+len(base.Rules))
	merged.Rules = append(merged.Rules, overlay.Rules...)
	merged.Rules = append(merged.Rules, base.Rules...)

	// Merge children.
	merged.Children = mergeChildConfigs(base.Children, overlay.Children)

	return merged
}

// mergeChildConfigs merges child configurations.
func mergeChildConfigs(base, overlay []ChildConfig) []ChildConfig {
	if len(overlay) == 0 {
		return base
	}
	if len(base) == 0 {
		return overlay
	}

	// Build map of base children by name.
	baseChildren := make(map[string]ChildConfig)
	for _, cc := range base {
		baseChildren[cc.Name] = cc
	}

	merged := make([]ChildConfig, 0)
	mergedNames := make(map[string]bool)

	// Add overlay children, merging with base if exists.
	for _, overlayCC := range overlay {
		if baseCC, exists := baseChildren[overlayCC.Name]; exists {
			mergedChild := ChildConfig{
				Name:    baseCC.Name,
				Match:   baseCC.Match,
				Inherit: baseCC.Inherit,
			}
			if hasCriteria(overlayCC.Match) {
				mergedChild.Match = overlayCC.Match
			}
			// Override inherit flag if overlay has rules or different inherit setting.
			if len(overlayCC.Rules) > 0 || overlayCC.Inherit != baseCC.Inherit {
				mergedChild.Inherit = overlayCC.Inherit
			}
			// Prepend overlay rules.
			mergedChild.Rules = append(overlayCC.Rules, baseCC.Rules...)
			merged = append(merged, mergedChild)
			mergedNames[overlayCC.Name] = true
		} else {
			merged = append(merged, overlayCC)
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

// Clone creates a deep copy of the NetworkACLConfig.
func (c *NetworkACLConfig) Clone() *NetworkACLConfig {
	if c == nil {
		return nil
	}

	return &NetworkACLConfig{
		NetworkACL: *c.NetworkACL.Clone(),
	}
}

// Clone creates a deep copy of the Config.
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

// Clone creates a deep copy of the ProcessConfig.
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

// Clone creates a deep copy of the ChildConfig.
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

// Validate validates the Config. This is a convenience method that wraps
// ValidateConfig for use when working directly with Config objects.
func (c *Config) Validate() error {
	return ValidateConfig(&NetworkACLConfig{NetworkACL: *c})
}
