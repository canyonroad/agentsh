// Package pnacl provides Process Network ACL (PNACL) functionality for
// per-process network access control policies.
package pnacl

import (
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/gobwas/glob"
)

// MatchMode specifies how process matching is performed.
type MatchMode string

const (
	// MatchModeFlexible allows partial matches (any criterion matching is sufficient).
	MatchModeFlexible MatchMode = "flexible"
	// MatchModeStrict requires all specified criteria to match.
	MatchModeStrict MatchMode = "strict"
)

// MatchSpecificity represents how specific a match is, used for prioritization.
type MatchSpecificity int

const (
	// MatchSpecificityNone indicates no match.
	MatchSpecificityNone MatchSpecificity = iota
	// MatchSpecificityDefault indicates a default/fallback match.
	MatchSpecificityDefault
	// MatchSpecificityGlob indicates a glob pattern match.
	MatchSpecificityGlob
	// MatchSpecificityExact indicates an exact match.
	MatchSpecificityExact
)

// ProcessInfo contains information about a process for matching purposes.
type ProcessInfo struct {
	// Name is the process name (e.g., "claude-code").
	Name string
	// Path is the full executable path (e.g., "/usr/bin/claude-code").
	Path string
	// BundleID is the macOS bundle identifier (e.g., "com.anthropic.claudecode").
	BundleID string
	// PackageFamilyName is the Windows package family name.
	PackageFamilyName string
	// PID is the process ID.
	PID int
	// ParentPID is the parent process ID.
	ParentPID int
}

// ProcessMatchCriteria defines criteria for matching a process.
type ProcessMatchCriteria struct {
	// ProcessName is the process name to match (e.g., "claude-code").
	ProcessName string `yaml:"process_name,omitempty"`
	// Path is the executable path pattern with glob support (e.g., "/usr/bin/claude*").
	Path string `yaml:"path,omitempty"`
	// BundleID is the macOS bundle identifier (e.g., "com.anthropic.claudecode").
	BundleID string `yaml:"bundle_id,omitempty"`
	// PackageFamilyName is the Windows package family name.
	PackageFamilyName string `yaml:"package_family_name,omitempty"`
	// Strict enables strict matching mode where all specified criteria must match.
	Strict bool `yaml:"strict,omitempty"`
}

// MatcherConnectionContext provides context for matching a network connection to a process policy.
// This type is used by ConfigMatcher.Match() and contains both process and connection information.
type MatcherConnectionContext struct {
	// Process contains information about the process making the connection.
	Process ProcessInfo
	// Host is the target hostname (may be empty if connecting by IP).
	Host string
	// Port is the target port number.
	Port int
	// Protocol is the connection protocol (e.g., "tcp", "udp").
	Protocol string
}

// MatchedProcessACL represents the resolved ACL configuration for a matched process.
// It contains the policy details that should be applied to the process's connections.
type MatchedProcessACL struct {
	// Name is the human-readable name for this process policy.
	Name string
	// Match contains the criteria that matched this process.
	Match ProcessMatchCriteria
	// Default is the default decision for this process's connections.
	Default Decision
	// Rules are the network rules for this process.
	Rules []NetworkTarget
	// Children are the child process configurations.
	Children []ChildConfig
	// Specificity indicates how specific this match is.
	Specificity MatchSpecificity
}

// ProcessMatcher matches processes against a single set of criteria.
// This is the original simple matcher for single-process matching.
type ProcessMatcher struct {
	criteria ProcessMatchCriteria
	mode     MatchMode
	pathGlob glob.Glob
}

// NewProcessMatcher creates a new ProcessMatcher from criteria.
// This is the original constructor for backward compatibility.
func NewProcessMatcher(criteria ProcessMatchCriteria) (*ProcessMatcher, error) {
	m := &ProcessMatcher{
		criteria: criteria,
		mode:     MatchModeFlexible,
	}

	if criteria.Strict {
		m.mode = MatchModeStrict
	}

	// Compile path glob if specified.
	if criteria.Path != "" {
		g, err := glob.Compile(criteria.Path, '/')
		if err != nil {
			return nil, err
		}
		m.pathGlob = g
	}

	return m, nil
}

// Matches checks if the given process info matches this matcher's criteria.
func (m *ProcessMatcher) Matches(info ProcessInfo) bool {
	if m.mode == MatchModeStrict {
		return m.matchStrictSimple(info)
	}
	return m.matchFlexibleSimple(info)
}

// matchFlexibleSimple returns true if any specified criterion matches.
func (m *ProcessMatcher) matchFlexibleSimple(info ProcessInfo) bool {
	// If no criteria are specified, don't match anything.
	if !hasCriteria(m.criteria) {
		return false
	}

	// Check process name.
	if m.criteria.ProcessName != "" {
		if matchProcessName(m.criteria.ProcessName, info.Name, false) {
			return true
		}
	}

	// Check path.
	if m.pathGlob != nil {
		if m.pathGlob.Match(info.Path) {
			return true
		}
	}

	// Check bundle ID (macOS).
	if m.criteria.BundleID != "" && info.BundleID != "" {
		if strings.EqualFold(m.criteria.BundleID, info.BundleID) {
			return true
		}
	}

	// Check package family name (Windows).
	if m.criteria.PackageFamilyName != "" && info.PackageFamilyName != "" {
		if strings.EqualFold(m.criteria.PackageFamilyName, info.PackageFamilyName) {
			return true
		}
	}

	return false
}

// matchStrictSimple returns true only if all specified criteria match.
func (m *ProcessMatcher) matchStrictSimple(info ProcessInfo) bool {
	// If no criteria are specified, don't match anything.
	if !hasCriteria(m.criteria) {
		return false
	}

	// Check process name if specified.
	if m.criteria.ProcessName != "" {
		if !matchProcessName(m.criteria.ProcessName, info.Name, true) {
			return false
		}
	}

	// Check path if specified.
	if m.pathGlob != nil {
		if !m.pathGlob.Match(info.Path) {
			return false
		}
	}

	// Check bundle ID if specified.
	if m.criteria.BundleID != "" {
		if !strings.EqualFold(m.criteria.BundleID, info.BundleID) {
			return false
		}
	}

	// Check package family name if specified.
	if m.criteria.PackageFamilyName != "" {
		if !strings.EqualFold(m.criteria.PackageFamilyName, info.PackageFamilyName) {
			return false
		}
	}

	return true
}

// Mode returns the matching mode for this matcher.
func (m *ProcessMatcher) Mode() MatchMode {
	return m.mode
}

// Criteria returns the match criteria for this matcher.
func (m *ProcessMatcher) Criteria() ProcessMatchCriteria {
	return m.criteria
}

// ConfigMatcher matches processes against a full configuration and returns the
// appropriate ProcessACL for network policy evaluation.
// ConfigMatcher is safe for concurrent use.
type ConfigMatcher struct {
	mu sync.RWMutex

	// config is the underlying network ACL configuration.
	config *Config

	// compiledMatchers caches compiled matchers for each process config.
	compiledMatchers []*compiledConfigMatcher
}

// compiledConfigMatcher contains a pre-compiled matcher for a process config.
type compiledConfigMatcher struct {
	config   ProcessConfig
	pathGlob glob.Glob
}

// NewConfigMatcher creates a new ConfigMatcher from a NetworkACLConfig.
// Returns an error if the configuration contains invalid patterns.
func NewConfigMatcher(config *NetworkACLConfig) (*ConfigMatcher, error) {
	if config == nil {
		return &ConfigMatcher{
			config:           &Config{},
			compiledMatchers: nil,
		}, nil
	}

	return NewConfigMatcherFromConfig(&config.NetworkACL)
}

// NewConfigMatcherFromConfig creates a new ConfigMatcher from a Config.
// Returns an error if the configuration contains invalid patterns.
func NewConfigMatcherFromConfig(config *Config) (*ConfigMatcher, error) {
	if config == nil {
		return &ConfigMatcher{
			config:           &Config{},
			compiledMatchers: nil,
		}, nil
	}

	m := &ConfigMatcher{
		config:           config,
		compiledMatchers: make([]*compiledConfigMatcher, 0, len(config.Processes)),
	}

	// Pre-compile all matchers for efficient matching.
	for _, pc := range config.Processes {
		cm := &compiledConfigMatcher{
			config: pc,
		}

		// Compile path glob if specified.
		if pc.Match.Path != "" {
			g, err := glob.Compile(pc.Match.Path, '/')
			if err != nil {
				return nil, err
			}
			cm.pathGlob = g
		}

		m.compiledMatchers = append(m.compiledMatchers, cm)
	}

	return m, nil
}

// Match finds the most specific matching process configuration for the given connection context.
// Returns the MatchedProcessACL and true if a match is found, or nil and false if no match.
// The matcher returns the most specific match: exact name > glob > default.
func (m *ConfigMatcher) Match(ctx MatcherConnectionContext) (*MatchedProcessACL, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.config == nil || len(m.compiledMatchers) == 0 {
		return nil, false
	}

	var bestMatch *MatchedProcessACL
	var bestSpecificity MatchSpecificity = MatchSpecificityNone

	for _, cm := range m.compiledMatchers {
		matched, specificity := m.matchProcess(cm, ctx.Process)
		if !matched {
			continue
		}

		// Keep track of the most specific match.
		if specificity > bestSpecificity {
			bestMatch = &MatchedProcessACL{
				Name:        cm.config.Name,
				Match:       cm.config.Match,
				Default:     Decision(cm.config.Default),
				Rules:       cm.config.Rules,
				Children:    cm.config.Children,
				Specificity: specificity,
			}
			bestSpecificity = specificity
		}
	}

	if bestMatch == nil {
		return nil, false
	}

	return bestMatch, true
}

// Matches checks if the given process info matches any configuration in the matcher.
// This is a convenience method that wraps Match() for simple process matching.
func (m *ConfigMatcher) Matches(info ProcessInfo) bool {
	_, found := m.Match(MatcherConnectionContext{Process: info})
	return found
}

// matchProcess checks if a process matches the compiled matcher and returns the specificity.
func (m *ConfigMatcher) matchProcess(cm *compiledConfigMatcher, info ProcessInfo) (bool, MatchSpecificity) {
	criteria := cm.config.Match
	strict := criteria.Strict

	if strict {
		return m.matchStrict(cm, info)
	}
	return m.matchFlexible(cm, info)
}

// matchFlexible returns true if any specified criterion matches (OR semantics).
// Returns the highest specificity among all matched criteria.
func (m *ConfigMatcher) matchFlexible(cm *compiledConfigMatcher, info ProcessInfo) (bool, MatchSpecificity) {
	criteria := cm.config.Match

	// If no criteria are specified, don't match anything.
	if !hasCriteria(criteria) {
		return false, MatchSpecificityNone
	}

	var maxSpecificity MatchSpecificity = MatchSpecificityNone
	matched := false

	// Check process name.
	if criteria.ProcessName != "" {
		if nameMatched, spec := matchProcessNameWithSpecificity(criteria.ProcessName, info.Name, false); nameMatched {
			matched = true
			if spec > maxSpecificity {
				maxSpecificity = spec
			}
		}
	}

	// Check path.
	if cm.pathGlob != nil {
		if matchPath(criteria.Path, info.Path) {
			matched = true
			spec := determinePathSpecificity(criteria.Path)
			if spec > maxSpecificity {
				maxSpecificity = spec
			}
		}
	}

	// Check bundle ID (macOS).
	if criteria.BundleID != "" && info.BundleID != "" {
		if matchBundleID(criteria.BundleID, info.BundleID) {
			matched = true
			if MatchSpecificityExact > maxSpecificity {
				maxSpecificity = MatchSpecificityExact
			}
		}
	}

	// Check package family name (Windows).
	if criteria.PackageFamilyName != "" && info.PackageFamilyName != "" {
		if strings.EqualFold(criteria.PackageFamilyName, info.PackageFamilyName) {
			matched = true
			if MatchSpecificityExact > maxSpecificity {
				maxSpecificity = MatchSpecificityExact
			}
		}
	}

	return matched, maxSpecificity
}

// matchStrict returns true only if all specified criteria match (AND semantics).
func (m *ConfigMatcher) matchStrict(cm *compiledConfigMatcher, info ProcessInfo) (bool, MatchSpecificity) {
	criteria := cm.config.Match

	// If no criteria are specified, don't match anything.
	if !hasCriteria(criteria) {
		return false, MatchSpecificityNone
	}

	var minSpecificity MatchSpecificity = MatchSpecificityExact

	// Check process name if specified.
	if criteria.ProcessName != "" {
		if matched, spec := matchProcessNameWithSpecificity(criteria.ProcessName, info.Name, true); !matched {
			return false, MatchSpecificityNone
		} else if spec < minSpecificity {
			minSpecificity = spec
		}
	}

	// Check path if specified.
	if cm.pathGlob != nil {
		if !matchPath(criteria.Path, info.Path) {
			return false, MatchSpecificityNone
		}
		spec := determinePathSpecificity(criteria.Path)
		if spec < minSpecificity {
			minSpecificity = spec
		}
	}

	// Check bundle ID if specified.
	if criteria.BundleID != "" {
		if !matchBundleID(criteria.BundleID, info.BundleID) {
			return false, MatchSpecificityNone
		}
	}

	// Check package family name if specified.
	if criteria.PackageFamilyName != "" {
		if !strings.EqualFold(criteria.PackageFamilyName, info.PackageFamilyName) {
			return false, MatchSpecificityNone
		}
	}

	return true, minSpecificity
}

// matchProcessName matches a process name against a pattern.
// When strict is false, it supports both exact match and basename extraction.
// When strict is true, it requires an exact match (case-insensitive).
func matchProcessName(pattern, name string, strict bool) bool {
	matched, _ := matchProcessNameWithSpecificity(pattern, name, strict)
	return matched
}

// matchProcessNameWithSpecificity matches a process name and returns specificity.
func matchProcessNameWithSpecificity(pattern, name string, strict bool) (bool, MatchSpecificity) {
	// Normalize to lowercase for comparison.
	pattern = strings.ToLower(pattern)
	name = strings.ToLower(name)

	// Direct match (highest specificity).
	if pattern == name {
		return true, MatchSpecificityExact
	}

	// In strict mode, only exact match is allowed.
	if strict {
		return false, MatchSpecificityNone
	}

	// Match against basename (for paths passed as names).
	basename := strings.ToLower(filepath.Base(name))
	if pattern == basename {
		return true, MatchSpecificityExact
	}

	// On Windows, also try without .exe extension.
	if runtime.GOOS == "windows" {
		withoutExt := strings.TrimSuffix(basename, ".exe")
		if pattern == withoutExt {
			return true, MatchSpecificityExact
		}
	}

	// Check if pattern contains wildcards for glob-like matching.
	if strings.ContainsAny(pattern, "*?") {
		// Use filepath.Match for simple glob patterns in process names.
		if matched, _ := filepath.Match(pattern, name); matched {
			return true, MatchSpecificityGlob
		}
		if matched, _ := filepath.Match(pattern, basename); matched {
			return true, MatchSpecificityGlob
		}
	}

	return false, MatchSpecificityNone
}

// matchPath matches a path against a pattern with glob support.
// The pattern can contain wildcards like * and **.
func matchPath(pattern, path string) bool {
	if pattern == "" || path == "" {
		return false
	}

	// Use the gobwas/glob library for advanced glob matching.
	g, err := glob.Compile(pattern, '/')
	if err != nil {
		return false
	}

	return g.Match(path)
}

// matchBundleID matches a bundle ID pattern against a bundle ID.
// On macOS, bundle IDs are case-insensitive.
func matchBundleID(pattern, bundleID string) bool {
	if pattern == "" || bundleID == "" {
		return false
	}

	// Exact match (case-insensitive).
	return strings.EqualFold(pattern, bundleID)
}

// determinePathSpecificity determines the specificity of a path pattern.
func determinePathSpecificity(pattern string) MatchSpecificity {
	if pattern == "" {
		return MatchSpecificityNone
	}

	// Check if pattern contains glob characters.
	if strings.ContainsAny(pattern, "*?[]{}") {
		return MatchSpecificityGlob
	}

	return MatchSpecificityExact
}

// hasCriteria returns true if at least one matching criterion is specified.
func hasCriteria(c ProcessMatchCriteria) bool {
	return c.ProcessName != "" ||
		c.Path != "" ||
		c.BundleID != "" ||
		c.PackageFamilyName != ""
}

// Config returns a copy of the underlying configuration.
// This method is safe for concurrent use.
func (m *ConfigMatcher) Config() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.config == nil {
		return nil
	}

	return m.config.Clone()
}

// UpdateConfig replaces the configuration and recompiles all matchers.
// This method is safe for concurrent use.
func (m *ConfigMatcher) UpdateConfig(config *Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if config == nil {
		m.config = &Config{}
		m.compiledMatchers = nil
		return nil
	}

	// Compile new matchers.
	newMatchers := make([]*compiledConfigMatcher, 0, len(config.Processes))
	for _, pc := range config.Processes {
		cm := &compiledConfigMatcher{
			config: pc,
		}

		if pc.Match.Path != "" {
			g, err := glob.Compile(pc.Match.Path, '/')
			if err != nil {
				return err
			}
			cm.pathGlob = g
		}

		newMatchers = append(newMatchers, cm)
	}

	m.config = config
	m.compiledMatchers = newMatchers
	return nil
}

// MatchChild finds a matching child configuration within a MatchedProcessACL.
// Returns the ChildConfig and true if a match is found, or nil and false otherwise.
func (m *ConfigMatcher) MatchChild(acl *MatchedProcessACL, childInfo ProcessInfo) (*ChildConfig, bool) {
	if acl == nil || len(acl.Children) == 0 {
		return nil, false
	}

	for i := range acl.Children {
		child := &acl.Children[i]

		// Create a temporary matcher for the child criteria.
		cm := &compiledConfigMatcher{
			config: ProcessConfig{
				Match: child.Match,
			},
		}

		// Compile path glob if specified.
		if child.Match.Path != "" {
			g, err := glob.Compile(child.Match.Path, '/')
			if err != nil {
				continue
			}
			cm.pathGlob = g
		}

		if matched, _ := m.matchFlexible(cm, childInfo); matched {
			return child, true
		}
	}

	return nil, false
}

// GetDefaultDecision returns the global default decision from the configuration.
func (m *ConfigMatcher) GetDefaultDecision() Decision {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.config == nil || m.config.Default == "" {
		return DecisionDeny
	}

	return Decision(m.config.Default)
}

// ProcessCount returns the number of process configurations.
func (m *ConfigMatcher) ProcessCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.compiledMatchers)
}
