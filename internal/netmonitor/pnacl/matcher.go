// Package pnacl provides Process Network ACL (PNACL) functionality for
// per-process network access control policies.
package pnacl

import (
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gobwas/glob"
)

// MatchMode specifies how process matching is performed.
type MatchMode string

const (
	// MatchModeFlexible allows partial matches (process name only).
	MatchModeFlexible MatchMode = "flexible"
	// MatchModeStrict requires all specified criteria to match.
	MatchModeStrict MatchMode = "strict"
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

// ProcessMatcher matches processes against criteria.
type ProcessMatcher struct {
	criteria ProcessMatchCriteria
	mode     MatchMode

	// Compiled patterns for efficient matching.
	pathGlob glob.Glob
}

// NewProcessMatcher creates a new process matcher from criteria.
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
		// Use '/' as separator for path matching.
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
		return m.matchStrict(info)
	}
	return m.matchFlexible(info)
}

// matchFlexible returns true if any specified criterion matches.
func (m *ProcessMatcher) matchFlexible(info ProcessInfo) bool {
	matched := false

	// Check process name.
	if m.criteria.ProcessName != "" {
		if matchProcessName(m.criteria.ProcessName, info.Name) {
			matched = true
		}
	}

	// Check path.
	if m.pathGlob != nil {
		if m.pathGlob.Match(info.Path) {
			matched = true
		}
	}

	// Check bundle ID (macOS).
	if m.criteria.BundleID != "" && info.BundleID != "" {
		if strings.EqualFold(m.criteria.BundleID, info.BundleID) {
			matched = true
		}
	}

	// Check package family name (Windows).
	if m.criteria.PackageFamilyName != "" && info.PackageFamilyName != "" {
		if strings.EqualFold(m.criteria.PackageFamilyName, info.PackageFamilyName) {
			matched = true
		}
	}

	// If no criteria were specified, don't match anything.
	if !hasCriteria(m.criteria) {
		return false
	}

	return matched
}

// matchStrict returns true only if all specified criteria match.
func (m *ProcessMatcher) matchStrict(info ProcessInfo) bool {
	// If no criteria are specified, don't match anything.
	if !hasCriteria(m.criteria) {
		return false
	}

	// Check process name if specified.
	if m.criteria.ProcessName != "" {
		if !matchProcessName(m.criteria.ProcessName, info.Name) {
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

// matchProcessName matches a process name against a pattern.
// Supports both exact match and basename extraction.
func matchProcessName(pattern, name string) bool {
	// Normalize to lowercase for comparison.
	pattern = strings.ToLower(pattern)
	name = strings.ToLower(name)

	// Direct match.
	if pattern == name {
		return true
	}

	// Match against basename (for paths passed as names).
	basename := strings.ToLower(filepath.Base(name))
	if pattern == basename {
		return true
	}

	// On Windows, also try without .exe extension.
	if runtime.GOOS == "windows" {
		withoutExt := strings.TrimSuffix(basename, ".exe")
		if pattern == withoutExt {
			return true
		}
	}

	return false
}

// hasCriteria returns true if at least one matching criterion is specified.
func hasCriteria(c ProcessMatchCriteria) bool {
	return c.ProcessName != "" ||
		c.Path != "" ||
		c.BundleID != "" ||
		c.PackageFamilyName != ""
}

// Mode returns the matching mode for this matcher.
func (m *ProcessMatcher) Mode() MatchMode {
	return m.mode
}

// Criteria returns the match criteria for this matcher.
func (m *ProcessMatcher) Criteria() ProcessMatchCriteria {
	return m.criteria
}
