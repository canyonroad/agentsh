// Package identity provides cross-platform process identification.
// It defines how to match processes by name, path, and other attributes
// across different operating systems.
package identity

import (
	"runtime"
	"sync"

	"github.com/agentsh/agentsh/internal/policy/pattern"
)

// ProcessIdentity defines how to identify a process across platforms.
type ProcessIdentity struct {
	Name        string `yaml:"name"`        // Identifier for this process identity
	Description string `yaml:"description"` // Human-readable description

	// Platform-specific matching rules
	Linux   *PlatformMatch `yaml:"linux,omitempty"`
	Darwin  *PlatformMatch `yaml:"darwin,omitempty"`
	Windows *PlatformMatch `yaml:"windows,omitempty"`

	// AllPlatforms is applied to all platforms as a fallback
	AllPlatforms *PlatformMatch `yaml:"all_platforms,omitempty"`
}

// PlatformMatch defines matching rules for a specific platform.
type PlatformMatch struct {
	// Comm matches the process name (comm field on Linux, p_comm on macOS).
	// These are exact strings or patterns.
	Comm []string `yaml:"comm,omitempty"`

	// ExePath matches the full executable path.
	// Useful for distinguishing between processes with the same name.
	ExePath []string `yaml:"exe_path,omitempty"`

	// Cmdline patterns match against the full command line.
	// Use with caution - cmdline can be spoofed.
	Cmdline []string `yaml:"cmdline,omitempty"`

	// BundleID is macOS-specific: matches the app bundle identifier.
	// Example: "com.cursor.Cursor"
	BundleID []string `yaml:"bundle_id,omitempty"`

	// ExeName is Windows-specific: matches just the executable name
	// without path (e.g., "cursor.exe").
	ExeName []string `yaml:"exe_name,omitempty"`
}

// ProcessInfo contains information about a process used for matching.
type ProcessInfo struct {
	PID      int
	PPID     int
	Comm     string   // Process name (from /proc/PID/comm or equivalent)
	ExePath  string   // Full path to executable
	Cmdline  []string // Command line arguments
	BundleID string   // macOS bundle identifier (if available)
}

// currentPlatform returns the current platform for matching.
func currentPlatform() string {
	return runtime.GOOS
}

// GetPlatformMatch returns the appropriate PlatformMatch for the current platform.
func (pi *ProcessIdentity) GetPlatformMatch() *PlatformMatch {
	var pm *PlatformMatch

	switch currentPlatform() {
	case "linux":
		pm = pi.Linux
	case "darwin":
		pm = pi.Darwin
	case "windows":
		pm = pi.Windows
	}

	// Merge with AllPlatforms if both exist
	if pm != nil && pi.AllPlatforms != nil {
		merged := pm.Merge(pi.AllPlatforms)
		return merged
	}

	// Use AllPlatforms as fallback if platform-specific not defined
	if pm == nil && pi.AllPlatforms != nil {
		return pi.AllPlatforms
	}

	return pm
}

// Merge combines two PlatformMatch structs, with the receiver taking precedence.
func (pm *PlatformMatch) Merge(other *PlatformMatch) *PlatformMatch {
	if pm == nil {
		return other
	}
	if other == nil {
		return pm
	}

	return &PlatformMatch{
		Comm:     append(append([]string{}, pm.Comm...), other.Comm...),
		ExePath:  append(append([]string{}, pm.ExePath...), other.ExePath...),
		Cmdline:  append(append([]string{}, pm.Cmdline...), other.Cmdline...),
		BundleID: append(append([]string{}, pm.BundleID...), other.BundleID...),
		ExeName:  append(append([]string{}, pm.ExeName...), other.ExeName...),
	}
}

// IsEmpty checks if the PlatformMatch has no patterns defined.
func (pm *PlatformMatch) IsEmpty() bool {
	if pm == nil {
		return true
	}
	return len(pm.Comm) == 0 &&
		len(pm.ExePath) == 0 &&
		len(pm.Cmdline) == 0 &&
		len(pm.BundleID) == 0 &&
		len(pm.ExeName) == 0
}

// ProcessMatcher matches processes against a set of identities.
type ProcessMatcher struct {
	mu         sync.RWMutex
	identities map[string]*ProcessIdentity
	compiled   map[string]*compiledIdentity
	registry   *pattern.ClassRegistry
}

// compiledIdentity holds pre-compiled patterns for an identity.
type compiledIdentity struct {
	comm     *pattern.PatternSet
	exePath  *pattern.PatternSet
	cmdline  *pattern.PatternSet
	bundleID *pattern.PatternSet
	exeName  *pattern.PatternSet
}

// NewProcessMatcher creates a new process matcher.
func NewProcessMatcher() *ProcessMatcher {
	return &ProcessMatcher{
		identities: make(map[string]*ProcessIdentity),
		compiled:   make(map[string]*compiledIdentity),
		registry:   pattern.NewClassRegistry(),
	}
}

// NewProcessMatcherWithRegistry creates a matcher with a custom class registry.
func NewProcessMatcherWithRegistry(registry *pattern.ClassRegistry) *ProcessMatcher {
	return &ProcessMatcher{
		identities: make(map[string]*ProcessIdentity),
		compiled:   make(map[string]*compiledIdentity),
		registry:   registry,
	}
}

// AddIdentity adds a process identity to the matcher.
func (m *ProcessMatcher) AddIdentity(id *ProcessIdentity) error {
	if id.Name == "" {
		return ErrEmptyName
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.identities[id.Name] = id
	delete(m.compiled, id.Name) // Invalidate cache

	return nil
}

// RemoveIdentity removes a process identity from the matcher.
func (m *ProcessMatcher) RemoveIdentity(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.identities, name)
	delete(m.compiled, name)
}

// GetIdentity returns an identity by name.
func (m *ProcessMatcher) GetIdentity(name string) (*ProcessIdentity, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	id, ok := m.identities[name]
	return id, ok
}

// ListIdentities returns all identity names.
func (m *ProcessMatcher) ListIdentities() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.identities))
	for name := range m.identities {
		names = append(names, name)
	}
	return names
}

// Matches checks which identities match the given process info.
// Returns a list of matching identity names.
func (m *ProcessMatcher) Matches(info *ProcessInfo) []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	var matches []string
	resolver := m.registry.GetResolver()

	for name, identity := range m.identities {
		compiled, err := m.getCompiled(name, identity)
		if err != nil {
			continue
		}

		if m.matchesCompiled(info, compiled, resolver) {
			matches = append(matches, name)
		}
	}

	return matches
}

// MatchesIdentity checks if a process matches a specific identity.
func (m *ProcessMatcher) MatchesIdentity(info *ProcessInfo, name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	identity, ok := m.identities[name]
	if !ok {
		return false
	}

	compiled, err := m.getCompiled(name, identity)
	if err != nil {
		return false
	}

	return m.matchesCompiled(info, compiled, m.registry.GetResolver())
}

// getCompiled returns the compiled patterns for an identity, compiling if needed.
// Caller must hold the lock.
func (m *ProcessMatcher) getCompiled(name string, identity *ProcessIdentity) (*compiledIdentity, error) {
	if compiled, ok := m.compiled[name]; ok {
		return compiled, nil
	}

	compiled, err := m.compileIdentity(identity)
	if err != nil {
		return nil, err
	}

	m.compiled[name] = compiled
	return compiled, nil
}

// compileIdentity compiles the patterns for an identity.
func (m *ProcessMatcher) compileIdentity(identity *ProcessIdentity) (*compiledIdentity, error) {
	pm := identity.GetPlatformMatch()
	if pm == nil || pm.IsEmpty() {
		return &compiledIdentity{}, nil
	}

	compiled := &compiledIdentity{}
	var err error

	if len(pm.Comm) > 0 {
		compiled.comm, err = pattern.NewPatternSet(pm.Comm)
		if err != nil {
			return nil, err
		}
	}

	if len(pm.ExePath) > 0 {
		compiled.exePath, err = pattern.NewPatternSet(pm.ExePath)
		if err != nil {
			return nil, err
		}
	}

	if len(pm.Cmdline) > 0 {
		compiled.cmdline, err = pattern.NewPatternSet(pm.Cmdline)
		if err != nil {
			return nil, err
		}
	}

	if len(pm.BundleID) > 0 {
		compiled.bundleID, err = pattern.NewPatternSet(pm.BundleID)
		if err != nil {
			return nil, err
		}
	}

	if len(pm.ExeName) > 0 {
		compiled.exeName, err = pattern.NewPatternSet(pm.ExeName)
		if err != nil {
			return nil, err
		}
	}

	return compiled, nil
}

// matchesCompiled checks if process info matches compiled patterns.
func (m *ProcessMatcher) matchesCompiled(info *ProcessInfo, compiled *compiledIdentity, resolver func(string) ([]string, error)) bool {
	// Match comm
	if compiled.comm != nil && compiled.comm.Len() > 0 {
		match, _ := compiled.comm.MatchAnyWithResolver(info.Comm, resolver)
		if match {
			return true
		}
	}

	// Match exe path
	if compiled.exePath != nil && compiled.exePath.Len() > 0 {
		match, _ := compiled.exePath.MatchAnyWithResolver(info.ExePath, resolver)
		if match {
			return true
		}
	}

	// Match cmdline (join arguments)
	if compiled.cmdline != nil && compiled.cmdline.Len() > 0 && len(info.Cmdline) > 0 {
		for _, arg := range info.Cmdline {
			match, _ := compiled.cmdline.MatchAnyWithResolver(arg, resolver)
			if match {
				return true
			}
		}
	}

	// Match bundle ID (macOS)
	if compiled.bundleID != nil && compiled.bundleID.Len() > 0 && info.BundleID != "" {
		match, _ := compiled.bundleID.MatchAnyWithResolver(info.BundleID, resolver)
		if match {
			return true
		}
	}

	// Match exe name (Windows - extract from exe path)
	if compiled.exeName != nil && compiled.exeName.Len() > 0 && info.ExePath != "" {
		exeName := extractExeName(info.ExePath)
		match, _ := compiled.exeName.MatchAnyWithResolver(exeName, resolver)
		if match {
			return true
		}
	}

	return false
}

// extractExeName extracts the executable name from a path.
func extractExeName(path string) string {
	// Handle both forward and back slashes
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[i+1:]
		}
	}
	return path
}

// ClassRegistry returns the class registry used by this matcher.
func (m *ProcessMatcher) ClassRegistry() *pattern.ClassRegistry {
	return m.registry
}

// Clear removes all identities from the matcher.
func (m *ProcessMatcher) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.identities = make(map[string]*ProcessIdentity)
	m.compiled = make(map[string]*compiledIdentity)
}
