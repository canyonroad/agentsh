package identity

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuiltinIdentities_Defined(t *testing.T) {
	// Verify essential identities are defined
	essentialIdentities := []string{
		"cursor",
		"vscode",
		"claude-desktop",
		"aider",
	}

	for _, name := range essentialIdentities {
		t.Run(name, func(t *testing.T) {
			identity, ok := BuiltinIdentities[name]
			assert.True(t, ok, "identity %q should be defined", name)
			assert.Equal(t, name, identity.Name)
			assert.NotEmpty(t, identity.Description)
		})
	}
}

func TestBuiltinIdentities_HavePlatformMatches(t *testing.T) {
	for name, identity := range BuiltinIdentities {
		t.Run(name, func(t *testing.T) {
			// Each identity should have at least one platform match
			hasMatch := identity.Linux != nil ||
				identity.Darwin != nil ||
				identity.Windows != nil ||
				identity.AllPlatforms != nil
			assert.True(t, hasMatch, "identity %q should have platform matches", name)

			// GetPlatformMatch should return something
			pm := identity.GetPlatformMatch()
			if pm != nil {
				assert.False(t, pm.IsEmpty(), "identity %q platform match should not be empty", name)
			}
		})
	}
}

func TestLoadBuiltinIdentities(t *testing.T) {
	m := NewProcessMatcher()

	err := LoadBuiltinIdentities(m)
	require.NoError(t, err)

	// Should have loaded all built-in identities
	identities := m.ListIdentities()
	assert.Len(t, identities, len(BuiltinIdentities))

	// Verify a few specific ones
	_, ok := m.GetIdentity("cursor")
	assert.True(t, ok)

	_, ok = m.GetIdentity("vscode")
	assert.True(t, ok)
}

func TestNewMatcherWithBuiltins(t *testing.T) {
	m, err := NewMatcherWithBuiltins()
	require.NoError(t, err)
	require.NotNil(t, m)

	// Should have all built-in identities
	assert.Len(t, m.ListIdentities(), len(BuiltinIdentities))
}

func TestBuiltinIdentities_CursorMatching(t *testing.T) {
	m, err := NewMatcherWithBuiltins()
	require.NoError(t, err)

	tests := []struct {
		name string
		info *ProcessInfo
		want bool
	}{
		{
			name: "cursor comm",
			info: &ProcessInfo{Comm: "cursor"},
			want: true,
		},
		{
			name: "Cursor comm",
			info: &ProcessInfo{Comm: "Cursor"},
			want: true,
		},
		{
			name: "cursor exe path linux",
			info: &ProcessInfo{ExePath: "/usr/bin/cursor"},
			want: true,
		},
		{
			name: "bash",
			info: &ProcessInfo{Comm: "bash"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := m.MatchesIdentity(tt.info, "cursor")
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestBuiltinIdentities_VSCodeMatching(t *testing.T) {
	m, err := NewMatcherWithBuiltins()
	require.NoError(t, err)

	tests := []struct {
		name string
		info *ProcessInfo
		want bool
	}{
		{
			name: "code comm",
			info: &ProcessInfo{Comm: "code"},
			want: true,
		},
		{
			name: "code-oss comm",
			info: &ProcessInfo{Comm: "code-oss"},
			want: true,
		},
		// Note: "Code" with capital C is macOS-specific (from Darwin.Comm)
		// On Linux, the comm is lowercase "code"
		{
			name: "vscode exe path",
			info: &ProcessInfo{ExePath: "/usr/share/vscode/code"},
			want: true,
		},
		{
			name: "vim",
			info: &ProcessInfo{Comm: "vim"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := m.MatchesIdentity(tt.info, "vscode")
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestBuiltinIdentities_AiderMatching(t *testing.T) {
	m, err := NewMatcherWithBuiltins()
	require.NoError(t, err)

	tests := []struct {
		name string
		info *ProcessInfo
		want bool
	}{
		{
			name: "aider comm",
			info: &ProcessInfo{Comm: "aider"},
			want: true,
		},
		{
			name: "aider-chat comm",
			info: &ProcessInfo{Comm: "aider-chat"},
			want: true,
		},
		{
			name: "python with aider in cmdline",
			info: &ProcessInfo{Comm: "python", Cmdline: []string{"python", "-m", "aider"}},
			want: true,
		},
		{
			name: "bash",
			info: &ProcessInfo{Comm: "bash"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := m.MatchesIdentity(tt.info, "aider")
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestBuiltinIdentities_MultipleMatches(t *testing.T) {
	m, err := NewMatcherWithBuiltins()
	require.NoError(t, err)

	// Process that doesn't match anything
	matches := m.Matches(&ProcessInfo{Comm: "bash"})
	assert.Empty(t, matches)

	// Process that matches cursor
	matches = m.Matches(&ProcessInfo{Comm: "cursor"})
	assert.Contains(t, matches, "cursor")
}
