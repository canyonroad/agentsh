package identity

import (
	"runtime"
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

	// Platform-specific test cases
	// Linux patterns: Comm: []string{"cursor", "Cursor"}, ExePath: []string{"*/cursor", "*/Cursor"}
	// Darwin patterns: Comm: []string{"Cursor", "Cursor Helper*"}, ExePath: []string{"*/Cursor.app/*"}
	// Windows patterns: ExeName: []string{"Cursor.exe", "cursor.exe"}, ExePath: []string{"*\\Cursor\\*"}

	tests := []struct {
		name     string
		info     *ProcessInfo
		want     bool
		platform string // empty means all platforms
	}{
		{
			name:     "cursor comm lowercase",
			info:     &ProcessInfo{Comm: "cursor"},
			want:     true,
			platform: "linux", // only Linux has lowercase "cursor" in Comm
		},
		{
			name: "Cursor comm capitalized",
			info: &ProcessInfo{Comm: "Cursor"},
			want: true, // works on both Linux and Darwin
		},
		{
			name:     "cursor exe path linux",
			info:     &ProcessInfo{ExePath: "/usr/bin/cursor"},
			want:     true,
			platform: "linux",
		},
		{
			name:     "cursor exe path darwin",
			info:     &ProcessInfo{ExePath: "/Applications/Cursor.app/Contents/MacOS/Cursor"},
			want:     true,
			platform: "darwin",
		},
		{
			name:     "cursor exe path windows",
			info:     &ProcessInfo{ExePath: "C:\\Users\\test\\AppData\\Local\\Cursor\\Cursor.exe"},
			want:     true,
			platform: "windows",
		},
		{
			name: "bash",
			info: &ProcessInfo{Comm: "bash"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.platform != "" && tt.platform != runtime.GOOS {
				t.Skipf("skipping %s-specific test on %s", tt.platform, runtime.GOOS)
			}
			result := m.MatchesIdentity(tt.info, "cursor")
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestBuiltinIdentities_VSCodeMatching(t *testing.T) {
	m, err := NewMatcherWithBuiltins()
	require.NoError(t, err)

	// Platform-specific test cases
	// Linux patterns: Comm: []string{"code", "code-oss"}, ExePath: []string{"*/code", "*/code-oss", "*/vscode/*"}
	// Darwin patterns: Comm: []string{"Code", "Code Helper*"}, ExePath: []string{"*/Visual Studio Code.app/*", "*/VSCode.app/*"}
	// Windows patterns: ExeName: []string{"Code.exe", "code.exe"}, ExePath: []string{"*\\Microsoft VS Code\\*"}

	tests := []struct {
		name     string
		info     *ProcessInfo
		want     bool
		platform string // empty means all platforms
	}{
		{
			name:     "code comm lowercase",
			info:     &ProcessInfo{Comm: "code"},
			want:     true,
			platform: "linux", // only Linux has lowercase "code" in Comm
		},
		{
			name:     "code-oss comm",
			info:     &ProcessInfo{Comm: "code-oss"},
			want:     true,
			platform: "linux", // only Linux has "code-oss" in Comm
		},
		{
			name:     "Code comm capitalized",
			info:     &ProcessInfo{Comm: "Code"},
			want:     true,
			platform: "darwin", // only Darwin has capitalized "Code" in Comm
		},
		{
			name:     "vscode exe path linux",
			info:     &ProcessInfo{ExePath: "/usr/share/vscode/code"},
			want:     true,
			platform: "linux",
		},
		{
			name:     "vscode exe path darwin",
			info:     &ProcessInfo{ExePath: "/Applications/Visual Studio Code.app/Contents/MacOS/Electron"},
			want:     true,
			platform: "darwin",
		},
		{
			name:     "vscode exe path windows",
			info:     &ProcessInfo{ExePath: "C:\\Program Files\\Microsoft VS Code\\Code.exe"},
			want:     true,
			platform: "windows",
		},
		{
			name: "vim",
			info: &ProcessInfo{Comm: "vim"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.platform != "" && tt.platform != runtime.GOOS {
				t.Skipf("skipping %s-specific test on %s", tt.platform, runtime.GOOS)
			}
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

	// Process that matches cursor - use capitalized "Cursor" which works on both Linux and Darwin
	matches = m.Matches(&ProcessInfo{Comm: "Cursor"})
	assert.Contains(t, matches, "cursor")
}
