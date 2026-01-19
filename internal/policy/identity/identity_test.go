package identity

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessIdentity_GetPlatformMatch(t *testing.T) {
	identity := &ProcessIdentity{
		Name: "test",
		Linux: &PlatformMatch{
			Comm: []string{"linux-comm"},
		},
		Darwin: &PlatformMatch{
			Comm: []string{"darwin-comm"},
		},
		Windows: &PlatformMatch{
			Comm: []string{"windows-comm"},
		},
		AllPlatforms: &PlatformMatch{
			ExePath: []string{"*/common/*"},
		},
	}

	pm := identity.GetPlatformMatch()
	require.NotNil(t, pm)

	// Should have both platform-specific and AllPlatforms patterns merged
	assert.NotEmpty(t, pm.Comm)
	assert.NotEmpty(t, pm.ExePath)
	assert.Contains(t, pm.ExePath, "*/common/*")
}

func TestProcessIdentity_GetPlatformMatch_AllPlatformsOnly(t *testing.T) {
	identity := &ProcessIdentity{
		Name: "test",
		AllPlatforms: &PlatformMatch{
			Comm: []string{"universal"},
		},
	}

	pm := identity.GetPlatformMatch()
	require.NotNil(t, pm)
	assert.Contains(t, pm.Comm, "universal")
}

func TestProcessIdentity_GetPlatformMatch_Empty(t *testing.T) {
	identity := &ProcessIdentity{
		Name: "test",
	}

	pm := identity.GetPlatformMatch()
	assert.Nil(t, pm)
}

func TestPlatformMatch_Merge(t *testing.T) {
	pm1 := &PlatformMatch{
		Comm:    []string{"a"},
		ExePath: []string{"path1"},
	}
	pm2 := &PlatformMatch{
		Comm:     []string{"b"},
		BundleID: []string{"com.test"},
	}

	merged := pm1.Merge(pm2)
	assert.Equal(t, []string{"a", "b"}, merged.Comm)
	assert.Equal(t, []string{"path1"}, merged.ExePath)
	assert.Equal(t, []string{"com.test"}, merged.BundleID)
}

func TestPlatformMatch_Merge_Nil(t *testing.T) {
	pm := &PlatformMatch{Comm: []string{"a"}}

	assert.Equal(t, pm, pm.Merge(nil))
	assert.Equal(t, pm, (*PlatformMatch)(nil).Merge(pm))
}

func TestPlatformMatch_IsEmpty(t *testing.T) {
	assert.True(t, (*PlatformMatch)(nil).IsEmpty())
	assert.True(t, (&PlatformMatch{}).IsEmpty())
	assert.False(t, (&PlatformMatch{Comm: []string{"a"}}).IsEmpty())
	assert.False(t, (&PlatformMatch{ExePath: []string{"a"}}).IsEmpty())
	assert.False(t, (&PlatformMatch{Cmdline: []string{"a"}}).IsEmpty())
	assert.False(t, (&PlatformMatch{BundleID: []string{"a"}}).IsEmpty())
	assert.False(t, (&PlatformMatch{ExeName: []string{"a"}}).IsEmpty())
}

func TestProcessMatcher_AddIdentity(t *testing.T) {
	m := NewProcessMatcher()

	err := m.AddIdentity(&ProcessIdentity{
		Name: "test",
		AllPlatforms: &PlatformMatch{
			Comm: []string{"test-process"},
		},
	})
	require.NoError(t, err)

	id, ok := m.GetIdentity("test")
	assert.True(t, ok)
	assert.Equal(t, "test", id.Name)
}

func TestProcessMatcher_AddIdentity_EmptyName(t *testing.T) {
	m := NewProcessMatcher()

	err := m.AddIdentity(&ProcessIdentity{})
	assert.ErrorIs(t, err, ErrEmptyName)
}

func TestProcessMatcher_RemoveIdentity(t *testing.T) {
	m := NewProcessMatcher()

	_ = m.AddIdentity(&ProcessIdentity{Name: "test"})
	assert.True(t, len(m.ListIdentities()) > 0)

	m.RemoveIdentity("test")
	_, ok := m.GetIdentity("test")
	assert.False(t, ok)
}

func TestProcessMatcher_Matches(t *testing.T) {
	m := NewProcessMatcher()

	_ = m.AddIdentity(&ProcessIdentity{
		Name: "cursor",
		AllPlatforms: &PlatformMatch{
			Comm: []string{"cursor", "Cursor"},
		},
	})

	_ = m.AddIdentity(&ProcessIdentity{
		Name: "vscode",
		AllPlatforms: &PlatformMatch{
			Comm: []string{"code", "Code"},
		},
	})

	tests := []struct {
		name     string
		info     *ProcessInfo
		expected []string
	}{
		{
			name:     "matches cursor",
			info:     &ProcessInfo{Comm: "cursor"},
			expected: []string{"cursor"},
		},
		{
			name:     "matches vscode",
			info:     &ProcessInfo{Comm: "code"},
			expected: []string{"vscode"},
		},
		{
			name:     "no match",
			info:     &ProcessInfo{Comm: "bash"},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := m.Matches(tt.info)
			if tt.expected == nil {
				assert.Empty(t, matches)
			} else {
				assert.ElementsMatch(t, tt.expected, matches)
			}
		})
	}
}

func TestProcessMatcher_MatchesIdentity(t *testing.T) {
	m := NewProcessMatcher()

	_ = m.AddIdentity(&ProcessIdentity{
		Name: "cursor",
		AllPlatforms: &PlatformMatch{
			Comm: []string{"cursor"},
		},
	})

	assert.True(t, m.MatchesIdentity(&ProcessInfo{Comm: "cursor"}, "cursor"))
	assert.False(t, m.MatchesIdentity(&ProcessInfo{Comm: "bash"}, "cursor"))
	assert.False(t, m.MatchesIdentity(&ProcessInfo{Comm: "cursor"}, "nonexistent"))
}

func TestProcessMatcher_GlobPatterns(t *testing.T) {
	m := NewProcessMatcher()

	_ = m.AddIdentity(&ProcessIdentity{
		Name: "electron-app",
		AllPlatforms: &PlatformMatch{
			Comm: []string{"*Helper*"},
		},
	})

	assert.True(t, m.MatchesIdentity(&ProcessInfo{Comm: "Cursor Helper"}, "electron-app"))
	assert.True(t, m.MatchesIdentity(&ProcessInfo{Comm: "Code Helper (GPU)"}, "electron-app"))
	assert.False(t, m.MatchesIdentity(&ProcessInfo{Comm: "bash"}, "electron-app"))
}

func TestProcessMatcher_ExePathMatching(t *testing.T) {
	m := NewProcessMatcher()

	_ = m.AddIdentity(&ProcessIdentity{
		Name: "cursor",
		AllPlatforms: &PlatformMatch{
			ExePath: []string{"*/Cursor.app/*", "*/cursor/*"},
		},
	})

	tests := []struct {
		exePath string
		want    bool
	}{
		{"/Applications/Cursor.app/Contents/MacOS/Cursor", true},
		{"/usr/local/bin/cursor/cursor", true},
		{"/usr/bin/bash", false},
	}

	for _, tt := range tests {
		t.Run(tt.exePath, func(t *testing.T) {
			result := m.MatchesIdentity(&ProcessInfo{ExePath: tt.exePath}, "cursor")
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestProcessMatcher_BundleIDMatching(t *testing.T) {
	m := NewProcessMatcher()

	_ = m.AddIdentity(&ProcessIdentity{
		Name: "cursor",
		AllPlatforms: &PlatformMatch{
			BundleID: []string{"com.cursor.Cursor"},
		},
	})

	assert.True(t, m.MatchesIdentity(&ProcessInfo{BundleID: "com.cursor.Cursor"}, "cursor"))
	assert.False(t, m.MatchesIdentity(&ProcessInfo{BundleID: "com.apple.Terminal"}, "cursor"))
	assert.False(t, m.MatchesIdentity(&ProcessInfo{BundleID: ""}, "cursor"))
}

func TestProcessMatcher_ClassPatterns(t *testing.T) {
	m := NewProcessMatcher()

	_ = m.AddIdentity(&ProcessIdentity{
		Name: "shell-like",
		AllPlatforms: &PlatformMatch{
			Comm: []string{"@shell"},
		},
	})

	// @shell class includes bash, zsh, fish, etc.
	assert.True(t, m.MatchesIdentity(&ProcessInfo{Comm: "bash"}, "shell-like"))
	assert.True(t, m.MatchesIdentity(&ProcessInfo{Comm: "zsh"}, "shell-like"))
	assert.False(t, m.MatchesIdentity(&ProcessInfo{Comm: "vim"}, "shell-like"))
}

func TestProcessMatcher_Clear(t *testing.T) {
	m := NewProcessMatcher()

	_ = m.AddIdentity(&ProcessIdentity{Name: "a"})
	_ = m.AddIdentity(&ProcessIdentity{Name: "b"})
	assert.Len(t, m.ListIdentities(), 2)

	m.Clear()
	assert.Empty(t, m.ListIdentities())
}

func TestExtractExeName(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/usr/bin/bash", "bash"},
		{"C:\\Windows\\System32\\cmd.exe", "cmd.exe"},
		{"bash", "bash"},
		{"/Applications/Cursor.app/Contents/MacOS/Cursor", "Cursor"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, extractExeName(tt.path))
		})
	}
}
