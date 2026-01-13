package pnacl

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessMatcher_FlexibleMode(t *testing.T) {
	tests := []struct {
		name     string
		criteria ProcessMatchCriteria
		info     ProcessInfo
		want     bool
	}{
		{
			name: "match by process name",
			criteria: ProcessMatchCriteria{
				ProcessName: "claude-code",
			},
			info: ProcessInfo{
				Name: "claude-code",
				Path: "/usr/bin/claude-code",
			},
			want: true,
		},
		{
			name: "match by process name case insensitive",
			criteria: ProcessMatchCriteria{
				ProcessName: "Claude-Code",
			},
			info: ProcessInfo{
				Name: "claude-code",
			},
			want: true,
		},
		{
			name: "no match wrong process name",
			criteria: ProcessMatchCriteria{
				ProcessName: "other-app",
			},
			info: ProcessInfo{
				Name: "claude-code",
			},
			want: false,
		},
		{
			name: "match by path glob",
			criteria: ProcessMatchCriteria{
				Path: "/usr/bin/claude*",
			},
			info: ProcessInfo{
				Name: "claude-code",
				Path: "/usr/bin/claude-code",
			},
			want: true,
		},
		{
			name: "match by path glob with multiple segments",
			criteria: ProcessMatchCriteria{
				Path: "/usr/*/claude-code",
			},
			info: ProcessInfo{
				Path: "/usr/bin/claude-code",
			},
			want: true,
		},
		{
			name: "no match wrong path",
			criteria: ProcessMatchCriteria{
				Path: "/opt/bin/*",
			},
			info: ProcessInfo{
				Path: "/usr/bin/claude-code",
			},
			want: false,
		},
		{
			name: "match by bundle ID",
			criteria: ProcessMatchCriteria{
				BundleID: "com.anthropic.claudecode",
			},
			info: ProcessInfo{
				Name:     "claude-code",
				BundleID: "com.anthropic.claudecode",
			},
			want: true,
		},
		{
			name: "match by bundle ID case insensitive",
			criteria: ProcessMatchCriteria{
				BundleID: "COM.ANTHROPIC.CLAUDECODE",
			},
			info: ProcessInfo{
				BundleID: "com.anthropic.claudecode",
			},
			want: true,
		},
		{
			name: "match by package family name",
			criteria: ProcessMatchCriteria{
				PackageFamilyName: "Anthropic.ClaudeCode_abc123",
			},
			info: ProcessInfo{
				Name:              "claude-code",
				PackageFamilyName: "Anthropic.ClaudeCode_abc123",
			},
			want: true,
		},
		{
			name: "flexible mode any criterion matches",
			criteria: ProcessMatchCriteria{
				ProcessName: "wrong-name",
				BundleID:    "com.anthropic.claudecode",
			},
			info: ProcessInfo{
				Name:     "claude-code",
				BundleID: "com.anthropic.claudecode",
			},
			want: true,
		},
		{
			name: "no criteria no match",
			criteria: ProcessMatchCriteria{},
			info: ProcessInfo{
				Name: "claude-code",
			},
			want: false,
		},
		{
			name: "match basename from path in name",
			criteria: ProcessMatchCriteria{
				ProcessName: "claude-code",
			},
			info: ProcessInfo{
				Name: "/usr/bin/claude-code",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewProcessMatcher(tt.criteria)
			require.NoError(t, err)

			got := m.Matches(tt.info)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestProcessMatcher_StrictMode(t *testing.T) {
	tests := []struct {
		name     string
		criteria ProcessMatchCriteria
		info     ProcessInfo
		want     bool
	}{
		{
			name: "strict mode all criteria must match",
			criteria: ProcessMatchCriteria{
				ProcessName: "claude-code",
				Path:        "/usr/bin/claude-code",
				Strict:      true,
			},
			info: ProcessInfo{
				Name: "claude-code",
				Path: "/usr/bin/claude-code",
			},
			want: true,
		},
		{
			name: "strict mode fails if one criterion doesn't match",
			criteria: ProcessMatchCriteria{
				ProcessName: "claude-code",
				Path:        "/opt/bin/claude-code",
				Strict:      true,
			},
			info: ProcessInfo{
				Name: "claude-code",
				Path: "/usr/bin/claude-code",
			},
			want: false,
		},
		{
			name: "strict mode with bundle ID",
			criteria: ProcessMatchCriteria{
				ProcessName: "claude-code",
				BundleID:    "com.anthropic.claudecode",
				Strict:      true,
			},
			info: ProcessInfo{
				Name:     "claude-code",
				BundleID: "com.anthropic.claudecode",
			},
			want: true,
		},
		{
			name: "strict mode missing bundle ID fails",
			criteria: ProcessMatchCriteria{
				ProcessName: "claude-code",
				BundleID:    "com.anthropic.claudecode",
				Strict:      true,
			},
			info: ProcessInfo{
				Name:     "claude-code",
				BundleID: "", // Missing bundle ID.
			},
			want: false,
		},
		{
			name: "strict mode no criteria no match",
			criteria: ProcessMatchCriteria{
				Strict: true,
			},
			info: ProcessInfo{
				Name: "claude-code",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewProcessMatcher(tt.criteria)
			require.NoError(t, err)

			assert.Equal(t, MatchModeStrict, m.Mode())

			got := m.Matches(tt.info)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestProcessMatcher_InvalidGlob(t *testing.T) {
	// Invalid glob pattern should return an error.
	_, err := NewProcessMatcher(ProcessMatchCriteria{
		Path: "[invalid",
	})
	assert.Error(t, err)
}

func TestProcessMatcher_Mode(t *testing.T) {
	// Default mode is flexible.
	m, err := NewProcessMatcher(ProcessMatchCriteria{
		ProcessName: "test",
	})
	require.NoError(t, err)
	assert.Equal(t, MatchModeFlexible, m.Mode())

	// Strict mode.
	m, err = NewProcessMatcher(ProcessMatchCriteria{
		ProcessName: "test",
		Strict:      true,
	})
	require.NoError(t, err)
	assert.Equal(t, MatchModeStrict, m.Mode())
}

func TestProcessMatcher_Criteria(t *testing.T) {
	criteria := ProcessMatchCriteria{
		ProcessName:       "claude-code",
		Path:              "/usr/bin/*",
		BundleID:          "com.anthropic.claudecode",
		PackageFamilyName: "Anthropic.ClaudeCode",
		Strict:            true,
	}

	m, err := NewProcessMatcher(criteria)
	require.NoError(t, err)

	got := m.Criteria()
	assert.Equal(t, criteria.ProcessName, got.ProcessName)
	assert.Equal(t, criteria.Path, got.Path)
	assert.Equal(t, criteria.BundleID, got.BundleID)
	assert.Equal(t, criteria.PackageFamilyName, got.PackageFamilyName)
	assert.Equal(t, criteria.Strict, got.Strict)
}

func TestMatchProcessName(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"claude-code", "claude-code", true},
		{"CLAUDE-CODE", "claude-code", true},
		{"claude-code", "CLAUDE-CODE", true},
		{"claude-code", "/usr/bin/claude-code", true},
		{"other", "claude-code", false},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.name, func(t *testing.T) {
			got := matchProcessName(tt.pattern, tt.name)
			assert.Equal(t, tt.want, got)
		})
	}
}
