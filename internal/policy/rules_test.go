package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestCommandRule_ContextParsing(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		minDepth int
		maxDepth int
	}{
		{
			name: "direct only",
			yaml: `
- name: test
  commands: [git]
  decision: allow
  context: [direct]
`,
			minDepth: 0,
			maxDepth: 0,
		},
		{
			name: "nested only",
			yaml: `
- name: test
  commands: [git]
  decision: allow
  context: [nested]
`,
			minDepth: 1,
			maxDepth: -1, // unlimited
		},
		{
			name: "explicit depth range",
			yaml: `
- name: test
  commands: [git]
  decision: allow
  context:
    min_depth: 1
    max_depth: 3
`,
			minDepth: 1,
			maxDepth: 3,
		},
		{
			name: "default is all depths",
			yaml: `
- name: test
  commands: [git]
  decision: allow
`,
			minDepth: 0,
			maxDepth: -1,
		},
		{
			name: "direct and nested",
			yaml: `
- name: test
  commands: [git]
  decision: allow
  context: [direct, nested]
`,
			minDepth: 0,
			maxDepth: -1,
		},
		{
			name: "nested and direct order reversed",
			yaml: `
- name: test
  commands: [git]
  decision: allow
  context: [nested, direct]
`,
			minDepth: 0,
			maxDepth: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rules []CommandRule
			err := yaml.Unmarshal([]byte(tt.yaml), &rules)
			require.NoError(t, err)
			require.Len(t, rules, 1)

			assert.Equal(t, tt.minDepth, rules[0].Context.MinDepth)
			assert.Equal(t, tt.maxDepth, rules[0].Context.MaxDepth)
		})
	}
}

func TestContextConfig_MatchesDepth(t *testing.T) {
	tests := []struct {
		name     string
		config   ContextConfig
		depth    int
		expected bool
	}{
		{
			name:     "direct only matches depth 0",
			config:   ContextConfig{MinDepth: 0, MaxDepth: 0},
			depth:    0,
			expected: true,
		},
		{
			name:     "direct only does not match depth 1",
			config:   ContextConfig{MinDepth: 0, MaxDepth: 0},
			depth:    1,
			expected: false,
		},
		{
			name:     "nested only matches depth 1",
			config:   ContextConfig{MinDepth: 1, MaxDepth: -1},
			depth:    1,
			expected: true,
		},
		{
			name:     "nested only matches depth 5",
			config:   ContextConfig{MinDepth: 1, MaxDepth: -1},
			depth:    5,
			expected: true,
		},
		{
			name:     "nested only does not match depth 0",
			config:   ContextConfig{MinDepth: 1, MaxDepth: -1},
			depth:    0,
			expected: false,
		},
		{
			name:     "range 1-3 matches depth 2",
			config:   ContextConfig{MinDepth: 1, MaxDepth: 3},
			depth:    2,
			expected: true,
		},
		{
			name:     "range 1-3 does not match depth 4",
			config:   ContextConfig{MinDepth: 1, MaxDepth: 3},
			depth:    4,
			expected: false,
		},
		{
			name:     "all depths matches depth 0",
			config:   ContextConfig{MinDepth: 0, MaxDepth: -1},
			depth:    0,
			expected: true,
		},
		{
			name:     "all depths matches depth 100",
			config:   ContextConfig{MinDepth: 0, MaxDepth: -1},
			depth:    100,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.MatchesDepth(tt.depth)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestContextConfig_UnmarshalYAML_Errors(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "unknown context value",
			yaml: `
- name: test
  commands: [git]
  decision: allow
  context: [unknown]
`,
			wantErr: "unknown context value: unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rules []CommandRule
			err := yaml.Unmarshal([]byte(tt.yaml), &rules)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestDefaultContext(t *testing.T) {
	ctx := DefaultContext()
	assert.Equal(t, 0, ctx.MinDepth)
	assert.Equal(t, -1, ctx.MaxDepth)
}
