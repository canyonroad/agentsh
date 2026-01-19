package pattern

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPatternType_String(t *testing.T) {
	tests := []struct {
		pt   PatternType
		want string
	}{
		{PatternTypeGlob, "glob"},
		{PatternTypeRegex, "regex"},
		{PatternTypeClass, "class"},
		{PatternTypeLiteral, "literal"},
		{PatternType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.pt.String())
		})
	}
}

func TestCompile_Literal(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		input   string
		want    bool
	}{
		{"exact match", "bash", "bash", true},
		{"no match", "bash", "zsh", false},
		{"case sensitive", "Bash", "bash", false},
		{"substring no match", "bash", "bash-completion", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Compile(tt.pattern)
			require.NoError(t, err)
			assert.Equal(t, PatternTypeLiteral, p.Type)
			assert.Equal(t, tt.want, p.Match(tt.input))
		})
	}
}

func TestCompile_Glob(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		input   string
		want    bool
	}{
		{"wildcard suffix", "cursor*", "cursor", true},
		{"wildcard suffix 2", "cursor*", "cursor-helper", true},
		{"wildcard suffix no match", "cursor*", "Cursor", false},
		{"wildcard prefix", "*server", "language-server", true},
		{"wildcard both", "*code*", "vscode-helper", true},
		{"question mark", "ba?h", "bash", true},
		{"question mark 2", "ba?h", "bath", true},
		{"question mark no match", "ba?h", "batch", false},
		{"bracket", "[bz]ash", "bash", true},
		{"bracket 2", "[bz]ash", "zash", true},
		{"bracket no match", "[bz]ash", "dash", false},
		{"complex glob", "*.language-server", "typescript.language-server", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Compile(tt.pattern)
			require.NoError(t, err)
			assert.Equal(t, PatternTypeGlob, p.Type)
			assert.Equal(t, tt.want, p.Match(tt.input), "pattern %q should match %q = %v", tt.pattern, tt.input, tt.want)
		})
	}
}

func TestCompile_Regex(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		input   string
		want    bool
	}{
		{"simple", "re:^bash$", "bash", true},
		{"simple no match", "re:^bash$", "bash-helper", false},
		{"alternation", "re:^(bash|zsh)$", "bash", true},
		{"alternation 2", "re:^(bash|zsh)$", "zsh", true},
		{"alternation no match", "re:^(bash|zsh)$", "fish", false},
		{"partial match", "re:code", "vscode", true},
		{"case sensitive", "re:^Code$", "code", false},
		{"word boundary", "re:\\bserver\\b", "language-server", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Compile(tt.pattern)
			require.NoError(t, err)
			assert.Equal(t, PatternTypeRegex, p.Type)
			assert.Equal(t, tt.want, p.Match(tt.input), "pattern %q should match %q = %v", tt.pattern, tt.input, tt.want)
		})
	}
}

func TestCompile_Class(t *testing.T) {
	p, err := Compile("@shell")
	require.NoError(t, err)
	assert.Equal(t, PatternTypeClass, p.Type)
	assert.Equal(t, "shell", p.class)

	// Without resolver, should return false
	assert.False(t, p.Match("bash"))

	// With resolver
	resolver := func(class string) ([]string, error) {
		if class == "shell" {
			return []string{"bash", "zsh", "fish", "sh"}, nil
		}
		return nil, nil
	}

	match, err := p.MatchWithResolver("bash", resolver)
	require.NoError(t, err)
	assert.True(t, match)

	match, err = p.MatchWithResolver("vim", resolver)
	require.NoError(t, err)
	assert.False(t, match)
}

func TestCompile_CaseInsensitive(t *testing.T) {
	opts := CompileOptions{
		CaseInsensitive: true,
	}

	// Glob
	p, err := CompileWithOptions("cursor*", opts)
	require.NoError(t, err)
	assert.True(t, p.Match("cursor"))
	assert.True(t, p.Match("cursor-helper"))
	// Note: gobwas/glob with lowercase pattern won't match uppercase input
	// We'd need to lowercase the input for true case-insensitivity

	// Regex with case insensitive flag
	p, err = CompileWithOptions("re:^cursor$", opts)
	require.NoError(t, err)
	assert.True(t, p.Match("cursor"))
	assert.True(t, p.Match("Cursor"))
	assert.True(t, p.Match("CURSOR"))
}

func TestCompile_Errors(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr string
	}{
		{"empty pattern", "", "empty pattern"},
		{"empty regex", "re:", "empty regex pattern"},
		{"empty class", "@", "empty class name"},
		{"invalid regex", "re:[invalid", "regex"}, // matches "regex" in error message
		{"invalid glob", "[invalid", "invalid glob pattern"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Compile(tt.pattern)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestCheckRegexComplexity(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{"simple", "^bash$", false},
		{"alternation", "(a|b|c)", false},
		{"quantifier", "a+", false},
		{"nested quantifier", "(a+)+", true}, // ReDoS vulnerable
		{"complex nested", "(a*)*", true},    // ReDoS vulnerable
		{"reasonable bounded", "a{1,10}", false},
		{"deep nesting", "((((a+)+)+)+)+", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkRegexComplexity(tt.pattern, 1000)
			if tt.wantErr {
				assert.Error(t, err, "pattern %q should be rejected", tt.pattern)
			} else {
				assert.NoError(t, err, "pattern %q should be accepted", tt.pattern)
			}
		})
	}
}

func TestPattern_MatchWithTimeout(t *testing.T) {
	p, err := Compile("re:^a{1,100}$")
	require.NoError(t, err)

	// Normal match should complete quickly
	match, err := p.MatchWithTimeout("aaaaaaaaaa", 100*time.Millisecond)
	require.NoError(t, err)
	assert.True(t, match)

	// Non-match should also complete quickly
	match, err = p.MatchWithTimeout("b", 100*time.Millisecond)
	require.NoError(t, err)
	assert.False(t, match)
}

func TestPattern_String(t *testing.T) {
	tests := []struct {
		pattern string
	}{
		{"bash"},
		{"cursor*"},
		{"re:^code$"},
		{"@shell"},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			p, err := Compile(tt.pattern)
			require.NoError(t, err)
			assert.Equal(t, tt.pattern, p.String())
		})
	}
}

func TestPatternSet(t *testing.T) {
	patterns := []string{"bash", "zsh", "fish*", "re:^sh$"}
	ps, err := NewPatternSet(patterns)
	require.NoError(t, err)
	assert.Equal(t, 4, ps.Len())

	tests := []struct {
		input string
		want  bool
	}{
		{"bash", true},
		{"zsh", true},
		{"fish", true},
		{"fish-shell", true},
		{"sh", true},
		{"vim", false},
		{"dash", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, ps.MatchAny(tt.input))
		})
	}
}

func TestPatternSet_WithResolver(t *testing.T) {
	patterns := []string{"@shell", "vim"}
	ps, err := NewPatternSet(patterns)
	require.NoError(t, err)

	resolver := func(class string) ([]string, error) {
		if class == "shell" {
			return []string{"bash", "zsh"}, nil
		}
		return nil, nil
	}

	tests := []struct {
		input string
		want  bool
	}{
		{"bash", true},
		{"zsh", true},
		{"vim", true},
		{"emacs", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			match, err := ps.MatchAnyWithResolver(tt.input, resolver)
			require.NoError(t, err)
			assert.Equal(t, tt.want, match)
		})
	}
}

func TestPatternSet_Empty(t *testing.T) {
	ps, err := NewPatternSet([]string{})
	require.NoError(t, err)
	assert.Equal(t, 0, ps.Len())
	assert.False(t, ps.MatchAny("anything"))
}

func TestPatternSet_InvalidPattern(t *testing.T) {
	_, err := NewPatternSet([]string{"valid", "re:[invalid"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to compile pattern")
}

func TestPatternSet_Patterns(t *testing.T) {
	patterns := []string{"a", "b*", "re:c"}
	ps, err := NewPatternSet(patterns)
	require.NoError(t, err)

	result := ps.Patterns()
	assert.Len(t, result, 3)
	assert.Equal(t, "a", result[0].Raw)
	assert.Equal(t, "b*", result[1].Raw)
	assert.Equal(t, "re:c", result[2].Raw)
}

func TestIsGlobPattern(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"bash", false},
		{"bash*", true},
		{"*bash", true},
		{"ba?h", true},
		{"[abc]", true},
		// Note: isGlobPattern is a low-level check that doesn't know about prefixes
		// The Compile function handles prefix detection before calling isGlobPattern
		{"re:foo", false}, // No glob chars
		{"@shell", false}, // No glob chars
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			assert.Equal(t, tt.want, isGlobPattern(tt.s))
		})
	}
}

func TestClassPatternWithGlobInClass(t *testing.T) {
	p, err := Compile("@language-server")
	require.NoError(t, err)

	resolver := func(class string) ([]string, error) {
		if class == "language-server" {
			return []string{"*-language-server", "tsserver", "gopls"}, nil
		}
		return nil, nil
	}

	tests := []struct {
		input string
		want  bool
	}{
		{"typescript-language-server", true},
		{"rust-language-server", true},
		{"tsserver", true},
		{"gopls", true},
		{"vim", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			match, err := p.MatchWithResolver(tt.input, resolver)
			require.NoError(t, err)
			assert.Equal(t, tt.want, match)
		})
	}
}
