package ancestry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifier_Classify(t *testing.T) {
	c := NewClassifier()

	tests := []struct {
		comm string
		want ProcessClass
	}{
		// Shells
		{"bash", ClassShell},
		{"zsh", ClassShell},
		{"fish", ClassShell},
		{"sh", ClassShell},

		// Editors
		{"vim", ClassEditor},
		{"nvim", ClassEditor},
		{"code", ClassEditor},
		{"cursor", ClassEditor},

		// Build tools
		{"npm", ClassBuildTool},
		{"cargo", ClassBuildTool},
		{"go", ClassBuildTool},
		{"make", ClassBuildTool},

		// Language servers
		{"gopls", ClassLanguageServer},
		{"tsserver", ClassLanguageServer},
		{"rust-analyzer", ClassLanguageServer},

		// Language runtimes
		{"node", ClassLanguageRuntime},
		{"python", ClassLanguageRuntime},
		{"python3", ClassLanguageRuntime},
		{"ruby", ClassLanguageRuntime},

		// Unknown
		{"myprocess", ClassUnknown},
		{"unknown-thing", ClassUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.comm, func(t *testing.T) {
			got := c.Classify(tt.comm)
			assert.Equal(t, tt.want, got, "Classify(%q)", tt.comm)
		})
	}
}

func TestClassifier_ClassifyWithGlob(t *testing.T) {
	c := NewClassifier()

	// Language server patterns include "*-language-server"
	tests := []struct {
		comm string
		want ProcessClass
	}{
		{"typescript-language-server", ClassLanguageServer},
		{"rust-language-server", ClassLanguageServer},
		{"yaml-language-server", ClassLanguageServer},
	}

	for _, tt := range tests {
		t.Run(tt.comm, func(t *testing.T) {
			got := c.Classify(tt.comm)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClassifier_CustomRules(t *testing.T) {
	c := NewClassifier()

	// Add custom rule
	c.AddCustomRule("my-agent", ClassAgent)
	assert.Equal(t, ClassAgent, c.Classify("my-agent"))

	// Custom rule takes precedence
	c.AddCustomRule("bash", ClassAgent) // Override built-in
	assert.Equal(t, ClassAgent, c.Classify("bash"))

	// Remove custom rule
	c.RemoveCustomRule("bash")
	assert.Equal(t, ClassShell, c.Classify("bash"))
}

func TestClassifier_ClassifyChain(t *testing.T) {
	c := NewClassifier()

	via := []string{"bash", "npm", "node", "tsserver"}
	classes := c.ClassifyChain(via)

	require.Len(t, classes, 4)
	assert.Equal(t, ClassShell, classes[0])
	assert.Equal(t, ClassBuildTool, classes[1])
	assert.Equal(t, ClassLanguageRuntime, classes[2])
	assert.Equal(t, ClassLanguageServer, classes[3])
}

func TestClassifyProcess_Default(t *testing.T) {
	// Test the convenience function
	assert.Equal(t, ClassShell, ClassifyProcess("bash"))
	assert.Equal(t, ClassEditor, ClassifyProcess("vim"))
}

func TestAnalyzeChain(t *testing.T) {
	tests := []struct {
		name       string
		via        []string
		viaClasses []ProcessClass
		wantShell  bool
		wantEditor bool
		wantLSP    bool
	}{
		{
			name:       "shell only",
			via:        []string{"bash"},
			viaClasses: []ProcessClass{ClassShell},
			wantShell:  true,
		},
		{
			name:       "editor and shell",
			via:        []string{"bash", "vim"},
			viaClasses: []ProcessClass{ClassShell, ClassEditor},
			wantShell:  true,
			wantEditor: true,
		},
		{
			name:       "with language server",
			via:        []string{"bash", "gopls"},
			viaClasses: []ProcessClass{ClassShell, ClassLanguageServer},
			wantShell:  true,
			wantLSP:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := AnalyzeChain(tt.via, tt.viaClasses)
			assert.Equal(t, tt.wantShell, analysis.HasShell)
			assert.Equal(t, tt.wantEditor, analysis.HasEditor)
			assert.Equal(t, tt.wantLSP, analysis.HasLanguageServer)
		})
	}
}

func TestAnalyzeChain_ConsecutiveShells(t *testing.T) {
	tests := []struct {
		name                string
		viaClasses          []ProcessClass
		wantConsecutive     int
		wantShellLaundering bool
	}{
		{
			name:                "no shells",
			viaClasses:          []ProcessClass{ClassEditor, ClassBuildTool},
			wantConsecutive:     0,
			wantShellLaundering: false,
		},
		{
			name:                "one shell",
			viaClasses:          []ProcessClass{ClassShell},
			wantConsecutive:     1,
			wantShellLaundering: false,
		},
		{
			name:                "two consecutive shells",
			viaClasses:          []ProcessClass{ClassShell, ClassShell},
			wantConsecutive:     2,
			wantShellLaundering: false,
		},
		{
			name:                "three consecutive shells - laundering",
			viaClasses:          []ProcessClass{ClassShell, ClassShell, ClassShell},
			wantConsecutive:     3,
			wantShellLaundering: true,
		},
		{
			name:                "shells with break",
			viaClasses:          []ProcessClass{ClassShell, ClassShell, ClassEditor, ClassShell, ClassShell},
			wantConsecutive:     2,
			wantShellLaundering: false,
		},
		{
			name:                "shells with break then laundering",
			viaClasses:          []ProcessClass{ClassShell, ClassEditor, ClassShell, ClassShell, ClassShell},
			wantConsecutive:     3,
			wantShellLaundering: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := AnalyzeChain(nil, tt.viaClasses)
			assert.Equal(t, tt.wantConsecutive, analysis.ConsecutiveShells)
			assert.Equal(t, tt.wantShellLaundering, analysis.ShellLaundering)
		})
	}
}

func TestAnalyzeChain_FirstIndices(t *testing.T) {
	viaClasses := []ProcessClass{ClassBuildTool, ClassShell, ClassEditor, ClassAgent}
	analysis := AnalyzeChain(nil, viaClasses)

	assert.Equal(t, 1, analysis.FirstShellIndex)
	assert.Equal(t, 2, analysis.FirstEditorIndex)
	assert.Equal(t, 3, analysis.FirstAgentIndex)
}

func TestAnalyzeTaint(t *testing.T) {
	taint := &ProcessTaint{
		Via:        []string{"bash", "npm", "node"},
		ViaClasses: []ProcessClass{ClassShell, ClassBuildTool, ClassLanguageRuntime},
	}

	analysis := AnalyzeTaint(taint)
	assert.True(t, analysis.HasShell)
	assert.Equal(t, 0, analysis.FirstShellIndex)
}

func TestAnalyzeTaint_Nil(t *testing.T) {
	analysis := AnalyzeTaint(nil)
	assert.False(t, analysis.HasShell)
	assert.Equal(t, -1, analysis.FirstShellIndex)
}

func TestIsLikelyUserTerminal(t *testing.T) {
	tests := []struct {
		name  string
		taint *ProcessTaint
		want  bool
	}{
		{
			name:  "nil taint",
			taint: nil,
			want:  false,
		},
		{
			name: "depth 1 shell",
			taint: &ProcessTaint{
				Depth:      1,
				Via:        []string{"bash"},
				ViaClasses: []ProcessClass{ClassShell},
			},
			want: true,
		},
		{
			name: "depth 1 but not shell",
			taint: &ProcessTaint{
				Depth:      1,
				Via:        []string{"npm"},
				ViaClasses: []ProcessClass{ClassBuildTool},
			},
			want: false,
		},
		{
			name: "depth 2",
			taint: &ProcessTaint{
				Depth:      2,
				Via:        []string{"bash", "zsh"},
				ViaClasses: []ProcessClass{ClassShell, ClassShell},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsLikelyUserTerminal(tt.taint))
		})
	}
}

func TestIsLikelyEditorFeature(t *testing.T) {
	tests := []struct {
		name  string
		taint *ProcessTaint
		want  bool
	}{
		{
			name:  "nil taint",
			taint: nil,
			want:  false,
		},
		{
			name: "contains LSP",
			taint: &ProcessTaint{
				ViaClasses: []ProcessClass{ClassShell, ClassLanguageServer},
			},
			want: true,
		},
		{
			name: "contains build tool",
			taint: &ProcessTaint{
				ViaClasses: []ProcessClass{ClassShell, ClassBuildTool},
			},
			want: true,
		},
		{
			name: "only shell",
			taint: &ProcessTaint{
				ViaClasses: []ProcessClass{ClassShell},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsLikelyEditorFeature(tt.taint))
		})
	}
}

func TestChainContainsClass(t *testing.T) {
	classes := []ProcessClass{ClassShell, ClassBuildTool, ClassLanguageRuntime}

	assert.True(t, ChainContainsClass(classes, ClassShell))
	assert.True(t, ChainContainsClass(classes, ClassBuildTool))
	assert.False(t, ChainContainsClass(classes, ClassEditor))
	assert.False(t, ChainContainsClass(classes, ClassAgent))
}

func TestChainContainsComm(t *testing.T) {
	via := []string{"bash", "npm", "node"}

	assert.True(t, ChainContainsComm(via, []string{"bash"}))
	assert.True(t, ChainContainsComm(via, []string{"vim", "npm"}))
	assert.True(t, ChainContainsComm(via, []string{"no*"})) // glob
	assert.False(t, ChainContainsComm(via, []string{"vim"}))
	assert.False(t, ChainContainsComm(via, []string{"python"}))
}

func TestCountConsecutive(t *testing.T) {
	tests := []struct {
		name    string
		classes []ProcessClass
		target  ProcessClass
		want    int
	}{
		{
			name:    "none",
			classes: []ProcessClass{ClassEditor, ClassBuildTool},
			target:  ClassShell,
			want:    0,
		},
		{
			name:    "scattered",
			classes: []ProcessClass{ClassShell, ClassEditor, ClassShell},
			target:  ClassShell,
			want:    1,
		},
		{
			name:    "consecutive",
			classes: []ProcessClass{ClassShell, ClassShell, ClassShell},
			target:  ClassShell,
			want:    3,
		},
		{
			name:    "max at end",
			classes: []ProcessClass{ClassShell, ClassEditor, ClassShell, ClassShell},
			target:  ClassShell,
			want:    2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, CountConsecutive(tt.classes, tt.target))
		})
	}
}

func TestCountConsecutiveComm(t *testing.T) {
	via := []string{"bash", "bash", "npm", "bash", "bash", "bash"}

	assert.Equal(t, 3, CountConsecutiveComm(via, []string{"bash"}))
	assert.Equal(t, 1, CountConsecutiveComm(via, []string{"npm"}))
	assert.Equal(t, 0, CountConsecutiveComm(via, []string{"python"}))
}
