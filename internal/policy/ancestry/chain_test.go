package ancestry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConditionEvaluator_ViaIndex(t *testing.T) {
	e := NewConditionEvaluator()

	taint := &ProcessTaint{
		Via:        []string{"bash", "npm", "node"},
		ViaClasses: []ProcessClass{ClassShell, ClassBuildTool, ClassLanguageRuntime},
	}

	tests := []struct {
		name  string
		index int
		value string
		want  bool
	}{
		{"index 0 match", 0, "bash", true},
		{"index 1 match", 1, "npm", true},
		{"index 2 match", 2, "node", true},
		{"index 0 no match", 0, "zsh", false},
		{"index out of range", 5, "bash", false},
		{"glob pattern", 1, "n*", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cond := &ChainCondition{
				ViaIndex:      &tt.index,
				ViaIndexValue: tt.value,
			}
			assert.Equal(t, tt.want, e.Evaluate(cond, taint, nil))
		})
	}
}

func TestConditionEvaluator_ViaContains(t *testing.T) {
	e := NewConditionEvaluator()

	taint := &ProcessTaint{
		Via: []string{"bash", "npm", "node"},
	}

	tests := []struct {
		name     string
		patterns []string
		want     bool
	}{
		{"contains bash", []string{"bash"}, true},
		{"contains npm", []string{"npm"}, true},
		{"contains either", []string{"python", "npm"}, true},
		{"contains none", []string{"python", "ruby"}, false},
		{"glob pattern", []string{"no*"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cond := &ChainCondition{ViaContains: tt.patterns}
			assert.Equal(t, tt.want, e.Evaluate(cond, taint, nil))
		})
	}
}

func TestConditionEvaluator_ViaNotContains(t *testing.T) {
	e := NewConditionEvaluator()

	taint := &ProcessTaint{
		Via: []string{"bash", "npm", "node"},
	}

	tests := []struct {
		name     string
		patterns []string
		want     bool
	}{
		{"not contains python", []string{"python"}, true},
		{"not contains bash", []string{"bash"}, false},
		{"not contains either", []string{"python", "bash"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cond := &ChainCondition{ViaNotContains: tt.patterns}
			assert.Equal(t, tt.want, e.Evaluate(cond, taint, nil))
		})
	}
}

func TestConditionEvaluator_ClassContains(t *testing.T) {
	e := NewConditionEvaluator()

	taint := &ProcessTaint{
		ViaClasses: []ProcessClass{ClassShell, ClassBuildTool, ClassLanguageRuntime},
	}

	tests := []struct {
		name    string
		classes []string
		want    bool
	}{
		{"contains shell", []string{"shell"}, true},
		{"contains build_tool", []string{"build_tool"}, true},
		{"contains either", []string{"editor", "shell"}, true},
		{"contains none", []string{"editor", "agent"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cond := &ChainCondition{ClassContains: tt.classes}
			assert.Equal(t, tt.want, e.Evaluate(cond, taint, nil))
		})
	}
}

func TestConditionEvaluator_ConsecutiveClass(t *testing.T) {
	e := NewConditionEvaluator()

	taint := &ProcessTaint{
		ViaClasses: []ProcessClass{ClassShell, ClassShell, ClassShell, ClassBuildTool},
	}

	tests := []struct {
		name    string
		match   *ConsecutiveMatch
		want    bool
	}{
		{
			name:    "3+ shells matches",
			match:   &ConsecutiveMatch{Value: "shell", CountGE: 3},
			want:    true,
		},
		{
			name:    "4+ shells doesn't match",
			match:   &ConsecutiveMatch{Value: "shell", CountGE: 4},
			want:    false,
		},
		{
			name:    "at most 3 shells matches",
			match:   &ConsecutiveMatch{Value: "shell", CountLE: 3},
			want:    true,
		},
		{
			name:    "at most 2 shells doesn't match",
			match:   &ConsecutiveMatch{Value: "shell", CountLE: 2},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cond := &ChainCondition{ConsecutiveClass: tt.match}
			assert.Equal(t, tt.want, e.Evaluate(cond, taint, nil))
		})
	}
}

func TestConditionEvaluator_Depth(t *testing.T) {
	e := NewConditionEvaluator()

	taint := &ProcessTaint{Depth: 5}

	tests := []struct {
		name string
		cond *ChainCondition
		want bool
	}{
		{"depth_eq 5", &ChainCondition{DepthEQ: intPtr(5)}, true},
		{"depth_eq 3", &ChainCondition{DepthEQ: intPtr(3)}, false},
		{"depth_gt 4", &ChainCondition{DepthGT: intPtr(4)}, true},
		{"depth_gt 5", &ChainCondition{DepthGT: intPtr(5)}, false},
		{"depth_lt 6", &ChainCondition{DepthLT: intPtr(6)}, true},
		{"depth_lt 5", &ChainCondition{DepthLT: intPtr(5)}, false},
		{"depth_ge 5", &ChainCondition{DepthGE: intPtr(5)}, true},
		{"depth_ge 6", &ChainCondition{DepthGE: intPtr(6)}, false},
		{"depth_le 5", &ChainCondition{DepthLE: intPtr(5)}, true},
		{"depth_le 4", &ChainCondition{DepthLE: intPtr(4)}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, e.Evaluate(tt.cond, taint, nil))
		})
	}
}

func TestConditionEvaluator_TaintFlags(t *testing.T) {
	e := NewConditionEvaluator()

	taintedAgent := &ProcessTaint{IsAgent: true}
	taintedNotAgent := &ProcessTaint{IsAgent: false}

	tests := []struct {
		name      string
		taint     *ProcessTaint
		isTainted *bool
		isAgent   *bool
		want      bool
	}{
		{"is tainted (true)", taintedAgent, boolPtr(true), nil, true},
		{"is tainted (false)", taintedAgent, boolPtr(false), nil, false},
		{"not tainted", nil, boolPtr(false), nil, true},
		{"is agent (true)", taintedAgent, nil, boolPtr(true), true},
		{"is agent (false)", taintedNotAgent, nil, boolPtr(false), true},
		{"not agent", taintedNotAgent, nil, boolPtr(true), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cond := &ChainCondition{
				IsTainted: tt.isTainted,
				IsAgent:   tt.isAgent,
			}
			assert.Equal(t, tt.want, e.Evaluate(cond, tt.taint, nil))
		})
	}
}

func TestConditionEvaluator_ExecutionContext(t *testing.T) {
	e := NewConditionEvaluator()

	ctx := &ExecutionContext{
		Comm:    "curl",
		Args:    []string{"curl", "-X", "POST", "https://api.example.com"},
		ExePath: "/usr/bin/curl",
		Env: map[string]string{
			"HOME":    "/home/user",
			"API_KEY": "secret123",
		},
	}

	tests := []struct {
		name string
		cond *ChainCondition
		want bool
	}{
		{
			name: "comm matches",
			cond: &ChainCondition{CommMatches: []string{"curl"}},
			want: true,
		},
		{
			name: "comm glob",
			cond: &ChainCondition{CommMatches: []string{"cu*"}},
			want: true,
		},
		{
			name: "path matches",
			cond: &ChainCondition{PathMatches: []string{"*/curl"}},
			want: true,
		},
		{
			name: "args contain",
			cond: &ChainCondition{ArgsContain: []string{"POST"}},
			want: true,
		},
		{
			name: "args contain url",
			cond: &ChainCondition{ArgsContain: []string{"*example.com*"}},
			want: true,
		},
		{
			name: "env contains key",
			cond: &ChainCondition{EnvContains: []string{"API_KEY"}},
			want: true,
		},
		{
			name: "env contains value",
			cond: &ChainCondition{EnvContains: []string{"secret*"}},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, e.Evaluate(tt.cond, nil, ctx))
		})
	}
}

func TestConditionEvaluator_SourceConditions(t *testing.T) {
	e := NewConditionEvaluator()

	taint := &ProcessTaint{
		SourceName:  "cursor",
		ContextName: "ai_tools",
	}

	tests := []struct {
		name string
		cond *ChainCondition
		want bool
	}{
		{
			name: "source name match",
			cond: &ChainCondition{SourceName: []string{"cursor"}},
			want: true,
		},
		{
			name: "source name glob",
			cond: &ChainCondition{SourceName: []string{"cur*"}},
			want: true,
		},
		{
			name: "source name no match",
			cond: &ChainCondition{SourceName: []string{"vscode"}},
			want: false,
		},
		{
			name: "source context match",
			cond: &ChainCondition{SourceContext: []string{"ai_tools"}},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, e.Evaluate(tt.cond, taint, nil))
		})
	}
}

func TestConditionEvaluator_LogicalOr(t *testing.T) {
	e := NewConditionEvaluator()

	taint := &ProcessTaint{
		Depth: 3,
		Via:   []string{"bash"},
	}

	cond := &ChainCondition{
		Or: []*ChainCondition{
			{DepthEQ: intPtr(5)},           // false
			{ViaContains: []string{"bash"}}, // true
		},
	}

	assert.True(t, e.Evaluate(cond, taint, nil))

	// Both false
	cond.Or = []*ChainCondition{
		{DepthEQ: intPtr(5)},
		{ViaContains: []string{"python"}},
	}
	assert.False(t, e.Evaluate(cond, taint, nil))
}

func TestConditionEvaluator_LogicalAnd(t *testing.T) {
	e := NewConditionEvaluator()

	taint := &ProcessTaint{
		Depth: 3,
		Via:   []string{"bash"},
	}

	cond := &ChainCondition{
		And: []*ChainCondition{
			{DepthEQ: intPtr(3)},
			{ViaContains: []string{"bash"}},
		},
	}

	assert.True(t, e.Evaluate(cond, taint, nil))

	// One false
	cond.And = []*ChainCondition{
		{DepthEQ: intPtr(5)},
		{ViaContains: []string{"bash"}},
	}
	assert.False(t, e.Evaluate(cond, taint, nil))
}

func TestConditionEvaluator_LogicalNot(t *testing.T) {
	e := NewConditionEvaluator()

	taint := &ProcessTaint{Depth: 3}

	cond := &ChainCondition{
		Not: &ChainCondition{DepthEQ: intPtr(5)},
	}
	assert.True(t, e.Evaluate(cond, taint, nil))

	cond.Not = &ChainCondition{DepthEQ: intPtr(3)}
	assert.False(t, e.Evaluate(cond, taint, nil))
}

func TestConditionEvaluator_NilCondition(t *testing.T) {
	e := NewConditionEvaluator()
	assert.True(t, e.Evaluate(nil, nil, nil))
}

// Escape hatch scenario tests

func TestEscapeHatch_UserTerminal(t *testing.T) {
	e := NewConditionEvaluator()

	// User opens terminal from editor: depth=1, via=[shell]
	userTerminal := &ProcessTaint{
		Depth:      1,
		Via:        []string{"bash"},
		ViaClasses: []ProcessClass{ClassShell},
	}

	// Condition: depth=1 AND via[0] is shell
	cond := &ChainCondition{
		And: []*ChainCondition{
			{DepthEQ: intPtr(1)},
			{ViaIndex: intPtr(0), ViaIndexValue: "@shell"},
		},
	}

	assert.True(t, e.Evaluate(cond, userTerminal, nil))

	// AI spawned shell at depth 3 should not match
	aiShell := &ProcessTaint{
		Depth:      3,
		Via:        []string{"bash", "npm", "bash"},
		ViaClasses: []ProcessClass{ClassShell, ClassBuildTool, ClassShell},
	}
	assert.False(t, e.Evaluate(cond, aiShell, nil))
}

func TestEscapeHatch_EditorFeature(t *testing.T) {
	e := NewConditionEvaluator()

	// LSP or build tool in chain = editor feature
	lspChain := &ProcessTaint{
		Via:        []string{"bash", "gopls"},
		ViaClasses: []ProcessClass{ClassShell, ClassLanguageServer},
	}

	buildChain := &ProcessTaint{
		Via:        []string{"bash", "npm", "node"},
		ViaClasses: []ProcessClass{ClassShell, ClassBuildTool, ClassLanguageRuntime},
	}

	// Condition: chain contains LSP or build tool
	cond := &ChainCondition{
		Or: []*ChainCondition{
			{ClassContains: []string{"language_server"}},
			{ClassContains: []string{"build_tool"}},
		},
	}

	assert.True(t, e.Evaluate(cond, lspChain, nil))
	assert.True(t, e.Evaluate(cond, buildChain, nil))

	// Plain shell chain should not match
	shellChain := &ProcessTaint{
		Via:        []string{"bash", "bash"},
		ViaClasses: []ProcessClass{ClassShell, ClassShell},
	}
	assert.False(t, e.Evaluate(cond, shellChain, nil))
}

func TestEscapeHatch_ShellLaundering(t *testing.T) {
	e := NewConditionEvaluator()

	// 3+ consecutive shells = shell laundering
	laundering := &ProcessTaint{
		Via:        []string{"bash", "bash", "bash", "python"},
		ViaClasses: []ProcessClass{ClassShell, ClassShell, ClassShell, ClassLanguageRuntime},
	}

	cond := &ChainCondition{
		ConsecutiveClass: &ConsecutiveMatch{
			Value:   "shell",
			CountGE: 3,
		},
	}

	assert.True(t, e.Evaluate(cond, laundering, nil))

	// Only 2 consecutive shells - not laundering
	notLaundering := &ProcessTaint{
		Via:        []string{"bash", "bash", "python"},
		ViaClasses: []ProcessClass{ClassShell, ClassShell, ClassLanguageRuntime},
	}
	assert.False(t, e.Evaluate(cond, notLaundering, nil))
}

func TestEscapeHatch_DepthLimit(t *testing.T) {
	e := NewConditionEvaluator()

	deepChain := &ProcessTaint{Depth: 15}
	shallowChain := &ProcessTaint{Depth: 3}

	// Depth > 10 = suspicious
	cond := &ChainCondition{DepthGT: intPtr(10)}

	assert.True(t, e.Evaluate(cond, deepChain, nil))
	assert.False(t, e.Evaluate(cond, shallowChain, nil))
}

// Chain rule tests

func TestChainRuleEvaluator_PriorityOrder(t *testing.T) {
	e := NewChainRuleEvaluator()

	e.SetRules([]ChainRule{
		{Name: "low", Priority: 10, Condition: &ChainCondition{IsTainted: boolPtr(true)}, Action: ActionDeny},
		{Name: "high", Priority: 100, Condition: &ChainCondition{IsTainted: boolPtr(true)}, Action: ActionAllow},
		{Name: "medium", Priority: 50, Condition: &ChainCondition{IsTainted: boolPtr(true)}, Action: ActionApprove},
	})

	taint := &ProcessTaint{}
	rule := e.Evaluate(taint, nil)

	require.NotNil(t, rule)
	assert.Equal(t, "high", rule.Name)
	assert.Equal(t, ActionAllow, rule.Action)
}

func TestChainRuleEvaluator_NoMatch(t *testing.T) {
	e := NewChainRuleEvaluator()

	e.SetRules([]ChainRule{
		{Name: "only_agents", Condition: &ChainCondition{IsAgent: boolPtr(true)}, Action: ActionDeny},
	})

	taint := &ProcessTaint{IsAgent: false}
	rule := e.Evaluate(taint, nil)

	assert.Nil(t, rule)
}

func TestChainRuleEvaluator_Continue(t *testing.T) {
	e := NewChainRuleEvaluator()

	e.SetRules([]ChainRule{
		{
			Name:      "mark_agent",
			Priority:  100,
			Condition: &ChainCondition{ViaContains: []string{"aider"}},
			Action:    ActionMarkAsAgent,
			Continue:  true, // Continue evaluating
		},
		{
			Name:      "apply_policy",
			Priority:  50,
			Condition: &ChainCondition{IsTainted: boolPtr(true)},
			Action:    ActionApplyContextPolicy,
		},
	})

	taint := &ProcessTaint{Via: []string{"aider", "bash"}}

	// EvaluateAll should return both rules
	rules := e.EvaluateAll(taint, nil)
	require.Len(t, rules, 2)
	assert.Equal(t, "mark_agent", rules[0].Name)
	assert.Equal(t, "apply_policy", rules[1].Name)

	// EvaluateWithContinue should return both and final action
	matchedRules, finalAction := e.EvaluateWithContinue(taint, nil)
	require.Len(t, matchedRules, 2)
	assert.Equal(t, ActionApplyContextPolicy, finalAction)
}

func TestChainRuleEvaluator_EscapeHatchScenario(t *testing.T) {
	e := NewChainRuleEvaluator()

	// Configure escape hatch rules
	e.SetRules([]ChainRule{
		{
			Name:     "shell_laundering",
			Priority: 100,
			Condition: &ChainCondition{
				ConsecutiveClass: &ConsecutiveMatch{Value: "shell", CountGE: 3},
			},
			Action:  ActionDeny,
			Message: "Shell laundering detected",
		},
		{
			Name:     "user_terminal",
			Priority: 90,
			Condition: &ChainCondition{
				And: []*ChainCondition{
					{DepthEQ: intPtr(1)},
					{ClassContains: []string{"shell"}},
				},
			},
			Action:  ActionAllowNormalPolicy,
			Message: "User-opened terminal",
		},
		{
			Name:     "editor_feature",
			Priority: 80,
			Condition: &ChainCondition{
				Or: []*ChainCondition{
					{ClassContains: []string{"language_server"}},
					{ClassContains: []string{"build_tool"}},
				},
			},
			Action:  ActionAllowNormalPolicy,
			Message: "Editor feature",
		},
		{
			Name:      "default_context_policy",
			Priority:  0,
			Condition: &ChainCondition{IsTainted: boolPtr(true)},
			Action:    ActionApplyContextPolicy,
		},
	})

	// Test shell laundering
	launderingTaint := &ProcessTaint{
		Depth:      4,
		ViaClasses: []ProcessClass{ClassShell, ClassShell, ClassShell, ClassShell},
	}
	rule := e.Evaluate(launderingTaint, nil)
	require.NotNil(t, rule)
	assert.Equal(t, "shell_laundering", rule.Name)
	assert.Equal(t, ActionDeny, rule.Action)

	// Test user terminal
	userTerminalTaint := &ProcessTaint{
		Depth:      1,
		ViaClasses: []ProcessClass{ClassShell},
	}
	rule = e.Evaluate(userTerminalTaint, nil)
	require.NotNil(t, rule)
	assert.Equal(t, "user_terminal", rule.Name)
	assert.Equal(t, ActionAllowNormalPolicy, rule.Action)

	// Test editor feature
	lspTaint := &ProcessTaint{
		Depth:      3,
		ViaClasses: []ProcessClass{ClassShell, ClassLanguageServer, ClassLanguageRuntime},
	}
	rule = e.Evaluate(lspTaint, nil)
	require.NotNil(t, rule)
	assert.Equal(t, "editor_feature", rule.Name)

	// Test default tainted process
	normalTaint := &ProcessTaint{
		Depth:      2,
		ViaClasses: []ProcessClass{ClassShell, ClassUnknown},
	}
	rule = e.Evaluate(normalTaint, nil)
	require.NotNil(t, rule)
	assert.Equal(t, "default_context_policy", rule.Name)
	assert.Equal(t, ActionApplyContextPolicy, rule.Action)
}

// Helper functions
func intPtr(i int) *int       { return &i }
func boolPtr(b bool) *bool    { return &b }
