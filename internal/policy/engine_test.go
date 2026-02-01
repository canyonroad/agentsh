package policy

import (
	"runtime"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestEngine_CheckRegistry(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		RegistryRules: []RegistryRule{
			{
				Name:       "block-run-keys",
				Paths:      []string{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*`},
				Operations: []string{"set", "create", "delete"},
				Decision:   "deny",
				Priority:   100,
			},
			{
				Name:       "allow-app-settings",
				Paths:      []string{`HKCU\SOFTWARE\MyApp\*`},
				Operations: []string{"*"},
				Decision:   "allow",
				Priority:   50,
			},
		},
	}

	e, err := NewEngine(p, false)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	tests := []struct {
		name     string
		path     string
		op       string
		wantDec  types.Decision
		wantRule string
	}{
		{
			name:     "block run key write",
			path:     `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Malware`,
			op:       "set",
			wantDec:  types.DecisionDeny,
			wantRule: "block-run-keys",
		},
		{
			name:     "allow app settings",
			path:     `HKCU\SOFTWARE\MyApp\Config`,
			op:       "set",
			wantDec:  types.DecisionAllow,
			wantRule: "allow-app-settings",
		},
		{
			name:     "default deny unmatched",
			path:     `HKLM\SOFTWARE\RandomPath`,
			op:       "set",
			wantDec:  types.DecisionDeny,
			wantRule: "default-deny-registry",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := e.CheckRegistry(tt.path, tt.op)
			if dec.EffectiveDecision != tt.wantDec {
				t.Errorf("decision = %v, want %v", dec.EffectiveDecision, tt.wantDec)
			}
			if dec.Rule != tt.wantRule {
				t.Errorf("rule = %q, want %q", dec.Rule, tt.wantRule)
			}
		})
	}
}

func TestEngineCheckSignal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("signal handling not supported on Windows")
	}
	p := &Policy{
		Version: 1,
		Name:    "test",
		SignalRules: []SignalRule{
			{
				Name:     "deny-kill-external",
				Signals:  []string{"SIGKILL"},
				Target:   SignalTargetSpec{Type: "external"},
				Decision: "deny",
			},
		},
	}

	engine, err := NewEngine(p, false)
	require.NoError(t, err)

	// Create signal engine
	sigEngine := engine.SignalEngine()
	require.NotNil(t, sigEngine)
}

func TestEngine_CheckExecve_BasicAllow(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test-basic-allow",
		CommandRules: []CommandRule{
			{
				Name:     "allow-git",
				Commands: []string{"git"},
				Decision: "allow",
				Context:  DefaultContext(),
			},
		},
	}
	e, err := NewEngine(p, false)
	require.NoError(t, err)

	dec := e.CheckExecve("/usr/bin/git", []string{"git", "status"}, 0)
	require.Equal(t, types.DecisionAllow, dec.EffectiveDecision)
	require.Equal(t, "allow-git", dec.Rule)
}

func TestEngine_CheckExecve_ContextDirect(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test-context-direct",
		CommandRules: []CommandRule{
			{
				Name:     "allow-git-direct",
				Commands: []string{"git"},
				Decision: "allow",
				Context:  ContextConfig{MinDepth: 0, MaxDepth: 0}, // direct only
			},
		},
	}
	e, err := NewEngine(p, false)
	require.NoError(t, err)

	// Depth 0 should match
	dec := e.CheckExecve("/usr/bin/git", []string{"git", "status"}, 0)
	require.Equal(t, types.DecisionAllow, dec.EffectiveDecision)
	require.Equal(t, "allow-git-direct", dec.Rule)

	// Depth 1 should NOT match, fall through to default deny
	dec = e.CheckExecve("/usr/bin/git", []string{"git", "status"}, 1)
	require.Equal(t, types.DecisionDeny, dec.EffectiveDecision)
	require.Equal(t, "default-deny-execve", dec.Rule)
}

func TestEngine_CheckExecve_ContextNested(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test-context-nested",
		CommandRules: []CommandRule{
			{
				Name:     "block-curl-nested",
				Commands: []string{"curl"},
				Decision: "deny",
				Context:  ContextConfig{MinDepth: 1, MaxDepth: -1}, // nested only
			},
			{
				Name:     "allow-all",
				Commands: []string{"*"},
				Decision: "allow",
				Context:  DefaultContext(),
			},
		},
	}
	e, err := NewEngine(p, false)
	require.NoError(t, err)

	// Depth 0 (direct) should NOT match deny rule, fall through to allow-all
	dec := e.CheckExecve("/usr/bin/curl", []string{"curl", "http://example.com"}, 0)
	require.Equal(t, types.DecisionAllow, dec.EffectiveDecision)
	require.Equal(t, "allow-all", dec.Rule)

	// Depth 1+ should match deny rule
	dec = e.CheckExecve("/usr/bin/curl", []string{"curl", "http://example.com"}, 1)
	require.Equal(t, types.DecisionDeny, dec.EffectiveDecision)
	require.Equal(t, "block-curl-nested", dec.Rule)
}

func TestEngine_CheckExecve_ArgsPattern(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test-args-pattern",
		CommandRules: []CommandRule{
			{
				Name:         "block-rm-rf",
				Commands:     []string{"rm"},
				ArgsPatterns: []string{"-rf", "-fr"},
				Decision:     "deny",
				Context:      DefaultContext(),
			},
			{
				Name:     "allow-all",
				Commands: []string{"*"},
				Decision: "allow",
				Context:  DefaultContext(),
			},
		},
	}
	e, err := NewEngine(p, false)
	require.NoError(t, err)

	// rm without -rf should fall through to allow-all
	dec := e.CheckExecve("/bin/rm", []string{"rm", "file.txt"}, 0)
	require.Equal(t, types.DecisionAllow, dec.EffectiveDecision)
	require.Equal(t, "allow-all", dec.Rule)

	// rm -rf should be denied
	dec = e.CheckExecve("/bin/rm", []string{"rm", "-rf", "/"}, 0)
	require.Equal(t, types.DecisionDeny, dec.EffectiveDecision)
	require.Equal(t, "block-rm-rf", dec.Rule)
}

func TestEngine_CheckExecve_FullPathMatch(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test-full-path",
		CommandRules: []CommandRule{
			{
				Name:     "allow-specific-sh",
				Commands: []string{"/bin/sh"},
				Decision: "allow",
				Context:  DefaultContext(),
			},
		},
	}
	e, err := NewEngine(p, false)
	require.NoError(t, err)

	// Exact path match
	dec := e.CheckExecve("/bin/sh", []string{"sh"}, 0)
	require.Equal(t, types.DecisionAllow, dec.EffectiveDecision)
	require.Equal(t, "allow-specific-sh", dec.Rule)

	// Different path, same basename - should not match
	dec = e.CheckExecve("/usr/bin/sh", []string{"sh"}, 0)
	require.Equal(t, types.DecisionDeny, dec.EffectiveDecision)
	require.Equal(t, "default-deny-execve", dec.Rule)
}

func TestEngine_CheckExecve_PathGlobMatch(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test-path-glob",
		CommandRules: []CommandRule{
			{
				Name:     "allow-usr-bin",
				Commands: []string{"/usr/bin/*"},
				Decision: "allow",
				Context:  DefaultContext(),
			},
		},
	}
	e, err := NewEngine(p, false)
	require.NoError(t, err)

	// Should match the glob
	dec := e.CheckExecve("/usr/bin/git", []string{"git"}, 0)
	require.Equal(t, types.DecisionAllow, dec.EffectiveDecision)
	require.Equal(t, "allow-usr-bin", dec.Rule)

	// Different path - should not match
	dec = e.CheckExecve("/bin/git", []string{"git"}, 0)
	require.Equal(t, types.DecisionDeny, dec.EffectiveDecision)
}

func TestEngine_CheckExecve_BasenameGlobMatch(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test-basename-glob",
		CommandRules: []CommandRule{
			{
				Name:     "allow-python-variants",
				Commands: []string{"python*"},
				Decision: "allow",
				Context:  DefaultContext(),
			},
		},
	}
	e, err := NewEngine(p, false)
	require.NoError(t, err)

	// Should match python3
	dec := e.CheckExecve("/usr/bin/python3", []string{"python3"}, 0)
	require.Equal(t, types.DecisionAllow, dec.EffectiveDecision)
	require.Equal(t, "allow-python-variants", dec.Rule)

	// Should match python
	dec = e.CheckExecve("/usr/bin/python", []string{"python"}, 0)
	require.Equal(t, types.DecisionAllow, dec.EffectiveDecision)

	// Should not match ruby
	dec = e.CheckExecve("/usr/bin/ruby", []string{"ruby"}, 0)
	require.Equal(t, types.DecisionDeny, dec.EffectiveDecision)
}

func TestEngine_CheckExecve_DefaultDeny(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test-default-deny",
		CommandRules: []CommandRule{
			{
				Name:     "allow-git",
				Commands: []string{"git"},
				Decision: "allow",
				Context:  DefaultContext(),
			},
		},
	}
	e, err := NewEngine(p, false)
	require.NoError(t, err)

	// Should default deny for commands not matching any rule
	dec := e.CheckExecve("/usr/bin/wget", []string{"wget", "http://example.com"}, 0)
	require.Equal(t, types.DecisionDeny, dec.EffectiveDecision)
	require.Equal(t, "default-deny-execve", dec.Rule)
}

func TestEngine_GetEnvInject(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test-env-inject",
		EnvInject: map[string]string{
			"BASH_ENV":      "/usr/lib/agentsh/bash_startup.sh",
			"MY_CUSTOM_VAR": "custom_value",
		},
	}
	e, err := NewEngine(p, false)
	require.NoError(t, err)

	env := e.GetEnvInject()
	require.Len(t, env, 2)
	require.Equal(t, "/usr/lib/agentsh/bash_startup.sh", env["BASH_ENV"])
	require.Equal(t, "custom_value", env["MY_CUSTOM_VAR"])
}

func TestEngine_GetEnvInject_Nil(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test-env-inject-nil",
		// EnvInject not set
	}
	e, err := NewEngine(p, false)
	require.NoError(t, err)

	env := e.GetEnvInject()
	require.NotNil(t, env)
	require.Empty(t, env)
}

func TestEngine_GetEnvInject_NilEngine(t *testing.T) {
	var e *Engine
	env := e.GetEnvInject()
	require.NotNil(t, env)
	require.Empty(t, env)
}
