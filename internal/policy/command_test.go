package policy

import (
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestEngine_CheckCommand_BasenameMatch(t *testing.T) {
	// Legacy behavior: commands without paths match by basename
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{
				Name:     "deny-shell",
				Commands: []string{"sh", "bash"},
				Decision: "deny",
			},
		},
	}
	e, err := NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		command  string
		decision types.Decision
	}{
		{"basename sh", "sh", types.DecisionDeny},
		{"basename bash", "bash", types.DecisionDeny},
		{"/bin/sh matches sh basename", "/bin/sh", types.DecisionDeny},
		{"/usr/bin/bash matches bash basename", "/usr/bin/bash", types.DecisionDeny},
		{"./sh matches sh basename", "./sh", types.DecisionDeny},
		{"relative path/sh matches", "path/to/sh", types.DecisionDeny},
		{"zsh not matched", "zsh", types.DecisionAllow},
		{"/bin/zsh not matched", "/bin/zsh", types.DecisionAllow},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := e.CheckCommand(tc.command, nil)
			if dec.PolicyDecision != tc.decision {
				t.Errorf("expected %s, got %s (rule=%s)", tc.decision, dec.PolicyDecision, dec.Rule)
			}
		})
	}
}

func TestEngine_CheckCommand_FullPathMatch(t *testing.T) {
	// New behavior: commands with paths require exact path match
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{
				Name:     "deny-specific-sh",
				Commands: []string{"/bin/sh", "/usr/bin/bash"},
				Decision: "deny",
			},
		},
	}
	e, err := NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		command  string
		decision types.Decision
	}{
		{"/bin/sh exact match", "/bin/sh", types.DecisionDeny},
		{"/usr/bin/bash exact match", "/usr/bin/bash", types.DecisionDeny},
		// These should NOT match because the rule specifies full paths
		{"sh basename not matched", "sh", types.DecisionAllow},
		{"bash basename not matched", "bash", types.DecisionAllow},
		{"/usr/bin/sh not matched (path differs)", "/usr/bin/sh", types.DecisionAllow},
		{"/bin/bash not matched (path differs)", "/bin/bash", types.DecisionAllow},
		{"./sh not matched", "./sh", types.DecisionAllow},
		{"/tmp/sh not matched", "/tmp/sh", types.DecisionAllow},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := e.CheckCommand(tc.command, nil)
			if dec.PolicyDecision != tc.decision {
				t.Errorf("expected %s, got %s (rule=%s)", tc.decision, dec.PolicyDecision, dec.Rule)
			}
		})
	}
}

func TestEngine_CheckCommand_PathGlobMatch(t *testing.T) {
	// Glob patterns in paths
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{
				Name:     "deny-any-sh-in-bin",
				Commands: []string{"/*/sh", "/usr/*/sh"},
				Decision: "deny",
			},
		},
	}
	e, err := NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		command  string
		decision types.Decision
	}{
		{"/bin/sh matches /*/sh", "/bin/sh", types.DecisionDeny},
		{"/usr/bin/sh matches /usr/*/sh", "/usr/bin/sh", types.DecisionDeny},
		{"/sbin/sh matches /*/sh", "/sbin/sh", types.DecisionDeny},
		{"sh basename not matched", "sh", types.DecisionAllow},
		{"/tmp/foo/sh not matched", "/tmp/foo/sh", types.DecisionAllow},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := e.CheckCommand(tc.command, nil)
			if dec.PolicyDecision != tc.decision {
				t.Errorf("expected %s, got %s (rule=%s)", tc.decision, dec.PolicyDecision, dec.Rule)
			}
		})
	}
}

func TestEngine_CheckCommand_MixedRules(t *testing.T) {
	// Mix of basename and full path rules
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{
				Name:     "allow-system-python",
				Commands: []string{"/usr/bin/python3"},
				Decision: "allow",
			},
			{
				Name:     "deny-python-everywhere-else",
				Commands: []string{"python", "python3"},
				Decision: "deny",
			},
		},
	}
	e, err := NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		command  string
		decision types.Decision
		rule     string
	}{
		// Full path match takes precedence (first rule wins)
		{"/usr/bin/python3 allowed", "/usr/bin/python3", types.DecisionAllow, "allow-system-python"},
		// Basename matches
		{"python denied", "python", types.DecisionDeny, "deny-python-everywhere-else"},
		{"python3 denied", "python3", types.DecisionDeny, "deny-python-everywhere-else"},
		{"/tmp/python3 denied via basename", "/tmp/python3", types.DecisionDeny, "deny-python-everywhere-else"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := e.CheckCommand(tc.command, nil)
			if dec.PolicyDecision != tc.decision {
				t.Errorf("expected decision %s, got %s", tc.decision, dec.PolicyDecision)
			}
			if dec.Rule != tc.rule {
				t.Errorf("expected rule %q, got %q", tc.rule, dec.Rule)
			}
		})
	}
}

func TestEngine_CheckCommand_SecurityBypass(t *testing.T) {
	// Test that the old vulnerability is fixed:
	// Copying /bin/sh to /tmp/foo should NOT bypass a full-path deny rule
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{
				Name:     "deny-shell-full-path",
				Commands: []string{"/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/bash"},
				Decision: "deny",
			},
		},
	}
	e, err := NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		command  string
		decision types.Decision
	}{
		// These should be denied
		{"/bin/sh denied", "/bin/sh", types.DecisionDeny},
		{"/bin/bash denied", "/bin/bash", types.DecisionDeny},
		// These should be allowed (bypass attempt) because rule uses full paths
		{"/tmp/sh allowed (not in rule)", "/tmp/sh", types.DecisionAllow},
		{"/tmp/bash allowed (not in rule)", "/tmp/bash", types.DecisionAllow},
		{"./sh allowed (not in rule)", "./sh", types.DecisionAllow},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := e.CheckCommand(tc.command, nil)
			if dec.PolicyDecision != tc.decision {
				t.Errorf("expected %s, got %s (rule=%s)", tc.decision, dec.PolicyDecision, dec.Rule)
			}
		})
	}
}

func TestEngine_CheckCommand_CaseInsensitive(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{
				Name:     "deny-cmd",
				Commands: []string{"CMD.EXE", "/BIN/SH"},
				Decision: "deny",
			},
		},
	}
	e, err := NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		command  string
		decision types.Decision
	}{
		{"CMD.EXE matches", "CMD.EXE", types.DecisionDeny},
		{"cmd.exe matches", "cmd.exe", types.DecisionDeny},
		{"Cmd.Exe matches", "Cmd.Exe", types.DecisionDeny},
		{"/bin/sh matches /BIN/SH", "/bin/sh", types.DecisionDeny},
		{"/BIN/SH matches", "/BIN/SH", types.DecisionDeny},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := e.CheckCommand(tc.command, nil)
			if dec.PolicyDecision != tc.decision {
				t.Errorf("expected %s, got %s", tc.decision, dec.PolicyDecision)
			}
		})
	}
}

func TestEngine_CheckCommand_WithArgs(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{
				Name:         "deny-rm-rf",
				Commands:     []string{"rm"},
				ArgsPatterns: []string{"-rf*", "-fr*", "--force*"},
				Decision:     "deny",
			},
		},
	}
	e, err := NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		command  string
		args     []string
		decision types.Decision
	}{
		{"rm -rf denied", "rm", []string{"-rf", "/"}, types.DecisionDeny},
		{"rm -fr denied", "rm", []string{"-fr", "/"}, types.DecisionDeny},
		{"rm --force denied", "rm", []string{"--force", "-r", "/"}, types.DecisionDeny},
		{"rm without dangerous args allowed", "rm", []string{"file.txt"}, types.DecisionAllow},
		{"/bin/rm -rf denied", "/bin/rm", []string{"-rf", "/"}, types.DecisionDeny},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := e.CheckCommand(tc.command, tc.args)
			if dec.PolicyDecision != tc.decision {
				t.Errorf("expected %s, got %s (rule=%s)", tc.decision, dec.PolicyDecision, dec.Rule)
			}
		})
	}
}
