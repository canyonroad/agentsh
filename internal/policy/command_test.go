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
		{"zsh not matched", "zsh", types.DecisionDeny},          // default deny
		{"/bin/zsh not matched", "/bin/zsh", types.DecisionDeny}, // default deny
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
		// These should NOT match the rule (rule specifies full paths) -> default deny
		{"sh basename not matched", "sh", types.DecisionDeny},
		{"bash basename not matched", "bash", types.DecisionDeny},
		{"/usr/bin/sh not matched (path differs)", "/usr/bin/sh", types.DecisionDeny},
		{"/bin/bash not matched (path differs)", "/bin/bash", types.DecisionDeny},
		{"./sh not matched", "./sh", types.DecisionDeny},
		{"/tmp/sh not matched", "/tmp/sh", types.DecisionDeny},
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
		{"sh basename not matched", "sh", types.DecisionDeny},           // default deny
		{"/tmp/foo/sh not matched", "/tmp/foo/sh", types.DecisionDeny}, // default deny
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
	// Test that full-path rules only match exact paths.
	// With default-deny, copied shells are still blocked (by default, not by rule).
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
		rule     string
	}{
		// These are denied by the explicit rule
		{"/bin/sh denied by rule", "/bin/sh", types.DecisionDeny, "deny-shell-full-path"},
		{"/bin/bash denied by rule", "/bin/bash", types.DecisionDeny, "deny-shell-full-path"},
		// These are denied by default-deny (rule doesn't match, but no allow rule either)
		{"/tmp/sh denied by default", "/tmp/sh", types.DecisionDeny, "default-deny-commands"},
		{"/tmp/bash denied by default", "/tmp/bash", types.DecisionDeny, "default-deny-commands"},
		{"./sh denied by default", "./sh", types.DecisionDeny, "default-deny-commands"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := e.CheckCommand(tc.command, nil)
			if dec.PolicyDecision != tc.decision {
				t.Errorf("expected %s, got %s (rule=%s)", tc.decision, dec.PolicyDecision, dec.Rule)
			}
			if dec.Rule != tc.rule {
				t.Errorf("expected rule %q, got %q", tc.rule, dec.Rule)
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
				ArgsPatterns: []string{"-rf", "-fr", "--force"},
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
		{"rm without dangerous args denied (default)", "rm", []string{"file.txt"}, types.DecisionDeny}, // default deny
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

func TestEngine_CheckCommand_DefaultDeny(t *testing.T) {
	// Test that commands are denied by default when no rule matches.
	// This is consistent with file_rules, network_rules, and unix_socket_rules.
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{
				Name:     "allow-ls",
				Commands: []string{"ls"},
				Decision: "allow",
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
		{"ls allowed by rule", "ls", types.DecisionAllow, "allow-ls"},
		{"/bin/ls allowed by rule", "/bin/ls", types.DecisionAllow, "allow-ls"},
		{"cat denied by default", "cat", types.DecisionDeny, "default-deny-commands"},
		{"/bin/cat denied by default", "/bin/cat", types.DecisionDeny, "default-deny-commands"},
		{"rm denied by default", "rm", types.DecisionDeny, "default-deny-commands"},
		{"python denied by default", "python", types.DecisionDeny, "default-deny-commands"},
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

func TestEngine_CheckCommand_EmptyPolicy(t *testing.T) {
	// Test that with no command rules, all commands are denied by default.
	p := &Policy{
		Version:      1,
		Name:         "test",
		CommandRules: []CommandRule{}, // No rules
	}
	e, err := NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	tests := []string{"ls", "cat", "rm", "/bin/sh", "/usr/bin/python3"}
	for _, cmd := range tests {
		t.Run(cmd, func(t *testing.T) {
			dec := e.CheckCommand(cmd, nil)
			if dec.PolicyDecision != types.DecisionDeny {
				t.Errorf("expected deny for %q, got %s", cmd, dec.PolicyDecision)
			}
			if dec.Rule != "default-deny-commands" {
				t.Errorf("expected rule 'default-deny-commands', got %q", dec.Rule)
			}
		})
	}
}

func TestEngine_CheckCommand_GitSafetyRules(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{
				Name:         "no-direct-push-to-main",
				Commands:     []string{"git"},
				ArgsPatterns: []string{`push.*(origin\s+)?(main|master)`},
				Decision:     "deny",
			},
			{
				Name:         "no-force-push",
				Commands:     []string{"git"},
				ArgsPatterns: []string{`push.*(--force|-f)`},
				Decision:     "deny",
			},
			{
				Name:         "no-hard-reset",
				Commands:     []string{"git"},
				ArgsPatterns: []string{`reset.*(--hard)`},
				Decision:     "deny",
			},
			{
				Name:         "no-git-clean",
				Commands:     []string{"git"},
				ArgsPatterns: []string{`clean.*(-f|--force)`},
				Decision:     "deny",
			},
			{
				Name:     "allow-git",
				Commands: []string{"git"},
				Decision: "allow",
			},
		},
	}
	e, err := NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		args     []string
		decision types.Decision
		rule     string
	}{
		// push to main/master should be blocked
		{"push origin main", []string{"push", "origin", "main"}, types.DecisionDeny, "no-direct-push-to-main"},
		{"push main", []string{"push", "main"}, types.DecisionDeny, "no-direct-push-to-main"},
		{"push origin master", []string{"push", "origin", "master"}, types.DecisionDeny, "no-direct-push-to-main"},
		// push to feature branch should be allowed
		{"push origin feature", []string{"push", "origin", "feature"}, types.DecisionAllow, "allow-git"},
		// checkout main should be allowed (not a push)
		{"checkout main", []string{"checkout", "main"}, types.DecisionAllow, "allow-git"},
		
		// force push should be blocked
		{"push --force", []string{"push", "--force"}, types.DecisionDeny, "no-force-push"},
		{"push -f", []string{"push", "-f"}, types.DecisionDeny, "no-force-push"},
		// push origin main --force matches no-direct-push-to-main first (rule order)
		{"push origin main --force", []string{"push", "origin", "main", "--force"}, types.DecisionDeny, "no-direct-push-to-main"},
		
		// hard reset should be blocked
		{"reset --hard", []string{"reset", "--hard"}, types.DecisionDeny, "no-hard-reset"},
		{"reset --hard HEAD~1", []string{"reset", "--hard", "HEAD~1"}, types.DecisionDeny, "no-hard-reset"},
		// soft reset should be allowed
		{"reset --soft", []string{"reset", "--soft"}, types.DecisionAllow, "allow-git"},
		
		// git clean -f should be blocked
		{"clean -f", []string{"clean", "-f"}, types.DecisionDeny, "no-git-clean"},
		{"clean -fd", []string{"clean", "-fd"}, types.DecisionDeny, "no-git-clean"},
		{"clean --force", []string{"clean", "--force"}, types.DecisionDeny, "no-git-clean"},
		// git status should be allowed
		{"status", []string{"status"}, types.DecisionAllow, "allow-git"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := e.CheckCommand("git", tc.args)
			if dec.PolicyDecision != tc.decision {
				t.Errorf("expected decision %s, got %s (rule=%s)", tc.decision, dec.PolicyDecision, dec.Rule)
			}
			if dec.Rule != tc.rule {
				t.Errorf("expected rule %q, got %q", tc.rule, dec.Rule)
			}
		})
	}
}
