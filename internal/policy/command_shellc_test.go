package policy

import (
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

// TestEngine_CheckCommand_ShellCDerive verifies that a policy rule targeting
// an inner binary fires when the binary is invoked via `<shell> -c "<cmd>"`.
// Before the shellparse integration, `sh -c "shutdown now"` only matched
// rules targeting `sh`, so `deny bin=shutdown` was trivially bypassable.
func TestEngine_CheckCommand_ShellCDerive(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{Name: "deny-shutdown", Commands: []string{"shutdown"}, Decision: "deny"},
			{Name: "allow-shells", Commands: []string{"sh", "bash", "dash", "zsh"}, Decision: "allow"},
			{Name: "allow-reboot-absolute", Commands: []string{"/sbin/reboot"}, Decision: "allow"},
		},
	}
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		command  string
		args     []string
		decision types.Decision
		rule     string
	}{
		// --- the bug fix ---
		{"sh -c 'shutdown now' → derived deny", "/bin/sh", []string{"-c", "shutdown now"}, types.DecisionDeny, "deny-shutdown"},
		{"bash -c 'shutdown' → derived deny", "/bin/bash", []string{"-c", "shutdown"}, types.DecisionDeny, "deny-shutdown"},
		{"bash -euxc 'shutdown' → clustered safe options, derived deny", "/bin/bash", []string{"-euxc", "shutdown"}, types.DecisionDeny, "deny-shutdown"},
		{"sh -e -c 'shutdown' → split safe option + c, derived deny", "/bin/sh", []string{"-e", "-c", "shutdown"}, types.DecisionDeny, "deny-shutdown"},
		{"bash -e -u -c 'shutdown' → multi-split, derived deny", "/bin/bash", []string{"-e", "-u", "-c", "shutdown"}, types.DecisionDeny, "deny-shutdown"},
		{"sh -l -c 'shutdown' → login option hides -c, bypass-deny", "/bin/sh", []string{"-l", "-c", "shutdown"}, types.DecisionDeny, "shellc-wrapper-bypass"},
		{"bash -o errexit -c 'shutdown' → operand option hides -c, bypass-deny", "/bin/bash", []string{"-o", "errexit", "-c", "shutdown"}, types.DecisionDeny, "shellc-wrapper-bypass"},
		{"sh -c 'shutdown now' argv0 → POSIX positional params ignored, derived deny", "/bin/sh", []string{"-c", "shutdown now", "argv0_name"}, types.DecisionDeny, "deny-shutdown"},
		{"sh -c 'shutdown' argv0 p1 p2 → positional params ignored, derived deny", "/bin/sh", []string{"-c", "shutdown", "argv0_name", "p1", "p2"}, types.DecisionDeny, "deny-shutdown"},
		{"uppercase shell path (case-insensitive FS) → derived deny", "/BIN/SH", []string{"-c", "shutdown now"}, types.DecisionDeny, "deny-shutdown"},
		{"dash -c 'exec shutdown' → wrapper stripped, derived deny", "/bin/dash", []string{"-c", "exec shutdown"}, types.DecisionDeny, "deny-shutdown"},
		{"sh -c 'nohup shutdown' → wrapper stripped, derived deny", "/bin/sh", []string{"-c", "nohup shutdown"}, types.DecisionDeny, "deny-shutdown"},
		{"sh -c 'nice shutdown' → wrapper stripped, derived deny", "/bin/sh", []string{"-c", "nice shutdown"}, types.DecisionDeny, "deny-shutdown"},
		{"bash -c 'nohup exec shutdown' → chained wrappers, derived deny", "/bin/bash", []string{"-c", "nohup exec shutdown"}, types.DecisionDeny, "deny-shutdown"},
		{"sh -c 'nice -n 19 shutdown' → nice -n N parsed, derived deny", "/bin/sh", []string{"-c", "nice -n 19 shutdown"}, types.DecisionDeny, "deny-shutdown"},
		{"sh -c 'nice -n -5 shutdown' → nice -n negative parsed, derived deny", "/bin/sh", []string{"-c", "nice -n -5 shutdown"}, types.DecisionDeny, "deny-shutdown"},
		{"absolute path shutdown via sh", "sh", []string{"-c", "/sbin/shutdown now"}, types.DecisionDeny, "deny-shutdown"},
		// --- time/env transparent wrappers (R15) ---
		{"sh -c 'time shutdown' → time stripped, derived deny", "/bin/sh", []string{"-c", "time shutdown"}, types.DecisionDeny, "deny-shutdown"},
		{"sh -c 'env shutdown' → env stripped, derived deny", "/bin/sh", []string{"-c", "env shutdown"}, types.DecisionDeny, "deny-shutdown"},
		{"sh -c 'time nohup shutdown' → time+nohup chained, derived deny", "/bin/sh", []string{"-c", "time nohup shutdown"}, types.DecisionDeny, "deny-shutdown"},
		{"sh -c 'env nohup shutdown' → env+nohup chained, derived deny", "/bin/sh", []string{"-c", "env nohup shutdown"}, types.DecisionDeny, "deny-shutdown"},
		{"sh -c 'exec env shutdown' → exec+env chained, derived deny", "/bin/sh", []string{"-c", "exec env shutdown"}, types.DecisionDeny, "deny-shutdown"},
		{"sh -c 'time -p shutdown' → time flag bypass", "/bin/sh", []string{"-c", "time -p shutdown"}, types.DecisionDeny, "shellc-wrapper-bypass"},
		{"sh -c 'env -i shutdown' → env flag bypass", "/bin/sh", []string{"-c", "env -i shutdown"}, types.DecisionDeny, "shellc-wrapper-bypass"},
		{"sh -c 'env -u PATH shutdown' → env -u bypass", "/bin/sh", []string{"-c", "env -u PATH shutdown"}, types.DecisionDeny, "shellc-wrapper-bypass"},
		{"sh -c 'env VAR=val shutdown' → env with assign is byte-allowlist evasion bypass", "/bin/sh", []string{"-c", "env VAR=val shutdown"}, types.DecisionDeny, "shellc-wrapper-bypass"},
		// --- zsh treated as known shell: outer allow bin=zsh doesn't mask inner deny.
		{"zsh -c 'shutdown' → derived deny", "zsh", []string{"-c", "shutdown now"}, types.DecisionDeny, "deny-shutdown"},
		{"zsh -c 'nohup shutdown' → wrapper stripped, derived deny", "/usr/bin/zsh", []string{"-c", "nohup shutdown"}, types.DecisionDeny, "deny-shutdown"},
		{"zsh -c 'exec -a foo shutdown' → bypass deny", "zsh", []string{"-c", "exec -a foo shutdown"}, types.DecisionDeny, "shellc-wrapper-bypass"},
		// --- env-assignment parse-through: strip leading NAME=VALUE and
		// derive past them so `deny-shutdown` fires instead of falling
		// back to the outer shell allow.
		{"sh -c 'PATH=/tmp shutdown' → assign parse-through, derived deny", "/bin/sh", []string{"-c", "PATH=/tmp shutdown"}, types.DecisionDeny, "deny-shutdown"},
		{"sh -c 'FOO=bar shutdown now' → assign parse-through with arg, derived deny", "/bin/sh", []string{"-c", "FOO=bar shutdown now"}, types.DecisionDeny, "deny-shutdown"},
		{"sh -c 'PATH=/tmp nohup shutdown' → assign + wrapper parse-through, derived deny", "/bin/sh", []string{"-c", "PATH=/tmp nohup shutdown"}, types.DecisionDeny, "deny-shutdown"},
		{"sh -c 'FOO=1 BAR=2 nice -n 19 shutdown' → multi-assign + nice -n parse-through, derived deny", "/bin/sh", []string{"-c", "FOO=1 BAR=2 nice -n 19 shutdown"}, types.DecisionDeny, "deny-shutdown"},
		{"sh -c 'FOO= exec shutdown' → empty-value assign + exec parse-through, derived deny", "/bin/sh", []string{"-c", "FOO= exec shutdown"}, types.DecisionDeny, "deny-shutdown"},
		// --- nested derivation ---
		{"sh -c 'bash -c shutdown' → recursive derive", "/bin/sh", []string{"-c", "bash -c shutdown"}, types.DecisionDeny, "deny-shutdown"},

		// --- original allow path still works when derived command has no explicit rule ---
		{"sh -c 'ls' → no ls rule, fall back to shell allow", "/bin/sh", []string{"-c", "ls"}, types.DecisionAllow, "allow-shells"},
		{"sh -c 'echo hi' → builtin rejects derive, shell allow", "/bin/sh", []string{"-c", "echo hi"}, types.DecisionAllow, "allow-shells"},

		// --- opaque scripts (metachars, pipes, subshells, globs, …) fail
		// closed because policy contains a restrictive command rule
		// (`deny-shutdown`). Without this, `sh -c "shutdown; true"` would
		// silently fall through to `allow-shells`.
		{"sh -c 'ls | wc' → pipe is opaque", "/bin/sh", []string{"-c", "ls | wc"}, types.DecisionDeny, "shellc-opaque-script"},
		{"sh -c 'shutdown; true' → semicolon is opaque", "/bin/sh", []string{"-c", "shutdown; true"}, types.DecisionDeny, "shellc-opaque-script"},
		{"sh -c 'foo && shutdown' → && is opaque", "/bin/sh", []string{"-c", "foo && shutdown"}, types.DecisionDeny, "shellc-opaque-script"},
		{"sh -c 'shutdown || true' → || is opaque", "/bin/sh", []string{"-c", "shutdown || true"}, types.DecisionDeny, "shellc-opaque-script"},
		{"sh -c 'foo > out' → redirect is opaque", "/bin/sh", []string{"-c", "foo > out"}, types.DecisionDeny, "shellc-opaque-script"},
		{"sh -c 'foo < in' → redirect-in is opaque", "/bin/sh", []string{"-c", "foo < in"}, types.DecisionDeny, "shellc-opaque-script"},
		{"sh -c '(shutdown)' → subshell is opaque", "/bin/sh", []string{"-c", "(shutdown)"}, types.DecisionDeny, "shellc-opaque-script"},
		{"sh -c 'ls *.go' → glob is opaque", "/bin/sh", []string{"-c", "ls *.go"}, types.DecisionDeny, "shellc-opaque-script"},
		{"sh -c 'echo \"hi there\"' → quoted string is opaque", "/bin/sh", []string{"-c", "echo \"hi there\""}, types.DecisionDeny, "shellc-opaque-script"},
		{"sh -c 'echo $FOO' → variable expansion is opaque", "/bin/sh", []string{"-c", "echo $FOO"}, types.DecisionDeny, "shellc-opaque-script"},
		{"sh -c 'echo `date`' → command substitution is opaque", "/bin/sh", []string{"-c", "echo `date`"}, types.DecisionDeny, "shellc-opaque-script"},

		// --- bare invocations unchanged ---
		{"bare sh", "/bin/sh", nil, types.DecisionAllow, "allow-shells"},
		{"bare bash", "bash", nil, types.DecisionAllow, "allow-shells"},
		{"bare shutdown", "shutdown", nil, types.DecisionDeny, "deny-shutdown"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := e.CheckCommand(tc.command, tc.args)
			if dec.PolicyDecision != tc.decision {
				t.Errorf("decision: got %s, want %s (rule=%q)", dec.PolicyDecision, tc.decision, dec.Rule)
			}
			if dec.Rule != tc.rule {
				t.Errorf("rule: got %q, want %q", dec.Rule, tc.rule)
			}
		})
	}
}

// TestEngine_CheckCommand_ShellCDerive_OriginalDenyWins verifies that if the
// shell itself is denied, we return that deny without evaluating the inner
// command. This protects operators who use "deny all shells" as a baseline.
func TestEngine_CheckCommand_ShellCDerive_OriginalDenyWins(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{Name: "deny-shells", Commands: []string{"sh", "bash"}, Decision: "deny"},
			{Name: "allow-ls", Commands: []string{"ls"}, Decision: "allow"},
		},
	}
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}
	dec := e.CheckCommand("/bin/sh", []string{"-c", "ls"})
	if dec.PolicyDecision != types.DecisionDeny {
		t.Fatalf("expected deny, got %s (rule=%q)", dec.PolicyDecision, dec.Rule)
	}
	if dec.Rule != "deny-shells" {
		t.Errorf("expected rule deny-shells, got %q", dec.Rule)
	}
}

// TestEngine_CheckCommand_ShellCDerive_DefaultDenyNotEscalated verifies that
// a derived command that hits default-deny (no matching rule) does NOT
// override an original allow. Otherwise `allow-shells` would require an
// explicit allow rule for every binary a shell can launch.
func TestEngine_CheckCommand_ShellCDerive_DefaultDenyNotEscalated(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{Name: "allow-shells", Commands: []string{"sh", "bash"}, Decision: "allow"},
		},
	}
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}
	// No rule targets shutdown, so the default-deny applies at the derived
	// level — but because it's a default-deny (matched=false), we return
	// the original (allow-shells).
	dec := e.CheckCommand("/bin/sh", []string{"-c", "shutdown now"})
	if dec.PolicyDecision != types.DecisionAllow {
		t.Fatalf("expected allow-shells, got %s (rule=%q)", dec.PolicyDecision, dec.Rule)
	}
	if dec.Rule != "allow-shells" {
		t.Errorf("expected rule allow-shells, got %q", dec.Rule)
	}
}

// TestEngine_CheckCommand_ShellCDerive_NotAShell verifies we don't try to
// peek past non-shell binaries, even if their args include `-c`.
func TestEngine_CheckCommand_ShellCDerive_NotAShell(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{Name: "deny-shutdown", Commands: []string{"shutdown"}, Decision: "deny"},
			{Name: "allow-python", Commands: []string{"python3"}, Decision: "allow"},
		},
	}
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}
	// python -c "shutdown" is a python string, not a shell script. Don't
	// derive.
	dec := e.CheckCommand("python3", []string{"-c", "shutdown"})
	if dec.PolicyDecision != types.DecisionAllow {
		t.Fatalf("expected allow-python, got %s (rule=%q)", dec.PolicyDecision, dec.Rule)
	}
	if dec.Rule != "allow-python" {
		t.Errorf("expected rule allow-python, got %q", dec.Rule)
	}
}

// TestEngine_CheckCommand_ShellCDerive_ApproveEscalates verifies that an
// explicit `approve` rule on the inner binary is honored when invoked via
// `<shell> -c`. Before the strictness comparison, only deny escalated, so an
// operator using approval gating could be bypassed via `sh -c "cmd"`.
func TestEngine_CheckCommand_ShellCDerive_ApproveEscalates(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{Name: "approve-shutdown", Commands: []string{"shutdown"}, Decision: "approve", Message: "needs approval"},
			{Name: "allow-shells", Commands: []string{"sh", "bash"}, Decision: "allow"},
		},
	}
	e, err := NewEngine(p, true /*enforceApprovals*/, true)
	if err != nil {
		t.Fatal(err)
	}
	dec := e.CheckCommand("/bin/sh", []string{"-c", "shutdown now"})
	if dec.PolicyDecision != types.DecisionApprove {
		t.Fatalf("PolicyDecision: got %s, want approve (rule=%q)", dec.PolicyDecision, dec.Rule)
	}
	if dec.Rule != "approve-shutdown" {
		t.Errorf("Rule: got %q, want approve-shutdown", dec.Rule)
	}
	if dec.Approval == nil || !dec.Approval.Required {
		t.Errorf("expected Approval.Required=true, got %+v", dec.Approval)
	}
}

// TestEngine_CheckCommand_ShellCDerive_RedirectEscalates verifies that an
// explicit `redirect` rule on the inner binary is honored when invoked via
// `<shell> -c`. Without this, operators relying on command rewriting (e.g.
// `rm → trash`) could be silently bypassed by wrapping in `sh -c`.
func TestEngine_CheckCommand_ShellCDerive_RedirectEscalates(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{
				Name:       "redirect-rm",
				Commands:   []string{"rm"},
				Decision:   "redirect",
				RedirectTo: &CommandRedirect{Command: "trash"},
			},
			{Name: "allow-shells", Commands: []string{"sh", "bash"}, Decision: "allow"},
		},
	}
	e, err := NewEngine(p, false, true /*enforceRedirects*/)
	if err != nil {
		t.Fatal(err)
	}
	dec := e.CheckCommand("/bin/sh", []string{"-c", "rm foo"})
	if dec.PolicyDecision != types.DecisionRedirect {
		t.Fatalf("PolicyDecision: got %s, want redirect (rule=%q)", dec.PolicyDecision, dec.Rule)
	}
	if dec.Rule != "redirect-rm" {
		t.Errorf("Rule: got %q, want redirect-rm", dec.Rule)
	}
	if dec.Redirect == nil || dec.Redirect.Command != "trash" {
		t.Errorf("expected Redirect.Command=trash, got %+v", dec.Redirect)
	}
}

// TestEngine_CheckCommand_ShellCDerive_AuditEscalates verifies that an
// explicit `audit` rule on the inner binary is honored when invoked via
// `<shell> -c`. The effective decision stays allow, but PolicyDecision is
// audit so downstream logging fires — without this, `sh -c "sudo …"` would
// escape audit capture that operators configured for direct `sudo` calls.
func TestEngine_CheckCommand_ShellCDerive_AuditEscalates(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{Name: "audit-sudo", Commands: []string{"sudo"}, Decision: "audit"},
			{Name: "allow-shells", Commands: []string{"sh", "bash"}, Decision: "allow"},
		},
	}
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}
	dec := e.CheckCommand("/bin/sh", []string{"-c", "sudo id"})
	if dec.PolicyDecision != types.DecisionAudit {
		t.Fatalf("PolicyDecision: got %s, want audit (rule=%q)", dec.PolicyDecision, dec.Rule)
	}
	if dec.EffectiveDecision != types.DecisionAllow {
		t.Errorf("EffectiveDecision: got %s, want allow (audit is allow+log)", dec.EffectiveDecision)
	}
	if dec.Rule != "audit-sudo" {
		t.Errorf("Rule: got %q, want audit-sudo", dec.Rule)
	}
}

// TestEngine_CheckCommand_ShellCDerive_NoDowngrade verifies that a derived
// rule with a STRICTLY LESS restrictive decision does not weaken the
// original. Example: `sh -c "ls"` where the shell itself is gated by an
// approve rule — the inner `allow-ls` must not drop us below approve.
func TestEngine_CheckCommand_ShellCDerive_NoDowngrade(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{Name: "approve-shells", Commands: []string{"sh", "bash"}, Decision: "approve"},
			{Name: "allow-ls", Commands: []string{"ls"}, Decision: "allow"},
		},
	}
	e, err := NewEngine(p, true, true)
	if err != nil {
		t.Fatal(err)
	}
	dec := e.CheckCommand("/bin/sh", []string{"-c", "ls"})
	if dec.PolicyDecision != types.DecisionApprove {
		t.Fatalf("PolicyDecision: got %s, want approve (rule=%q)", dec.PolicyDecision, dec.Rule)
	}
	if dec.Rule != "approve-shells" {
		t.Errorf("Rule: got %q, want approve-shells", dec.Rule)
	}
}

// TestEngine_CheckCommand_ShellCDerive_StrictnessOrdering walks through a
// nested shell-c chain where each depth matches a different strictness,
// confirming that the strictest wins regardless of position in the chain.
// `sh -c "bash -c shutdown"` with allow-sh + audit-bash + deny-shutdown
// should end up deny.
func TestEngine_CheckCommand_ShellCDerive_StrictnessOrdering(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{Name: "deny-shutdown", Commands: []string{"shutdown"}, Decision: "deny"},
			{Name: "audit-bash", Commands: []string{"bash"}, Decision: "audit"},
			{Name: "allow-sh", Commands: []string{"sh"}, Decision: "allow"},
		},
	}
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}
	dec := e.CheckCommand("/bin/sh", []string{"-c", "bash -c shutdown"})
	if dec.PolicyDecision != types.DecisionDeny {
		t.Fatalf("PolicyDecision: got %s, want deny (rule=%q)", dec.PolicyDecision, dec.Rule)
	}
	if dec.Rule != "deny-shutdown" {
		t.Errorf("Rule: got %q, want deny-shutdown", dec.Rule)
	}
}

// TestEngine_CheckCommand_ShellCDerive_AuditPreservesShellEnvPolicy is a
// regression test for round-10 roborev: audit/approve don't rewrite the
// executing command (the outer shell still runs), so the shell rule's
// EnvPolicy must survive when an inner audit/approve rule promotes the
// decision. Without this, env_allow configured on allow-shells would
// silently vanish whenever a stricter audit/approve rule matched the
// derived inner binary, weakening the operator's env-filtering posture.
func TestEngine_CheckCommand_ShellCDerive_AuditPreservesShellEnvPolicy(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{
				Name:        "audit-sudo",
				Commands:    []string{"sudo"},
				Decision:    "audit",
				EnvAllow:    []string{"SUDO_SPECIFIC"},
				EnvMaxBytes: 64,
			},
			{
				Name:        "allow-shells",
				Commands:    []string{"sh", "bash"},
				Decision:    "allow",
				EnvAllow:    []string{"PATH", "HOME", "SHELL_SPECIFIC"},
				EnvMaxBytes: 16384,
			},
		},
	}
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}

	dec := e.CheckCommand("/bin/sh", []string{"-c", "sudo id"})
	if dec.PolicyDecision != types.DecisionAudit {
		t.Fatalf("PolicyDecision: got %s, want audit", dec.PolicyDecision)
	}
	// EnvPolicy must be the OUTER shell's, because the outer shell is
	// what actually executes under an audit decision.
	if !containsString(dec.EnvPolicy.Allow, "SHELL_SPECIFIC") {
		t.Errorf("expected shell rule's Allow to survive, got %v", dec.EnvPolicy.Allow)
	}
	if containsString(dec.EnvPolicy.Allow, "SUDO_SPECIFIC") {
		t.Errorf("inner audit-sudo env allow leaked into result: %v", dec.EnvPolicy.Allow)
	}
	if dec.EnvPolicy.MaxBytes != 16384 {
		t.Errorf("expected shell MaxBytes=16384, got %d", dec.EnvPolicy.MaxBytes)
	}
}

// TestEngine_CheckCommand_ShellCDerive_ApprovePreservesShellEnvPolicy
// mirrors the audit test for approve: after the human approves, the
// ORIGINAL shell command still runs, so the shell rule's env restrictions
// must continue to apply.
func TestEngine_CheckCommand_ShellCDerive_ApprovePreservesShellEnvPolicy(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{
				Name:     "approve-shutdown",
				Commands: []string{"shutdown"},
				Decision: "approve",
				EnvAllow: []string{"INNER_ONLY"},
			},
			{
				Name:     "allow-shells",
				Commands: []string{"sh"},
				Decision: "allow",
				EnvAllow: []string{"PATH", "HOME"},
			},
		},
	}
	e, err := NewEngine(p, true /*enforceApprovals*/, true)
	if err != nil {
		t.Fatal(err)
	}
	dec := e.CheckCommand("/bin/sh", []string{"-c", "shutdown now"})
	if dec.PolicyDecision != types.DecisionApprove {
		t.Fatalf("PolicyDecision: got %s, want approve", dec.PolicyDecision)
	}
	if !containsString(dec.EnvPolicy.Allow, "PATH") || !containsString(dec.EnvPolicy.Allow, "HOME") {
		t.Errorf("expected shell env Allow to survive, got %v", dec.EnvPolicy.Allow)
	}
	if containsString(dec.EnvPolicy.Allow, "INNER_ONLY") {
		t.Errorf("inner rule env Allow leaked: %v", dec.EnvPolicy.Allow)
	}
}

// TestEngine_CheckCommand_ShellCDerive_RedirectUsesInnerEnvPolicy
// documents the deliberate non-preservation for redirect: a redirect
// REPLACES the command, so the outer shell no longer runs and the new
// target's EnvPolicy is what governs execution.
func TestEngine_CheckCommand_ShellCDerive_RedirectUsesInnerEnvPolicy(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{
				Name:       "redirect-rm",
				Commands:   []string{"rm"},
				Decision:   "redirect",
				RedirectTo: &CommandRedirect{Command: "trash"},
				EnvAllow:   []string{"TRASH_SPECIFIC"},
			},
			{
				Name:     "allow-shells",
				Commands: []string{"sh"},
				Decision: "allow",
				EnvAllow: []string{"SHELL_ONLY"},
			},
		},
	}
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}
	dec := e.CheckCommand("/bin/sh", []string{"-c", "rm foo"})
	if dec.PolicyDecision != types.DecisionRedirect {
		t.Fatalf("PolicyDecision: got %s, want redirect", dec.PolicyDecision)
	}
	if !containsString(dec.EnvPolicy.Allow, "TRASH_SPECIFIC") {
		t.Errorf("expected inner redirect env Allow, got %v", dec.EnvPolicy.Allow)
	}
	if containsString(dec.EnvPolicy.Allow, "SHELL_ONLY") {
		t.Errorf("outer shell env Allow leaked into redirect: %v", dec.EnvPolicy.Allow)
	}
}

func containsString(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// TestEngine_CheckCommand_ShellCDerive_BypassFailsClosed verifies that a
// shell-c invocation containing a known command-exec wrapper in a flag form
// we can't safely collapse results in a DENY — not a silent fall-through
// to the outer shell's allow rule. Without this check, an operator relying
// on `allow bin=sh` would be blind to `sh -c "exec -a name shutdown"`,
// `sh -c "nohup --help shutdown"`, `sh -c "nice --adjustment=N shutdown"`,
// etc. The outer allow rule wasn't written to cover wrappers.
func TestEngine_CheckCommand_ShellCDerive_BypassFailsClosed(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{Name: "deny-shutdown", Commands: []string{"shutdown"}, Decision: "deny"},
			{Name: "allow-shells", Commands: []string{"sh", "bash"}, Decision: "allow"},
		},
	}
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		command string
		args    []string
	}{
		{"exec -a custom argv0", "/bin/sh", []string{"-c", "exec -a foo shutdown"}},
		{"command -v (probe form)", "/bin/sh", []string{"-c", "command -v shutdown"}},
		{"nohup --help", "/bin/sh", []string{"-c", "nohup --help shutdown"}},
		{"nohup -x", "/bin/sh", []string{"-c", "nohup -x shutdown"}},
		{"nice -n bogus (non-numeric)", "/bin/sh", []string{"-c", "nice -n bogus shutdown"}},
		{"nice -19 (unsupported form)", "/bin/sh", []string{"-c", "nice -19 shutdown"}},
		{"nice --adjustment=N (byte-allowlist evasion)", "/bin/sh", []string{"-c", "nice --adjustment=19 shutdown"}},
		{"nohup --preserve-status=1 (byte-allowlist evasion)", "/bin/sh", []string{"-c", "nohup --preserve-status=1 shutdown"}},
		// Unsafe shell options hiding -c.
		{"bash -lc shutdown (login + c cluster)", "/bin/bash", []string{"-lc", "shutdown"}},
		{"bash -l -c shutdown (login split)", "/bin/bash", []string{"-l", "-c", "shutdown"}},
		{"bash -o errexit -c shutdown (operand option)", "/bin/bash", []string{"-o", "errexit", "-c", "shutdown"}},
		{"bash --rcfile=X -c shutdown (long option)", "/bin/bash", []string{"--rcfile=/tmp/rc", "-c", "shutdown"}},
		{"bash --norc -c shutdown (long option)", "/bin/bash", []string{"--norc", "-c", "shutdown"}},
		{"bash -ic shutdown (interactive + c)", "/bin/bash", []string{"-ic", "shutdown"}},
		// Env-assignment prefix with inner bypass (parse-through strips
		// the assignment but the inner form is still unparsable).
		{"assign + exec -a", "/bin/sh", []string{"-c", "VAR=x exec -a foo shutdown"}},
		{"assign + nohup --preserve-status", "/bin/sh", []string{"-c", "PATH=/tmp nohup --preserve-status=1 shutdown"}},
		{"assign + command -v", "/bin/sh", []string{"-c", "FOO=1 command -v shutdown"}},
		// Env-assignment with a dirty VALUE (byte outside the narrow
		// allowlist). The shell accepts these, but we can't safely
		// parse-through, so fail closed.
		{"dirty VALUE with colon", "/bin/sh", []string{"-c", "PATH=/tmp:/bin shutdown"}},
		{"dirty VALUE with glob", "/bin/sh", []string{"-c", "PATH=*/bad nohup shutdown"}},
		{"dirty VALUE with dollar", "/bin/sh", []string{"-c", "FOO=$VAR shutdown"}},
		{"dirty VALUE with embedded equals", "/bin/sh", []string{"-c", "FOO=a=b shutdown"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := e.CheckCommand(tc.command, tc.args)
			if dec.PolicyDecision != types.DecisionDeny {
				t.Errorf("PolicyDecision: got %s, want deny (rule=%q)", dec.PolicyDecision, dec.Rule)
			}
			if dec.Rule != "shellc-wrapper-bypass" {
				t.Errorf("Rule: got %q, want shellc-wrapper-bypass", dec.Rule)
			}
		})
	}
}

// TestEngine_CheckCommand_ShellCDerive_OuterDenyBeatsBypass verifies that
// when the outer shell rule is itself deny, we don't promote to
// shellc-wrapper-bypass — the baseline deny already applies. (Strictness
// comparison: outer deny has the same strictness as bypass deny, so no
// upgrade happens.)
func TestEngine_CheckCommand_ShellCDerive_OuterDenyBeatsBypass(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{Name: "deny-shells", Commands: []string{"sh"}, Decision: "deny"},
		},
	}
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}
	dec := e.CheckCommand("/bin/sh", []string{"-c", "exec -a foo shutdown"})
	if dec.PolicyDecision != types.DecisionDeny {
		t.Fatalf("expected deny, got %s", dec.PolicyDecision)
	}
	if dec.Rule != "deny-shells" {
		t.Errorf("expected outer deny-shells, got %q", dec.Rule)
	}
}

// TestEngine_CheckCommand_ShellCDerive_BypassNotAShell verifies we don't
// fail closed on non-shell binaries that happen to use a `-c` flag with
// wrapper-looking syntax (e.g. python -c "nohup -x something" is a python
// string, not a shell script).
func TestEngine_CheckCommand_ShellCDerive_BypassNotAShell(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{Name: "allow-python", Commands: []string{"python3"}, Decision: "allow"},
		},
	}
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}
	dec := e.CheckCommand("python3", []string{"-c", "exec -a foo shutdown"})
	if dec.PolicyDecision != types.DecisionAllow {
		t.Fatalf("expected allow, got %s (rule=%q)", dec.PolicyDecision, dec.Rule)
	}
	if dec.Rule != "allow-python" {
		t.Errorf("expected allow-python, got %q", dec.Rule)
	}
}

// TestEngine_CheckCommand_ShellCDerive_OpaqueAllowOnlyPolicy verifies that
// an allow-only policy (no deny/approve/redirect/audit/soft_delete rules)
// does NOT trigger opaque-script fail-closed. Operators who've decided a
// broad `allow sh` is acceptable shouldn't suddenly have every pipeline
// denied; the opaque promotion is strictly a defense against silent
// fall-through past a restrictive rule.
func TestEngine_CheckCommand_ShellCDerive_OpaqueAllowOnlyPolicy(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{Name: "allow-shells", Commands: []string{"sh", "bash"}, Decision: "allow"},
			{Name: "allow-ls", Commands: []string{"ls"}, Decision: "allow"},
		},
	}
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}
	dec := e.CheckCommand("/bin/sh", []string{"-c", "ls | wc"})
	if dec.PolicyDecision != types.DecisionAllow {
		t.Fatalf("expected allow (no restrictive rule), got %s (rule=%q)", dec.PolicyDecision, dec.Rule)
	}
	if dec.Rule != "allow-shells" {
		t.Errorf("expected allow-shells, got %q", dec.Rule)
	}
}

// TestEngine_CheckCommand_ShellCDerive_DepthCapFailsClosed verifies that a
// shell-c chain deeper than maxShellCDeriveDepth fails closed instead of
// silently returning the outer allow. Without this, an attacker could
// smuggle a denied command past inspection by wrapping it in enough nested
// `sh -c "sh -c …"` layers.
func TestEngine_CheckCommand_ShellCDerive_DepthCapFailsClosed(t *testing.T) {
	// Temporarily lower the cap to 1 so a single nesting level exceeds it.
	// Restoring via defer keeps the package-level var honest across tests.
	orig := maxShellCDeriveDepth
	maxShellCDeriveDepth = 1
	defer func() { maxShellCDeriveDepth = orig }()

	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{Name: "deny-shutdown", Commands: []string{"shutdown"}, Decision: "deny"},
			{Name: "allow-shells", Commands: []string{"sh", "bash"}, Decision: "allow"},
		},
	}
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}
	// Depth 2 chain: outer sh-c wraps a bash-c that wraps shutdown.
	// With cap=1, the loop peels the outermost sh-c once, then exits
	// still holding `bash -c shutdown` — which is still derivable. The
	// post-loop check must deny.
	dec := e.CheckCommand("/bin/sh", []string{"-c", "bash -c shutdown"})
	if dec.PolicyDecision != types.DecisionDeny {
		t.Fatalf("expected deny (cap exceeded), got %s (rule=%q)", dec.PolicyDecision, dec.Rule)
	}
	if dec.Rule != "shellc-depth-exceeded" {
		t.Errorf("expected rule shellc-depth-exceeded, got %q", dec.Rule)
	}
}

// TestEngine_CheckCommand_ShellCDerive_DepthCapAllowOnlyPolicy verifies
// that when NO restrictive rule exists, depth-cap exhaustion does NOT
// fire — the allow-only policy admits the chain via the outer allow,
// same as the non-nested cases.
//
// Wait — actually the depth-cap check currently fires regardless of
// hasRestrictiveCommandRule (it just promotes by strictness). If the
// outer is `allow` (strictness 0), deny (strictness 4) > 0, so the
// cap-exceeded deny always wins when the loop terminates with a
// still-derivable tail. That's actually the desired behavior: even
// under a broad allow, a runaway nesting chain is suspicious enough
// to fail closed. This test pins that behavior so we don't accidentally
// regress.
func TestEngine_CheckCommand_ShellCDerive_DepthCapAllowOnlyFailsClosed(t *testing.T) {
	orig := maxShellCDeriveDepth
	maxShellCDeriveDepth = 1
	defer func() { maxShellCDeriveDepth = orig }()

	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{Name: "allow-shells", Commands: []string{"sh", "bash"}, Decision: "allow"},
		},
	}
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}
	dec := e.CheckCommand("/bin/sh", []string{"-c", "bash -c shutdown"})
	if dec.PolicyDecision != types.DecisionDeny {
		t.Fatalf("expected deny (cap exceeded fails closed), got %s (rule=%q)", dec.PolicyDecision, dec.Rule)
	}
	if dec.Rule != "shellc-depth-exceeded" {
		t.Errorf("expected rule shellc-depth-exceeded, got %q", dec.Rule)
	}
}

// TestEngine_CheckCommand_ShellCDerive_DepthCapLoopCompletes verifies the
// cap-exceeded path does NOT fire when the loop exits naturally (the tail
// isn't derivable). This is the no-false-positive case — a chain that
// bottoms out in a plain binary within the cap must not be flagged.
func TestEngine_CheckCommand_ShellCDerive_DepthCapLoopCompletes(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{Name: "deny-shutdown", Commands: []string{"shutdown"}, Decision: "deny"},
			{Name: "allow-shells", Commands: []string{"sh", "bash"}, Decision: "allow"},
		},
	}
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}
	// `sh -c "ls"` — loop peels once, inner tail is `ls`, not derivable
	// (not a shell), so the post-loop check sees ok=false and doesn't fire.
	dec := e.CheckCommand("/bin/sh", []string{"-c", "ls"})
	if dec.PolicyDecision != types.DecisionAllow {
		t.Fatalf("expected allow (loop completes cleanly), got %s (rule=%q)", dec.PolicyDecision, dec.Rule)
	}
	if dec.Rule != "allow-shells" {
		t.Errorf("expected allow-shells, got %q", dec.Rule)
	}
}

// TestEngine_CheckCommand_ShellCDerive_ShimRealSuffix verifies that the shim
// install layout — where `/bin/sh` is the shim binary and `/bin/sh.real` is
// the renamed original shell — is treated as a known shell for derive
// purposes. Without this, `allow sh.real` (present in default.yaml for shim
// integration) + `deny shutdown` would fall through to allow, silently
// re-opening the exact bypass CheckCommand is meant to close when the shim
// forwards via `agentsh exec -- /bin/sh.real -c "shutdown now"`.
//
// This test is the end-to-end assertion that caught the v0.19.0-rc1/rc2
// release-CI regression: smoke.sh ran `AGENTSH_SHIM_FORCE=1 /bin/sh -c
// 'shutdown now'`, the shim forwarded to `/bin/sh.real`, and the engine
// returned DecisionAllow (rule=allow-shim-shells) instead of DecisionDeny.
func TestEngine_CheckCommand_ShellCDerive_ShimRealSuffix(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []CommandRule{
			{Name: "deny-shutdown", Commands: []string{"shutdown"}, Decision: "deny"},
			{Name: "allow-shim-shells", Commands: []string{"sh", "bash", "sh.real", "bash.real"}, Decision: "allow"},
		},
	}
	e, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		command  string
		args     []string
		decision types.Decision
		rule     string
	}{
		// --- primary regression cases ---
		{"/bin/sh.real -c 'shutdown now' → derived deny (shim flow)", "/bin/sh.real", []string{"-c", "shutdown now"}, types.DecisionDeny, "deny-shutdown"},
		{"/bin/bash.real -c 'shutdown' → derived deny (shim flow)", "/bin/bash.real", []string{"-c", "shutdown"}, types.DecisionDeny, "deny-shutdown"},
		{"/usr/bin/sh.real -c 'shutdown' → derived deny (alt install path)", "/usr/bin/sh.real", []string{"-c", "shutdown"}, types.DecisionDeny, "deny-shutdown"},
		// --- ensure wrapper/opaque handling still applies through .real ---
		{"/bin/sh.real -c 'nohup shutdown' → wrapper stripped, derived deny", "/bin/sh.real", []string{"-c", "nohup shutdown"}, types.DecisionDeny, "deny-shutdown"},
		{"/bin/sh.real -c 'shutdown; true' → opaque is deny-on-restrictive-policy", "/bin/sh.real", []string{"-c", "shutdown; true"}, types.DecisionDeny, "shellc-opaque-script"},
		{"/bin/sh.real -l -c 'shutdown' → login option bypass-deny", "/bin/sh.real", []string{"-l", "-c", "shutdown"}, types.DecisionDeny, "shellc-wrapper-bypass"},
		// --- allow path when inner has no explicit rule ---
		{"/bin/sh.real -c 'ls' → no ls rule, fall back to shim-shells allow", "/bin/sh.real", []string{"-c", "ls"}, types.DecisionAllow, "allow-shim-shells"},
		// --- bare invocation of .real still allowed ---
		{"bare /bin/sh.real → allow", "/bin/sh.real", nil, types.DecisionAllow, "allow-shim-shells"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := e.CheckCommand(tc.command, tc.args)
			if dec.PolicyDecision != tc.decision {
				t.Errorf("decision: got %s, want %s (rule=%q)", dec.PolicyDecision, tc.decision, dec.Rule)
			}
			if dec.Rule != tc.rule {
				t.Errorf("rule: got %q, want %q", dec.Rule, tc.rule)
			}
		})
	}
}
