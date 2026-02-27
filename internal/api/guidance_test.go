package api

import (
	"fmt"
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestGuidance_NetworkBlocked_HTTPToHTTPSSubstitution(t *testing.T) {
	req := types.ExecRequest{
		Command: "curl",
		Args:    []string{"-sS", "http://ifconfig.me"},
	}
	res := types.ExecResult{ExitCode: 7}
	blocked := []types.Event{
		{
			Type:      "net_connect",
			Operation: "connect",
			Domain:    "ifconfig.me",
			Remote:    "ifconfig.me:80",
			Policy: &types.PolicyInfo{
				Decision:          types.DecisionDeny,
				EffectiveDecision: types.DecisionDeny,
				Rule:              "default-deny-network",
			},
		},
	}

	g := guidanceForResponse(req, res, blocked)
	if g == nil || g.Status != "blocked" || !g.Blocked {
		t.Fatalf("expected blocked guidance, got %+v", g)
	}
	foundHTTPS := false
	for _, s := range g.Substitutions {
		if s.Command == "curl -sS https://ifconfig.me" {
			foundHTTPS = true
			break
		}
	}
	if !foundHTTPS {
		t.Fatalf("expected https curl substitution, got %+v", g.Substitutions)
	}
}

func TestGuidance_CommandFailed_PyenvShimSuggestsSystemPython(t *testing.T) {
	req := types.ExecRequest{
		Command: "python",
		Args:    []string{"-c", "print(1)"},
	}
	res := types.ExecResult{
		ExitCode: 127,
		Error: &types.ExecError{
			Code:    "E_COMMAND_FAILED",
			Message: "start: fork/exec /home/test/.pyenv/shims/python: permission denied",
		},
	}

	g := guidanceForResponse(req, res, nil)
	if g == nil || g.Status != "failed" {
		t.Fatalf("expected failed guidance, got %+v", g)
	}
	found := false
	for _, s := range g.Substitutions {
		if s.Command == "/usr/bin/python3" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected /usr/bin/python3 substitution, got %+v", g.Substitutions)
	}
}

func TestGuidance_ApprovalBlocked_IsRetryable(t *testing.T) {
	req := types.ExecRequest{
		Command: "curl",
		Args:    []string{"-sS", "https://ifconfig.me"},
	}
	res := types.ExecResult{ExitCode: 126}
	blocked := []types.Event{
		{
			Type:      "net_connect",
			Operation: "connect",
			Domain:    "ifconfig.me",
			Remote:    "ifconfig.me:443",
			Policy: &types.PolicyInfo{
				Decision:          types.DecisionApprove,
				EffectiveDecision: types.DecisionDeny,
				Rule:              "approve-unknown-https",
				Approval:          &types.ApprovalInfo{Required: true, Mode: types.ApprovalModeEnforced},
			},
		},
	}

	g := guidanceForResponse(req, res, blocked)
	if g == nil || g.Status != "blocked" || !g.Retryable {
		t.Fatalf("expected retryable blocked guidance, got %+v", g)
	}
	foundApprovalHint := false
	for _, s := range g.Suggestions {
		if s.Action == "request_approval" {
			foundApprovalHint = true
			break
		}
	}
	if !foundApprovalHint {
		t.Fatalf("expected request_approval suggestion, got %+v", g.Suggestions)
	}
}

func TestGuidanceForPolicyDenied_PkgApprovalDenied_CommandPolicyAllow(t *testing.T) {
	// When command policy is "allow" but package approval is denied,
	// guidance should still show request_approval and be retryable.
	req := types.ExecRequest{Command: "npm", Args: []string{"install", "pkg"}}
	pre := policy.Decision{
		PolicyDecision:    types.DecisionAllow,
		EffectiveDecision: types.DecisionDeny,
	}
	preEv := types.Event{Type: "command_policy", Operation: "exec"}

	g := guidanceForPolicyDenied(req, pre, preEv, nil, true)
	if g == nil {
		t.Fatal("expected guidance, got nil")
	}
	if !g.Retryable {
		t.Fatal("expected Retryable=true for package approval denial")
	}
	foundApproval := false
	for _, s := range g.Suggestions {
		if s.Action == "request_approval" {
			foundApproval = true
			break
		}
	}
	if !foundApproval {
		t.Fatalf("expected request_approval suggestion, got %+v", g.Suggestions)
	}
}

func TestGuidanceForPolicyDenied_PkgApprovalTimeout(t *testing.T) {
	// Package approval timeout should be retryable with request_approval guidance.
	req := types.ExecRequest{Command: "pip", Args: []string{"install", "pkg"}}
	pre := policy.Decision{
		PolicyDecision:    types.DecisionAllow,
		EffectiveDecision: types.DecisionDeny,
	}
	preEv := types.Event{Type: "command_policy", Operation: "exec"}
	timeoutErr := fmt.Errorf("approval request timeout after 30s")

	g := guidanceForPolicyDenied(req, pre, preEv, timeoutErr, true)
	if g == nil {
		t.Fatal("expected guidance, got nil")
	}
	if !g.Retryable {
		t.Fatal("expected Retryable=true for timeout")
	}
	if g.Reason != "approval timed out" {
		t.Fatalf("expected 'approval timed out' reason, got %q", g.Reason)
	}
}

func TestGuidanceForPolicyDenied_NoPkgApproval_CommandPolicyAllow(t *testing.T) {
	// When neither command approval nor package approval is involved,
	// guidance should show adjust_policy and not be retryable.
	req := types.ExecRequest{Command: "rm", Args: []string{"-rf", "/"}}
	pre := policy.Decision{
		PolicyDecision:    types.DecisionDeny,
		EffectiveDecision: types.DecisionDeny,
	}
	preEv := types.Event{Type: "command_policy", Operation: "exec"}

	g := guidanceForPolicyDenied(req, pre, preEv, nil, false)
	if g == nil {
		t.Fatal("expected guidance, got nil")
	}
	if g.Retryable {
		t.Fatal("expected Retryable=false for pure policy denial")
	}
	foundAdjust := false
	for _, s := range g.Suggestions {
		if s.Action == "adjust_policy" {
			foundAdjust = true
			break
		}
	}
	if !foundAdjust {
		t.Fatalf("expected adjust_policy suggestion, got %+v", g.Suggestions)
	}
}
