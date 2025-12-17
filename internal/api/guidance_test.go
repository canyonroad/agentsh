package api

import (
	"testing"

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
