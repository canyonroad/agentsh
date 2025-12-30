package report

import (
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestDetectBlockedFindings(t *testing.T) {
	deny := types.DecisionDeny
	events := []types.Event{
		{ID: "1", Type: "file_write", Path: "/etc/hosts", Policy: &types.PolicyInfo{Decision: deny, Rule: "no-system"}},
		{ID: "2", Type: "file_write", Path: "/etc/passwd", Policy: &types.PolicyInfo{Decision: deny, Rule: "no-system"}},
	}

	findings := detectFindings(events)

	var blocked *Finding
	for i := range findings {
		if findings[i].Category == "blocked" {
			blocked = &findings[i]
			break
		}
	}

	if blocked == nil {
		t.Fatal("expected blocked finding")
	}
	if blocked.Severity != SeverityCritical {
		t.Errorf("blocked should be critical, got %s", blocked.Severity)
	}
	if blocked.Count != 2 {
		t.Errorf("expected count 2, got %d", blocked.Count)
	}
}

func TestDetectRedirectFindings(t *testing.T) {
	redirect := types.DecisionRedirect
	events := []types.Event{
		{ID: "1", Type: "command_redirect", Policy: &types.PolicyInfo{Decision: redirect}},
	}

	findings := detectFindings(events)

	var redir *Finding
	for i := range findings {
		if findings[i].Category == "redirect" {
			redir = &findings[i]
			break
		}
	}

	if redir == nil {
		t.Fatal("expected redirect finding")
	}
	if redir.Severity != SeverityInfo {
		t.Errorf("redirect should be info, got %s", redir.Severity)
	}
}

func TestDetectSensitivePathAnomaly(t *testing.T) {
	allow := types.DecisionAllow
	events := []types.Event{
		{ID: "1", Type: "file_read", Path: "/home/user/.ssh/id_rsa", Policy: &types.PolicyInfo{Decision: allow}},
	}

	findings := detectFindings(events)

	var anomaly *Finding
	for i := range findings {
		if findings[i].Category == "anomaly" {
			anomaly = &findings[i]
			break
		}
	}

	if anomaly == nil {
		t.Fatal("expected anomaly finding for sensitive path")
	}
	if anomaly.Severity != SeverityWarning {
		t.Errorf("anomaly should be warning, got %s", anomaly.Severity)
	}
}
