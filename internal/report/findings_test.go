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

func TestDetectMCPToolBlockedFinding(t *testing.T) {
	events := []types.Event{
		{ID: "1", Type: "mcp_tool_call_intercepted", Fields: map[string]any{
			"server_id": "s", "tool_name": "t", "action": "block", "reason": "version_pin",
		}},
		{ID: "2", Type: "mcp_tool_call_intercepted", Fields: map[string]any{
			"server_id": "s", "tool_name": "t2", "action": "allow",
		}},
	}

	findings := detectFindings(events)

	var found *Finding
	for i := range findings {
		if findings[i].Category == "mcp_tool_blocked" {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatal("expected mcp_tool_blocked finding")
	}
	if found.Severity != SeverityCritical {
		t.Errorf("expected critical severity, got %s", found.Severity)
	}
	if found.Count != 1 {
		t.Errorf("expected count 1 (only blocked, not allowed), got %d", found.Count)
	}
}

func TestDetectMCPCrossServerFinding(t *testing.T) {
	events := []types.Event{
		{ID: "1", Type: "mcp_cross_server_blocked", Fields: map[string]any{
			"rule": "read_then_send", "severity": "critical",
			"blocked_server_id": "evil", "blocked_tool_name": "exfil",
		}},
	}

	findings := detectFindings(events)

	var found *Finding
	for i := range findings {
		if findings[i].Category == "mcp_cross_server" {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatal("expected mcp_cross_server finding")
	}
	if found.Severity != SeverityCritical {
		t.Errorf("expected critical severity, got %s", found.Severity)
	}
	if found.Count != 1 {
		t.Errorf("expected count 1, got %d", found.Count)
	}
}

func TestDetectMCPToolBlockedFinding_AllowOnly(t *testing.T) {
	// Only "allow" intercepted events should NOT create a finding
	events := []types.Event{
		{ID: "1", Type: "mcp_tool_call_intercepted", Fields: map[string]any{
			"server_id": "s", "tool_name": "t", "action": "allow",
		}},
	}

	findings := detectFindings(events)

	for _, f := range findings {
		if f.Category == "mcp_tool_blocked" {
			t.Error("should not create mcp_tool_blocked finding for allow-only events")
		}
	}
}

func TestDetectMCPCrossServerFinding_HighSeverity(t *testing.T) {
	events := []types.Event{
		{ID: "1", Type: "mcp_cross_server_blocked", Fields: map[string]any{
			"rule": "read_then_send", "severity": "high",
			"blocked_server_id": "srv", "blocked_tool_name": "tool",
		}},
	}

	findings := detectFindings(events)

	var found *Finding
	for i := range findings {
		if findings[i].Category == "mcp_cross_server" {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatal("expected mcp_cross_server finding")
	}
	if found.Severity != SeverityCritical {
		t.Errorf("expected critical severity for high event, got %s", found.Severity)
	}
}

func TestDetectMCPCrossServerFinding_MediumSeverity(t *testing.T) {
	events := []types.Event{
		{ID: "1", Type: "mcp_cross_server_blocked", Fields: map[string]any{
			"rule": "read_then_send", "severity": "medium",
			"blocked_server_id": "srv", "blocked_tool_name": "tool",
		}},
	}

	findings := detectFindings(events)

	var found *Finding
	for i := range findings {
		if findings[i].Category == "mcp_cross_server" {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatal("expected mcp_cross_server finding")
	}
	if found.Severity != SeverityWarning {
		t.Errorf("expected warning severity for medium event, got %s", found.Severity)
	}
}

func TestDetectMCPCrossServerFinding_MixedSeverity(t *testing.T) {
	// When multiple cross-server events have different severities,
	// the finding should use the highest observed severity.
	events := []types.Event{
		{ID: "1", Type: "mcp_cross_server_blocked", Fields: map[string]any{
			"rule": "read_then_send", "severity": "medium",
			"blocked_server_id": "srv1", "blocked_tool_name": "tool1",
		}},
		{ID: "2", Type: "mcp_cross_server_blocked", Fields: map[string]any{
			"rule": "read_then_send", "severity": "critical",
			"blocked_server_id": "srv2", "blocked_tool_name": "tool2",
		}},
	}

	findings := detectFindings(events)

	var found *Finding
	for i := range findings {
		if findings[i].Category == "mcp_cross_server" {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatal("expected mcp_cross_server finding")
	}
	if found.Severity != SeverityCritical {
		t.Errorf("expected critical (highest) severity for mixed events, got %s", found.Severity)
	}
	if found.Count != 2 {
		t.Errorf("expected count 2, got %d", found.Count)
	}
}
