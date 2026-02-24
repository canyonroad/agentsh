package report

import (
	"regexp"
	"strings"

	"github.com/agentsh/agentsh/pkg/types"
)

// Sensitive path patterns for anomaly detection.
var sensitivePaths = []*regexp.Regexp{
	regexp.MustCompile(`^/etc/`),
	regexp.MustCompile(`^/usr/`),
	regexp.MustCompile(`\.ssh/`),
	regexp.MustCompile(`\.aws/`),
	regexp.MustCompile(`\.gnupg/`),
	regexp.MustCompile(`credentials`),
	regexp.MustCompile(`\.env$`),
	regexp.MustCompile(`\.pem$`),
	regexp.MustCompile(`\.key$`),
}

// detectFindings analyzes events and returns notable findings.
func detectFindings(events []types.Event) []Finding {
	var findings []Finding

	// Track counts for various categories
	var blockedEvents []string
	var redirectEvents []string
	var softDeleteEvents []string
	var approvedEvents []string
	var deniedEvents []string
	var sensitivePathEvents []string
	var failedCmdEvents []string
	var directIPEvents []string
	var unusualPortEvents []string
	var mcpHighRiskEvents []string
	var mcpChangedEvents []string
	var mcpDetectionEvents []string
	var mcpToolBlockedEvents []string
	var mcpCrossServerEvents []string

	uniqueHosts := make(map[string]bool)

	for _, ev := range events {
		// MCP tool security events (don't require Policy)
		switch ev.Type {
		case "mcp_tool_seen":
			maxSeverity := stringField(ev.Fields, "max_severity")
			if maxSeverity == "critical" || maxSeverity == "high" {
				mcpHighRiskEvents = append(mcpHighRiskEvents, ev.ID)
			}
			if detections, ok := ev.Fields["detections"].([]any); ok && len(detections) > 0 {
				mcpDetectionEvents = append(mcpDetectionEvents, ev.ID)
			}
		case "mcp_tool_changed":
			mcpChangedEvents = append(mcpChangedEvents, ev.ID)
		case "mcp_detection":
			mcpDetectionEvents = append(mcpDetectionEvents, ev.ID)
		case "mcp_tool_call_intercepted":
			if stringField(ev.Fields, "action") == "block" {
				mcpToolBlockedEvents = append(mcpToolBlockedEvents, ev.ID)
			}
		case "mcp_cross_server_blocked":
			mcpCrossServerEvents = append(mcpCrossServerEvents, ev.ID)
		}

		if ev.Policy == nil {
			continue
		}

		decision := ev.Policy.Decision
		if ev.Policy.EffectiveDecision != "" {
			decision = ev.Policy.EffectiveDecision
		}

		// Policy violations
		switch decision {
		case types.DecisionDeny:
			blockedEvents = append(blockedEvents, ev.ID)
		case types.DecisionRedirect:
			redirectEvents = append(redirectEvents, ev.ID)
		case types.DecisionSoftDelete:
			softDeleteEvents = append(softDeleteEvents, ev.ID)
		}

		// Check for approvals
		if ev.Policy.Approval != nil {
			if ev.Policy.Decision == types.DecisionApprove {
				approvedEvents = append(approvedEvents, ev.ID)
			}
		}

		// Anomaly: sensitive path access
		if ev.Path != "" {
			for _, re := range sensitivePaths {
				if re.MatchString(ev.Path) {
					sensitivePathEvents = append(sensitivePathEvents, ev.ID)
					break
				}
			}
		}

		// Anomaly: direct IP connections (not domain)
		if ev.Remote != "" && ev.Domain == "" && ev.Type == "net_connect" {
			directIPEvents = append(directIPEvents, ev.ID)
		}

		// Anomaly: unusual ports (not 80/443)
		if ev.Remote != "" && ev.Type == "net_connect" {
			parts := strings.Split(ev.Remote, ":")
			if len(parts) == 2 && parts[1] != "80" && parts[1] != "443" {
				unusualPortEvents = append(unusualPortEvents, ev.ID)
			}
		}

		// Track unique hosts
		if ev.Domain != "" {
			uniqueHosts[ev.Domain] = true
		}

		// Failed commands
		if ev.Type == "process_exit" || ev.Type == "command_exit" {
			if exitCode, ok := ev.Fields["exit_code"].(float64); ok && exitCode != 0 {
				failedCmdEvents = append(failedCmdEvents, ev.ID)
			}
		}
	}

	// Build findings from collected data
	if len(blockedEvents) > 0 {
		findings = append(findings, Finding{
			Severity:    SeverityCritical,
			Category:    "blocked",
			Title:       "Operations blocked",
			Description: "Operations were denied by policy",
			Count:       len(blockedEvents),
			Events:      blockedEvents,
		})
	}

	if len(deniedEvents) > 0 {
		findings = append(findings, Finding{
			Severity:    SeverityCritical,
			Category:    "denied_approval",
			Title:       "Approvals denied",
			Description: "Requested operations were denied by operator",
			Count:       len(deniedEvents),
			Events:      deniedEvents,
		})
	}

	if len(softDeleteEvents) > 0 {
		findings = append(findings, Finding{
			Severity:    SeverityWarning,
			Category:    "soft_delete",
			Title:       "Files soft-deleted",
			Description: "Files were moved to trash (recoverable via agentsh trash)",
			Count:       len(softDeleteEvents),
			Events:      softDeleteEvents,
		})
	}

	if len(sensitivePathEvents) > 0 {
		findings = append(findings, Finding{
			Severity:    SeverityWarning,
			Category:    "anomaly",
			Title:       "Sensitive path access",
			Description: "Access to sensitive paths detected (credentials, SSH keys, etc.)",
			Count:       len(sensitivePathEvents),
			Events:      sensitivePathEvents,
		})
	}

	if len(directIPEvents) > 0 {
		findings = append(findings, Finding{
			Severity:    SeverityWarning,
			Category:    "anomaly",
			Title:       "Direct IP connections",
			Description: "Network connections to IP addresses instead of domains",
			Count:       len(directIPEvents),
			Events:      directIPEvents,
		})
	}

	if len(unusualPortEvents) > 0 {
		findings = append(findings, Finding{
			Severity:    SeverityWarning,
			Category:    "anomaly",
			Title:       "Unusual port connections",
			Description: "Network connections to non-standard ports (not 80/443)",
			Count:       len(unusualPortEvents),
			Events:      unusualPortEvents,
		})
	}

	if len(uniqueHosts) > 10 {
		findings = append(findings, Finding{
			Severity:    SeverityWarning,
			Category:    "anomaly",
			Title:       "High host diversity",
			Description: "Connections to many unique hosts detected",
			Count:       len(uniqueHosts),
		})
	}

	if len(redirectEvents) > 0 {
		findings = append(findings, Finding{
			Severity:    SeverityInfo,
			Category:    "redirect",
			Title:       "Operations redirected",
			Description: "Commands or paths were substituted per policy",
			Count:       len(redirectEvents),
			Events:      redirectEvents,
		})
	}

	if len(approvedEvents) > 0 {
		findings = append(findings, Finding{
			Severity:    SeverityInfo,
			Category:    "approved",
			Title:       "Approvals granted",
			Description: "Operations required and received human approval",
			Count:       len(approvedEvents),
			Events:      approvedEvents,
		})
	}

	if len(failedCmdEvents) > 0 {
		findings = append(findings, Finding{
			Severity:    SeverityInfo,
			Category:    "failed_command",
			Title:       "Commands failed",
			Description: "Commands exited with non-zero status",
			Count:       len(failedCmdEvents),
			Events:      failedCmdEvents,
		})
	}

	// MCP tool security findings
	if len(mcpChangedEvents) > 0 {
		findings = append(findings, Finding{
			Severity:    SeverityCritical,
			Category:    "mcp_rug_pull",
			Title:       "MCP tool changes detected",
			Description: "MCP tool definitions changed after initial registration (potential rug pull attack)",
			Count:       len(mcpChangedEvents),
			Events:      mcpChangedEvents,
		})
	}

	if len(mcpHighRiskEvents) > 0 {
		findings = append(findings, Finding{
			Severity:    SeverityCritical,
			Category:    "mcp_high_risk",
			Title:       "High-risk MCP tools",
			Description: "MCP tools with critical or high severity security detections",
			Count:       len(mcpHighRiskEvents),
			Events:      mcpHighRiskEvents,
		})
	}

	if len(mcpDetectionEvents) > 0 {
		findings = append(findings, Finding{
			Severity:    SeverityWarning,
			Category:    "mcp_detection",
			Title:       "MCP security detections",
			Description: "Security patterns detected in MCP tool definitions",
			Count:       len(mcpDetectionEvents),
			Events:      mcpDetectionEvents,
		})
	}

	if len(mcpToolBlockedEvents) > 0 {
		findings = append(findings, Finding{
			Severity:    SeverityCritical,
			Category:    "mcp_tool_blocked",
			Title:       "MCP tool calls blocked",
			Description: "MCP tool calls were blocked by the LLM proxy",
			Count:       len(mcpToolBlockedEvents),
			Events:      mcpToolBlockedEvents,
		})
	}

	if len(mcpCrossServerEvents) > 0 {
		findings = append(findings, Finding{
			Severity:    SeverityCritical,
			Category:    "mcp_cross_server",
			Title:       "Cross-server attacks blocked",
			Description: "Suspicious cross-server tool call patterns were detected and blocked",
			Count:       len(mcpCrossServerEvents),
			Events:      mcpCrossServerEvents,
		})
	}

	return findings
}

// stringField extracts a string value from event Fields.
func stringField(fields map[string]any, key string) string {
	if fields == nil {
		return ""
	}
	if v, ok := fields[key].(string); ok {
		return v
	}
	return ""
}
