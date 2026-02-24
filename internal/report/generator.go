package report

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/store"
	"github.com/agentsh/agentsh/pkg/types"
)

// Generator creates reports from session data.
type Generator struct {
	store      store.EventStore
	llmLogPath string
}

// NewGenerator creates a new report generator.
func NewGenerator(s store.EventStore) *Generator {
	return &Generator{store: s}
}

// WithLLMLogPath sets the path to the llm-requests.jsonl file for LLM stats.
// The path should point to the llm-requests.jsonl file for the session.
// If not set or the file doesn't exist, LLM stats will be omitted from the report.
func (g *Generator) WithLLMLogPath(path string) *Generator {
	g.llmLogPath = path
	return g
}

// Generate creates a report for the given session.
func (g *Generator) Generate(ctx context.Context, sess types.Session, level Level) (*Report, error) {
	// Query all events for this session
	events, err := g.store.QueryEvents(ctx, types.EventQuery{
		SessionID: sess.ID,
		Asc:       true,
	})
	if err != nil {
		return nil, err
	}

	report := &Report{
		SessionID:   sess.ID,
		GeneratedAt: time.Now().UTC(),
		Level:       level,
		Session:     sess,
	}

	// Calculate duration
	if len(events) > 0 {
		first := events[0].Timestamp
		last := events[len(events)-1].Timestamp
		report.Duration = last.Sub(first)
	}

	// Count decisions and build activity summary
	report.Decisions = countDecisions(events)
	report.Activity = buildActivitySummary(events)
	report.Findings = detectFindings(events)

	// For detailed reports, include full data
	if level == LevelDetailed {
		report.Timeline = events
		report.BlockedOps = extractBlockedOps(events)
		report.Redirects = extractRedirects(events)
		report.CommandHistory = extractCommands(events)
		report.AllFilePaths = buildFullPathMap(events)
		report.AllNetworkHosts = buildFullHostMap(events)
	}

	// Parse LLM stats if llm-requests.jsonl path is configured
	if g.llmLogPath != "" {
		llmStats, dlpStats, err := ParseLLMRequestsFile(g.llmLogPath)
		if err != nil {
			// Log warning but don't fail the report generation
			// (the file might not exist for older sessions)
		} else {
			report.LLMUsage = llmStats
			report.DLPEvents = dlpStats
		}
	}

	// Extract MCP tool summary from events
	report.MCPSummary = extractMCPSummary(events)

	return report, nil
}

func countDecisions(events []types.Event) DecisionCounts {
	var counts DecisionCounts
	for _, ev := range events {
		if ev.Policy == nil {
			continue
		}
		decision := ev.Policy.Decision
		if ev.Policy.EffectiveDecision != "" {
			decision = ev.Policy.EffectiveDecision
		}
		switch decision {
		case types.DecisionAllow, types.DecisionAudit:
			counts.Allowed++
		case types.DecisionDeny:
			counts.Blocked++
		case types.DecisionRedirect:
			counts.Redirected++
		case types.DecisionSoftDelete:
			counts.SoftDelete++
		case types.DecisionApprove:
			if ev.Policy.Approval != nil && ev.Policy.Approval.Required {
				counts.Approved++
			}
		}
	}
	return counts
}

func buildActivitySummary(events []types.Event) ActivitySummary {
	summary := ActivitySummary{
		TopPaths: make(map[string]int),
		TopHosts: make(map[string]int),
		TopCmds:  make(map[string]int),
	}

	pathCounts := make(map[string]int)
	hostCounts := make(map[string]int)
	cmdCounts := make(map[string]int)

	for _, ev := range events {
		switch {
		case strings.HasPrefix(ev.Type, "file_") || strings.HasPrefix(ev.Type, "dir_"):
			summary.FileOps++
			if ev.Path != "" {
				// Group by directory for top paths
				dir := filepath.Dir(ev.Path)
				pathCounts[dir]++
			}
		case ev.Type == "net_connect" || ev.Type == "dns_query":
			summary.NetworkOps++
			if ev.Domain != "" {
				hostCounts[ev.Domain]++
			}
		case ev.Type == "command_intercept" || ev.Type == "process_start" ||
			ev.Type == "command_started" || ev.Type == "command_policy":
			summary.Commands++
			// Try to extract command from Fields
			cmd := ""
			if c, ok := ev.Fields["command"].(string); ok {
				cmd = c
			} else if c, ok := ev.Fields["cmd"].(string); ok {
				cmd = c
			}
			if cmd != "" {
				// Extract base command name
				parts := strings.Fields(cmd)
				if len(parts) > 0 {
					base := filepath.Base(parts[0])
					cmdCounts[base]++
				}
			}
		}
	}

	// Get top N entries
	summary.TopPaths = topN(pathCounts, 5)
	summary.TopHosts = topN(hostCounts, 5)
	summary.TopCmds = topN(cmdCounts, 5)

	return summary
}

func topN(m map[string]int, n int) map[string]int {
	if len(m) <= n {
		return m
	}
	result := make(map[string]int)
	for i := 0; i < n; i++ {
		maxKey := ""
		maxVal := 0
		for k, v := range m {
			if _, exists := result[k]; !exists && v > maxVal {
				maxKey = k
				maxVal = v
			}
		}
		if maxKey != "" {
			result[maxKey] = maxVal
		}
	}
	return result
}

func extractBlockedOps(events []types.Event) []BlockedDetail {
	var blocked []BlockedDetail
	for _, ev := range events {
		if ev.Policy == nil {
			continue
		}
		decision := ev.Policy.Decision
		if ev.Policy.EffectiveDecision != "" {
			decision = ev.Policy.EffectiveDecision
		}
		if decision == types.DecisionDeny {
			target := ev.Path
			if target == "" {
				target = ev.Domain
			}
			if target == "" {
				target = ev.Remote
			}
			blocked = append(blocked, BlockedDetail{
				Timestamp: ev.Timestamp,
				Type:      ev.Type,
				Target:    target,
				Rule:      ev.Policy.Rule,
				Message:   ev.Policy.Message,
			})
		}
	}
	return blocked
}

func extractRedirects(events []types.Event) []RedirectDetail {
	var redirects []RedirectDetail
	for _, ev := range events {
		if ev.Policy == nil || ev.Policy.Redirect == nil {
			continue
		}
		if ev.Policy.Decision == types.DecisionRedirect || ev.Policy.EffectiveDecision == types.DecisionRedirect {
			// Build original from event context
			original := ev.Path
			if original == "" {
				if cmd, ok := ev.Fields["command"].(string); ok {
					original = cmd
				}
			}
			// RedirectInfo has Command field for target
			redirectTo := ev.Policy.Redirect.Command
			if redirectTo == "" {
				redirectTo = ev.Policy.Redirect.Reason
			}
			redirects = append(redirects, RedirectDetail{
				Timestamp:  ev.Timestamp,
				Original:   original,
				RedirectTo: redirectTo,
				Rule:       ev.Policy.Rule,
			})
		}
	}
	return redirects
}

func extractCommands(events []types.Event) []CommandDetail {
	var cmds []CommandDetail
	for _, ev := range events {
		// Match both old-style and new-style event types
		if ev.Type != "command_intercept" && ev.Type != "process_start" &&
			ev.Type != "command_started" && ev.Type != "command_policy" {
			continue
		}
		cmd := ""
		if c, ok := ev.Fields["command"].(string); ok {
			cmd = c
		} else if c, ok := ev.Fields["cmd"].(string); ok {
			cmd = c
		}
		cmds = append(cmds, CommandDetail{
			Timestamp: ev.Timestamp,
			Command:   cmd,
		})
	}
	return cmds
}

func buildFullPathMap(events []types.Event) map[string]int {
	m := make(map[string]int)
	for _, ev := range events {
		if ev.Path != "" {
			m[ev.Path]++
		}
	}
	return m
}

func buildFullHostMap(events []types.Event) map[string]int {
	m := make(map[string]int)
	for _, ev := range events {
		if ev.Domain != "" {
			m[ev.Domain]++
		}
	}
	return m
}

// extractMCPSummary extracts MCP tool inspection statistics from events.
func extractMCPSummary(events []types.Event) *MCPToolSummary {
	toolsByServer := make(map[string]int)
	bySeverity := make(map[string]int)
	seenTools := make(map[string]bool) // key: server_id:tool_name
	var highRiskTools []MCPToolRisk
	var changedTools int
	var totalDetections int
	var toolCallsTotal int
	var interceptedTotal int
	var interceptedBlocked int
	var crossServerBlocked int
	var networkConnections int

	for _, ev := range events {
		switch ev.Type {
		case "mcp_tool_seen":
			serverID := stringFromFields(ev.Fields, "server_id")
			toolName := stringFromFields(ev.Fields, "tool_name")
			if serverID != "" && toolName != "" {
				key := serverID + ":" + toolName
				if !seenTools[key] {
					seenTools[key] = true
					toolsByServer[serverID]++
				}
			}

			// Count detections
			if detections, ok := ev.Fields["detections"].([]any); ok && len(detections) > 0 {
				totalDetections += len(detections)
				maxSeverity := stringFromFields(ev.Fields, "max_severity")
				if maxSeverity != "" {
					bySeverity[maxSeverity]++
				}
				// Track high risk tools
				if maxSeverity == "critical" || maxSeverity == "high" {
					highRiskTools = append(highRiskTools, MCPToolRisk{
						ServerID:    serverID,
						ToolName:    toolName,
						MaxSeverity: maxSeverity,
						Detections:  len(detections),
					})
				}
			}

		case "mcp_tool_changed":
			changedTools++
			// Also count as detection since it's a potential rug pull
			totalDetections++
			bySeverity["high"]++

		case "mcp_detection":
			totalDetections++
			severity := stringFromFields(ev.Fields, "severity")
			if severity != "" {
				bySeverity[severity]++
			}

		case "mcp_tool_called":
			toolCallsTotal++

		case "mcp_tool_call_intercepted":
			interceptedTotal++
			if stringFromFields(ev.Fields, "action") == "block" {
				interceptedBlocked++
			}

		case "mcp_cross_server_blocked":
			crossServerBlocked++

		case "mcp_network_connection":
			networkConnections++
		}
	}

	// Return nil if no MCP events found
	if len(seenTools) == 0 && totalDetections == 0 &&
		toolCallsTotal == 0 && interceptedTotal == 0 &&
		crossServerBlocked == 0 && networkConnections == 0 {
		return nil
	}

	return &MCPToolSummary{
		ToolsSeen:          len(seenTools),
		ServersCount:       len(toolsByServer),
		DetectionsTotal:    totalDetections,
		ChangedTools:       changedTools,
		ToolsByServer:      toolsByServer,
		BySeverity:         bySeverity,
		HighRiskTools:      highRiskTools,
		ToolCallsTotal:     toolCallsTotal,
		InterceptedTotal:   interceptedTotal,
		InterceptedBlocked: interceptedBlocked,
		CrossServerBlocked: crossServerBlocked,
		NetworkConnections: networkConnections,
	}
}

// stringFromFields extracts a string value from event Fields.
func stringFromFields(fields map[string]any, key string) string {
	if fields == nil {
		return ""
	}
	if v, ok := fields[key].(string); ok {
		return v
	}
	return ""
}
