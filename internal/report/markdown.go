package report

import (
	"fmt"
	"sort"
	"strings"
)

// FormatMarkdown renders a report as markdown.
func FormatMarkdown(r *Report) string {
	var sb strings.Builder

	// Header
	sb.WriteString(fmt.Sprintf("# Session Report: %s", r.SessionID))
	if r.Level == LevelDetailed {
		sb.WriteString(" (Detailed)")
	}
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("**Generated:** %s\n\n", r.GeneratedAt.Format("2006-01-02 15:04:05 UTC")))

	// Overview
	sb.WriteString("## Overview\n")
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Duration | %s |\n", r.Duration.String()))
	sb.WriteString(fmt.Sprintf("| Commands | %d |\n", r.Activity.Commands))
	sb.WriteString(fmt.Sprintf("| Policy | %s |\n", r.Session.Policy))
	sb.WriteString(fmt.Sprintf("| Status | %s |\n", r.Session.State))
	sb.WriteString("\n")

	// Decision Summary
	sb.WriteString("## Decision Summary\n")
	sb.WriteString("| Decision | Count |\n")
	sb.WriteString("|----------|-------|\n")
	if r.Decisions.Allowed > 0 {
		sb.WriteString(fmt.Sprintf("| Allowed | %d |\n", r.Decisions.Allowed))
	}
	if r.Decisions.Blocked > 0 {
		sb.WriteString(fmt.Sprintf("| Blocked | %d |\n", r.Decisions.Blocked))
	}
	if r.Decisions.Redirected > 0 {
		sb.WriteString(fmt.Sprintf("| Redirected | %d |\n", r.Decisions.Redirected))
	}
	if r.Decisions.SoftDelete > 0 {
		sb.WriteString(fmt.Sprintf("| Soft-deleted | %d |\n", r.Decisions.SoftDelete))
	}
	if r.Decisions.Approved > 0 {
		sb.WriteString(fmt.Sprintf("| Approved | %d |\n", r.Decisions.Approved))
	}
	if r.Decisions.Denied > 0 {
		sb.WriteString(fmt.Sprintf("| Denied | %d |\n", r.Decisions.Denied))
	}
	sb.WriteString("\n")

	// Findings
	if len(r.Findings) > 0 {
		sb.WriteString("## Findings\n")
		for _, f := range r.Findings {
			icon := severityIcon(f.Severity)
			sb.WriteString(fmt.Sprintf("%s **%s** (%d) - %s\n", icon, f.Title, f.Count, f.Description))
		}
		sb.WriteString("\n")
	}

	// Top Activity (summary level)
	sb.WriteString("## Top Activity\n")
	if len(r.Activity.TopPaths) > 0 {
		sb.WriteString(fmt.Sprintf("**Files (%d ops):** %s\n", r.Activity.FileOps, formatTopN(r.Activity.TopPaths)))
	}
	if len(r.Activity.TopHosts) > 0 {
		sb.WriteString(fmt.Sprintf("**Network (%d conns):** %s\n", r.Activity.NetworkOps, formatTopN(r.Activity.TopHosts)))
	}
	if len(r.Activity.TopCmds) > 0 {
		sb.WriteString(fmt.Sprintf("**Commands (%d):** %s\n", r.Activity.Commands, formatTopN(r.Activity.TopCmds)))
	}
	sb.WriteString("\n")

	// Detailed sections
	if r.Level == LevelDetailed {
		// Blocked Operations
		if len(r.BlockedOps) > 0 {
			sb.WriteString("## Blocked Operations\n")
			sb.WriteString("| Time | Type | Target | Rule | Message |\n")
			sb.WriteString("|------|------|--------|------|--------|\n")
			for _, b := range r.BlockedOps {
				sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
					b.Timestamp.Format("15:04:05"), b.Type, b.Target, b.Rule, b.Message))
			}
			sb.WriteString("\n")
		}

		// Redirects
		if len(r.Redirects) > 0 {
			sb.WriteString("## Redirects\n")
			sb.WriteString("| Time | Original | Redirected To | Rule |\n")
			sb.WriteString("|------|----------|---------------|------|\n")
			for _, rd := range r.Redirects {
				sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
					rd.Timestamp.Format("15:04:05"), rd.Original, rd.RedirectTo, rd.Rule))
			}
			sb.WriteString("\n")
		}

		// Event Timeline
		if len(r.Timeline) > 0 {
			sb.WriteString("## Event Timeline\n")
			sb.WriteString("| Time | Type | Decision | Summary |\n")
			sb.WriteString("|------|------|----------|--------|\n")
			for _, ev := range r.Timeline {
				decision := ""
				if ev.Policy != nil {
					decision = string(ev.Policy.Decision)
				}
				summary := ev.Path
				if summary == "" {
					summary = ev.Domain
				}
				if summary == "" {
					summary = ev.Remote
				}
				sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
					ev.Timestamp.Format("15:04:05"), ev.Type, decision, truncate(summary, 50)))
			}
			sb.WriteString("\n")
		}

		// Command History
		if len(r.CommandHistory) > 0 {
			sb.WriteString("## Command History\n")
			for i, cmd := range r.CommandHistory {
				sb.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, cmd.Timestamp.Format("15:04:05"), cmd.Command))
			}
			sb.WriteString("\n")
		}

		// All File Paths
		if len(r.AllFilePaths) > 0 {
			sb.WriteString("## All File Paths\n")
			paths := sortedKeys(r.AllFilePaths)
			for _, p := range paths {
				sb.WriteString(fmt.Sprintf("- %s (%d)\n", p, r.AllFilePaths[p]))
			}
			sb.WriteString("\n")
		}

		// All Network Hosts
		if len(r.AllNetworkHosts) > 0 {
			sb.WriteString("## All Network Hosts\n")
			hosts := sortedKeys(r.AllNetworkHosts)
			for _, h := range hosts {
				sb.WriteString(fmt.Sprintf("- %s (%d)\n", h, r.AllNetworkHosts[h]))
			}
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

func severityIcon(s Severity) string {
	switch s {
	case SeverityCritical:
		return "[CRITICAL]"
	case SeverityWarning:
		return "[WARNING]"
	case SeverityInfo:
		return "[INFO]"
	default:
		return ""
	}
}

func formatTopN(m map[string]int) string {
	var parts []string
	for k, v := range m {
		parts = append(parts, fmt.Sprintf("`%s` (%d)", k, v))
	}
	return strings.Join(parts, ", ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
