package cli

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/spf13/cobra"
)

func newDebugCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "debug",
		Short: "Debugging and diagnostic commands",
	}

	cmd.AddCommand(newDebugStatsCmd())
	cmd.AddCommand(newDebugPendingCmd())
	cmd.AddCommand(newDebugPolicyTestCmd())

	return cmd
}

func newDebugStatsCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "stats SESSION_ID",
		Short: "Show session statistics",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID := args[0]
			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{
				HTTPBaseURL: cfg.serverAddr,
				GRPCAddr:    cfg.grpcAddr,
				APIKey:      cfg.apiKey,
				Transport:   cfg.transport,
			})
			if err != nil {
				return err
			}

			// Get session info
			sess, err := c.GetSession(cmd.Context(), sessionID)
			if err != nil {
				return fmt.Errorf("session not found: %w", err)
			}

			// Query all events for this session
			params := url.Values{}
			params.Set("limit", "10000") // Get a lot of events for accurate stats
			events, err := c.QuerySessionEvents(cmd.Context(), sessionID, params)
			if err != nil {
				return fmt.Errorf("failed to query events: %w", err)
			}

			stats := computeStats(sess, events)

			if jsonOutput {
				return printJSON(cmd, stats)
			}

			return printStatsHuman(cmd, stats)
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output as JSON")
	return cmd
}

// SessionStats holds computed session statistics.
type SessionStats struct {
	SessionID   string         `json:"session_id"`
	State       string         `json:"state"`
	Duration    string         `json:"duration"`
	DurationSec float64        `json:"duration_sec"`
	EventCounts map[string]int `json:"event_counts"`
	Decisions   struct {
		Allow  int `json:"allow"`
		Deny   int `json:"deny"`
		Prompt int `json:"prompt"`
	} `json:"decisions"`
	TotalEvents int `json:"total_events"`
}

func computeStats(sess types.Session, events []types.Event) SessionStats {
	stats := SessionStats{
		SessionID:   sess.ID,
		State:       string(sess.State),
		EventCounts: make(map[string]int),
	}

	// Compute duration
	duration := time.Since(sess.CreatedAt)
	stats.Duration = formatDuration(duration)
	stats.DurationSec = duration.Seconds()

	// Count events by type and decision
	for _, ev := range events {
		stats.EventCounts[ev.Type]++
		stats.TotalEvents++

		if ev.Policy != nil {
			switch ev.Policy.EffectiveDecision {
			case types.DecisionAllow:
				stats.Decisions.Allow++
			case types.DecisionDeny:
				stats.Decisions.Deny++
			case types.DecisionApprove:
				stats.Decisions.Prompt++
			}
		}
	}

	return stats
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60
	return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
}

func printStatsHuman(cmd *cobra.Command, stats SessionStats) error {
	w := cmd.OutOrStdout()

	fmt.Fprintf(w, "Session: %s\n", stats.SessionID)
	fmt.Fprintf(w, "State:   %s\n", stats.State)
	fmt.Fprintf(w, "Uptime:  %s\n", stats.Duration)
	fmt.Fprintln(w)

	// Events by type
	fmt.Fprintln(w, "Events:")
	if len(stats.EventCounts) == 0 {
		fmt.Fprintln(w, "  (none)")
	} else {
		// Sort event types for consistent output
		types := make([]string, 0, len(stats.EventCounts))
		for t := range stats.EventCounts {
			types = append(types, t)
		}
		sort.Strings(types)

		maxLen := 0
		for _, t := range types {
			if len(t) > maxLen {
				maxLen = len(t)
			}
		}

		for _, t := range types {
			fmt.Fprintf(w, "  %-*s  %d\n", maxLen, t, stats.EventCounts[t])
		}
		fmt.Fprintf(w, "  %s\n", strings.Repeat("─", maxLen+8))
		fmt.Fprintf(w, "  %-*s  %d\n", maxLen, "Total", stats.TotalEvents)
	}
	fmt.Fprintln(w)

	// Decisions
	fmt.Fprintln(w, "Decisions:")
	total := stats.Decisions.Allow + stats.Decisions.Deny + stats.Decisions.Prompt
	if total == 0 {
		fmt.Fprintln(w, "  (none)")
	} else {
		printDecisionLine(w, "allow", stats.Decisions.Allow, total)
		printDecisionLine(w, "deny", stats.Decisions.Deny, total)
		printDecisionLine(w, "prompt", stats.Decisions.Prompt, total)
	}

	return nil
}

func printDecisionLine(w interface{ Write([]byte) (int, error) }, name string, count, total int) {
	if count == 0 {
		return
	}
	pct := float64(count) / float64(total) * 100
	fmt.Fprintf(w, "  %-8s %5d (%.1f%%)\n", name, count, pct)
}

func newDebugPendingCmd() *cobra.Command {
	var sessionID string
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "pending",
		Short: "List pending approval requests",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{
				HTTPBaseURL: cfg.serverAddr,
				GRPCAddr:    cfg.grpcAddr,
				APIKey:      cfg.apiKey,
				Transport:   cfg.transport,
			})
			if err != nil {
				return err
			}

			approvals, err := c.ListApprovals(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to list approvals: %w", err)
			}

			// Filter by session if specified
			if sessionID != "" {
				filtered := make([]map[string]any, 0)
				for _, a := range approvals {
					if sid, ok := a["session_id"].(string); ok && sid == sessionID {
						filtered = append(filtered, a)
					}
				}
				approvals = filtered
			}

			if jsonOutput {
				return printJSON(cmd, approvals)
			}

			return printPendingHuman(cmd, approvals)
		},
	}

	cmd.Flags().StringVar(&sessionID, "session", "", "Filter by session ID")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output as JSON")
	return cmd
}

func printPendingHuman(cmd *cobra.Command, approvals []map[string]any) error {
	w := cmd.OutOrStdout()

	if len(approvals) == 0 {
		fmt.Fprintln(w, "No pending approvals")
		return nil
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSESSION\tOPERATION\tPATH\tAGE")

	for _, a := range approvals {
		id := getString(a, "id")
		sessID := getString(a, "session_id")
		op := getString(a, "operation")
		path := getString(a, "path")

		// Truncate long values
		if len(sessID) > 12 {
			sessID = sessID[:12] + "…"
		}
		if len(path) > 30 {
			path = "…" + path[len(path)-29:]
		}

		age := "?"
		if ts, ok := a["requested_at"].(string); ok {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				age = formatAge(time.Since(t))
			}
		}

		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", id, sessID, op, path, age)
	}
	tw.Flush()

	fmt.Fprintf(w, "\n%d pending approval(s)\n", len(approvals))
	return nil
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func formatAge(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh ago", int(d.Hours()))
}

func newDebugPolicyTestCmd() *cobra.Command {
	var sessionID string
	var operation string
	var path string
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "policy-test",
		Short: "Test what policy would decide for an operation",
		RunE: func(cmd *cobra.Command, args []string) error {
			if operation == "" {
				return fmt.Errorf("--op is required")
			}
			if path == "" {
				return fmt.Errorf("--path is required")
			}

			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{
				HTTPBaseURL: cfg.serverAddr,
				GRPCAddr:    cfg.grpcAddr,
				APIKey:      cfg.apiKey,
				Transport:   cfg.transport,
			})
			if err != nil {
				return err
			}

			result, err := c.PolicyTest(cmd.Context(), sessionID, operation, path)
			if err != nil {
				return fmt.Errorf("policy test failed: %w", err)
			}

			if jsonOutput {
				return printJSON(cmd, result)
			}

			return printPolicyTestHuman(cmd, operation, path, result)
		},
	}

	cmd.Flags().StringVar(&sessionID, "session", "", "Session ID (uses session's policy)")
	cmd.Flags().StringVar(&operation, "op", "", "Operation type (file_read, file_write, net_connect, exec)")
	cmd.Flags().StringVar(&path, "path", "", "Path or target to test")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output as JSON")

	return cmd
}

func printPolicyTestHuman(cmd *cobra.Command, op, path string, result map[string]any) error {
	w := cmd.OutOrStdout()

	fmt.Fprintf(w, "Operation: %s\n", op)
	fmt.Fprintf(w, "Path:      %s\n", path)
	fmt.Fprintln(w)

	decision := strings.ToUpper(getString(result, "decision"))
	rule := getString(result, "rule")
	reason := getString(result, "reason")
	source := getString(result, "policy_file")

	fmt.Fprintf(w, "Decision:  %s\n", decision)
	if rule != "" {
		fmt.Fprintf(w, "Rule:      %s\n", rule)
	}
	if reason != "" {
		fmt.Fprintf(w, "Reason:    %s\n", reason)
	}
	if source != "" {
		fmt.Fprintf(w, "Source:    %s\n", source)
	}

	return nil
}
