// internal/cli/mcp_cmd.go
package cli

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/store/sqlite"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/spf13/cobra"
)

// truncate truncates s to at most max characters, adding "..." if truncated.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func newMCPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "MCP tool inspection commands",
	}

	cmd.AddCommand(newMCPToolsCmd())
	cmd.AddCommand(newMCPServersCmd())
	cmd.AddCommand(newMCPEventsCmd())
	cmd.AddCommand(newMCPCallsCmd())
	cmd.AddCommand(newMCPDetectionsCmd())
	cmd.AddCommand(newMCPPinsCmd())

	return cmd
}

func newMCPToolsCmd() *cobra.Command {
	var (
		serverID string
		jsonOut  bool
		directDB bool
		dbPath   string
	)

	cmd := &cobra.Command{
		Use:   "tools",
		Short: "List registered MCP tools",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !directDB {
				return fmt.Errorf("API mode not yet implemented, use --direct-db")
			}

			if dbPath == "" {
				dbPath = getenvDefault("AGENTSH_DB_PATH", "./data/events.db")
			}
			st, err := sqlite.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open database: %w", err)
			}
			defer st.Close()

			filter := sqlite.MCPToolFilter{ServerID: serverID}
			tools, err := st.ListMCPTools(cmd.Context(), filter)
			if err != nil {
				return err
			}

			if len(tools) == 0 {
				cmd.Println("No MCP tools found")
				return nil
			}

			if jsonOut {
				return printJSON(cmd, tools)
			}

			// Table output
			cmd.Println("SERVER              TOOL                HASH        LAST SEEN            DETECTIONS")
			for _, t := range tools {
				detections := fmt.Sprintf("%d", t.DetectionCount)
				if t.MaxSeverity != "" {
					detections = fmt.Sprintf("%d (%s)", t.DetectionCount, t.MaxSeverity)
				}
				cmd.Printf("%-19s %-19s %-11s %-20s %s\n",
					truncate(t.ServerID, 19),
					truncate(t.ToolName, 19),
					truncate(t.ToolHash, 11),
					t.LastSeen.Format("2006-01-02 15:04:05"),
					detections,
				)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&serverID, "server", "", "Filter by server ID")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")
	cmd.Flags().BoolVar(&directDB, "direct-db", false, "Query local SQLite directly")
	cmd.Flags().StringVar(&dbPath, "db-path", "", "SQLite DB path (used with --direct-db)")

	return cmd
}

func newMCPServersCmd() *cobra.Command {
	var (
		jsonOut  bool
		directDB bool
		dbPath   string
	)

	cmd := &cobra.Command{
		Use:   "servers",
		Short: "List known MCP servers",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !directDB {
				return fmt.Errorf("API mode not yet implemented, use --direct-db")
			}

			if dbPath == "" {
				dbPath = getenvDefault("AGENTSH_DB_PATH", "./data/events.db")
			}
			st, err := sqlite.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open database: %w", err)
			}
			defer st.Close()

			servers, err := st.ListMCPServers(cmd.Context())
			if err != nil {
				return err
			}

			if len(servers) == 0 {
				cmd.Println("No MCP servers found")
				return nil
			}

			if jsonOut {
				return printJSON(cmd, servers)
			}

			cmd.Println("SERVER              TOOLS  LAST SEEN            DETECTIONS")
			for _, s := range servers {
				cmd.Printf("%-19s %-6d %-20s %d\n",
					truncate(s.ServerID, 19),
					s.ToolCount,
					s.LastSeen.Format("2006-01-02 15:04:05"),
					s.DetectionCount,
				)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")
	cmd.Flags().BoolVar(&directDB, "direct-db", false, "Query local SQLite directly")
	cmd.Flags().StringVar(&dbPath, "db-path", "", "SQLite DB path (used with --direct-db)")

	return cmd
}

func newMCPEventsCmd() *cobra.Command {
	var (
		sessionID string
		serverID  string
		eventType string
		since     string
		limit     int
		jsonOut   bool
		directDB  bool
		dbPath    string
	)

	cmd := &cobra.Command{
		Use:   "events",
		Short: "Query MCP-related events",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !directDB {
				return fmt.Errorf("API mode not yet implemented, use --direct-db")
			}

			if dbPath == "" {
				dbPath = getenvDefault("AGENTSH_DB_PATH", "./data/events.db")
			}
			st, err := sqlite.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open database: %w", err)
			}
			defer st.Close()

			// Build query with MCP event types
			mcpTypes := []string{"mcp_tool_seen", "mcp_tool_changed", "mcp_detection"}
			if eventType != "" {
				mcpTypes = []string{eventType}
			}

			q := types.EventQuery{
				SessionID: sessionID,
				Types:     mcpTypes,
				Limit:     limit,
			}

			if since != "" {
				t, err := parseTimeOrAgo(since)
				if err != nil {
					return fmt.Errorf("invalid --since: %w", err)
				}
				q.Since = &t
			}

			events, err := st.QueryEvents(cmd.Context(), q)
			if err != nil {
				return err
			}

			// Filter by server if specified (check payload if needed)
			// For now, just display all matching events
			_ = serverID // reserved for future filtering

			if len(events) == 0 {
				cmd.Println("No MCP events found")
				return nil
			}

			if jsonOut {
				return printJSON(cmd, events)
			}

			// Table output
			cmd.Println("TIMESTAMP            TYPE                SESSION")
			for _, e := range events {
				cmd.Printf("%-20s %-19s %s\n",
					e.Timestamp.Format("2006-01-02 15:04:05"),
					truncate(e.Type, 19),
					truncate(e.SessionID, 20),
				)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&sessionID, "session", "", "Filter by session ID")
	cmd.Flags().StringVar(&serverID, "server", "", "Filter by server ID")
	cmd.Flags().StringVar(&eventType, "type", "", "Event type: mcp_tool_seen|mcp_tool_changed|mcp_detection")
	cmd.Flags().StringVar(&since, "since", "", "Start time (RFC3339) or duration (e.g. 1h)")
	cmd.Flags().IntVar(&limit, "limit", 100, "Result limit")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")
	cmd.Flags().BoolVar(&directDB, "direct-db", false, "Query local SQLite directly")
	cmd.Flags().StringVar(&dbPath, "db-path", "", "SQLite DB path (used with --direct-db)")

	return cmd
}

func newMCPCallsCmd() *cobra.Command {
	var (
		sessionID string
		serverID  string
		toolName  string
		action    string
		since     string
		limit     int
		jsonOut   bool
		directDB  bool
		dbPath    string
	)

	cmd := &cobra.Command{
		Use:   "calls",
		Short: "Query MCP tool call interceptions",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !directDB {
				return fmt.Errorf("API mode not yet implemented, use --direct-db")
			}

			if limit <= 0 {
				return fmt.Errorf("--limit must be a positive integer")
			}

			if dbPath == "" {
				dbPath = getenvDefault("AGENTSH_DB_PATH", "./data/events.db")
			}
			st, err := sqlite.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open database: %w", err)
			}
			defer st.Close()

			q := types.EventQuery{
				SessionID: sessionID,
				Types:     []string{"mcp_tool_call_intercepted"},
				Limit:     limit,
			}

			if toolName != "" {
				q.PathLike = "%" + toolName + "%"
			}
			if serverID != "" {
				q.DomainLike = "%" + serverID + "%"
			}
			if action != "" {
				switch action {
				case "allow":
					d := types.DecisionAllow
					q.Decision = &d
				case "block":
					d := types.DecisionDeny
					q.Decision = &d
				default:
					return fmt.Errorf("invalid --action %q: must be \"allow\" or \"block\"", action)
				}
			}
			if since != "" {
				t, err := parseTimeOrAgo(since)
				if err != nil {
					return fmt.Errorf("invalid --since: %w", err)
				}
				q.Since = &t
			}

			events, err := st.QueryEvents(cmd.Context(), q)
			if err != nil {
				return err
			}

			if len(events) == 0 {
				cmd.Println("No MCP tool calls found")
				return nil
			}

			if jsonOut {
				return printJSON(cmd, events)
			}

			// Table output
			cmd.Println("TIMESTAMP            TOOL                SERVER              ACTION  REASON")
			for _, e := range events {
				tool, _ := e.Fields["tool_name"].(string)
				server, _ := e.Fields["server_id"].(string)
				act, _ := e.Fields["action"].(string)
				reason, _ := e.Fields["reason"].(string)
				cmd.Printf("%-20s %-19s %-19s %-7s %s\n",
					e.Timestamp.Format("2006-01-02 15:04:05"),
					truncate(tool, 19),
					truncate(server, 19),
					act,
					reason,
				)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&sessionID, "session", "", "Filter by session ID")
	cmd.Flags().StringVar(&serverID, "server", "", "Filter by server ID")
	cmd.Flags().StringVar(&toolName, "tool", "", "Filter by tool name")
	cmd.Flags().StringVar(&action, "action", "", "Filter by action: allow|block")
	cmd.Flags().StringVar(&since, "since", "", "Start time (RFC3339) or duration (e.g. 1h)")
	cmd.Flags().IntVar(&limit, "limit", 100, "Result limit")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")
	cmd.Flags().BoolVar(&directDB, "direct-db", false, "Query local SQLite directly")
	cmd.Flags().StringVar(&dbPath, "db-path", "", "SQLite DB path (used with --direct-db)")

	return cmd
}

func newMCPDetectionsCmd() *cobra.Command {
	var (
		severity string
		serverID string
		jsonOut  bool
		directDB bool
		dbPath   string
	)

	cmd := &cobra.Command{
		Use:   "detections",
		Short: "Show tools with security detections",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !directDB {
				return fmt.Errorf("API mode not yet implemented, use --direct-db")
			}

			if dbPath == "" {
				dbPath = getenvDefault("AGENTSH_DB_PATH", "./data/events.db")
			}
			st, err := sqlite.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open database: %w", err)
			}
			defer st.Close()

			filter := sqlite.MCPToolFilter{
				ServerID:      serverID,
				HasDetections: true,
			}
			tools, err := st.ListMCPTools(cmd.Context(), filter)
			if err != nil {
				return err
			}

			// Filter by severity if specified
			if severity != "" {
				var filtered []sqlite.MCPTool
				for _, t := range tools {
					if matchesSeverity(t.MaxSeverity, severity) {
						filtered = append(filtered, t)
					}
				}
				tools = filtered
			}

			if len(tools) == 0 {
				cmd.Println("No tools with detections found")
				return nil
			}

			if jsonOut {
				return printJSON(cmd, tools)
			}

			cmd.Println("SERVER              TOOL                SEVERITY   DETECTIONS")
			for _, t := range tools {
				cmd.Printf("%-19s %-19s %-10s %d\n",
					truncate(t.ServerID, 19),
					truncate(t.ToolName, 19),
					t.MaxSeverity,
					t.DetectionCount,
				)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&severity, "severity", "", "Minimum severity: low|medium|high|critical")
	cmd.Flags().StringVar(&serverID, "server", "", "Filter by server ID")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")
	cmd.Flags().BoolVar(&directDB, "direct-db", false, "Query local SQLite directly")
	cmd.Flags().StringVar(&dbPath, "db-path", "", "SQLite DB path (used with --direct-db)")

	return cmd
}

// matchesSeverity returns true if toolSeverity >= minSeverity
func matchesSeverity(toolSeverity, minSeverity string) bool {
	levels := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	toolLevel := levels[toolSeverity]
	minLevel := levels[minSeverity]
	return toolLevel >= minLevel
}
