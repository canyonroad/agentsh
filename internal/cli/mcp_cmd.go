// internal/cli/mcp_cmd.go
package cli

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/store/sqlite"
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
	cmd.AddCommand(newMCPDetectionsCmd())

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
	return &cobra.Command{
		Use:   "events",
		Short: "Query MCP-related events",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println("MCP events command - not yet implemented")
			return nil
		},
	}
}

func newMCPDetectionsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "detections",
		Short: "Show tools with security detections",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println("MCP detections command - not yet implemented")
			return nil
		},
	}
}
