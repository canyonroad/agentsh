package cli

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/spf13/cobra"
)

func newProxyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Manage the LLM proxy",
	}

	cmd.AddCommand(newProxyStatusCmd())
	return cmd
}

func newProxyStatusCmd() *cobra.Command {
	var outputJSON bool

	cmd := &cobra.Command{
		Use:   "status [SESSION_ID]",
		Short: "Show LLM proxy status",
		Long: `Show status of the embedded LLM proxy for a session.

Examples:
  # Status for latest session
  agentsh proxy status

  # Status for specific session
  agentsh proxy status abc123

  # JSON output
  agentsh proxy status --json`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID := ""
			if len(args) > 0 {
				sessionID = args[0]
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

			// Resolve empty or "latest" to actual session ID
			if sessionID == "" || sessionID == "latest" {
				sessions, err := c.ListSessions(cmd.Context())
				if err != nil {
					return fmt.Errorf("list sessions: %w", err)
				}
				if len(sessions) == 0 {
					return fmt.Errorf("no sessions found")
				}
				// Find most recent by CreatedAt
				latest := sessions[0]
				for _, s := range sessions[1:] {
					if s.CreatedAt.After(latest.CreatedAt) {
						latest = s
					}
				}
				sessionID = latest.ID
			}

			status, err := c.GetProxyStatus(cmd.Context(), sessionID)
			if err != nil {
				return fmt.Errorf("get proxy status: %w", err)
			}

			if outputJSON {
				return printJSON(cmd, status)
			}

			// Extract fields with defaults
			state, _ := status["state"].(string)
			if state == "" {
				state = "unknown"
			}
			address, _ := status["address"].(string)
			if address == "" {
				address = "-"
			}
			mode, _ := status["mode"].(string)
			if mode == "" {
				mode = "embedded"
			}
			dlpMode, _ := status["dlp_mode"].(string)
			if dlpMode == "" {
				dlpMode = "disabled"
			}
			activePatterns := int(getFloat(status, "active_patterns"))
			totalRequests := int(getFloat(status, "total_requests"))
			requestsWithRedactions := int(getFloat(status, "requests_with_redactions"))
			totalInputTokens := int(getFloat(status, "total_input_tokens"))
			totalOutputTokens := int(getFloat(status, "total_output_tokens"))

			// Human-readable output matching spec format
			fmt.Fprintf(cmd.OutOrStdout(), "Session: %s\n", sessionID)
			fmt.Fprintf(cmd.OutOrStdout(), "Proxy: %s on %s\n", state, address)
			fmt.Fprintf(cmd.OutOrStdout(), "Mode: %s\n", mode)
			fmt.Fprintf(cmd.OutOrStdout(), "DLP: %s (%d patterns active)\n", dlpMode, activePatterns)
			fmt.Fprintf(cmd.OutOrStdout(), "Requests: %d (%d with redactions)\n", totalRequests, requestsWithRedactions)
			fmt.Fprintf(cmd.OutOrStdout(), "Tokens: %d in / %d out\n", totalInputTokens, totalOutputTokens)

			return nil
		},
	}

	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output in JSON format")

	return cmd
}

// getFloat extracts a float64 from a map, handling JSON number types.
func getFloat(m map[string]any, key string) float64 {
	if m == nil {
		return 0
	}
	if v, ok := m[key].(float64); ok {
		return v
	}
	if v, ok := m[key].(int); ok {
		return float64(v)
	}
	return 0
}
