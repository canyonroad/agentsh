package cli

import (
	"fmt"

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

// ProxyStatus represents the status of the embedded LLM proxy for a session.
type ProxyStatus struct {
	State                  string `json:"state"`
	Address                string `json:"address"`
	Mode                   string `json:"mode"`
	DLPMode                string `json:"dlp_mode"`
	ActivePatterns         int    `json:"active_patterns"`
	TotalRequests          int    `json:"total_requests"`
	RequestsWithRedactions int    `json:"requests_with_redactions"`
	TotalInputTokens       int    `json:"total_input_tokens"`
	TotalOutputTokens      int    `json:"total_output_tokens"`
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
			sessionID := "latest"
			if len(args) > 0 {
				sessionID = args[0]
			}

			// TODO: Integrate with API client once GetProxyStatus is implemented
			// For now, return a placeholder indicating the session
			// This structure is ready for full integration:
			//
			// cfg := getClientConfig(cmd)
			// c, err := client.NewForCLI(client.CLIOptions{
			//     HTTPBaseURL: cfg.serverAddr,
			//     GRPCAddr:    cfg.grpcAddr,
			//     APIKey:      cfg.apiKey,
			//     Transport:   cfg.transport,
			// })
			// if err != nil {
			//     return err
			// }
			// status, err := c.GetProxyStatus(cmd.Context(), sessionID)
			// if err != nil {
			//     return err
			// }

			// Placeholder status until API integration
			status := ProxyStatus{
				State:                  "not available",
				Address:                "-",
				Mode:                   "embedded",
				DLPMode:                "redact",
				ActivePatterns:         0,
				TotalRequests:          0,
				RequestsWithRedactions: 0,
				TotalInputTokens:       0,
				TotalOutputTokens:      0,
			}

			if outputJSON {
				return printJSON(cmd, status)
			}

			// Human-readable output matching spec format
			fmt.Fprintf(cmd.OutOrStdout(), "Session: %s\n", sessionID)
			fmt.Fprintf(cmd.OutOrStdout(), "Proxy: %s on %s\n", status.State, status.Address)
			fmt.Fprintf(cmd.OutOrStdout(), "Mode: %s\n", status.Mode)
			fmt.Fprintf(cmd.OutOrStdout(), "DLP: %s (%d patterns active)\n", status.DLPMode, status.ActivePatterns)
			fmt.Fprintf(cmd.OutOrStdout(), "Requests: %d (%d with redactions)\n", status.TotalRequests, status.RequestsWithRedactions)
			fmt.Fprintf(cmd.OutOrStdout(), "Tokens: %d in / %d out\n", status.TotalInputTokens, status.TotalOutputTokens)

			return nil
		},
	}

	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output in JSON format")

	return cmd
}
