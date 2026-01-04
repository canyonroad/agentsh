package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/spf13/cobra"
)

func newSessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Manage sessions",
	}

	cmd.AddCommand(newSessionCreateCmd())
	cmd.AddCommand(newSessionListCmd())
	cmd.AddCommand(newSessionInfoCmd())
	cmd.AddCommand(newSessionUpdateCmd())
	cmd.AddCommand(newSessionDestroyCmd())
	cmd.AddCommand(newSessionAttachCmd())
	cmd.AddCommand(newSessionLogsCmd())

	return cmd
}

func newSessionCreateCmd() *cobra.Command {
	var workspace string
	var policy string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new session",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{HTTPBaseURL: cfg.serverAddr, GRPCAddr: cfg.grpcAddr, APIKey: cfg.apiKey, Transport: cfg.transport})
			if err != nil {
				return err
			}
			s, err := c.CreateSession(cmd.Context(), workspace, policy)
			if err != nil {
				return err
			}
			return printJSON(cmd, s)
		},
	}
	cmd.Flags().StringVar(&workspace, "workspace", ".", "Workspace directory")
	cmd.Flags().StringVar(&policy, "policy", "default", "Policy name")
	return cmd
}

func newSessionListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List sessions",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{HTTPBaseURL: cfg.serverAddr, GRPCAddr: cfg.grpcAddr, APIKey: cfg.apiKey, Transport: cfg.transport})
			if err != nil {
				return err
			}
			sessions, err := c.ListSessions(cmd.Context())
			if err != nil {
				return err
			}
			return printJSON(cmd, sessions)
		},
	}
	return cmd
}

func newSessionInfoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info SESSION_ID",
		Short: "Show session info",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{HTTPBaseURL: cfg.serverAddr, GRPCAddr: cfg.grpcAddr, APIKey: cfg.apiKey, Transport: cfg.transport})
			if err != nil {
				return err
			}
			s, err := c.GetSession(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return printJSON(cmd, s)
		},
	}
	return cmd
}

func newSessionDestroyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "destroy SESSION_ID",
		Short: "Destroy a session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{HTTPBaseURL: cfg.serverAddr, GRPCAddr: cfg.grpcAddr, APIKey: cfg.apiKey, Transport: cfg.transport})
			if err != nil {
				return err
			}
			if err := c.DestroySession(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "ok")
			return nil
		},
	}
	return cmd
}

func newSessionUpdateCmd() *cobra.Command {
	var cwd string
	var setEnv []string
	var unsetEnv []string
	cmd := &cobra.Command{
		Use:   "update SESSION_ID",
		Short: "Update session state (cwd/env) without exec",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			patch := types.SessionPatchRequest{
				Cwd:   cwd,
				Env:   map[string]string{},
				Unset: unsetEnv,
			}
			for _, kv := range setEnv {
				k, v, ok := strings.Cut(kv, "=")
				if !ok {
					return fmt.Errorf("invalid --set-env %q (expected KEY=VALUE)", kv)
				}
				patch.Env[k] = v
			}

			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{HTTPBaseURL: cfg.serverAddr, GRPCAddr: cfg.grpcAddr, APIKey: cfg.apiKey, Transport: cfg.transport})
			if err != nil {
				return err
			}
			s, err := c.PatchSession(cmd.Context(), args[0], patch)
			if err != nil {
				return err
			}
			return printJSON(cmd, s)
		},
	}
	cmd.Flags().StringVar(&cwd, "cwd", "", "Set session cwd (virtual path under /workspace)")
	cmd.Flags().StringArrayVar(&setEnv, "set-env", nil, "Set env var KEY=VALUE (repeatable)")
	cmd.Flags().StringArrayVar(&unsetEnv, "unset-env", nil, "Unset env var KEY (repeatable)")
	return cmd
}

// LogType represents supported log types for session logs command.
type LogType string

const (
	LogTypeAll  LogType = ""    // Show all log types
	LogTypeLLM  LogType = "llm" // LLM request/response logs
	LogTypeFS   LogType = "fs"  // Filesystem access logs
	LogTypeNet  LogType = "net" // Network access logs
	LogTypeExec LogType = "exec" // Command execution logs
)

// ValidLogTypes returns the list of valid log type values.
func ValidLogTypes() []string {
	return []string{"llm", "fs", "net", "exec"}
}

func newSessionLogsCmd() *cobra.Command {
	var logType string

	cmd := &cobra.Command{
		Use:   "logs SESSION_ID",
		Short: "View session logs",
		Long: `View session logs with optional filtering by type.

Supported log types:
  llm   - LLM request/response logs (from embedded proxy)
  fs    - Filesystem access logs
  net   - Network access logs
  exec  - Command execution logs

When no type is specified, all log types are shown.`,
		Example: `  # View all logs for a session
  agentsh session logs abc123

  # View only LLM request/response logs
  agentsh session logs abc123 --type=llm

  # View only filesystem logs
  agentsh session logs abc123 --type=fs`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID := args[0]

			// Validate log type if specified
			if logType != "" {
				valid := false
				for _, t := range ValidLogTypes() {
					if logType == t {
						valid = true
						break
					}
				}
				if !valid {
					return fmt.Errorf("invalid log type %q: must be one of %v", logType, ValidLogTypes())
				}
			}

			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{HTTPBaseURL: cfg.serverAddr, GRPCAddr: cfg.grpcAddr, APIKey: cfg.apiKey, Transport: cfg.transport})
			if err != nil {
				return err
			}

			// Handle LLM logs specially - they come from llm-requests.jsonl
			if logType == string(LogTypeLLM) {
				return DisplayLLMLogs(cmd.OutOrStdout(), sessionID, false)
			}

			// For other log types (or all), query session events via API
			// Query events from the session
			evs, err := c.QuerySessionEvents(cmd.Context(), sessionID, nil)
			if err != nil {
				return err
			}

			// Filter by type if specified
			if logType != "" {
				var filtered []types.Event
				for _, ev := range evs {
					if ev.Type == logType {
						filtered = append(filtered, ev)
					}
				}
				evs = filtered
			}

			return printJSON(cmd, evs)
		},
	}

	cmd.Flags().StringVar(&logType, "type", "", "Filter logs by type (llm, fs, net, exec)")

	return cmd
}

func printJSON(cmd *cobra.Command, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(cmd.OutOrStdout(), string(b))
	return err
}
