package cli

import (
	"encoding/json"
	"fmt"

	"github.com/agentsh/agentsh/internal/client"
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
	cmd.AddCommand(newSessionDestroyCmd())

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
			c := client.New(cfg.serverAddr, cfg.apiKey)
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
			c := client.New(cfg.serverAddr, cfg.apiKey)
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
			c := client.New(cfg.serverAddr, cfg.apiKey)
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
			c := client.New(cfg.serverAddr, cfg.apiKey)
			if err := c.DestroySession(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "ok")
			return nil
		},
	}
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
