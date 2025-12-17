package cli

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/spf13/cobra"
)

func newApproveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "approve",
		Short: "List/resolve pending approvals",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List pending approvals",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{HTTPBaseURL: cfg.serverAddr, GRPCAddr: cfg.grpcAddr, APIKey: cfg.apiKey, Transport: cfg.transport})
			if err != nil {
				return err
			}
			approvals, err := c.ListApprovals(cmd.Context())
			if err != nil {
				return err
			}
			return printJSON(cmd, approvals)
		},
	})

	var allow bool
	var deny bool
	var reason string
	resolveCmd := &cobra.Command{
		Use:   "resolve APPROVAL_ID",
		Short: "Approve or deny a pending approval",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if allow == deny {
				return fmt.Errorf("choose exactly one of --allow or --deny")
			}
			decision := "deny"
			if allow {
				decision = "approve"
			}
			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{HTTPBaseURL: cfg.serverAddr, GRPCAddr: cfg.grpcAddr, APIKey: cfg.apiKey, Transport: cfg.transport})
			if err != nil {
				return err
			}
			if err := c.ResolveApproval(cmd.Context(), args[0], decision, reason); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "ok")
			return nil
		},
	}
	resolveCmd.Flags().BoolVar(&allow, "allow", false, "Approve")
	resolveCmd.Flags().BoolVar(&deny, "deny", false, "Deny")
	resolveCmd.Flags().StringVar(&reason, "reason", "", "Reason (optional)")
	cmd.AddCommand(resolveCmd)

	return cmd
}
