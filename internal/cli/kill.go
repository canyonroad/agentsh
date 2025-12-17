package cli

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/spf13/cobra"
)

func newKillCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kill SESSION_ID COMMAND_ID",
		Short: "Kill a running command in a session",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{HTTPBaseURL: cfg.serverAddr, GRPCAddr: cfg.grpcAddr, APIKey: cfg.apiKey, Transport: cfg.transport})
			if err != nil {
				return err
			}
			if err := c.KillCommand(cmd.Context(), args[0], args[1]); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "ok")
			return nil
		},
	}
	return cmd
}
