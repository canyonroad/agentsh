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
			c := client.New(cfg.serverAddr, cfg.apiKey)
			if err := c.KillCommand(cmd.Context(), args[0], args[1]); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "ok")
			return nil
		},
	}
	return cmd
}
