package cli

import (
	"strings"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/spf13/cobra"
)

func newExecCmd() *cobra.Command {
	var timeout string
	c := &cobra.Command{
		Use:   "exec SESSION_ID -- COMMAND [ARGS...]",
		Short: "Execute a command in a session",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID := args[0]
			start := 1
			if args[1] == "--" {
				start = 2
			}
			if start >= len(args) {
				return cmd.Help()
			}
			command := args[start]
			cmdArgs := args[start+1:]

			cfg := getClientConfig(cmd)
			c := client.New(cfg.serverAddr, cfg.apiKey)
			resp, err := c.Exec(cmd.Context(), sessionID, types.ExecRequest{
				Command: command,
				Args:    cmdArgs,
				Timeout: strings.TrimSpace(timeout),
			})
			if err != nil {
				return err
			}
			return printJSON(cmd, resp)
		},
		DisableFlagsInUseLine: true,
	}
	c.Flags().StringVar(&timeout, "timeout", "", "Command timeout (e.g. 30s, 5m)")
	return c
}
