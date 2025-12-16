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
			sep := -1
			for i, a := range args {
				if a == "--" {
					sep = i
					break
				}
			}
			if sep == -1 || sep == len(args)-1 {
				return cmd.Help()
			}

			sessionID := args[0]
			command := args[sep+1]
			cmdArgs := args[sep+2:]

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
