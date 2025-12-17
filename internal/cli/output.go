package cli

import (
	"fmt"
	"strconv"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/spf13/cobra"
)

func newOutputCmd() *cobra.Command {
	var stream string
	var offset int64
	var limit int64
	cmd := &cobra.Command{
		Use:   "output SESSION_ID COMMAND_ID",
		Short: "Fetch paginated command output",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID := args[0]
			commandID := args[1]
			cfg := getClientConfig(cmd)
			c, err := client.NewForCLI(client.CLIOptions{HTTPBaseURL: cfg.serverAddr, GRPCAddr: cfg.grpcAddr, APIKey: cfg.apiKey, Transport: cfg.transport})
			if err != nil {
				return err
			}
			out, err := c.OutputChunk(cmd.Context(), sessionID, commandID, stream, offset, limit)
			if err != nil {
				return err
			}
			// Print only the data chunk by default (like `tail`/pagination helper).
			if data, ok := out["data"].(string); ok {
				_, _ = fmt.Fprint(cmd.OutOrStdout(), data)
				if hasMore, ok := out["has_more"].(bool); ok && hasMore {
					if total, ok := out["total_bytes"].(float64); ok {
						next := offset + int64(len(data))
						_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "\n-- more -- offset=%s total=%s\n", strconv.FormatInt(next, 10), strconv.FormatInt(int64(total), 10))
					}
				}
				return nil
			}
			return printJSON(cmd, out)
		},
	}
	cmd.Flags().StringVar(&stream, "stream", "stdout", "stdout|stderr")
	cmd.Flags().Int64Var(&offset, "offset", 0, "Byte offset")
	cmd.Flags().Int64Var(&limit, "limit", 64*1024, "Max bytes to return")
	return cmd
}
