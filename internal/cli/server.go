package cli

import (
	"context"
	"fmt"

	"github.com/agentsh/agentsh/internal/server"
	"github.com/spf13/cobra"
)

func newServerCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Start the agentsh server",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			cfg, err := loadLocalConfig(configPath)
			if err != nil {
				return err
			}

			s, err := server.New(cfg)
			if err != nil {
				return err
			}
			defer s.Close()

			fmt.Fprintf(cmd.OutOrStdout(), "agentsh server listening on %s\n", cfg.Server.HTTP.Addr)
			return s.Run(ctx)
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "", "Path to server config YAML (default: ./config.yml, ./config.yaml, or /etc/agentsh/config.yaml)")
	return cmd
}
