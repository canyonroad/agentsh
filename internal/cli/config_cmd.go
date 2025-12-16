package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newConfigCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage configuration",
	}
	cmd.PersistentFlags().StringVar(&path, "path", "", "Config file path (defaults to AGENTSH_CONFIG or config.yml)")

	cmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Show resolved config (after defaults and env overrides)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadLocalConfig(path)
			if err != nil {
				return err
			}
			return printJSON(cmd, cfg)
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "validate",
		Short: "Validate config file",
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := loadLocalConfig(path); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "ok")
			return nil
		},
	})

	return cmd
}
