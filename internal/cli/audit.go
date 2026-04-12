package cli

import "github.com/spf13/cobra"

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit log management commands",
	}

	cmd.AddCommand(newAuditVerifyCmd())
	cmd.AddCommand(newAuditChainCmd())
	return cmd
}
