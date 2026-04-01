//go:build darwin

package cli

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/platform/darwin"
	"github.com/spf13/cobra"
)

func newActivateExtensionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "activate-extension",
		Short: "Activate the AgentSH system extension",
		Long:  "Submits an activation request for the AgentSH system extension. Requires user approval in System Settings.",
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr := darwin.NewSysExtManager()

			fmt.Println("Activating AgentSH system extension...")
			result, err := mgr.Activate()

			switch result {
			case darwin.ActivateOK:
				fmt.Println("System extension activated successfully.")
				return nil
			case darwin.ActivateNeedsApproval:
				fmt.Println("System extension requires approval.")
				fmt.Println("Open System Settings → General → Login Items & Extensions")
				fmt.Println("and allow the AgentSH extension.")
				return nil
			default:
				if err != nil {
					return fmt.Errorf("activation failed: %w", err)
				}
				return fmt.Errorf("activation failed")
			}
		},
	}
}
