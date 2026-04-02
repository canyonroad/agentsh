//go:build darwin

package cli

import (
	"fmt"
	"os/exec"
	"time"

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

			// Pre-create the policy socket directory so the server doesn't
			// need root at runtime. Uses root:staff 0775 — all normal macOS
			// users are in the staff group and can create the socket file.
			ensurePolicySocketDir()

			fmt.Println("Activating AgentSH system extension...")
			result, err := mgr.Activate()

			switch result {
			case darwin.ActivateOK:
				fmt.Println("System extension activated successfully.")
				openFullDiskAccessSettings()
				return nil
			case darwin.ActivateNeedsApproval:
				fmt.Println("System extension requires approval.")
				fmt.Println("Opening System Settings — please allow the AgentSH extension.")
				openEndpointSecuritySettings()
				// Wait a bit then prompt for FDA
				fmt.Println("\nAfter approving the extension, you also need to grant Full Disk Access.")
				fmt.Println("Press Enter when you've approved the extension to open Full Disk Access settings...")
				fmt.Scanln()
				openFullDiskAccessSettings()
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

// ensurePolicySocketDir creates /Library/Application Support/agentsh/ with
// group-writable permissions so the server can create the policy socket
// without running as root. This path persists across reboots (unlike /var/run).
func ensurePolicySocketDir() {
	dir := "/Library/Application Support/agentsh"
	if err := exec.Command("mkdir", "-p", dir).Run(); err != nil {
		fmt.Printf("Warning: could not create %s: %v\n", dir, err)
		return
	}
	// root:staff 0775 — any user in staff group can create the socket
	exec.Command("chown", "root:staff", dir).Run()
	exec.Command("chmod", "775", dir).Run()
}

// openFullDiskAccessSettings opens System Settings to the Full Disk Access pane.
func openFullDiskAccessSettings() {
	fmt.Println("Opening Full Disk Access settings...")
	fmt.Println("Please enable Full Disk Access for the AgentSH system extension.")
	// Small delay to let the extension launch before user navigates
	time.Sleep(500 * time.Millisecond)
	exec.Command("open", "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles").Run()
}

// openEndpointSecuritySettings opens System Settings to the Endpoint Security Extensions pane.
func openEndpointSecuritySettings() {
	exec.Command("open", "x-apple.systempreferences:com.apple.preference.security?Privacy_EndpointSecurity").Run()
}
