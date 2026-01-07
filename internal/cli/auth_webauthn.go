package cli

import (
	"encoding/base64"
	"fmt"

	"github.com/spf13/cobra"
)

func newAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Authentication management commands",
	}
	cmd.AddCommand(newAuthWebAuthnCmd())
	return cmd
}

func newAuthWebAuthnCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "webauthn",
		Short: "WebAuthn credential management",
	}
	cmd.AddCommand(newWebAuthnListCmd())
	cmd.AddCommand(newWebAuthnRegisterCmd())
	cmd.AddCommand(newWebAuthnDeleteCmd())
	return cmd
}

func newWebAuthnListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List registered WebAuthn credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO: Implement via API call
			fmt.Fprintln(cmd.OutOrStdout(), "WebAuthn credentials:")
			fmt.Fprintln(cmd.OutOrStdout(), "(API integration pending)")
			return nil
		},
	}
}

func newWebAuthnRegisterCmd() *cobra.Command {
	var name string

	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a new WebAuthn credential (security key)",
		Long: `Register a new WebAuthn credential such as a YubiKey or platform authenticator.

This command initiates a registration ceremony. You will need to:
1. Insert/activate your security key
2. Complete the registration in a browser or via the API

Example:
  agentsh auth webauthn register --name "My YubiKey"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "Starting WebAuthn registration for credential: %s\n", name)
			fmt.Fprintln(cmd.OutOrStdout(), "(Full registration flow requires browser interaction)")
			fmt.Fprintln(cmd.OutOrStdout(), "Use the web UI at http://localhost:18080/auth/webauthn/register")
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Name for the credential (e.g., 'My YubiKey')")
	cmd.MarkFlagRequired("name")

	return cmd
}

func newWebAuthnDeleteCmd() *cobra.Command {
	var credID string

	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a WebAuthn credential",
		RunE: func(cmd *cobra.Command, args []string) error {
			if credID == "" {
				return fmt.Errorf("--credential-id is required")
			}

			// Validate base64
			_, err := base64.StdEncoding.DecodeString(credID)
			if err != nil {
				return fmt.Errorf("invalid credential ID (must be base64): %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Deleting credential: %s\n", credID)
			fmt.Fprintln(cmd.OutOrStdout(), "(API integration pending)")
			return nil
		},
	}

	cmd.Flags().StringVar(&credID, "credential-id", "", "Base64-encoded credential ID to delete")
	cmd.MarkFlagRequired("credential-id")

	return cmd
}
