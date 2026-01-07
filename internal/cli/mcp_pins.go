package cli

import (
	"fmt"
	"os"

	"github.com/agentsh/agentsh/internal/mcpinspect"
	"github.com/spf13/cobra"
)

func newMCPPinsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pins",
		Short: "Manage MCP tool version pins",
	}

	cmd.AddCommand(newMCPPinsListCmd())
	cmd.AddCommand(newMCPPinsTrustCmd())
	cmd.AddCommand(newMCPPinsDiffCmd())
	cmd.AddCommand(newMCPPinsResetCmd())

	return cmd
}

func getPinStore() (*mcpinspect.PinStore, error) {
	path := os.Getenv("AGENTSH_PINS_PATH")
	if path == "" {
		path = getenvDefault("AGENTSH_DATA_DIR", "./data") + "/mcp_pins.db"
	}
	return mcpinspect.NewPinStore(path)
}

func newMCPPinsListCmd() *cobra.Command {
	var (
		serverID string
		jsonOut  bool
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List pinned tool versions",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := getPinStore()
			if err != nil {
				return fmt.Errorf("open pin store: %w", err)
			}
			defer store.Close()

			pins, err := store.List(serverID)
			if err != nil {
				return err
			}

			if len(pins) == 0 {
				cmd.Println("No pins found")
				return nil
			}

			if jsonOut {
				return printJSON(cmd, pins)
			}

			cmd.Println("SERVER              TOOL                HASH                     TRUSTED AT")
			for _, p := range pins {
				cmd.Printf("%-19s %-19s %-24s %s\n",
					truncate(p.ServerID, 19),
					truncate(p.ToolName, 19),
					truncate(p.Hash, 24),
					p.TrustedAt.Format("2006-01-02 15:04:05"),
				)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&serverID, "server", "", "Filter by server ID")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")

	return cmd
}

func newMCPPinsTrustCmd() *cobra.Command {
	var (
		serverID string
		toolName string
		hash     string
	)

	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Pin a tool at its current or specified hash",
		RunE: func(cmd *cobra.Command, args []string) error {
			if serverID == "" || toolName == "" {
				return fmt.Errorf("--server and --tool are required")
			}

			store, err := getPinStore()
			if err != nil {
				return fmt.Errorf("open pin store: %w", err)
			}
			defer store.Close()

			if hash == "" {
				return fmt.Errorf("--hash is required (tool hash from tools list)")
			}

			if err := store.Trust(serverID, toolName, hash); err != nil {
				return err
			}

			cmd.Printf("Pinned %s:%s at %s\n", serverID, toolName, truncate(hash, 16))
			return nil
		},
	}

	cmd.Flags().StringVar(&serverID, "server", "", "Server ID")
	cmd.Flags().StringVar(&toolName, "tool", "", "Tool name")
	cmd.Flags().StringVar(&hash, "hash", "", "Content hash to pin")

	return cmd
}

func newMCPPinsDiffCmd() *cobra.Command {
	var (
		serverID string
		toolName string
	)

	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Show difference between pinned and current tool version",
		RunE: func(cmd *cobra.Command, args []string) error {
			if serverID == "" || toolName == "" {
				return fmt.Errorf("--server and --tool are required")
			}

			store, err := getPinStore()
			if err != nil {
				return fmt.Errorf("open pin store: %w", err)
			}
			defer store.Close()

			pin, err := store.Get(serverID, toolName)
			if err != nil {
				return err
			}
			if pin == nil {
				return fmt.Errorf("tool %s:%s is not pinned", serverID, toolName)
			}

			cmd.Printf("Pinned hash: %s\n", pin.Hash)
			cmd.Printf("Trusted at:  %s\n", pin.TrustedAt.Format("2006-01-02 15:04:05"))
			cmd.Println("\nNote: To see current hash, use 'agentsh mcp tools --server <server>'")
			return nil
		},
	}

	cmd.Flags().StringVar(&serverID, "server", "", "Server ID")
	cmd.Flags().StringVar(&toolName, "tool", "", "Tool name")

	return cmd
}

func newMCPPinsResetCmd() *cobra.Command {
	var (
		serverID string
		toolName string
		all      bool
	)

	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Remove a tool's version pin",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := getPinStore()
			if err != nil {
				return fmt.Errorf("open pin store: %w", err)
			}
			defer store.Close()

			if all {
				if err := store.ResetAll(); err != nil {
					return err
				}
				cmd.Println("All pins removed")
				return nil
			}

			if serverID == "" {
				return fmt.Errorf("--server is required (or use --all)")
			}

			if toolName == "" {
				if err := store.ResetServer(serverID); err != nil {
					return err
				}
				cmd.Printf("All pins for server %s removed\n", serverID)
				return nil
			}

			if err := store.Reset(serverID, toolName); err != nil {
				return err
			}
			cmd.Printf("Pin for %s:%s removed\n", serverID, toolName)
			return nil
		},
	}

	cmd.Flags().StringVar(&serverID, "server", "", "Server ID")
	cmd.Flags().StringVar(&toolName, "tool", "", "Tool name")
	cmd.Flags().BoolVar(&all, "all", false, "Remove all pins")

	return cmd
}
