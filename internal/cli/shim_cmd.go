package cli

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/shim"
	"github.com/spf13/cobra"
)

func newShimCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shim",
		Short: "Manage shell shim installation (advanced)",
	}
	cmd.AddCommand(newShimInstallShellCmd())
	cmd.AddCommand(newShimUninstallShellCmd())
	return cmd
}

func newShimInstallShellCmd() *cobra.Command {
	var root string
	var shimPath string
	var bash bool

	c := &cobra.Command{
		Use:   "install-shell",
		Short: "Install /bin/sh (and optionally /bin/bash) shim under a rootfs",
		RunE: func(cmd *cobra.Command, args []string) error {
			if shimPath == "" {
				return fmt.Errorf("--shim is required")
			}
			return shim.InstallShellShim(shim.InstallShellShimOptions{
				Root:        root,
				ShimPath:    shimPath,
				InstallBash: bash,
			})
		},
		DisableFlagsInUseLine: true,
	}

	c.Flags().StringVar(&root, "root", "/", "Root filesystem to modify")
	c.Flags().StringVar(&shimPath, "shim", "", "Path to agentsh shell shim binary (agentsh-shell-shim)")
	c.Flags().BoolVar(&bash, "bash", false, "Also install shim for /bin/bash if present")
	return c
}

func newShimUninstallShellCmd() *cobra.Command {
	var root string
	var bash bool

	c := &cobra.Command{
		Use:   "uninstall-shell",
		Short: "Restore /bin/sh.real (and optionally /bin/bash.real) under a rootfs",
		RunE: func(cmd *cobra.Command, args []string) error {
			return shim.UninstallShellShim(shim.InstallShellShimOptions{
				Root:        root,
				InstallBash: bash,
			})
		},
		DisableFlagsInUseLine: true,
	}

	c.Flags().StringVar(&root, "root", "/", "Root filesystem to modify")
	c.Flags().BoolVar(&bash, "bash", false, "Also restore /bin/bash.real if present")
	return c
}
