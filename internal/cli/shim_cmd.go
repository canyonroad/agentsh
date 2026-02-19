package cli

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

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
	cmd.AddCommand(newShimStatusCmd())
	return cmd
}

func newShimInstallShellCmd() *cobra.Command {
	var root string
	var shimPath string
	var bash bool
	var bashOnly bool
	var iUnderstand bool
	var dryRun bool
	var output string

	c := &cobra.Command{
		Use:   "install-shell",
		Short: "Install /bin/sh (and optionally /bin/bash) shim under a rootfs",
		RunE: func(cmd *cobra.Command, args []string) error {
			if shimPath == "" {
				return fmt.Errorf("--shim is required")
			}
			if bash && bashOnly {
				return fmt.Errorf("--bash and --bash-only are mutually exclusive")
			}
			if isHostRoot(root) && !iUnderstand && !dryRun {
				return fmt.Errorf("refusing to modify host rootfs (%q); pass --i-understand-this-modifies-the-host to continue", root)
			}
			opts := shim.InstallShellShimOptions{
				Root:        root,
				ShimPath:    shimPath,
				InstallBash: bash || bashOnly,
				BashOnly:    bashOnly,
			}
			if dryRun {
				p, err := shim.PlanInstallShellShim(opts)
				if err != nil {
					return err
				}
				return printShimPlan(cmd, p, output)
			}
			return shim.InstallShellShim(opts)
		},
		DisableFlagsInUseLine: true,
	}

	c.Flags().StringVar(&root, "root", "/", "Root filesystem to modify")
	c.Flags().StringVar(&shimPath, "shim", "", "Path to agentsh shell shim binary (agentsh-shell-shim)")
	c.Flags().BoolVar(&bash, "bash", false, "Also install shim for /bin/bash if present")
	c.Flags().BoolVar(&bashOnly, "bash-only", false, "Install shim only for /bin/bash, leaving /bin/sh untouched")
	c.Flags().BoolVar(&iUnderstand, "i-understand-this-modifies-the-host", false, "Allow modifying the host filesystem when --root=/")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "Show planned actions without modifying the filesystem")
	c.Flags().StringVar(&output, "output", "shell", "Output format: shell|json")
	return c
}

func newShimUninstallShellCmd() *cobra.Command {
	var root string
	var bash bool
	var iUnderstand bool
	var dryRun bool
	var output string

	c := &cobra.Command{
		Use:   "uninstall-shell",
		Short: "Restore /bin/sh.real (and optionally /bin/bash.real) under a rootfs",
		RunE: func(cmd *cobra.Command, args []string) error {
			if isHostRoot(root) && !iUnderstand && !dryRun {
				return fmt.Errorf("refusing to modify host rootfs (%q); pass --i-understand-this-modifies-the-host to continue", root)
			}
			if dryRun {
				p, err := shim.PlanUninstallShellShim(shim.InstallShellShimOptions{
					Root:        root,
					InstallBash: bash,
				})
				if err != nil {
					return err
				}
				return printShimPlan(cmd, p, output)
			}
			return shim.UninstallShellShim(shim.InstallShellShimOptions{
				Root:        root,
				InstallBash: bash,
			})
		},
		DisableFlagsInUseLine: true,
	}

	c.Flags().StringVar(&root, "root", "/", "Root filesystem to modify")
	c.Flags().BoolVar(&bash, "bash", false, "Also restore /bin/bash.real if present")
	c.Flags().BoolVar(&iUnderstand, "i-understand-this-modifies-the-host", false, "Allow modifying the host filesystem when --root=/")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "Show planned actions without modifying the filesystem")
	c.Flags().StringVar(&output, "output", "shell", "Output format: shell|json")
	return c
}

func newShimStatusCmd() *cobra.Command {
	var root string
	var shimPath string
	var bash bool
	var output string

	c := &cobra.Command{
		Use:   "status",
		Short: "Show shim status under a rootfs",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := shim.GetShellShimStatus(root, shimPath, bash)
			if err != nil {
				return err
			}
			switch strings.ToLower(strings.TrimSpace(output)) {
			case "", "shell":
				printTarget := func(ts shim.ShellShimTargetStatus) {
					fmt.Fprintf(cmd.OutOrStdout(),
						"%s: state=%s target=%s exists=%v type=%s real_exists=%v shim_matches=%v\n",
						ts.Name, ts.State, ts.TargetPath, ts.TargetExists, ts.TargetType, ts.RealExists, ts.ShimMatches,
					)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "root=%s\n", st.Root)
				if st.ShimPath != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "shim=%s\n", st.ShimPath)
				}
				printTarget(st.Sh)
				if st.Bash != nil {
					printTarget(*st.Bash)
				}
				return nil
			case "json":
				return printJSON(cmd, st)
			default:
				return fmt.Errorf("invalid --output %q (expected shell|json)", output)
			}
		},
		DisableFlagsInUseLine: true,
	}
	c.Flags().StringVar(&root, "root", "/", "Root filesystem to inspect")
	c.Flags().StringVar(&shimPath, "shim", "", "Optional shim binary path (enables shim byte comparison)")
	c.Flags().BoolVar(&bash, "bash", false, "Include /bin/bash status")
	c.Flags().StringVar(&output, "output", "shell", "Output format: shell|json")
	return c
}

func isHostRoot(root string) bool {
	root = strings.TrimSpace(root)
	if root == "" {
		return true
	}
	clean := filepath.Clean(root)
	return clean == string(filepath.Separator)
}

func printShimPlan(cmd *cobra.Command, p *shim.ShellShimPlan, output string) error {
	switch strings.ToLower(strings.TrimSpace(output)) {
	case "", "shell":
		for _, a := range p.Actions {
			switch a.Op {
			case "rename":
				fmt.Fprintf(cmd.OutOrStdout(), "rename %s -> %s\n", a.From, a.To)
			case "write":
				fmt.Fprintf(cmd.OutOrStdout(), "write %s (%s)\n", a.Path, a.Note)
			case "remove":
				fmt.Fprintf(cmd.OutOrStdout(), "remove %s (%s)\n", a.Path, a.Note)
			case "skip":
				fmt.Fprintf(cmd.OutOrStdout(), "skip %s (%s)\n", a.Path, a.Note)
			default:
				b, _ := json.Marshal(a)
				fmt.Fprintf(cmd.OutOrStdout(), "note %s\n", string(b))
			}
		}
		return nil
	case "json":
		return printJSON(cmd, p)
	default:
		return fmt.Errorf("invalid --output %q (expected shell|json)", output)
	}
}
