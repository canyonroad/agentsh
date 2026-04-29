package cli

import (
	"github.com/agentsh/agentsh/internal/skillcheck"
	"github.com/agentsh/agentsh/internal/skillcheck/provider"
	"github.com/spf13/cobra"
)

// skillcheckConfig holds optional overrides for the skillcheck cobra layer,
// used primarily to inject a TrashDir in tests.
type skillcheckConfig struct {
	TrashDir string // if empty, restore/list-quarantined use the default (empty, which prints usage)
}

func newSkillcheckCmd() *cobra.Command {
	return newSkillcheckCmdWith(skillcheckConfig{})
}

func newSkillcheckCmdWith(cfg skillcheckConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "skillcheck",
		Short: "Scan, inspect, and manage AI agent skill installations",
		Long: `skillcheck scans AI agent skill directories under ~/.claude/skills/ and
~/.claude/plugins/*/skills/ for security issues.

Subcommands:
  scan <path>        Scan a single skill directory and print its verdict.
  doctor             List configured scan providers and their status.
  list-quarantined   List skills that have been quarantined (Task 16+).
  restore            Restore a quarantined skill (Task 16+).
  cache              Manage the verdict cache (Task 16+).`,
		SilenceUsage: true,
	}

	cmd.AddCommand(
		newSkillcheckScanCmd(),
		newSkillcheckDoctorCmd(),
		newSkillcheckListQuarantinedCmd(),
		newSkillcheckRestoreCmd(cfg.TrashDir),
		newSkillcheckCacheCmd(),
	)
	return cmd
}

func buildDefaultProviders() map[string]skillcheck.ProviderEntry {
	return map[string]skillcheck.ProviderEntry{
		"local": {Provider: provider.NewLocalProvider()},
	}
}

func newSkillcheckScanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan <path>",
		Short: "Scan a skill directory and print its verdict",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cli := &skillcheck.CLI{
				Stdout:    cmd.OutOrStdout(),
				Providers: buildDefaultProviders(),
			}
			code := cli.Run(cmd.Context(), append([]string{"scan"}, args...))
			if code != 0 {
				return &ExitError{code: code}
			}
			return nil
		},
	}
}

func newSkillcheckDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "List configured scan providers and their status",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli := &skillcheck.CLI{
				Stdout:    cmd.OutOrStdout(),
				Providers: buildDefaultProviders(),
			}
			code := cli.Run(cmd.Context(), []string{"doctor"})
			if code != 0 {
				return &ExitError{code: code}
			}
			return nil
		},
	}
}

func newSkillcheckListQuarantinedCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list-quarantined",
		Short: "List quarantined skills (not implemented yet, see Task 16+)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli := &skillcheck.CLI{
				Stdout:    cmd.OutOrStdout(),
				Providers: map[string]skillcheck.ProviderEntry{},
			}
			cli.Run(cmd.Context(), []string{"list-quarantined"})
			return nil
		},
	}
}

func newSkillcheckRestoreCmd(trashDir string) *cobra.Command {
	return &cobra.Command{
		Use:   "restore",
		Short: "Restore a quarantined skill (not implemented yet, see Task 16+)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli := &skillcheck.CLI{
				Stdout:    cmd.OutOrStdout(),
				Providers: map[string]skillcheck.ProviderEntry{},
				TrashDir:  trashDir,
			}
			cli.Run(cmd.Context(), append([]string{"restore"}, args...))
			return nil
		},
	}
}

func newSkillcheckCacheCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Manage the verdict cache (not implemented yet, see Task 16+)",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "prune",
		Short: "Prune stale cache entries (not implemented yet, see Task 16+)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli := &skillcheck.CLI{
				Stdout:    cmd.OutOrStdout(),
				Providers: map[string]skillcheck.ProviderEntry{},
			}
			cli.Run(cmd.Context(), append([]string{"cache", "prune"}, args...))
			return nil
		},
	})
	// Running `cache` without a subcommand also returns the placeholder.
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		cli := &skillcheck.CLI{
			Stdout:    cmd.OutOrStdout(),
			Providers: map[string]skillcheck.ProviderEntry{},
		}
		cli.Run(cmd.Context(), []string{"cache"})
		return nil
	}
	return cmd
}
