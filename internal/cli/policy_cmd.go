package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/spf13/cobra"
)

func newPolicyCmd() *cobra.Command {
	var configPath string
	var dir string

	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage policies",
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "Config file path (defaults to AGENTSH_CONFIG or config.yml)")
	cmd.PersistentFlags().StringVar(&dir, "dir", "", "Policies directory (overrides config policies.dir)")

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List policies in the policies directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			pdir, err := resolvePolicyDir(configPath, dir)
			if err != nil {
				return err
			}
			entries, err := os.ReadDir(pdir)
			if err != nil {
				return err
			}
			var names []string
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				n := e.Name()
				if strings.HasSuffix(n, ".yml") || strings.HasSuffix(n, ".yaml") {
					names = append(names, n)
				}
			}
			sort.Strings(names)
			return printJSON(cmd, map[string]any{"dir": pdir, "policies": names})
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "show NAME_OR_PATH",
		Short: "Show policy as JSON",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pdir, err := resolvePolicyDir(configPath, dir)
			if err != nil {
				return err
			}
			p, err := resolvePolicyPath(pdir, args[0])
			if err != nil {
				return err
			}
			po, err := policy.LoadFromFile(p)
			if err != nil {
				return err
			}
			return printJSON(cmd, po)
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "validate NAME_OR_PATH",
		Short: "Validate a policy file (parse + compile)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pdir, err := resolvePolicyDir(configPath, dir)
			if err != nil {
				return err
			}
			p, err := resolvePolicyPath(pdir, args[0])
			if err != nil {
				return err
			}
			po, err := policy.LoadFromFile(p)
			if err != nil {
				return err
			}
			if _, err := policy.NewEngine(po, false); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "ok")
			return nil
		},
	})

	return cmd
}

func resolvePolicyDir(configPath, override string) (string, error) {
	if strings.TrimSpace(override) != "" {
		return override, nil
	}
	cfg, err := loadLocalConfig(configPath)
	if err == nil && strings.TrimSpace(cfg.Policies.Dir) != "" {
		return cfg.Policies.Dir, nil
	}
	// If no config is available, fall back to local conventions.
	if _, err2 := os.Stat("configs"); err2 == nil {
		return "configs", nil
	}
	return ".", nil
}

func resolvePolicyPath(dir, nameOrPath string) (string, error) {
    if nameOrPath == "" {
        return "", fmt.Errorf("policy name/path is required")
    }
    if strings.ContainsRune(nameOrPath, os.PathSeparator) || strings.HasSuffix(nameOrPath, ".yml") || strings.HasSuffix(nameOrPath, ".yaml") {
        p := nameOrPath
        if !filepath.IsAbs(p) {
            p = filepath.Clean(p)
        }
        if _, err := os.Stat(p); err == nil {
            return p, nil
        }
        // If it's a relative path inside dir, try that.
        p2 := filepath.Join(dir, nameOrPath)
        if _, err := os.Stat(p2); err == nil {
            return p2, nil
        }
    }
    // CLI resolution remains permissive for direct paths; allowlist enforcement is server-side.
    return policy.ResolvePolicyPath(dir, nameOrPath)
}
