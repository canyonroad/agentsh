package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/policygen"
	"github.com/agentsh/agentsh/pkg/types"
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

	// Generate subcommand
	var (
		genOutput       string
		genName         string
		genThreshold    int
		genIncludeBlock bool
		genArgPatterns  bool
		genDirectDB     bool
		genDBPath       string
	)

	generateCmd := &cobra.Command{
		Use:   "generate <session-id|latest>",
		Short: "Generate a policy from session activity",
		Long: `Generate a restrictive policy based on observed session behavior.

This command analyzes events from a session and creates a policy that
would allow only the operations that were performed during that session.

Examples:
  # Generate policy from latest session
  agentsh policy generate latest --output=ci-policy.yaml

  # Generate with custom name and threshold
  agentsh policy generate abc123 --name=production-build --threshold=10

  # Quick preview to stdout
  agentsh policy generate latest`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionArg := args[0]
			ctx := cmd.Context()

			var sess types.Session
			var events []types.Event
			var err error

			if genDirectDB {
				if genDBPath == "" {
					genDBPath = getenvDefault("AGENTSH_DB_PATH", "./data/events.db")
				}
				sess, events, err = loadReportFromDB(ctx, genDBPath, sessionArg)
			} else {
				cfg := getClientConfig(cmd)
				sess, events, err = loadReportFromAPI(ctx, cfg, sessionArg)
			}

			if err != nil {
				return err
			}

			// Create generator with mock store
			store := &memoryEventStore{events: events}
			gen := policygen.NewGenerator(store)

			opts := policygen.Options{
				Name:           genName,
				Threshold:      genThreshold,
				IncludeBlocked: genIncludeBlock,
				ArgPatterns:    genArgPatterns,
			}

			if opts.Name == "" {
				opts.Name = fmt.Sprintf("generated-%s", truncateSessionID(sess.ID))
			}

			policy, err := gen.Generate(ctx, sess, opts)
			if err != nil {
				return fmt.Errorf("generate policy: %w", err)
			}

			yaml := policygen.FormatYAML(policy, opts.Name)

			if genOutput != "" {
				if err := os.WriteFile(genOutput, []byte(yaml), 0644); err != nil {
					return fmt.Errorf("write output file: %w", err)
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "Policy written to %s\n", genOutput)
			} else {
				fmt.Fprint(cmd.OutOrStdout(), yaml)
			}

			return nil
		},
	}

	generateCmd.Flags().StringVar(&genOutput, "output", "", "Output file path (default: stdout)")
	generateCmd.Flags().StringVar(&genName, "name", "", "Policy name (default: generated-<session-id>)")
	generateCmd.Flags().IntVar(&genThreshold, "threshold", 5, "Files in same dir before collapsing to glob")
	generateCmd.Flags().BoolVar(&genIncludeBlock, "include-blocked", true, "Include blocked ops as comments")
	generateCmd.Flags().BoolVar(&genArgPatterns, "arg-patterns", true, "Generate arg patterns for risky commands")
	generateCmd.Flags().BoolVar(&genDirectDB, "direct-db", false, "Query local database directly (offline mode)")
	generateCmd.Flags().StringVar(&genDBPath, "db-path", "", "Path to events database")

	cmd.AddCommand(generateCmd)

	return cmd
}

func resolvePolicyDir(configPath, override string) (string, error) {
	if strings.TrimSpace(override) != "" {
		return override, nil
	}
	cfg, _, err := loadLocalConfig(configPath)
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

func truncateSessionID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
